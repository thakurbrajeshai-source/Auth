// SecureChannel.cs  (.NET 8+)
// Program.cs wiring:
//   builder.Services.AddMemoryCache();                       // use a shared/encrypted store if you scale out
//   builder.Services.AddSingleton<SecureSessionService>();
//   builder.Services.AddSingleton<IConnectionMultiplexer>(ConnectionMultiplexer.Connect("redis:6379"));
//   builder.Services.AddRateLimiter(o => o.AddFixedWindowLimiter("handshake", x => { x.PermitLimit = 10; x.Window = TimeSpan.FromMinutes(1); }));
//   ...
//   app.UseRateLimiter(); app.UseAuthentication(); app.UseAuthorization();
//   app.UseMiddleware<SecureChannelMiddleware>();            // must run AFTER authentication
//   app.MapControllers();

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;
using StackExchange.Redis;

public sealed record Envelope(string Iv, string Data);
public sealed record HandshakeReq(string ClientPub);
public sealed record HandshakeRes(string Kid, string ServerPub, string Salt, int ExpiresIn);
public sealed record SecureSession(byte[] C2S, byte[] S2C, string UserId);

// ---------------- Session / handshake ----------------
public sealed class SecureSessionService(IMemoryCache cache)
{
    public const int LifetimeSeconds = 1800;
    const string V = "sec-v1";

    public HandshakeRes Create(byte[] clientPub, string userId)
    {
        using var server = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var client = ECDiffieHellman.Create();
        client.ImportSubjectPublicKeyInfo(clientPub, out _);      // throws CryptographicException on garbage

        // Throws if the client key is not on P-256 (curves must match).
        byte[] secret = server.DeriveRawSecretAgreement(client.PublicKey);

        var kid = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));
        var salt = RandomNumberGenerator.GetBytes(32);
        var serverPub = server.ExportSubjectPublicKeyInfo();

        // Must match the client byte-for-byte: SHA256(clientPub || serverPub || kid)
        var transcript = SHA256.HashData(Cat(clientPub, serverPub, Encoding.UTF8.GetBytes(kid)));

        byte[] Derive(string label) => HKDF.DeriveKey(
            HashAlgorithmName.SHA256, secret, 32, salt,
            Cat(Encoding.UTF8.GetBytes($"{V}|{label}|"), transcript));

        var c2s = Derive("c2s");
        var s2c = Derive("s2c");
        CryptographicOperations.ZeroMemory(secret);

        cache.Set("sk:" + kid, new SecureSession(c2s, s2c, userId), TimeSpan.FromSeconds(LifetimeSeconds));

        return new HandshakeRes(kid, Convert.ToBase64String(serverPub), Convert.ToBase64String(salt), LifetimeSeconds);
    }

    public SecureSession? Get(string kid) => cache.TryGetValue("sk:" + kid, out SecureSession? s) ? s : null;
    public void Revoke(string kid) => cache.Remove("sk:" + kid);   // call on logout

    static byte[] Cat(params byte[][] p) => p.SelectMany(x => x).ToArray();
}

[ApiController, Route("api/session")]
public sealed class SessionController(SecureSessionService sessions) : ControllerBase
{
    [HttpPost("key"), Authorize, EnableRateLimiting("handshake")]
    public IActionResult Key(HandshakeReq req)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId is null) return Unauthorized();
        try { return Ok(sessions.Create(Convert.FromBase64String(req.ClientPub), userId)); }
        catch (Exception e) when (e is CryptographicException or FormatException) { return BadRequest(); }
    }
}

// ---------------- Per-request decrypt / encrypt ----------------
public sealed class SecureChannelMiddleware(RequestDelegate next, SecureSessionService sessions, IConnectionMultiplexer redis)
{
    static readonly JsonSerializerOptions J = new(JsonSerializerDefaults.Web);
    const string V = "sec-v1";
    const int SkewSeconds = 60;

    public async Task InvokeAsync(HttpContext ctx)
    {
        var path = ctx.Request.Path;
        if (!path.StartsWithSegments("/api") || path.StartsWithSegments("/api/session")) { await next(ctx); return; }

        // Generic failures only: never tell the caller WHICH check failed.
        string? kid = ctx.Request.Headers["X-Kid"], tsRaw = ctx.Request.Headers["X-Ts"], requestId = ctx.Request.Headers["X-Request-Id"];
        if (kid is null || kid.Length > 32 || requestId is null || requestId.Length > 64 || !long.TryParse(tsRaw, out var ts))
        { ctx.Response.StatusCode = 400; return; }

        var s = sessions.Get(kid);
        if (s is null) { ctx.Response.StatusCode = 440; return; }                 // client re-handshakes

        if (ctx.User.FindFirstValue(ClaimTypes.NameIdentifier) != s.UserId ||
            Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - ts) > SkewSeconds)
        { ctx.Response.StatusCode = 400; return; }

        // ---- decrypt request body (if any). Decrypt BEFORE recording requestId so
        //      unauthenticated callers can't burn IDs. ----
        byte[] plain = [];
        if (ctx.Request.ContentLength is > 0)
        {
            ctx.Features.Get<IHttpMaxRequestBodySizeFeature>()!.MaxRequestBodySize = 1_000_000;

            Envelope? env;
            try { env = await JsonSerializer.DeserializeAsync<Envelope>(ctx.Request.Body, J); }
            catch (JsonException) { env = null; }

            // RawTarget = path+query exactly as sent (Request.Path is already decoded and would not match).
            var raw = ctx.Features.Get<IHttpRequestFeature>()!.RawTarget;
            var aad = Encoding.UTF8.GetBytes($"{V}|c2s|{kid}|{ctx.Request.Method}|{raw}|{ts}|{requestId}");

            if (!TryOpen(s.C2S, env, aad, out plain)) { ctx.Response.StatusCode = 400; return; }
        }

        // ---- replay protection: atomic SET NX with TTL ----
        var fresh = await redis.GetDatabase().StringSetAsync(
            $"rp:{kid}:{requestId}", 1, TimeSpan.FromSeconds(SkewSeconds * 2 + 5), When.NotExists);
        if (!fresh) { ctx.Response.StatusCode = 400; return; }

        ctx.Request.Body = new MemoryStream(plain);
        ctx.Request.ContentLength = plain.Length;
        if (plain.Length > 0) ctx.Request.ContentType = "application/json";

        // ---- run the pipeline, buffer the response, encrypt it ----
        var original = ctx.Response.Body;
        await using var buffer = new MemoryStream();
        ctx.Response.Body = buffer;
        try { await next(ctx); }
        finally { ctx.Response.Body = original; }

        if (buffer.Length > 0)
        {
            // AAD binds direction, session, the request it answers, and the status code.
            var aad = Encoding.UTF8.GetBytes($"{V}|s2c|{kid}|{requestId}|{ctx.Response.StatusCode}");
            var envOut = Seal(s.S2C, buffer.ToArray(), aad);

            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength = null;
            ctx.Response.Headers.CacheControl = "no-store";
            await JsonSerializer.SerializeAsync(ctx.Response.Body, envOut, J);
        }
    }

    static Envelope Seal(byte[] key, byte[] plain, byte[] aad)
    {
        var iv = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[plain.Length];
        var tag = new byte[16];
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(iv, plain, ct, tag, aad);
        return new Envelope(Convert.ToBase64String(iv), Convert.ToBase64String(ct.Concat(tag).ToArray()));
    }

    static bool TryOpen(byte[] key, Envelope? env, byte[] aad, out byte[] plain)
    {
        plain = [];
        if (env is null) return false;
        try
        {
            var iv = Convert.FromBase64String(env.Iv);
            var data = Convert.FromBase64String(env.Data);
            if (iv.Length != 12 || data.Length < 16) return false;

            plain = new byte[data.Length - 16];
            using var gcm = new AesGcm(key, 16);
            gcm.Decrypt(iv, data.AsSpan(0, data.Length - 16), data.AsSpan(data.Length - 16), plain, aad);
            return true;
        }
        catch (Exception e) when (e is CryptographicException or FormatException) { return false; }
    }
}
