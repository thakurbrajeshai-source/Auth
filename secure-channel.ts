// secure-channel.ts  (Angular)
// Register: providers: [{ provide: HTTP_INTERCEPTORS, useClass: SecureInterceptor, multi: true }]
// Put it AFTER your auth interceptor so the handshake request carries the bearer token.

import { Injectable, Injector } from '@angular/core';
import {
  HttpClient, HttpErrorResponse, HttpEvent, HttpHandler, HttpInterceptor,
  HttpRequest, HttpResponse,
} from '@angular/common/http';
import { Observable, catchError, firstValueFrom, from, of, switchMap, throwError } from 'rxjs';

const V = 'sec-v1';
const enc = new TextEncoder();
const dec = new TextDecoder();

interface Envelope { iv: string; data: string }
interface HandshakeRes { kid: string; serverPub: string; salt: string; expiresIn: number }
interface Session { kid: string; c2s: CryptoKey; s2c: CryptoKey; expiresAt: number }

const toB64 = (buf: ArrayBuffer | Uint8Array): string => {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
};
const fromB64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

@Injectable({ providedIn: 'root' })
export class SecureChannel {
  private session?: Session;
  private pending?: Promise<Session>;

  // Injector (not HttpClient) avoids the circular dependency interceptor -> HttpClient -> interceptor.
  constructor(private injector: Injector) {}

  reset() { this.session = undefined; }

  async getSession(): Promise<Session> {
    if (this.session && Date.now() < this.session.expiresAt) return this.session;
    return (this.pending ??= this.handshake().finally(() => (this.pending = undefined)));
  }

  // ---------- 1) Handshake ----------
  private async handshake(): Promise<Session> {
    const http = this.injector.get(HttpClient);

    const kp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']); // private key non-extractable
    const clientPub = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));

    const res = await firstValueFrom(
      http.post<HandshakeRes>('/api/session/key', { clientPub: toB64(clientPub) }));

    const serverPub = fromB64(res.serverPub);
    const serverKey = await crypto.subtle.importKey(
      'spki', serverPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const secret = await crypto.subtle.deriveBits({ name: 'ECDH', public: serverKey }, kp.privateKey, 256);

    // Transcript binds the keys to this exact handshake (both public keys + kid).
    const transcript = new Uint8Array(await crypto.subtle.digest(
      'SHA-256', concat(clientPub, serverPub, enc.encode(res.kid))));

    const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
    const salt = fromB64(res.salt);
    const derive = (label: 'c2s' | 's2c', usage: KeyUsage) =>
      crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt, info: concat(enc.encode(`${V}|${label}|`), transcript) },
        ikm, { name: 'AES-GCM', length: 256 }, false, [usage]);

    this.session = {
      kid: res.kid,
      c2s: await derive('c2s', 'encrypt'),
      s2c: await derive('s2c', 'decrypt'),
      expiresAt: Date.now() + res.expiresIn * 1000 * 0.8, // renew before server expiry
    };
    return this.session;
  }

  // ---------- 2) Request encryption ----------
  async encryptRequest(req: HttpRequest<unknown>) {
    const s = await this.getSession();
    const requestId = crypto.randomUUID();
    const ts = Math.floor(Date.now() / 1000).toString();
    const headers = { 'X-Kid': s.kid, 'X-Ts': ts, 'X-Request-Id': requestId };

    let body: Envelope | null = null;
    if (req.body !== null && req.body !== undefined) {
      const aad = enc.encode(`${V}|c2s|${s.kid}|${req.method}|${req.urlWithParams}|${ts}|${requestId}`);
      body = await this.seal(s.c2s, enc.encode(JSON.stringify(req.body)), aad);
    }
    return { s, requestId, headers, body };
  }

  // ---------- 3) Response decryption ----------
  async decryptBody(env: Envelope, status: number, requestId: string, s: Session): Promise<unknown> {
    const aad = enc.encode(`${V}|s2c|${s.kid}|${requestId}|${status}`);
    const plain = await this.open(s.s2c, env, aad);
    return plain.length ? JSON.parse(dec.decode(plain)) : null;
  }

  private async seal(key: CryptoKey, plain: Uint8Array, aad: Uint8Array): Promise<Envelope> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plain); // ct || 16-byte tag
    return { iv: toB64(iv), data: toB64(ct) };
  }

  private async open(key: CryptoKey, env: Envelope, aad: Uint8Array): Promise<Uint8Array> {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(env.iv), additionalData: aad, tagLength: 128 },
      key, fromB64(env.data));
    return new Uint8Array(pt);
  }
}

@Injectable()
export class SecureInterceptor implements HttpInterceptor {
  constructor(private injector: Injector) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (!req.url.startsWith('/api/') || req.url.startsWith('/api/session/')) return next.handle(req);
    return this.run(req, next, true);
  }

  private run(req: HttpRequest<any>, next: HttpHandler, canRetry: boolean): Observable<HttpEvent<any>> {
    const ch = this.injector.get(SecureChannel);

    return from(ch.encryptRequest(req)).pipe(
      switchMap(({ s, requestId, headers, body }) =>
        next.handle(req.clone({ body, setHeaders: headers, responseType: 'json' })).pipe(
          switchMap(ev => {
            if (ev instanceof HttpResponse && ev.body?.iv && ev.body?.data) {
              return from(ch.decryptBody(ev.body, ev.status, requestId, s))
                .pipe(switchMap(plain => of(ev.clone({ body: plain }))));
            }
            return of(ev);
          }),
          catchError((err: unknown) => {
            if (err instanceof HttpErrorResponse) {
              // Server forgot/expired our session: re-handshake once and retry.
              if (err.status === 440 && canRetry) { ch.reset(); return this.run(req, next, false); }
              // Encrypted error body (e.g. validation errors).
              if (err.error?.iv && err.error?.data) {
                return from(ch.decryptBody(err.error, err.status, requestId, s)).pipe(
                  switchMap(plain => throwError(() => new HttpErrorResponse({
                    error: plain, headers: err.headers, status: err.status,
                    statusText: err.statusText, url: err.url ?? undefined,
                  }))));
              }
            }
            return throwError(() => err);
          }),
        )),
    );
  }
}
