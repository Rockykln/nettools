import { THEME_BOOT_HASH } from './theme-boot';
import { parseIPv6 } from './net';

export function clientIp(req: Request): string {
  return req.headers.get('cf-connecting-ip') ?? '0.0.0.0';
}

/** Rate-limit key: the IPv4 address, or the /64 network for IPv6 (one end user usually owns a whole /64). */
export function rateKey(ip: string): string {
  const b = parseIPv6(ip);
  if (!b) return ip;
  // IPv4-mapped (::ffff:a.b.c.d) would otherwise put every such client into the same /64.
  if (b.subarray(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) return Array.from(b.subarray(12)).join('.');
  return Array.from(b.subarray(0, 8), (x) => x.toString(16).padStart(2, '0')).join('') + '::/64';
}

export function json(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set('content-type', 'application/json; charset=utf-8');
  if (!headers.has('cache-control')) headers.set('cache-control', 'no-store');
  return new Response(JSON.stringify(data, null, 2), { ...init, headers });
}

export function text(body: string, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set('content-type', 'text/plain; charset=utf-8');
  if (!headers.has('cache-control')) headers.set('cache-control', 'no-store');
  return new Response(body, { ...init, headers });
}

// Fails open: if the binding is unavailable, the request is allowed.
export async function allow(limiter: RateLimit | undefined, key: string): Promise<boolean> {
  if (!limiter) return true;
  try {
    return (await limiter.limit({ key })).success;
  } catch {
    console.warn({ event: 'ratelimit_unavailable' });
    return true;
  }
}

const CSP = [
  "default-src 'self'",
  `script-src 'self' ${THEME_BOOT_HASH}`,
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self' https://api4.ipify.org https://api6.ipify.org",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export function withSecurityHeaders(res: Response): Response {
  const out = new Response(res.body, res);
  const h = out.headers;
  if (!h.has('content-security-policy')) h.set('content-security-policy', CSP);
  h.set('x-content-type-options', 'nosniff');
  // Rate limits count per minute.
  if (out.status === 429 && !h.has('retry-after')) h.set('retry-after', '60');
  // /go sends no referrer, so external sites never see which lookup a visitor came from.
  if (!h.has('referrer-policy')) h.set('referrer-policy', 'strict-origin-when-cross-origin');
  h.set('permissions-policy', 'camera=(), microphone=(), geolocation=(), browsing-topics=()');
  h.set('strict-transport-security', 'max-age=31536000');
  return out;
}
