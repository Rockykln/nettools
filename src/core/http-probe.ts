// Fetches a URL hop by hop so redirects, timings and headers of every step are visible.
import { isIP, normalizeDomain } from './net';
import { checkTarget } from './guard';

export const USER_AGENT = 'Mozilla/5.0 (compatible; nettools/1.0; +https://net.rockykln.com)';

export interface Hop {
  url: string;
  status: number;
  statusText: string;
  ms: number;
  location: string | null;
  headers: [string, string][];
}

export interface Chain {
  hops: Hop[];
  /** Set when the last request failed (DNS, TLS, timeout) or the redirect limit was hit. */
  error: string | null;
  /**
   * What stopped the chain: `refused` (the guard rejected a host), `unresolved` (its addresses could not be
   * determined), `network` (connection, TLS or timeout) or `redirect` (loop, limit or a target that is not followed).
   */
  errorKind?: 'refused' | 'unresolved' | 'network' | 'redirect';
}

const ALLOWED_PORTS = ['80', '443', '8080', '8443'];

// Accepts "example.com", "https://example.com/path" or an IP; returns a normalized http(s) URL.
export function normalizeUrl(input: string): string | null {
  let s = input.trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!isIP(host) && !normalizeDomain(host)?.includes('.')) return null;
  // Other ports would turn the HTTP checks into a port scanner; the port checker covers them.
  if (url.port && !ALLOWED_PORTS.includes(url.port)) return null;
  url.hash = '';
  // fetch() refuses URLs with credentials, and they should not end up in cache keys or result pages.
  url.username = '';
  url.password = '';
  return url.toString();
}

/** Resolves a Location header against the current URL and applies the same rules as for the start URL. */
export function redirectTarget(location: string, base: string): { url: string } | { error: string } {
  let next: URL;
  try {
    next = new URL(location, base);
  } catch {
    return { error: `Invalid redirect target: ${location}` };
  }
  if (next.protocol !== 'http:' && next.protocol !== 'https:') return { error: `Redirect to a non-HTTP address: ${next.protocol}` };
  // Same port rule as for the start URL, so a redirect cannot reach arbitrary ports.
  if (next.port && !ALLOWED_PORTS.includes(next.port)) return { error: `Redirect to port ${next.port}, which is not checked` };
  next.hash = '';
  next.username = '';
  next.password = '';
  return { url: next.toString() };
}

export async function fetchChain(start: string, env: Env, maxHops = 5, timeoutMs = 8000): Promise<Chain> {
  const hops: Hop[] = [];
  const deadline = Date.now() + 15000;
  let url = start;
  for (let i = 0; i < maxHops; i++) {
    // Every hop is checked again: a public URL may redirect to a private or internal address.
    const target = await checkTarget(new URL(url).hostname, env);
    if (!target.ok) return { hops, error: target.reason, errorKind: target.kind === 'policy' ? 'refused' : 'unresolved' };
    const remaining = Math.min(timeoutMs, deadline - Date.now());
    if (remaining <= 0) return { hops, error: 'Gave up after 15 seconds', errorKind: 'network' };
    const t0 = Date.now();
    let res: Response;
    try {
      res = await fetch(url, {
        method: 'GET',
        redirect: 'manual',
        headers: { 'user-agent': USER_AGENT, accept: 'text/html,application/xhtml+xml,*/*;q=0.8' },
        signal: AbortSignal.timeout(remaining),
      });
    } catch (e) {
      const timedOut = e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError');
      return { hops, error: timedOut ? `No response within ${Math.round(remaining / 1000)} seconds` : 'Could not connect (DNS, TLS or network error)', errorKind: 'network' };
    }
    const ms = Date.now() - t0;
    res.body?.cancel().catch(() => {});
    const location = res.headers.get('location');
    hops.push({
      url,
      status: res.status,
      // Cloudflare error pages send "<none>" as reason phrase.
      statusText: /^<none>$/i.test(res.statusText) ? '' : res.statusText,
      ms,
      location,
      headers: [...res.headers.entries()].sort(([a], [b]) => a.localeCompare(b)),
    });
    if (res.status >= 300 && res.status < 400 && location) {
      const next = redirectTarget(location, url);
      if ('error' in next) return { hops, error: next.error, errorKind: 'redirect' };
      if (hops.some((h) => h.url === next.url)) return { hops, error: `Redirect loop back to ${next.url}`, errorKind: 'redirect' };
      url = next.url;
      continue;
    }
    return { hops, error: null };
  }
  return { hops, error: `Stopped after ${maxHops - 1} redirects`, errorKind: 'redirect' };
}
