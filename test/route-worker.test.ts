import { describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import { rateKey } from '../src/core/http';
import { mapLimit } from '../src/core/async';
import { cachedJson } from '../src/core/cache';

const events: { blobs: string[] }[] = [];
const env = {
  SITE_URL: 'https://net.example.com',
  ASSETS: { fetch: async () => new Response('asset', { status: 200 }) },
  EVENTS: { writeDataPoint: (d: { blobs: string[] }) => events.push(d) },
} as unknown as Env;
const exec = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

function call(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (!headers.has('user-agent')) headers.set('user-agent', 'Mozilla/5.0');
  headers.set('cf-connecting-ip', '203.0.113.9');
  return worker.fetch(new Request(`https://net.example.com${path}`, { ...init, headers }) as never, env, exec);
}

function expectSecurityHeaders(res: Response): void {
  expect(res.headers.get('content-security-policy')).toContain("default-src 'self'");
  expect(res.headers.get('x-content-type-options')).toBe('nosniff');
  expect(res.headers.get('strict-transport-security')).toMatch(/max-age=\d+/);
  expect(res.headers.get('permissions-policy')).not.toContain('interest-cohort');
}

describe('routing', () => {
  it('redirects trailing slashes without leaving the site', async () => {
    const res = await call('//evil.com/');
    expect(res.status).toBe(301);
    expect(res.headers.get('location')).toBe('/evil.com');
    expectSecurityHeaders(res);
  });

  it('redirects aliases and upper case to the canonical path, keeping the query', async () => {
    const res = await call('/My-IP/?x=1');
    expect(res.status).toBe(301);
    expect(res.headers.get('location')).toBe('/what-is-my-ip?x=1');
  });

  it('answers unsupported methods with 405 and an Allow header', async () => {
    const page = await call('/dns-lookup', { method: 'POST' });
    expect(page.status).toBe(405);
    expect(page.headers.get('allow')).toBe('GET, HEAD');
    const api = await call('/api/whois?q=example.com', { method: 'OPTIONS' });
    expect(api.status).toBe(405);
    expect(api.headers.get('content-type')).toContain('application/json');
    expect(api.headers.get('allow')).toBe('GET, HEAD');
    expect((await call('/api/tools', { method: 'DELETE' })).status).toBe(405);
    expect((await call('/badge/headers/example.com.svg', { method: 'POST' })).status).toBe(405);
  });

  it('refuses cross-site API calls from browsers and sends no CORS header', async () => {
    const res = await call('/api/whois?q=example.com', { headers: { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'cors' } });
    expect(res.status).toBe(403);
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
    expectSecurityHeaders(res);
  });

  it('keeps unknown API slugs out of metrics', async () => {
    events.length = 0;
    const res = await call('/api/secret-user-input-xyz');
    expect(res.status).toBe(404);
    expect(JSON.stringify(events)).not.toContain('secret-user-input-xyz');
    expect(events[0]?.blobs[1]).toBe('not_found');
  });

  it('serves the static tool list as cacheable JSON', async () => {
    const res = await call('/api/tools');
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toContain('max-age');
    expect(Array.isArray(await res.json())).toBe(true);
  });
});

describe('speed test endpoints', () => {
  it('streams the requested number of random bytes, uncached and capped', async () => {
    const res = await call('/api/speed-test/down?bytes=100000');
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect((await res.arrayBuffer()).byteLength).toBe(100000);
    const neg = await call('/api/speed-test/down?bytes=-5');
    expect((await neg.arrayBuffer()).byteLength).toBe(0);
  });

  it('accepts uploads only via POST', async () => {
    const up = await call('/api/speed-test/up', { method: 'POST', body: new Uint8Array(1234) });
    expect(await up.json()).toEqual({ bytes: 1234 });
    const get = await call('/api/speed-test/up');
    expect(get.status).toBe(405);
    expect(get.headers.get('allow')).toBe('POST');
    expect((await call('/api/speed-test/down', { method: 'POST' })).status).toBe(405);
  });

  it('refuses oversized uploads', async () => {
    const res = await call('/api/speed-test/up', { method: 'POST', body: new Uint8Array(18 * 1024 * 1024) });
    expect(res.status).toBe(413);
  });

  it('refuses requests from other sites', async () => {
    const res = await call('/api/speed-test/down?bytes=10', { headers: { 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'cors' } });
    expect(res.status).toBe(403);
  });
});

describe('error handling', () => {
  it('returns JSON for API errors', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const broken = { ...env, get SITE_URL(): string { throw new Error('boom'); } } as unknown as Env;
    const res = await worker.fetch(new Request('https://net.example.com/api/tools') as never, broken, exec);
    expect(res.status).toBe(500);
    expect(res.headers.get('content-type')).toContain('application/json');
    expectSecurityHeaders(res);
    spy.mockRestore();
  });
});

describe('helpers', () => {
  it('keys IPv4-mapped IPv6 addresses by their IPv4 address', () => {
    expect(rateKey('::ffff:203.0.113.7')).toBe('203.0.113.7');
    expect(rateKey('::ffff:203.0.113.7')).not.toBe(rateKey('::ffff:198.51.100.1'));
  });

  it('mapLimit runs every item even with a non-positive limit', async () => {
    expect(await mapLimit([1, 2, 3], 0, async (x) => x * 2)).toEqual([2, 4, 6]);
  });

  it('cachedJson works without the Cache API', async () => {
    expect(await cachedJson('k', () => Infinity, async () => 42)).toBe(42);
  });
});

describe('scanner paths', () => {
  it('short-circuits typical scanner probes only', async () => {
    const { isScannerPath } = await import('../src/index');
    for (const p of ['/wp-login.php', '/xmlrpc.php', '/.env', '/.git/config', '/phpmyadmin/', '/index.php', '/cgi-bin/x', '/backup.sql']) expect(isScannerPath(p)).toBe(true);
    for (const p of ['/', '/whois', '/api/whois', '/assets/style.css', '/llms.txt', '/robots-txt', '/.well-known/security.txt', '/ip-lookup']) expect(isScannerPath(p)).toBe(false);
  });
});

describe('crawler detection', () => {
  it('blocks crawlers but not link preview bots or browsers', async () => {
    const { isCrawler } = await import('../src/index');
    expect(isCrawler('Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +searchbot@anthropic.com)')).toBe(true);
    expect(isCrawler('Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)')).toBe(true);
    expect(isCrawler('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')).toBe(true);
    expect(isCrawler('Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)')).toBe(false);
    expect(isCrawler('Twitterbot/1.0')).toBe(false);
    expect(isCrawler('Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0')).toBe(false);
    expect(isCrawler('curl/8.9.1')).toBe(false);
    expect(isCrawler(null)).toBe(false);
  });
});
