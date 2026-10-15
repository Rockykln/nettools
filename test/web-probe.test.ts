import { describe, expect, it } from 'vitest';
import { readCapped, readJsonCapped } from '../src/core/body';
import { canonicalHost, isOwnHost, isPublicAddress } from '../src/core/guard';
import { normalizeUrl, redirectTarget, type Chain, type Hop } from '../src/core/http-probe';
import { frameAncestors, hstsMaxAge, securityFindings } from '../src/tools/http-headers';
import { verdictOf } from '../src/tools/is-it-down';

const stream = (...chunks: number[]) =>
  new ReadableStream<Uint8Array>({
    start(c) {
      for (const n of chunks) c.enqueue(new Uint8Array(n).fill(97));
      c.close();
    },
  });

const hop = (url: string, headers: [string, string][], status = 200): Hop => ({ url, status, statusText: '', ms: 1, location: null, headers });
const level = (headers: [string, string][], name: string) =>
  securityFindings(hop('https://example.com/', headers)).find((f) => f.header === name)?.level;

describe('guard ranges', () => {
  it('refuses special-purpose IPv6 and embedded private IPv4', () => {
    for (const ip of ['::', '::1', '::127.0.0.1', '::7f00:1', '::ffff:10.0.0.1', '64:ff9b::10.0.0.1', '64:ff9b:1::1', '2001:2::1', '2001:10::1', '3fff::1', 'fec0::1', 'ff02::1', '0.1.2.3', '100.100.1.1', '224.0.0.1', '255.255.255.255']) {
      expect(isPublicAddress(ip), ip).toBe(false);
    }
  });
  it('still accepts public IPv6', () => {
    for (const ip of ['2a00:1450:4001::200e', '2001:4860:4860::8888']) expect(isPublicAddress(ip), ip).toBe(true);
  });
  it('canonicalizes numeric IPv4 forms and IDNs', () => {
    expect(canonicalHost('2130706433')).toBe('127.0.0.1');
    expect(canonicalHost('0x7f.1')).toBe('127.0.0.1');
    expect(canonicalHost('0177.0.0.1')).toBe('127.0.0.1');
    expect(canonicalHost('[::1]')).toBe('::1');
    expect(canonicalHost('Bücher.Example.')).toBe('xn--bcher-kva.example');
    expect(canonicalHost('exa mple.com')).toBeNull();
    expect(canonicalHost('')).toBeNull();
  });
  it('treats an IP SITE_URL as a single address', () => {
    expect(isOwnHost('8.8.0.1', { SITE_URL: 'http://127.0.0.1:8787' })).toBe(false);
    expect(isOwnHost('127.0.0.1', { SITE_URL: 'http://127.0.0.1:8787' })).toBe(true);
    expect(isOwnHost('api.rockykln.com', { SITE_URL: 'https://net.rockykln.com' })).toBe(true);
    expect(isOwnHost('rockykln.com.evil.org', { SITE_URL: 'https://net.rockykln.com' })).toBe(false);
  });
});

describe('normalizeUrl', () => {
  it('drops credentials and fragments, keeps paths', () => {
    expect(normalizeUrl('https://user:pw@example.com/a b#x')).toBe('https://example.com/a%20b');
    expect(normalizeUrl('example.com:8443/x')).toBe('https://example.com:8443/x');
    expect(normalizeUrl('http://[2606:4700::1]/')).toBe('http://[2606:4700::1]/');
    expect(normalizeUrl('bücher.de')).toBe('https://xn--bcher-kva.de/');
  });
  it('rejects other schemes, ports and bare names', () => {
    for (const s of ['ftp://example.com', 'example.com:22', 'localhost', '', 'javascript:alert(1)']) expect(normalizeUrl(s), s).toBeNull();
  });
});

describe('redirectTarget', () => {
  it('resolves relative locations and strips credentials', () => {
    expect(redirectTarget('/next?a=1', 'https://example.com/old')).toEqual({ url: 'https://example.com/next?a=1' });
    expect(redirectTarget('//other.org/', 'http://example.com/')).toEqual({ url: 'http://other.org/' });
    expect(redirectTarget('https://u:p@example.com/#frag', 'http://example.com/')).toEqual({ url: 'https://example.com/' });
  });
  it('refuses other schemes and ports', () => {
    expect(redirectTarget('ftp://example.com/', 'https://example.com/')).toHaveProperty('error');
    expect(redirectTarget('https://example.com:6379/', 'https://example.com/')).toHaveProperty('error');
    expect(redirectTarget('http://[::1', 'https://example.com/')).toHaveProperty('error');
  });
});

describe('readCapped', () => {
  it('never returns more than the cap', async () => {
    expect((await readCapped(stream(10, 10, 10), 15)).byteLength).toBe(15);
    expect((await readCapped(stream(4, 4), 100)).byteLength).toBe(8);
    expect((await readCapped(null, 10)).byteLength).toBe(0);
  });
  it('rejects JSON over the cap', async () => {
    await expect(readJsonCapped(new Response('{"a":"0123456789"}'), 5)).rejects.toThrow('too large');
    expect(await readJsonCapped(new Response('{"a":1}'), 100)).toEqual({ a: 1 });
  });
});

describe('security header grading', () => {
  it('parses HSTS max-age variants', () => {
    expect(hstsMaxAge('max-age=31536000; includeSubDomains')).toBe(31536000);
    expect(hstsMaxAge('includeSubDomains; max-age="63072000"')).toBe(63072000);
    expect(hstsMaxAge('max-age = 31536000')).toBe(31536000);
    expect(hstsMaxAge('includeSubDomains')).toBeNull();
    expect(level([['strict-transport-security', 'max-age="31536000"']], 'Strict-Transport-Security')).toBe('ok');
  });
  it('only accepts effective clickjacking protection', () => {
    expect(level([['x-frame-options', 'DENY']], 'Clickjacking protection')).toBe('ok');
    expect(level([['x-frame-options', 'sameorigin']], 'Clickjacking protection')).toBe('ok');
    expect(level([['x-frame-options', 'ALLOWALL']], 'Clickjacking protection')).toBe('warn');
    expect(level([['x-frame-options', 'ALLOW-FROM https://a.example']], 'Clickjacking protection')).toBe('warn');
    expect(level([['content-security-policy', "default-src 'self'; frame-ancestors 'none'"]], 'Clickjacking protection')).toBe('ok');
    expect(level([['content-security-policy', 'frame-ancestors *']], 'Clickjacking protection')).toBe('warn');
    expect(level([['content-security-policy', 'frame-ancestors https:'], ['x-frame-options', 'DENY']], 'Clickjacking protection')).toBe('warn');
    expect(level([['content-security-policy', "script-src 'self'"]], 'Clickjacking protection')).toBe('warn');
    expect(frameAncestors("script-src 'self', frame-ancestors 'self'")).toEqual([["'self'"]]);
  });
  it('accepts duplicated nosniff', () => {
    expect(level([['x-content-type-options', 'nosniff, nosniff']], 'X-Content-Type-Options')).toBe('ok');
    expect(level([['x-content-type-options', 'sniff']], 'X-Content-Type-Options')).toBe('warn');
  });
});

describe('is-it-down verdict', () => {
  const chain = (c: Partial<Chain>): Chain => ({ hops: [], error: null, ...c });
  it('does not call refused or redirect-stopped targets down', () => {
    expect(verdictOf(chain({ error: 'Private', errorKind: 'refused' }))).toBe('refused');
    expect(verdictOf(chain({ hops: [hop('https://a.example/', [], 302)], error: 'Redirect loop', errorKind: 'redirect' }))).toBe('error');
    expect(verdictOf(chain({ hops: [hop('https://a.example/', [], 302)], error: 'private', errorKind: 'refused' }))).toBe('error');
    expect(verdictOf(chain({ error: 'Could not connect', errorKind: 'network' }))).toBe('down');
    expect(verdictOf(chain({ error: 'x does not resolve', errorKind: 'unresolved' }))).toBe('down');
    expect(verdictOf(chain({ hops: [hop('https://a.example/', [], 403)] }))).toBe('blocked');
    expect(verdictOf(chain({ hops: [hop('https://a.example/', [], 200)] }))).toBe('up');
  });
});
