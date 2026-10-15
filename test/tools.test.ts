import { describe, expect, it } from 'vitest';
import { emailGrade, headersGrade } from '../src/badges';
import { isPublicAddress } from '../src/core/guard';
import { rateKey } from '../src/core/http';
import type { ToolContext } from '../src/core/tool';
import { candidates, interpret } from '../src/tools/domain-availability';
import { securityFindings } from '../src/tools/http-headers';
import { LANDING_PAGES } from '../src/tools/landing';
import { normalizeMac } from '../src/tools/mac-lookup';
import { stats } from '../src/tools/tcp-ping';

describe('isPublicAddress', () => {
  it('refuses private, loopback, link-local and documentation ranges', () => {
    for (const ip of ['10.1.2.3', '127.0.0.1', '169.254.169.254', '172.16.0.1', '192.168.13.1', '100.64.0.1', '192.0.2.1', '::1', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1']) {
      expect(isPublicAddress(ip)).toBe(false);
    }
  });
  it('accepts public addresses', () => {
    for (const ip of ['1.1.1.1', '8.8.8.8', '2606:4700:4700::1111']) expect(isPublicAddress(ip)).toBe(true);
  });
});

describe('rateKey', () => {
  it('keys IPv6 by /64 and IPv4 by address', () => {
    expect(rateKey('2001:db8:1:2:aaaa::1')).toBe(rateKey('2001:db8:1:2:bbbb::9'));
    expect(rateKey('2001:db8:1:2::1')).not.toBe(rateKey('2001:db8:1:3::1'));
    expect(rateKey('203.0.113.7')).toBe('203.0.113.7');
  });
});

describe('badge grades', () => {
  const all = (level: string) => Object.fromEntries(['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'Clickjacking protection', 'Referrer-Policy'].map((k) => [k, level]));
  it('grades security headers', () => {
    expect(headersGrade(all('ok'), true)).toBe('A');
    expect(headersGrade(all('warn'), true)).toBe('F');
    expect(headersGrade({ ...all('ok'), 'Content-Security-Policy': 'warn' }, true)).toBe('B');
    expect(headersGrade(all('ok'), false)).toBe('F');
  });
  it('grades email security', () => {
    expect(emailGrade({ SPF: 'ok', DKIM: 'ok' }, 'reject', false)).toBe('A');
    expect(emailGrade({ SPF: 'ok', DKIM: 'ok' }, 'none', false)).toBe('B');
    expect(emailGrade({ SPF: 'bad', DKIM: 'info' }, null, false)).toBe('F');
    expect(emailGrade({}, 'reject', true)).toBe('A');
  });
});

describe('tcp ping stats', () => {
  it('computes min, avg, max, jitter and ignores failures', () => {
    const s = stats([
      { seq: 1, ms: 10, error: null },
      { seq: 2, ms: 14, error: null },
      { seq: 3, ms: null, error: 'timeout' },
      { seq: 4, ms: 12, error: null },
    ]);
    expect(s).toEqual({ sent: 4, received: 3, loss: 25, min: 10, avg: 12, max: 14, jitter: 3 });
  });
});

describe('normalizeMac', () => {
  it('accepts common notations and rejects junk', () => {
    expect(normalizeMac('00:00:5e:00:53:01')).toBe('00005E005301');
    expect(normalizeMac('0000.5e00.5301')).toBe('00005E005301');
    expect(normalizeMac('00-00-5E')).toBe('00005E');
    expect(normalizeMac('xyz')).toBeNull();
    expect(normalizeMac('00:00')).toBeNull();
  });
});

describe('domain availability', () => {
  it('builds candidates from a name or a domain', () => {
    expect(candidates('myproject')!.domains[0]).toBe('myproject.com');
    expect(candidates('https://myproject.dev/x')!.domains[0]).toBe('myproject.dev');
    expect(candidates('-bad-')).toBeNull();
  });
  it('interprets RDAP and WHOIS answers', () => {
    const base = { query: { input: 'x.example', kind: 'domain' as const, value: 'x.example' }, source: '' };
    expect(interpret('x.example', { ...base, rdap: null, whoisText: null, notFound: true }).status).toBe('available');
    expect(interpret('x.eu', { ...base, rdap: null, whoisText: 'Domain: x.eu\nStatus:      AVAILABLE', notFound: false }).status).toBe('available');
    expect(interpret('x.de', { ...base, rdap: null, whoisText: 'Domain: x.de\nStatus: connect', notFound: false }).status).toBe('taken');
    const taken = interpret('x.example', { ...base, rdap: { events: [{ eventAction: 'expiration', eventDate: '2030-01-02T00:00:00Z' }], entities: [] }, whoisText: null, notFound: false });
    expect(taken).toMatchObject({ status: 'taken', expires: '2030-01-02' });
    const io = interpret('x.io', { ...base, rdap: null, whoisText: 'Domain Name: x.io\nRegistrar: Example Registrar, Inc.\nRegistry Expiry Date: 2031-05-06T04:00:00Z', notFound: false });
    expect(io).toMatchObject({ status: 'taken', registrar: 'Example Registrar, Inc.', expires: '2031-05-06' });
  });
});

describe('securityFindings', () => {
  it('flags missing headers and short HSTS', () => {
    const hop = { url: 'https://example.com/', status: 200, statusText: 'OK', ms: 1, location: null, headers: [['strict-transport-security', 'max-age=3600'], ['x-content-type-options', 'nosniff']] as [string, string][] };
    const f = Object.fromEntries(securityFindings(hop).map((x) => [x.header, x.level]));
    expect(f['Strict-Transport-Security']).toBe('warn');
    expect(f['X-Content-Type-Options']).toBe('ok');
    expect(f['Content-Security-Policy']).toBe('warn');
  });
});

describe('landing pages', () => {
  it('never run a lookup themselves and preset the form', async () => {
    const mx = LANDING_PAGES.find((l) => l.slug === 'mx-lookup')!;
    const c = { url: new URL('https://net.example/mx-lookup?name=example.com'), env: {}, req: new Request('https://net.example/'), clientIp: '192.0.2.1' } as unknown as ToolContext;
    const out = String(await mx.render(c));
    expect(out).not.toContain('Results for');
    expect(out).toContain('<option selected>MX</option>');
  });
});
