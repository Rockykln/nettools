import { describe, expect, it } from 'vitest';
import { esc, html, raw } from '../src/core/html';
import { cidrContains, isIPv4, isIPv6, normalizeDomain, reverseName, socketHost } from '../src/core/net';
import { parseQuery } from '../src/tools/whois';

describe('IP parsing', () => {
  it('validates IPv4', () => {
    expect(isIPv4('192.0.2.1')).toBe(true);
    expect(isIPv4('256.0.0.1')).toBe(false);
    expect(isIPv4('01.2.3.4')).toBe(false);
  });

  it('validates IPv6', () => {
    for (const ok of ['::', '::1', '2001:db8::1', 'fe80::1:2:3:4', '::ffff:192.0.2.1', '1:2:3:4:5:6:7:8']) expect(isIPv6(ok)).toBe(true);
    for (const bad of ['1::2::3', '1:2:3:4:5:6:7:8:9', '12345::', ':1::', 'example.com', '::ffff:999.0.0.1']) expect(isIPv6(bad)).toBe(false);
  });

  it('builds reverse names', () => {
    expect(reverseName('192.0.2.1')).toBe('1.2.0.192.in-addr.arpa');
    expect(reverseName('2001:db8::1')).toBe(`1.${'0.'.repeat(23)}8.b.d.0.1.0.0.2.ip6.arpa`);
  });

  it('matches CIDR ranges', () => {
    expect(cidrContains('192.0.2.0/24', '192.0.2.200')).toBe(true);
    expect(cidrContains('192.0.2.0/24', '192.0.3.1')).toBe(false);
    expect(cidrContains('2001:db8::/32', '2001:db8:ffff::1')).toBe(true);
    expect(cidrContains('2001:db8::/32', '192.0.2.1')).toBe(false);
  });
});

describe('normalizeDomain', () => {
  it('accepts domains, URLs and e-mail addresses', () => {
    expect(normalizeDomain('Example.COM')).toBe('example.com');
    expect(normalizeDomain('https://www.example.com/path?q=1')).toBe('www.example.com');
    expect(normalizeDomain('user@example.org')).toBe('example.org');
    expect(normalizeDomain('_dmarc.example.com')).toBe('_dmarc.example.com');
  });

  it('converts IDNs to punycode', () => {
    expect(normalizeDomain('bücher.de')).toBe('xn--bcher-kva.de');
  });

  it('rejects junk', () => {
    expect(normalizeDomain('')).toBeNull();
    expect(normalizeDomain('192.0.2.1')).toBeNull();
    expect(normalizeDomain('<script>')).toBeNull();
    expect(normalizeDomain('-bad-.com')).toBeNull();
  });
});

describe('whois parseQuery', () => {
  it('detects the query kind', () => {
    expect(parseQuery('AS13335')).toMatchObject({ kind: 'asn', value: '13335' });
    expect(parseQuery('8.8.8.8')).toMatchObject({ kind: 'ip' });
    expect(parseQuery('https://example.com/')).toMatchObject({ kind: 'domain', value: 'example.com' });
    expect(parseQuery('localhost')).toBeNull();
  });
});

describe('html', () => {
  it('escapes interpolations but not nested templates', () => {
    const evil = '"><script>alert(1)</script>';
    expect(html`<p title="${evil}">${evil}</p>`.value).not.toContain('<script>');
    expect(html`<div>${html`<b>${'x'}</b>`}${raw('<i>y</i>')}</div>`.value).toBe('<div><b>x</b><i>y</i></div>');
    expect(esc(`&<>"'`)).toBe('&#38;&#60;&#62;&#34;&#39;');
  });
});

describe('socketHost', () => {
  it('brackets IPv6 literals only', () => {
    expect(socketHost('2001:db8::1')).toBe('[2001:db8::1]');
    expect(socketHost('[2001:db8::1]')).toBe('[2001:db8::1]');
    expect(socketHost('192.0.2.1')).toBe('192.0.2.1');
    expect(socketHost('example.com')).toBe('example.com');
  });
});
