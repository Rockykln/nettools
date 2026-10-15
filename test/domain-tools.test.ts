import { describe, expect, it } from 'vitest';
import { parse } from '../src/tools/asn-lookup';
import { candidates, interpret } from '../src/tools/domain-availability';
import { normalizeMac } from '../src/tools/mac-lookup';
import { collectHosts } from '../src/tools/subdomain-finder';
import type { Lookup } from '../src/tools/whois';

const base: Omit<Lookup, 'rdap' | 'whoisText' | 'notFound'> = { query: { input: 'x', kind: 'domain', value: 'x' }, source: '' };

describe('domain availability', () => {
  it('rejects names that cannot be registered', () => {
    expect(candidates('my_project')).toBeNull();
    expect(candidates('1.2.3')).toBeNull();
    expect(candidates('shop.example.ne.jp')!.domains[0]).toBe('example.ne.jp');
  });
  it('reads the registrar from nested entities and ignores epoch expiry dates', () => {
    const rdap = {
      entities: [{ roles: ['registrant'], entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar']]] }] }],
      events: [{ eventAction: 'expiration', eventDate: '1970-01-01T00:00:00Z' }],
    };
    const c = interpret('x.test', { ...base, rdap, whoisText: null, notFound: false });
    expect(c).toMatchObject({ status: 'taken', registrar: 'Example Registrar', expires: null });
  });
  it('does not mistake WHOIS terms of use for an unregistered name', () => {
    const text = '% The data is available for informational purposes.\nDomain: x.xx\nStatus: active';
    expect(interpret('x.xx', { ...base, rdap: null, whoisText: text, notFound: false }).status).toBe('taken');
  });
});

describe('normalizeMac', () => {
  it('pads groups without leading zeros (BSD/macOS arp output)', () => {
    expect(normalizeMac('0:1a:2b:3c:4d:5e')).toBe('001A2B3C4D5E');
    expect(normalizeMac('a:b:c:d:e:f')).toBe('0A0B0C0D0E0F');
  });
  it('accepts MA-M and MA-S prefixes and a prefix length suffix', () => {
    expect(normalizeMac('70-B3-D5-F2-F')).toBe('70B3D5F2F');
    expect(normalizeMac('70:B3:D5:1')).toBe('70B3D51');
    expect(normalizeMac('3C:22:FB/24')).toBe('3C22FB');
  });
  it('rejects malformed groups', () => {
    expect(normalizeMac('0:1a:2b')).toBeNull();
    expect(normalizeMac('001.a2b.3c4')).toBeNull();
    expect(normalizeMac('00:1a:2b:3c:4d:5e:6f')).toBeNull();
  });
});

describe('asn-lookup parse', () => {
  it('normalizes prefixes to network/length', () => {
    expect(parse('192.0.2.77/24')).toEqual({ kind: 'prefix', resource: '192.0.2.0/24' });
    expect(parse('192.0.2.0/255.255.255.0')).toEqual({ kind: 'prefix', resource: '192.0.2.0/24' });
    expect(parse('AS 3320')).toEqual({ kind: 'asn', asn: 3320 });
    expect(parse('AS0')).toBeNull();
  });
});

describe('subdomain-finder collectHosts', () => {
  it('drops email identities, counts each certificate once and merges trailing dots', () => {
    const e = (name_value: string, not_before: string, not_after: string) => ({ issuer_name: 'C=US, O=Let\'s Encrypt, CN=R3', name_value, not_before, not_after });
    const hosts = collectHosts('example.com', [
      e('www.example.com\nwww.example.com\nadmin@mail.example.com', '2024-01-01T00:00:00', '2024-04-01T00:00:00'),
      e('WWW.example.com.\n*.example.com\nexample.org', '2023-06-01T00:00:00', '2024-09-01T00:00:00'),
    ]);
    expect(hosts.map((h) => h.name)).toEqual(['www.example.com', '*.example.com']);
    expect(hosts[0]).toMatchObject({ certificates: 2, firstSeen: '2023-06-01T00:00:00', validUntil: '2024-09-01T00:00:00', issuer: "Let's Encrypt" });
    expect(hosts[1]!.wildcard).toBe(true);
  });
});
