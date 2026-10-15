import { afterEach, describe, expect, it, vi } from 'vitest';
import { candidateNames, checkWhoisAnswer, lookup, parseQuery, whoisNotFound } from '../src/tools/whois';

describe('whois candidateNames', () => {
  it('always ends with the registrable name, even for deep subdomains', () => {
    expect(candidateNames('a.b.c.example.com')).toEqual(['c.example.com', 'b.c.example.com', 'example.com'].sort((x, y) => y.length - x.length));
    expect(candidateNames('a.b.c.example.com').at(-1)).toBe('example.com');
    expect(candidateNames('www.example.co.uk')).toEqual(['www.example.co.uk', 'example.co.uk']);
    expect(candidateNames('example.com')).toEqual(['example.com']);
    expect(candidateNames('co.uk')).toEqual(['co.uk']);
  });
});

describe('whois parseQuery', () => {
  it('accepts AS numbers with a space and upper-case domains with a trailing dot', () => {
    expect(parseQuery('AS 13335')).toMatchObject({ kind: 'asn', value: '13335' });
    expect(parseQuery('ASN13335')).toMatchObject({ kind: 'asn', value: '13335' });
    expect(parseQuery('EXAMPLE.COM.')).toMatchObject({ kind: 'domain', value: 'example.com' });
    expect(parseQuery('bücher.de')).toMatchObject({ kind: 'domain', value: 'xn--bcher-kva.de' });
  });
});

describe('WHOIS text answers', () => {
  it('detects unregistered names across registries', () => {
    for (const text of [
      'Domain: x.de\nStatus: free',
      'Domain: x.eu\nStatus:      AVAILABLE',
      'No match for "X.CO.UK".',
      '%% NOT FOUND',
      '% nothing found',
      'x.nl is free',
      'No entries found for the selected source(s).',
      'No matching record.',
      'We do not have an entry in our database matching your query.',
      'No information available about domain name x.pl in the Registry NASK database.',
      '% Object does not exist',
    ]) {
      expect(whoisNotFound(text), text).toBe(true);
    }
  });
  it('does not treat registered names or terms of use as free', () => {
    expect(whoisNotFound('Domain: x.de\nStatus: connect')).toBe(false);
    expect(whoisNotFound('% This service is available for informational purposes only.\nDomain: x.xx\nStatus: active')).toBe(false);
    expect(whoisNotFound('Domain: x.de\nStatus: freeze')).toBe(false);
  });
  it('rejects empty and rate-limited answers instead of reporting them as taken', () => {
    expect(() => checkWhoisAnswer('whois.denic.de', '')).toThrow(/^No response/);
    expect(() => checkWhoisAnswer('whois.denic.de', '55000000002 Connection refused; access control limit reached')).toThrow(/^No response/);
    expect(() => checkWhoisAnswer('whois.denic.de', 'Domain: x.de\nStatus: connect')).not.toThrow();
  });
});

describe('RDAP lookup', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('skips 400 answers for subdomains and finds the registered name', async () => {
    vi.stubGlobal('caches', { default: { match: async () => undefined, put: async () => {} } });
    const urls: string[] = [];
    vi.stubGlobal('fetch', async (input: string) => {
      urls.push(input);
      if (input.includes('data.iana.org')) return Response.json({ services: [[['test'], ['https://rdap.example/']]] });
      if (input.endsWith('/domain/example.test')) return Response.json({ ldhName: 'EXAMPLE.TEST' });
      return new Response('bad request', { status: 400 });
    });
    const l = await lookup(parseQuery('a.b.c.d.example.test')!);
    expect(l.notFound).toBe(false);
    expect(l.source).toBe('https://rdap.example/domain/example.test');
    expect(urls.filter((u) => u.includes('/domain/'))).toHaveLength(3);
  });

  it('treats a 400 for the registered name itself as an error, not as available', async () => {
    vi.stubGlobal('caches', { default: { match: async () => undefined, put: async () => {} } });
    vi.stubGlobal('fetch', async (input: string) =>
      input.includes('data.iana.org') ? Response.json({ services: [[['test'], ['https://rdap.example/']]] }) : new Response('', { status: 400 }),
    );
    await expect(lookup(parseQuery('example.test')!)).rejects.toThrow('RDAP server returned HTTP 400');
  });
});
