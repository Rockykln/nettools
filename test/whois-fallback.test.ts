import { afterEach, describe, expect, it, vi } from 'vitest';

const ARIN_NET = `NetRange:       8.8.8.0 - 8.8.8.255
CIDR:           8.8.8.0/24
NetName:        GOGL
OrgName:        Google LLC
Country:        US
OrgAbuseEmail:  network-abuse@google.com
`;

const RIPE_NET = `% This is the RIPE Database query service.
inetnum:        193.0.0.0 - 193.0.7.255
netname:        RIPE-NCC
descr:          RIPE Network Coordination Centre
country:        NL
abuse-mailbox:  abuse@ripe.net
`;

const queries: string[] = [];
vi.mock('../src/core/transport', async (original) => ({
  ...(await original<typeof import('../src/core/transport')>()),
  whoisQuery: async (server: string, query: string) => {
    queries.push(`${server} ${query}`);
    return ARIN_NET;
  },
}));

const { ipOwnerFromWhois, lookupUncached, parseQuery, rirWhoisQuery, rirWhoisServer } = await import('../src/tools/whois');

describe('registry WHOIS fallback', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    queries.length = 0;
  });

  it('maps RDAP services of the regional registries to their WHOIS servers', () => {
    expect(rirWhoisServer('https://rdap.arin.net/registry/')).toBe('whois.arin.net');
    expect(rirWhoisServer('https://rdap.db.ripe.net/')).toBe('whois.ripe.net');
    expect(rirWhoisServer('https://rdap.verisign.com/com/v1/')).toBeNull();
    expect(rirWhoisQuery('whois.arin.net', parseQuery('AS7018')!)).toBe('a 7018');
    expect(rirWhoisQuery('whois.arin.net', parseQuery('8.8.8.8')!)).toBe('n 8.8.8.8');
    expect(rirWhoisQuery('whois.ripe.net', parseQuery('AS3320')!)).toBe('AS3320');
  });

  it('reads owner fields from ARIN and RIPE answers', () => {
    expect(ipOwnerFromWhois(ARIN_NET)).toEqual({
      network: 'GOGL', range: '8.8.8.0 – 8.8.8.255', organization: 'Google LLC', country: 'US', abuse: 'network-abuse@google.com',
    });
    expect(ipOwnerFromWhois(RIPE_NET)).toEqual({
      network: 'RIPE-NCC', range: '193.0.0.0 – 193.0.7.255', organization: 'RIPE Network Coordination Centre', country: 'NL', abuse: 'abuse@ripe.net',
    });
  });

  it('falls back to WHOIS when the RDAP server keeps failing', async () => {
    vi.stubGlobal('fetch', async (input: string) =>
      input.includes('data.iana.org')
        ? Response.json({ services: [[['8.0.0.0/8'], ['https://rdap.arin.net/registry/']]] })
        : new Response('', { status: 525 }),
    );
    const l = await lookupUncached(parseQuery('8.8.8.8')!);
    expect(l.source).toBe('whois://whois.arin.net');
    expect(l.whoisText).toBe(ARIN_NET);
    expect(l.notFound).toBe(false);
    expect(queries).toEqual(['whois.arin.net n 8.8.8.8']);
  });
});
