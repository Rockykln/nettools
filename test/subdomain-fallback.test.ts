import { afterEach, describe, expect, it, vi } from 'vitest';
import tool, { certSpotter, collectHosts } from '../src/tools/subdomain-finder';

const SPOTTER_PAGE = [
  {
    dns_names: ['www.example.org', 'example.org'],
    not_before: '2026-09-01T00:00:00Z',
    not_after: '2026-12-01T23:59:59Z',
    issuer: { name: "C=US, O=Let's Encrypt, CN=R11" },
  },
];

describe('subdomain finder fallback', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('maps Cert Spotter issuances to crt.sh entries', async () => {
    vi.stubGlobal('fetch', async () => Response.json(SPOTTER_PAGE));
    const entries = await certSpotter('example.org');
    expect(entries).toEqual([
      { name_value: 'www.example.org\nexample.org', not_before: '2026-09-01T00:00:00', not_after: '2026-12-01T23:59:59', issuer_name: "C=US, O=Let's Encrypt, CN=R11" },
    ]);
    expect(collectHosts('example.org', entries).map((h) => [h.name, h.issuer])).toEqual([
      ['example.org', "Let's Encrypt"],
      ['www.example.org', "Let's Encrypt"],
    ]);
  });

  it('follows the next page and stops after two', async () => {
    const urls: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      urls.push(url);
      return Response.json(SPOTTER_PAGE, { headers: { link: '<https://api.certspotter.com/issuances?after=123&domain=example.org>; rel="next"' } });
    });
    await certSpotter('example.org');
    expect(urls).toHaveLength(2);
    expect(urls[1]).toContain('&after=123');
  });

  it('answers from Cert Spotter when crt.sh fails', async () => {
    vi.stubGlobal('caches', { default: { match: async () => undefined, put: async () => {} } });
    vi.stubGlobal('fetch', async (url: string) =>
      url.startsWith('https://crt.sh/') ? new Response('', { status: 502 }) : Response.json(SPOTTER_PAGE),
    );
    const res = await tool.api!({ url: new URL('https://net.example.com/api/subdomain-finder?domain=example.org') } as never, '');
    const body = (await res.json()) as { source: string; hosts: { name: string }[] };
    expect(body.source).toBe('Cert Spotter');
    expect(body.hosts.map((h) => h.name)).toEqual(['example.org', 'www.example.org']);
  });

  it('does not ask Cert Spotter when crt.sh answers quickly', async () => {
    vi.stubGlobal('caches', { default: { match: async () => undefined, put: async () => {} } });
    const urls: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      urls.push(url);
      return url.startsWith('https://crt.sh/')
        ? Response.json([{ issuer_name: 'O=Test CA', name_value: 'a.example.net', not_before: '2026-01-01T00:00:00', not_after: '2027-01-01T00:00:00' }])
        : Response.json(SPOTTER_PAGE);
    });
    const res = await tool.api!({ url: new URL('https://net.example.com/api/subdomain-finder?domain=example.net') } as never, '');
    const body = (await res.json()) as { source: string };
    expect(body.source).toBe('crt.sh');
    await new Promise((r) => setTimeout(r, 10));
    expect(urls.some((u) => u.includes('certspotter'))).toBe(false);
  });

  it('names the real problem when a domain has too many certificates', async () => {
    vi.stubGlobal('caches', { default: { match: async () => undefined, put: async () => {} } });
    vi.stubGlobal('fetch', async (url: string) =>
      new Response('', { status: url.startsWith('https://crt.sh/') ? 502 : 504 }),
    );
    const res = await tool.api!({ url: new URL('https://net.example.com/api/subdomain-finder?domain=big.example') } as never, '');
    expect(res.status).toBe(502);
    expect(((await res.json()) as { error: string }).error).toContain('www.big.example');
  });
});
