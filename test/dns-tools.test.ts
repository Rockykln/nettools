import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DnsMessage, DnsRecord } from '../src/core/dns';

vi.mock('../src/core/cache', () => ({ cachedJson: (_k: string, _ttl: unknown, produce: () => Promise<unknown>) => produce() }));

type Answer = { rcode?: number; ad?: boolean; answers?: Partial<DnsRecord>[] } | null;
let answer: (name: string, type: number, cd: boolean) => Answer = () => null;

vi.mock('../src/core/transport', () => ({
  RESOLVERS: [{ id: 'cloudflare', name: 'Cloudflare' }],
  resolve: async (_r: unknown, name: string, type: number, _t?: number, opts: { cd?: boolean } = {}) => {
    const a = answer(name, type, !!opts.cd);
    if (!a) throw new Error('Cloudflare is not reachable right now');
    const rcode = a.rcode ?? 0;
    const message = {
      rcode, rcodeName: ['NOERROR', '', 'SERVFAIL', 'NXDOMAIN'][rcode], ad: !!a.ad,
      answers: (a.answers ?? []).map((x) => ({ ttl: 60, cls: 1, typeName: '', ...x })),
    } as unknown as DnsMessage;
    return { message, ms: 1 };
  },
}));

const { default: dnssec } = await import('../src/tools/dnssec-check');
const { rootHistory } = await import('../src/jobs/root-monitor');

async function check(name: string): Promise<{ status: number; body: { verdict: string; notes: string[]; zones: { zone: string; keys: unknown[] }[] } }> {
  const res = await dnssec.api!({ url: new URL(`https://x/api/dnssec-check?name=${name}`) } as never, '');
  return { status: res.status, body: await res.json() };
}

describe('dnssec-check', () => {
  beforeEach(() => {
    answer = () => ({});
  });

  it('reports a failed check instead of "not signed" when the resolver is unreachable', async () => {
    answer = (_n, type) => (type === 6 ? null : {});
    const r = await check('example.com');
    expect(r.status).toBe(502);
    expect(r.body.verdict).toBe('unknown');
  });

  it('ignores keys that belong to the target of a CNAME', async () => {
    answer = (name, type) =>
      type === 48 && name === 'www.example.com'
        ? { answers: [{ name: 'www.example.com.', type: 5, data: 'example.net.' }, { name: 'example.net.', type: 48, data: '257 3 13 AQID' }] }
        : {};
    const r = await check('www.example.com');
    expect(r.body.verdict).toBe('insecure');
    expect(r.body.zones.find((z) => z.zone === 'www.example.com')).toBeUndefined();
  });

  it('names the unsigned domain, not a signed public suffix above it', async () => {
    answer = (name, type) =>
      name === 'co.uk' && type === 48 ? { answers: [{ name: 'co.uk.', type: 48, data: '257 3 8 AwEAAQ==' }] }
        : name === 'co.uk' && type === 43 ? { answers: [{ name: 'co.uk.', type: 43, data: '1 8 2 AB' }] }
          : {};
    const r = await check('example.co.uk');
    expect(r.body.verdict).toBe('insecure');
    expect(r.body.notes[0]).toMatch(/^example\.co\.uk is not signed/);
  });
});

describe('root-monitor history', () => {
  it('averages a bucket over several colos instead of keeping the last one', async () => {
    const now = Math.floor(Date.now() / 1000);
    const rows = [
      { root: 'A', bucket: 47, colo: 'FRA', n: 1, ok: 1, avg_ms: 10, serial: 1 },
      { root: 'A', bucket: 47, colo: 'AMS', n: 1, ok: 1, avg_ms: 30, serial: 1 },
      { root: 'B', bucket: 47, colo: 'FRA', n: 1, ok: 0, avg_ms: null, serial: null },
      { root: 'B', bucket: 47, colo: 'AMS', n: 1, ok: 1, avg_ms: 20, serial: 1 },
    ];
    const stmt = { bind: () => stmt, all: async () => ({ results: rows }) };
    const latest = { all: async () => ({ results: [{ root: 'A', ts: now, colo: 'FRA', ok: 1, query_ms: 10, serial: 1, instance: null }] }) };
    let calls = 0;
    const env = { DB: { prepare: () => (calls++ === 0 ? stmt : latest) } } as unknown as Env;
    const h = await rootHistory(env);
    expect(h.roots.find((r) => r.letter === 'A')!.series[47]).toBe(20);
    expect(h.roots.find((r) => r.letter === 'B')!.series[47]).toBe(20);
    expect(h.roots.find((r) => r.letter === 'C')!.series[47]).toBeNull();
  });
});
