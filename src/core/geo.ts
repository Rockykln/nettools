import { isIPv4, isIPv6 } from './net';

// IP to country from DB-IP Lite (CC BY 4.0), stored as static assets by scripts/update-geo.mjs.
// A lookup reads the small index once per isolate and one chunk of at most 4096 ranges.

export const GEO_CREDIT = { name: 'DB-IP', url: 'https://db-ip.com', license: 'CC BY 4.0' };

interface GeoIndex {
  month: string;
  countries: string[];
  v4: number[];
  v6: string[];
}

export interface GeoResult {
  /** ISO 3166-1 alpha-2, or null for unassigned space. */
  code: string | null;
  /** Month of the data set, e.g. "2026-10". */
  month: string;
}

let indexPromise: Promise<GeoIndex> | null = null;
const chunks = new Map<string, Promise<Uint8Array>>();
const MAX_CHUNKS = 32;

async function asset(assets: Fetcher, path: string): Promise<Response> {
  const res = await assets.fetch(new Request(`https://assets.local/data/geo/${path}`));
  if (!res.ok) throw new Error(`Geo data ${path}: HTTP ${res.status}`);
  return res;
}

function loadIndex(assets: Fetcher): Promise<GeoIndex> {
  indexPromise ??= asset(assets, 'index.json').then((r) => r.json<GeoIndex>()).catch((e) => {
    indexPromise = null;
    throw e;
  });
  return indexPromise;
}

function loadChunk(assets: Fetcher, name: string): Promise<Uint8Array> {
  let p = chunks.get(name);
  if (!p) {
    if (chunks.size >= MAX_CHUNKS) chunks.delete(chunks.keys().next().value!);
    p = asset(assets, name).then(async (r) => new Uint8Array(await r.arrayBuffer()));
    p.catch(() => chunks.delete(name));
    chunks.set(name, p);
  }
  return p;
}

/** 16 bytes for IPv6, 4 for IPv4; null if not an address. */
export function addressBytes(ip: string): Uint8Array | null {
  if (isIPv4(ip)) return Uint8Array.from(ip.split('.').map(Number));
  if (!isIPv6(ip)) return null;
  let s = ip.toLowerCase();
  // Embedded IPv4 (::ffff:1.2.3.4) becomes two groups.
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const b = v4[1]!.split('.').map(Number);
    s = s.slice(0, -v4[1]!.length) + `${((b[0]! << 8) | b[1]!).toString(16)}:${((b[2]! << 8) | b[3]!).toString(16)}`;
  }
  const [head, tail] = s.includes('::') ? s.split('::') : [s, null];
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = tail === null ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  const out = new Uint8Array(16);
  groups.forEach((g, i) => {
    const n = parseInt(g, 16);
    out[i * 2] = n >> 8;
    out[i * 2 + 1] = n & 0xff;
  });
  return out;
}

function compare(a: Uint8Array, b: Uint8Array, bOffset: number): number {
  for (let i = 0; i < a.length; i++) {
    const d = a[i]! - b[bOffset + i]!;
    if (d) return d;
  }
  return 0;
}

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

/** Index of the last entry <= key in an ascending list, or -1. */
export function lastAtOrBelow(count: number, cmp: (i: number) => number): number {
  let lo = 0, hi = count - 1, found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (cmp(mid) <= 0) { found = mid; lo = mid + 1; } else hi = mid - 1;
  }
  return found;
}

export async function countryOf(assets: Fetcher, ip: string): Promise<GeoResult | null> {
  const key = addressBytes(ip);
  if (!key) return null;
  const index = await loadIndex(assets);
  const fam = key.length === 4 ? 'v4' : 'v6';
  const keyNum = fam === 'v4' ? ((key[0]! << 24) >>> 0) + (key[1]! << 16) + (key[2]! << 8) + key[3]! : 0;
  const keyHex = fam === 'v6' ? hex(key) : '';
  const chunk = fam === 'v4'
    ? lastAtOrBelow(index.v4.length, (i) => index.v4[i]! - keyNum)
    : lastAtOrBelow(index.v6.length, (i) => (index.v6[i]! < keyHex ? -1 : index.v6[i]! > keyHex ? 1 : 0));
  if (chunk < 0) return { code: null, month: index.month };
  const data = await loadChunk(assets, `${fam}-${chunk}.bin`);
  const row = key.length + 1;
  const i = lastAtOrBelow(data.length / row, (k) => compare(data.subarray(k * row, k * row + key.length), key, 0));
  const code = i < 0 ? '' : index.countries[data[i * row + key.length]!] ?? '';
  return { code: code || null, month: index.month };
}
