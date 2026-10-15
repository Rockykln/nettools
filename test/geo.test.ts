import { describe, expect, it } from 'vitest';
import { addressBytes, countryOf, lastAtOrBelow } from '../src/core/geo';

// The Workers types have no Node declarations; fetch the one function needed.
const { readFileSync } = (globalThis as unknown as {
  process: { getBuiltinModule(id: 'node:fs'): { readFileSync(path: string): Uint8Array } };
}).process.getBuiltinModule('node:fs');

// Serves public/data/geo from disk like the ASSETS binding.
const assets = {
  async fetch(req: Request) {
    const path = new URL(req.url).pathname;
    try {
      return new Response(readFileSync(`public${path}`));
    } catch {
      return new Response('not found', { status: 404 });
    }
  },
} as unknown as Fetcher;

describe('geo', () => {
  it('parses addresses to bytes', () => {
    expect([...addressBytes('1.2.3.4')!]).toEqual([1, 2, 3, 4]);
    expect([...addressBytes('2001:db8::1')!]).toEqual([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    expect([...addressBytes('::ffff:1.2.3.4')!].slice(10)).toEqual([0xff, 0xff, 1, 2, 3, 4]);
    expect(addressBytes('example.com')).toBeNull();
  });
  it('finds the last entry at or below a key', () => {
    const list = [10, 20, 30];
    expect(lastAtOrBelow(3, (i) => list[i]! - 5)).toBe(-1);
    expect(lastAtOrBelow(3, (i) => list[i]! - 20)).toBe(1);
    expect(lastAtOrBelow(3, (i) => list[i]! - 99)).toBe(2);
  });
  it('looks up countries in the bundled data', async () => {
    expect((await countryOf(assets, '1.0.0.1'))?.code).toBe('AU');
    expect((await countryOf(assets, '1.0.1.1'))?.code).toBe('CN');
    expect((await countryOf(assets, '0.1.2.3'))?.code).toBeNull();
    expect((await countryOf(assets, '255.255.255.255'))).not.toBeNull();
    expect((await countryOf(assets, '2003:e0::1'))?.code).toBe('DE');
    expect((await countryOf(assets, '::1'))?.code).toBeNull();
  });
});
