import { describe, expect, it } from 'vitest';
import { cidrContains, parseIPv6 } from '../src/core/net';
import { convert } from '../src/tools/ip-range-to-cidr';
import { parsePorts } from '../src/tools/port-checker';
import { parse as parseTcpPing } from '../src/tools/tcp-ping';

const list = (input: string) => convert(input).cidrs.map((s) => `${s.prefix}`);

describe('cidrContains', () => {
  it('rejects malformed prefixes instead of matching everything', () => {
    expect(cidrContains('10.0.0.0/', '8.8.8.8')).toBe(false);
    expect(cidrContains('10.0.0.0/8/9', '10.1.1.1')).toBe(false);
    expect(cidrContains('10.0.0.0/1e1', '10.1.1.1')).toBe(false);
    expect(cidrContains('10.0.0.0/8', '10.1.1.1')).toBe(true);
    expect(cidrContains('0.0.0.0/0', '8.8.8.8')).toBe(true);
    expect(cidrContains('2001:db8::1', '2001:db8::1')).toBe(true);
  });
});

describe('parseIPv6 edge cases', () => {
  it('accepts valid forms', () => {
    for (const ok of ['::', '::1', '1::', '1:2:3:4:5:6:7::', '::ffff:192.0.2.1', '1:2:3:4:5:6:1.2.3.4']) expect(parseIPv6(ok)).not.toBeNull();
  });
  it('rejects invalid forms', () => {
    for (const bad of [':::', '1:::2', ':1::2', '1::2::3', '1:2:3:4:5:6:7:8:9', '1::2:3:4:5:6:7:8', '00001::', '::ffff:01.2.3.4', 'fe80::1%eth0', '1:2:3:4:5:6:7:1.2.3.4']) {
      expect(parseIPv6(bad)).toBeNull();
    }
  });
});

describe('range to CIDR', () => {
  it('handles reversed ranges and shorthand', () => {
    expect(convert('10.0.0.20 - 10.0.0.5').cidrs).toEqual(convert('10.0.0.5-20').cidrs);
  });
  it('includes the whole block when a range end is a CIDR', () => {
    const r = convert('10.0.0.0/24 - 10.0.1.0/24');
    expect(r.cidrs).toHaveLength(1);
    expect(r.cidrs[0]!.prefix).toBe(23);
  });
  it('merges many overlapping ranges without hitting the block limit', () => {
    const input = Array.from({ length: 400 }, () => '10.0.0.1 - 10.0.255.254').join('\n');
    const r = convert(input);
    expect(r.errors).toEqual([]);
    expect(r.cidrs.length).toBe(rangeCount());
  });
  it('merges adjacent IPv6 ranges', () => {
    expect(list('2001:db8::-2001:db8::7fff\n2001:db8::8000-2001:db8::ffff')).toEqual(['112']);
  });
});

function rangeCount(): number {
  return convert('10.0.0.1 - 10.0.255.254').cidrs.length;
}

describe('port list parsing', () => {
  it('expands ranges and removes duplicates', () => {
    expect(parsePorts('20-23, 22 80', 10)).toEqual([20, 21, 22, 23, 80]);
  });
  it('rejects invalid ports and reversed ranges', () => {
    for (const bad of ['0', '65536', '25-20', '1-2-3', 'http', '80.0']) expect(parsePorts(bad, 10)).toHaveProperty('bad');
  });
  it('enforces the limit before expanding', () => {
    expect(parsePorts('1-65535', 5)).toEqual({ tooMany: true });
    expect(parsePorts('1,2,3,4,5,6', 5)).toEqual({ tooMany: true });
    expect(parsePorts('1,1,1,1,1,1', 5)).toEqual([1]);
  });
});

describe('tcp ping input', () => {
  const p = (q: string) => parseTcpPing(new URL(`https://x/tcp-ping?${q}`));
  it('accepts host:port, bracketed IPv6 and URLs', () => {
    expect(p('host=example.com:8443')).toEqual({ host: 'example.com', port: 8443 });
    expect(p('host=[2606:4700::1]:80')).toEqual({ host: '2606:4700::1', port: 80 });
    expect(p('host=http://example.com/path')).toEqual({ host: 'example.com', port: 80 });
    expect(p('host=2001:db8::1')).toEqual({ host: '2001:db8::1', port: 443 });
  });
  it('rejects non-decimal ports', () => {
    for (const port of ['1e3', '0x50', '80.0', '0', '65536', '25']) expect(p(`host=example.com&port=${port}`)).toHaveProperty('error');
  });
});
