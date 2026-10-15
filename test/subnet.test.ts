import { describe, expect, it } from 'vitest';
import { aggregate, classify, formatCount, hostRange, netmask, parseSubnet, rangeToCidrs, size, split, toIp, wildcard } from '../src/core/subnet';

describe('parseSubnet', () => {
  it('parses CIDR, dotted masks and bare addresses', () => {
    const a = parseSubnet('192.168.1.130/26')!;
    expect(toIp(a.network, 4)).toBe('192.168.1.128');
    expect(toIp(a.last, 4)).toBe('192.168.1.191');
    expect(parseSubnet('10.1.2.3 255.255.0.0')!.prefix).toBe(16);
    expect(parseSubnet('10.1.2.3/255.255.255.0')!.prefix).toBe(24);
    expect(parseSubnet('8.8.8.8')!.prefix).toBe(32);
    expect(parseSubnet('2001:db8::1/48')!.prefix).toBe(48);
  });

  it('rejects invalid input', () => {
    for (const bad of ['', '10.0.0.0/33', '10.0.0.0 255.0.255.0', 'example.com', '2001:db8::/129']) {
      expect(parseSubnet(bad)).toBeNull();
    }
  });
});

describe('IPv4 details', () => {
  it('computes mask, wildcard and hosts', () => {
    const s = parseSubnet('172.16.5.4/20')!;
    expect(netmask(s)).toBe('255.255.240.0');
    expect(wildcard(s)).toBe('0.0.15.255');
    const h = hostRange(s);
    expect(toIp(h.first, 4)).toBe('172.16.0.1');
    expect(toIp(h.last, 4)).toBe('172.16.15.254');
    expect(h.count).toBe(4094n);
    expect(classify(s)).toBe('Private (RFC 1918)');
  });

  it('handles /31 and /32 without network and broadcast', () => {
    expect(hostRange(parseSubnet('10.0.0.0/31')!).count).toBe(2n);
    expect(hostRange(parseSubnet('10.0.0.5/32')!).count).toBe(1n);
  });

  it('classifies public and special ranges', () => {
    expect(classify(parseSubnet('1.1.1.0/24')!)).toBe('Public');
    expect(classify(parseSubnet('100.64.1.0/24')!)).toBe('Carrier-grade NAT (RFC 6598)');
  });
});

describe('IPv6 and splitting', () => {
  it('computes IPv6 ranges', () => {
    const s = parseSubnet('2001:db8:abcd::/48')!;
    expect(toIp(s.last, 6)).toBe('2001:db8:abcd:ffff:ffff:ffff:ffff:ffff');
    expect(size(s)).toBe(1n << 80n);
    expect(formatCount(size(s))).toBe('2^80');
    expect(classify(s)).toBe('Documentation');
  });

  it('splits into smaller blocks', () => {
    const { blocks, total } = split(parseSubnet('192.168.0.0/24')!, 26);
    expect(total).toBe(4n);
    expect(blocks.map((b) => `${toIp(b.network, 4)}/${b.prefix}`)).toEqual([
      '192.168.0.0/26', '192.168.0.64/26', '192.168.0.128/26', '192.168.0.192/26',
    ]);
    expect(split(parseSubnet('10.0.0.0/8')!, 30, 10).blocks).toHaveLength(10);
  });
});

describe('rangeToCidrs and aggregate', () => {
  const fmt = (list: { network: bigint; prefix: number; version: 4 | 6 }[]) => list.map((s) => `${toIp(s.network, s.version)}/${s.prefix}`);
  it('converts ranges to minimal CIDRs', () => {
    const a = parseSubnet('10.0.0.5')!, b = parseSubnet('10.0.0.20')!;
    expect(fmt(rangeToCidrs(a.network, b.network, 4))).toEqual(['10.0.0.5/32', '10.0.0.6/31', '10.0.0.8/29', '10.0.0.16/30', '10.0.0.20/32']);
    const x = parseSubnet('192.168.0.0')!, y = parseSubnet('192.168.255.255')!;
    expect(fmt(rangeToCidrs(x.network, y.network, 4))).toEqual(['192.168.0.0/16']);
  });
  it('merges adjacent and overlapping blocks', () => {
    const list = ['10.0.0.0/25', '10.0.0.128/25', '10.0.1.0/24', '10.0.0.64/26', '10.0.3.0/24'].map((c) => parseSubnet(c)!);
    expect(fmt(aggregate(list))).toEqual(['10.0.0.0/23', '10.0.3.0/24']);
    expect(fmt(aggregate(['2001:db8::/33', '2001:db8:8000::/33'].map((c) => parseSubnet(c)!)))).toEqual(['2001:db8::/32']);
  });
});
