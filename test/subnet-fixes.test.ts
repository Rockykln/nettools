import { describe, expect, it } from 'vitest';
import { hostRange, parseSubnet, size, split, toIp } from '../src/core/subnet';

describe('parseSubnet input forms', () => {
  it('accepts wildcard masks', () => {
    expect(parseSubnet('10.0.0.0 0.0.0.255')!.prefix).toBe(24);
    expect(parseSubnet('10.0.0.0/0.0.255.255')!.prefix).toBe(16);
    // Ambiguous masks are read as netmasks.
    expect(parseSubnet('10.0.0.0 0.0.0.0')!.prefix).toBe(0);
    expect(parseSubnet('10.0.0.1 255.255.255.255')!.prefix).toBe(32);
  });
  it('rejects dotted masks on IPv6 and extra tokens', () => {
    expect(parseSubnet('2001:db8::1 255.255.255.0')).toBeNull();
    expect(parseSubnet('2001:db8::1/255.255.255.0')).toBeNull();
    expect(parseSubnet('10.0.0.1 255.255.255.0 foo')).toBeNull();
    expect(parseSubnet('10.0.0.1/24/8')).toBeNull();
    expect(parseSubnet('10.0.0.1/')).toBeNull();
  });
  it('strips brackets and zone ids', () => {
    expect(toIp(parseSubnet('fe80::1%eth0/64')!.network, 6)).toBe('fe80::');
    expect(parseSubnet('[2001:db8::1]')!.prefix).toBe(128);
  });
});

describe('prefix edge cases', () => {
  it('handles /0, /127 and /128', () => {
    expect(size(parseSubnet('1.2.3.4/0')!)).toBe(1n << 32n);
    expect(hostRange(parseSubnet('2001:db8::1/127')!).count).toBe(2n);
    expect(hostRange(parseSubnet('2001:db8::1/128')!).count).toBe(1n);
    expect(toIp(parseSubnet('::/0')!.last, 6)).toBe('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
  });
  it('limits split output but reports the full count', () => {
    const r = split(parseSubnet('2001:db8::/32')!, 64);
    expect(r.blocks).toHaveLength(256);
    expect(r.total).toBe(1n << 32n);
    expect(split(parseSubnet('10.0.0.0/24')!, 33).blocks).toHaveLength(0);
  });
});
