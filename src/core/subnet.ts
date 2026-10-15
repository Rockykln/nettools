// IPv4/IPv6 subnet arithmetic on BigInt. Pure functions.
import { formatIPv6 } from './dns';
import { ipToBigInt, isIPv4 } from './net';

export interface Subnet {
  version: 4 | 6;
  prefix: number;
  network: bigint;
  /** Last address in the block (broadcast for IPv4). */
  last: bigint;
  /** The address the user entered, which may lie inside the block. */
  input: bigint;
}

const width = (v: 4 | 6) => (v === 4 ? 32 : 128);

export function toIp(n: bigint, v: 4 | 6): string {
  if (v === 4) return [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 255n)).join('.');
  const b = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) {
    b[i] = Number(n & 255n);
    n >>= 8n;
  }
  return formatIPv6(b);
}

function maskToPrefix(mask: string): number | null {
  const m = ipToBigInt(mask);
  if (!m || m.v !== 4) return null;
  const bits = m.n.toString(2).padStart(32, '0');
  if (/^1*0*$/.test(bits)) return bits.indexOf('0') === -1 ? 32 : bits.indexOf('0');
  // Wildcard (inverse) mask as used in Cisco ACLs, e.g. 0.0.0.255 for /24.
  if (/^0*1*$/.test(bits)) return bits.indexOf('1');
  return null;
}

// Accepts "192.168.1.10/24", "192.168.1.10 255.255.255.0", "10.0.0.0 0.0.0.255", "2001:db8::/48" or a bare address.
export function parseSubnet(input: string): Subnet | null {
  const s = input.trim().replace(/\s+/g, ' ');
  let addr: string;
  let prefix: number | null;
  let dotted = false;
  const slash = s.split('/');
  if (slash.length > 2) return null;
  if (slash.length === 2) {
    addr = slash[0]!.trim();
    const p = slash[1]!.trim();
    dotted = !/^\d{1,3}$/.test(p);
    prefix = !dotted ? Number(p) : isIPv4(p) ? maskToPrefix(p) : null;
  } else if (s.includes(' ')) {
    const parts = s.split(' ');
    if (parts.length !== 2) return null;
    addr = parts[0]!;
    dotted = true;
    prefix = isIPv4(parts[1]!) ? maskToPrefix(parts[1]!) : null;
  } else {
    addr = s;
    prefix = isIPv4(s) ? 32 : 128;
  }
  // Zone ids ("fe80::1%eth0") only matter on the local host.
  addr = addr.replace(/^\[(.*)\]$/, '$1').replace(/%[\w.-]+$/, '');
  const ip = ipToBigInt(addr);
  if (!ip || prefix === null || prefix < 0 || prefix > width(ip.v)) return null;
  // A dotted mask only makes sense for IPv4.
  if (dotted && ip.v !== 4) return null;
  const w = BigInt(width(ip.v));
  const hostBits = w - BigInt(prefix);
  const all = (1n << w) - 1n;
  const hostMask = (1n << hostBits) - 1n;
  const network = ip.n & (all ^ hostMask);
  return { version: ip.v, prefix, network, last: network | hostMask, input: ip.n };
}

export function size(s: Subnet): bigint {
  return s.last - s.network + 1n;
}

export function netmask(s: Subnet): string {
  const w = BigInt(width(s.version));
  const all = (1n << w) - 1n;
  return toIp(all ^ ((1n << (w - BigInt(s.prefix))) - 1n), s.version);
}

export function wildcard(s: Subnet): string {
  return toIp((1n << BigInt(width(s.version) - s.prefix)) - 1n, s.version);
}

/** Usable host range. IPv4 /31 and /32 have no network/broadcast addresses (RFC 3021). */
export function hostRange(s: Subnet): { first: bigint; last: bigint; count: bigint } {
  if (s.version === 6 || s.prefix >= 31) return { first: s.network, last: s.last, count: size(s) };
  return { first: s.network + 1n, last: s.last - 1n, count: size(s) - 2n };
}

const V4_SPECIAL: [string, string][] = [
  ['0.0.0.0/8', 'This network'],
  ['10.0.0.0/8', 'Private (RFC 1918)'],
  ['100.64.0.0/10', 'Carrier-grade NAT (RFC 6598)'],
  ['127.0.0.0/8', 'Loopback'],
  ['169.254.0.0/16', 'Link-local'],
  ['172.16.0.0/12', 'Private (RFC 1918)'],
  ['192.0.2.0/24', 'Documentation (TEST-NET-1)'],
  ['192.168.0.0/16', 'Private (RFC 1918)'],
  ['198.18.0.0/15', 'Benchmarking'],
  ['198.51.100.0/24', 'Documentation (TEST-NET-2)'],
  ['203.0.113.0/24', 'Documentation (TEST-NET-3)'],
  ['224.0.0.0/4', 'Multicast'],
  ['240.0.0.0/4', 'Reserved'],
];

const V6_SPECIAL: [string, string][] = [
  ['::1/128', 'Loopback'],
  ['::ffff:0:0/96', 'IPv4-mapped'],
  ['64:ff9b::/96', 'NAT64'],
  ['2001:db8::/32', 'Documentation'],
  ['2002::/16', '6to4'],
  ['fc00::/7', 'Unique local (private)'],
  ['fe80::/10', 'Link-local'],
  ['ff00::/8', 'Multicast'],
  ['2000::/3', 'Global unicast'],
];

/** Address type of the network, e.g. "Private (RFC 1918)" or "Public". */
export function classify(s: Subnet): string {
  for (const [cidr, label] of s.version === 4 ? V4_SPECIAL : V6_SPECIAL) {
    const block = parseSubnet(cidr)!;
    if (s.network >= block.network && s.last <= block.last) return label;
  }
  return s.version === 4 ? 'Public' : 'Other';
}

/** Splits a subnet into blocks of `newPrefix`, returning at most `limit` of them. */
export function split(s: Subnet, newPrefix: number, limit = 256): { blocks: Subnet[]; total: bigint } {
  if (newPrefix <= s.prefix || newPrefix > width(s.version)) return { blocks: [], total: 0n };
  const total = 1n << BigInt(newPrefix - s.prefix);
  const step = 1n << BigInt(width(s.version) - newPrefix);
  const blocks: Subnet[] = [];
  for (let i = 0n; i < total && i < BigInt(limit); i++) {
    const network = s.network + i * step;
    blocks.push({ version: s.version, prefix: newPrefix, network, last: network + step - 1n, input: network });
  }
  return { blocks, total };
}

export function binary(n: bigint, v: 4 | 6): string {
  const bits = n.toString(2).padStart(width(v), '0');
  return v === 4 ? bits.match(/.{8}/g)!.join('.') : bits.match(/.{16}/g)!.join(':');
}

export function formatCount(n: bigint): string {
  if (n < 10n ** 15n) return n.toLocaleString('en-US');
  const exp = n.toString(2).length - 1;
  return n === 1n << BigInt(exp) ? `2^${exp}` : `≈ 2^${exp}`;
}

/** Smallest list of CIDR blocks that exactly covers start..end (inclusive). */
export function rangeToCidrs(start: bigint, end: bigint, v: 4 | 6): Subnet[] {
  const w = BigInt(width(v));
  const out: Subnet[] = [];
  let cur = start;
  while (cur <= end) {
    // Largest block that is aligned at `cur` and does not run past `end`.
    let bits = 0n;
    while (bits < w && (cur & ((1n << (bits + 1n)) - 1n)) === 0n && cur + (1n << (bits + 1n)) - 1n <= end) bits++;
    const last = cur + (1n << bits) - 1n;
    out.push({ version: v, prefix: Number(w - bits), network: cur, last, input: cur });
    cur = last + 1n;
  }
  return out;
}

/** Merges overlapping and adjacent blocks of one IP version and returns the minimal CIDR list. */
export function aggregate(blocks: Subnet[]): Subnet[] {
  if (!blocks.length) return [];
  const v = blocks[0]!.version;
  const sorted = [...blocks].sort((a, b) => (a.network < b.network ? -1 : a.network > b.network ? 1 : 0));
  const ranges: [bigint, bigint][] = [];
  for (const b of sorted) {
    const prev = ranges[ranges.length - 1];
    if (prev && b.network <= prev[1] + 1n) prev[1] = b.last > prev[1] ? b.last : prev[1];
    else ranges.push([b.network, b.last]);
  }
  return ranges.flatMap(([s, e]) => rangeToCidrs(s, e, v));
}
