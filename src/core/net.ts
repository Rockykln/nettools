// Input validation and address helpers shared by tools. Pure functions.

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function isIPv4(s: string): boolean {
  return IPV4.test(s);
}

export function parseIPv6(input: string): Uint8Array | null {
  let s = input;
  if (!s.includes(':') || !/^[0-9a-fA-F:.]+$/.test(s)) return null;
  // Embedded IPv4 suffix (e.g. ::ffff:192.0.2.1) becomes two hex groups.
  const v4 = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    if (!isIPv4(v4[2]!)) return null;
    const o = v4[2]!.split('.').map(Number) as [number, number, number, number];
    s = v4[1] + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
  }
  if (s.includes('.')) return null;
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const valid = (g: string) => /^[0-9a-fA-F]{1,4}$/.test(g);
  if (!head.every(valid) || !tail.every(valid)) return null;
  let groups: string[];
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = [...head, ...Array<string>(fill).fill('0'), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  const out = new Uint8Array(16);
  groups.forEach((g, i) => {
    const v = parseInt(g, 16);
    out[i * 2] = v >> 8;
    out[i * 2 + 1] = v & 0xff;
  });
  return out;
}

export function isIPv6(s: string): boolean {
  return parseIPv6(s) !== null;
}

export function isIP(s: string): boolean {
  return isIPv4(s) || isIPv6(s);
}

// Returns the ASCII (punycode) hostname, or null if the input is not a plausible domain name.
export function normalizeDomain(input: string): string | null {
  let s = input.trim().toLowerCase();
  if (!s) return null;
  // Accept pasted URLs and email addresses.
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^[^@/]*@/, '').split(/[/?#]/)[0]!;
  s = s.replace(/:\d+$/, '').replace(/\.$/, '');
  if (!s || s.length > 253) return null;
  let ascii: string;
  try {
    ascii = new URL(`http://${s}`).hostname;
  } catch {
    return null;
  }
  if (isIPv4(ascii) || ascii.startsWith('[')) return null;
  const label = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;
  const labels = ascii.split('.');
  if (labels.length < 1 || !labels.every((l) => label.test(l) || /^xn--[a-z0-9-]+$/.test(l))) return null;
  return ascii;
}

export function reverseName(ip: string): string | null {
  if (isIPv4(ip)) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  const b = parseIPv6(ip);
  if (!b) return null;
  const nibbles: string[] = [];
  for (const byte of b) nibbles.push((byte >> 4).toString(16), (byte & 0xf).toString(16));
  return nibbles.reverse().join('.') + '.ip6.arpa';
}

export function ipToBigInt(ip: string): { v: 4 | 6; n: bigint } | null {
  if (isIPv4(ip)) {
    return { v: 4, n: ip.split('.').reduce((acc, o) => (acc << 8n) | BigInt(o), 0n) };
  }
  const b = parseIPv6(ip);
  if (!b) return null;
  return { v: 6, n: b.reduce((acc, o) => (acc << 8n) | BigInt(o), 0n) };
}

export function cidrContains(cidr: string, ip: string): boolean {
  const parts = cidr.split('/');
  if (parts.length > 2) return false;
  const [base, bitsStr] = parts;
  const addr = ipToBigInt(ip);
  const net = base ? ipToBigInt(base) : null;
  if (!addr || !net || addr.v !== net.v) return false;
  const width = addr.v === 4 ? 32 : 128;
  if (bitsStr !== undefined && !/^\d{1,3}$/.test(bitsStr)) return false;
  const bits = bitsStr === undefined ? width : Number(bitsStr);
  if (bits > width) return false;
  const shift = BigInt(width - bits);
  return addr.n >> shift === net.n >> shift;
}

/** connect() needs IPv6 literals in brackets; a bare one fails with "cannot connect to the specified address". */
export function socketHost(host: string): string {
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}
