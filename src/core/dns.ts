// DNS wire format (RFC 1035) encoder/decoder. Pure functions, no runtime APIs,
// so it can be unit-tested outside the Workers runtime.

export const RR_TYPES = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33,
  DS: 43, RRSIG: 46, DNSKEY: 48, HTTPS: 65, CAA: 257,
} as const;
export type RrTypeName = keyof typeof RR_TYPES;

const TYPE_NAMES = new Map<number, string>(Object.entries(RR_TYPES).map(([k, v]) => [v, k]));
TYPE_NAMES.set(41, 'OPT');
TYPE_NAMES.set(64, 'SVCB');

export const CLASS_IN = 1;
export const CLASS_CH = 3;

const RCODES = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED', 'YXDOMAIN', 'YXRRSET', 'NXRRSET', 'NOTAUTH', 'NOTZONE'];

export function typeName(t: number): string {
  return TYPE_NAMES.get(t) ?? `TYPE${t}`;
}

export interface DnsRecord {
  name: string;
  type: number;
  typeName: string;
  cls: number;
  ttl: number;
  data: string;
}

export interface DnsMessage {
  id: number;
  rcode: number;
  rcodeName: string;
  aa: boolean;
  tc: boolean;
  rd: boolean;
  ra: boolean;
  ad: boolean;
  questions: { name: string; type: number; cls: number }[];
  answers: DnsRecord[];
  authority: DnsRecord[];
  additional: DnsRecord[];
}

export interface QueryOptions {
  id?: number;
  /** Recursion desired. Default true; set false for authoritative/root queries. */
  rd?: boolean;
  /** Ask a validating resolver to report DNSSEC status in the AD bit (RFC 6840). */
  ad?: boolean;
  /** Checking disabled: the resolver returns data even if DNSSEC validation fails. */
  cd?: boolean;
  cls?: number;
}

export function encodeName(name: string): Uint8Array {
  const trimmed = name.endsWith('.') ? name.slice(0, -1) : name;
  const out: number[] = [];
  if (trimmed.length > 0) {
    for (const label of trimmed.split('.')) {
      const bytes = new TextEncoder().encode(label);
      if (bytes.length === 0 || bytes.length > 63) throw new Error(`Invalid DNS label in "${name}"`);
      out.push(bytes.length, ...bytes);
    }
  }
  out.push(0);
  if (out.length > 255) throw new Error('DNS name too long');
  return Uint8Array.from(out);
}

export function buildQuery(name: string, type: number, opts: QueryOptions = {}): Uint8Array {
  const qname = encodeName(name);
  const msg = new Uint8Array(12 + qname.length + 4);
  const view = new DataView(msg.buffer);
  view.setUint16(0, opts.id ?? Math.floor(Math.random() * 0xffff));
  view.setUint16(2, (opts.rd === false ? 0 : 0x0100) | (opts.ad ? 0x0020 : 0) | (opts.cd ? 0x0010 : 0));
  view.setUint16(4, 1);
  msg.set(qname, 12);
  view.setUint16(12 + qname.length, type);
  view.setUint16(14 + qname.length, opts.cls ?? CLASS_IN);
  return msg;
}

class Reader {
  pos = 0;
  constructor(readonly buf: Uint8Array, readonly view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)) {}

  need(n: number): void {
    if (this.pos + n > this.buf.length) throw new Error('Truncated DNS message');
  }
  u8(): number { this.need(1); return this.buf[this.pos++]!; }
  u16(): number { this.need(2); const v = this.view.getUint16(this.pos); this.pos += 2; return v; }
  u32(): number { this.need(4); const v = this.view.getUint32(this.pos); this.pos += 4; return v; }
  bytes(n: number): Uint8Array { this.need(n); const b = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return b; }

  name(): string {
    const labels: string[] = [];
    let pos = this.pos;
    let jumped = false;
    let wireLen = 1;
    for (let hops = 0; hops < 128; hops++) {
      if (pos >= this.buf.length) throw new Error('Truncated DNS name');
      const len = this.buf[pos]!;
      if (len === 0) {
        if (!jumped) this.pos = pos + 1;
        return labels.length ? labels.join('.') + '.' : '.';
      }
      if ((len & 0xc0) === 0xc0) {
        if (pos + 1 >= this.buf.length) throw new Error('Truncated DNS pointer');
        if (!jumped) this.pos = pos + 2;
        pos = ((len & 0x3f) << 8) | this.buf[pos + 1]!;
        jumped = true;
        continue;
      }
      // 0x40 and 0x80 are obsolete/undefined label types (RFC 6891 section 5).
      if (len & 0xc0) throw new Error('Unsupported DNS label type');
      if (pos + 1 + len > this.buf.length) throw new Error('Truncated DNS label');
      wireLen += 1 + len;
      if (wireLen > 255) throw new Error('DNS name too long');
      labels.push(escapeLabel(this.buf.subarray(pos + 1, pos + 1 + len)));
      pos += 1 + len;
    }
    throw new Error('DNS name compression loop');
  }
}

function escapeLabel(b: Uint8Array): string {
  let s = '';
  for (const c of b) {
    if (c === 0x2e || c === 0x5c) s += '\\' + String.fromCharCode(c);
    else if (c > 0x20 && c < 0x7f) s += String.fromCharCode(c);
    else s += '\\' + c.toString().padStart(3, '0');
  }
  return s;
}

// Presentation format of a character string without the quotes (RFC 1035 section 5.1).
function escapeString(b: Uint8Array, special: number[] = []): string {
  let s = '';
  for (const c of b) {
    if (c === 0x22 || c === 0x5c || special.includes(c)) s += '\\' + String.fromCharCode(c);
    else if (c >= 0x20 && c < 0x7f) s += String.fromCharCode(c);
    else s += '\\' + c.toString().padStart(3, '0');
  }
  return s;
}

function charString(r: Reader): string {
  return escapeString(r.bytes(r.u8()));
}

const SVC_KEYS = ['mandatory', 'alpn', 'no-default-alpn', 'port', 'ipv4hint', 'ech', 'ipv6hint', 'dohpath', 'ohttp'];
const svcKey = (k: number) => SVC_KEYS[k] ?? `key${k}`;

// SVCB/HTTPS (RFC 9460): "priority target key=value ...".
function svcb(r: Reader, end: number): string {
  const out = [String(r.u16()), r.name()];
  while (r.pos < end) {
    const key = r.u16();
    const v = r.bytes(r.u16());
    const vr = new Reader(v);
    const list = (n: number, f: (b: Uint8Array) => string) => {
      if (v.length % n) throw new Error('Malformed SvcParam');
      const items: string[] = [];
      for (let i = 0; i < v.length; i += n) items.push(f(v.subarray(i, i + n)));
      return items.join(',');
    };
    let value: string | null;
    switch (key) {
      case 0:
        value = list(2, (b) => svcKey((b[0]! << 8) | b[1]!));
        break;
      case 1: {
        const ids: string[] = [];
        while (vr.pos < v.length) ids.push(escapeString(vr.bytes(vr.u8()), [0x2c]));
        value = `"${ids.join(',')}"`;
        break;
      }
      case 2:
      case 8:
        value = v.length ? `"${escapeString(v)}"` : null;
        break;
      case 3:
        value = String(vr.u16());
        break;
      case 4:
        value = list(4, (b) => Array.from(b).join('.'));
        break;
      case 5:
        value = base64(v);
        break;
      case 6:
        value = list(16, formatIPv6);
        break;
      default:
        value = v.length ? `"${escapeString(v)}"` : null;
    }
    out.push(value === null ? svcKey(key) : `${svcKey(key)}=${value}`);
  }
  return out.join(' ');
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('').toUpperCase();

function base64(b: Uint8Array): string {
  let s = '';
  for (const c of b) s += String.fromCharCode(c);
  return btoa(s);
}

export function formatIPv6(b: Uint8Array): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((b[i]! << 8) | b[i + 1]!);
  // Find the longest run of zero groups (length >= 2) for "::" compression.
  let bestStart = -1, bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  // IPv4-mapped addresses keep the IPv4 part in dotted form (RFC 5952 section 5).
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) return `::ffff:${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
  const parts = groups.map((g) => g.toString(16));
  if (bestStart < 0) return parts.join(':');
  const head = parts.slice(0, bestStart).join(':');
  const tail = parts.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

function rdata(r: Reader, type: number, len: number): string {
  const end = r.pos + len;
  r.need(len);
  let out: string;
  switch (type) {
    case RR_TYPES.A:
      out = Array.from(r.bytes(4)).join('.');
      break;
    case RR_TYPES.AAAA:
      out = formatIPv6(r.bytes(16));
      break;
    case RR_TYPES.NS:
    case RR_TYPES.CNAME:
    case RR_TYPES.PTR:
      out = r.name();
      break;
    case RR_TYPES.MX:
      out = `${r.u16()} ${r.name()}`;
      break;
    case RR_TYPES.TXT: {
      const parts: string[] = [];
      while (r.pos < end) parts.push(`"${charString(r)}"`);
      out = parts.join(' ');
      break;
    }
    case RR_TYPES.SOA:
      out = `${r.name()} ${r.name()} ${r.u32()} ${r.u32()} ${r.u32()} ${r.u32()} ${r.u32()}`;
      break;
    case RR_TYPES.SRV:
      out = `${r.u16()} ${r.u16()} ${r.u16()} ${r.name()}`;
      break;
    case RR_TYPES.CAA: {
      const flags = r.u8();
      const tag = charString(r);
      out = `${flags} ${tag} "${escapeString(r.bytes(end - r.pos))}"`;
      break;
    }
    case RR_TYPES.DS:
      out = `${r.u16()} ${r.u8()} ${r.u8()} ${hex(r.bytes(end - r.pos))}`;
      break;
    case RR_TYPES.DNSKEY:
      out = `${r.u16()} ${r.u8()} ${r.u8()} ${base64(r.bytes(end - r.pos))}`;
      break;
    case 64:
    case RR_TYPES.HTTPS:
      out = svcb(r, end);
      break;
    default:
      out = len ? `\\# ${len} ${hex(r.bytes(len))}` : '\\# 0';
  }
  if (r.pos > end) throw new Error('Malformed DNS record: data longer than RDLENGTH');
  r.pos = end;
  return out;
}

function record(r: Reader): DnsRecord {
  const name = r.name();
  const type = r.u16();
  const cls = r.u16();
  const ttl = r.u32();
  const len = r.u16();
  const data = rdata(r, type, len);
  return { name, type, typeName: typeName(type), cls, ttl, data };
}

export function parseMessage(buf: Uint8Array): DnsMessage {
  const r = new Reader(buf);
  const id = r.u16();
  const flags = r.u16();
  const qd = r.u16(), an = r.u16(), ns = r.u16(), ar = r.u16();
  const questions = [];
  for (let i = 0; i < qd; i++) questions.push({ name: r.name(), type: r.u16(), cls: r.u16() });
  const section = (n: number) => Array.from({ length: n }, () => record(r));
  const answers = section(an);
  const authority = section(ns);
  const additional = section(ar).filter((rec) => rec.type !== 41);
  const rcode = flags & 0x0f;
  return {
    id,
    rcode,
    rcodeName: RCODES[rcode] ?? `RCODE${rcode}`,
    aa: !!(flags & 0x0400),
    tc: !!(flags & 0x0200),
    rd: !!(flags & 0x0100),
    ra: !!(flags & 0x0080),
    ad: !!(flags & 0x0020),
    questions,
    answers,
    authority,
    additional,
  };
}

// Prefix a message with its 2-byte length, as required for DNS over TCP (RFC 7766).
export function frameTcp(msg: Uint8Array): Uint8Array {
  const out = new Uint8Array(msg.length + 2);
  new DataView(out.buffer).setUint16(0, msg.length);
  out.set(msg, 2);
  return out;
}

// Split a TCP byte stream into complete DNS messages. Returns the messages and the unconsumed rest.
export function unframeTcp(buf: Uint8Array): { messages: Uint8Array[]; rest: Uint8Array } {
  const messages: Uint8Array[] = [];
  let pos = 0;
  while (buf.length - pos >= 2) {
    const len = (buf[pos]! << 8) | buf[pos + 1]!;
    if (buf.length - pos - 2 < len) break;
    messages.push(buf.slice(pos + 2, pos + 2 + len));
    pos += 2 + len;
  }
  return { messages, rest: buf.slice(pos) };
}

/** DNSKEY key tag (RFC 4034 Appendix B) from the formatted record "flags protocol algorithm base64key". */
export function dnskeyTag(data: string): number | null {
  const [flags, proto, alg, ...key] = data.split(' ');
  if (!flags || !proto || !alg || !key.length) return null;
  let bytes: number[];
  try {
    bytes = [...atob(key.join(''))].map((ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
  const rdata = [Number(flags) >> 8, Number(flags) & 0xff, Number(proto), Number(alg), ...bytes];
  let ac = 0;
  rdata.forEach((b, i) => { ac += i & 1 ? b : b << 8; });
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}
