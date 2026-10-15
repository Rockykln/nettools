// SPF (RFC 7208) and DMARC (RFC 7489) record analysis. The TXT lookup is injected so this stays testable.

export type TxtLookup = (name: string) => Promise<string[]>;

/** Joins the character-strings of a formatted TXT record ("a" "b") into one string. */
export function txtValue(data: string): string {
  const parts = data.match(/"((?:[^"\\]|\\.)*)"/g) ?? [];
  // Presentation format: \DDD is a decimal byte, \X a literal X. Bytes are joined first so that
  // multi-byte UTF-8 sequences split across escapes decode correctly.
  const bytes: number[] = [];
  const enc = new TextEncoder();
  for (const p of parts) {
    const body = p.slice(1, -1);
    for (let i = 0; i < body.length; i++) {
      if (body[i] === '\\') {
        const ddd = body.slice(i + 1, i + 4);
        if (/^\d{3}$/.test(ddd) && Number(ddd) < 256) {
          bytes.push(Number(ddd));
          i += 3;
          continue;
        }
        if (i + 1 < body.length) i++;
      }
      const cp = body.codePointAt(i)!;
      if (cp > 0xffff) i++;
      bytes.push(...enc.encode(String.fromCodePoint(cp)));
    }
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

export interface SpfNode {
  domain: string;
  record: string | null;
  lookups: number;
  includes: SpfNode[];
  error: string | null;
  /** How the parent reached this node; absent on the root. */
  via?: 'include' | 'redirect';
}

export interface SpfResult {
  record: string | null;
  records: number;
  allQualifier: string | null;
  totalLookups: number;
  tree: SpfNode | null;
  problems: string[];
}

const LOOKUP_MECHS = /^[+\-~?]?(include:|a$|a:|a\/|mx$|mx:|mx\/|ptr$|ptr:|exists:)/i;
const ALL_TERM = /(?:^|\s)([+\-~?]?)all(?=\s|$)/i;

export function spfRecords(txts: string[]): string[] {
  return txts.filter((t) => /^v=spf1(\s|$)/i.test(t));
}

async function walk(domain: string, lookup: TxtLookup, budget: { queries: number }, depth: number, seen: Set<string>): Promise<SpfNode> {
  const node: SpfNode = { domain, record: null, lookups: 0, includes: [], error: null };
  const key = domain.toLowerCase().replace(/\.$/, '');
  if (seen.has(key)) {
    node.error = 'Include loop: this domain is already being evaluated';
    return node;
  }
  if (budget.queries <= 0 || depth > 10) {
    node.error = 'Not followed: too many nested lookups';
    return node;
  }
  budget.queries--;
  let records: string[];
  try {
    records = spfRecords(await lookup(domain));
  } catch {
    node.error = 'TXT lookup failed';
    return node;
  }
  if (records.length === 0) {
    node.error = 'No SPF record';
    return node;
  }
  if (records.length > 1) node.error = 'Multiple SPF records';
  node.record = records[0]!;
  const terms = node.record.trim().split(/\s+/).slice(1);
  // RFC 7208 6.1: redirect= is ignored when the record contains an "all" mechanism.
  const hasAll = terms.some((t) => /^[+\-~?]?all$/i.test(t));
  const inner = new Set(seen).add(key);
  for (const term of terms) {
    if (LOOKUP_MECHS.test(term)) node.lookups++;
    const include = term.match(/^[+\-~?]?include:(.+)$/i)?.[1];
    const redirect = hasAll ? undefined : term.match(/^redirect=(.+)$/i)?.[1];
    if (redirect) node.lookups++;
    const target = include ?? redirect;
    if (target && !target.includes('%')) {
      const child = await walk(target, lookup, budget, depth + 1, inner);
      child.via = include ? 'include' : 'redirect';
      node.includes.push(child);
    }
  }
  return node;
}

const total = (n: SpfNode): number => n.lookups + n.includes.reduce((a, c) => a + total(c), 0);

// The effective "all" of a record that ends in redirect= is the one of the redirect target.
function effectiveAll(n: SpfNode): string | null {
  const all = n.record?.match(ALL_TERM);
  if (all) return all[1] || '+';
  const next = n.includes.find((c) => c.via === 'redirect');
  return next ? effectiveAll(next) : null;
}

export async function analyzeSpf(domain: string, lookup: TxtLookup): Promise<SpfResult> {
  let txts: string[];
  try {
    txts = await lookup(domain);
  } catch {
    return { record: null, records: 0, allQualifier: null, totalLookups: 0, tree: null, problems: ['The TXT lookup for the domain failed, so SPF could not be checked. Try again later.'] };
  }
  const records = spfRecords(txts);
  const problems: string[] = [];
  if (records.length === 0) {
    return { record: null, records: 0, allQualifier: null, totalLookups: 0, tree: null, problems: ['No SPF record. Anyone can send mail that claims to come from this domain.'] };
  }
  if (records.length > 1) problems.push('More than one SPF record. Receivers treat this as a permanent error (permerror).');
  const record = records[0]!;
  const tree = await walk(domain, async (name) => (name === domain ? txts : lookup(name)), { queries: 12 }, 0, new Set());
  const lookups = total(tree);
  if (lookups > 10) problems.push(`${lookups} DNS lookups. The limit is 10; receivers will fail SPF with permerror.`);
  else if (lookups === 10) problems.push('Exactly 10 DNS lookups, the maximum. One more include will break SPF.');
  const ownAll = ALL_TERM.test(record);
  const allQualifier = effectiveAll(tree);
  const hasRedirect = tree.includes.some((c) => c.via === 'redirect') || (!ownAll && /(?:^|\s)redirect=/i.test(record));
  const redirectNode = tree.includes.find((c) => c.via === 'redirect');
  if (!allQualifier && !hasRedirect) problems.push('No "all" mechanism at the end; mail from unlisted servers gets a neutral result.');
  else if (!allQualifier && redirectNode && !redirectNode.error) problems.push(`The redirect target ${redirectNode.domain} has no "all" mechanism; mail from unlisted servers gets a neutral result.`);
  if (allQualifier === '+') problems.push('"+all" allows every server in the world to send for this domain.');
  if (allQualifier === '?') problems.push('"?all" is neutral and gives no protection.');
  if (/(?:^|\s)[+\-~?]?ptr(?=[:/\s]|$)/i.test(record)) problems.push('The "ptr" mechanism is deprecated and slow.');
  const failed = (n: SpfNode): string[] => [...(n.error && n !== tree ? [`${n.via === 'redirect' ? 'Redirect' : 'Include'} ${n.domain}: ${n.error}`] : []), ...n.includes.flatMap(failed)];
  for (const f of failed(tree)) problems.push(`${f}.`);
  return { record, records: records.length, allQualifier, totalLookups: lookups, tree, problems };
}

export interface DmarcResult {
  record: string | null;
  tags: Record<string, string>;
  problems: string[];
}

export function analyzeDmarc(txts: string[]): DmarcResult {
  const records = txts.filter((t) => /^v=DMARC1\s*(;|$)/i.test(t));
  if (records.length === 0) {
    return { record: null, tags: {}, problems: ['No DMARC record. Receivers get no policy for mail that fails SPF and DKIM.'] };
  }
  const record = records[0]!;
  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const [k, ...v] = part.split('=');
    if (k && v.length) tags[k.trim().toLowerCase()] = v.join('=').trim();
  }
  const problems: string[] = [];
  if (records.length > 1) problems.push('More than one DMARC record; receivers ignore all of them.');
  const p = tags.p?.toLowerCase();
  if (!p) problems.push('The required "p" tag is missing.');
  else if (p === 'none') problems.push('Policy "none" only monitors; spoofed mail is still delivered.');
  else if (!POLICIES.has(p)) problems.push(`Invalid policy "p=${tags.p}"; use none, quarantine or reject.`);
  const sp = tags.sp?.toLowerCase();
  if (sp !== undefined && !POLICIES.has(sp)) problems.push(`Invalid subdomain policy "sp=${tags.sp}"; use none, quarantine or reject.`);
  else if (sp === 'none' && (p === 'quarantine' || p === 'reject')) problems.push('Subdomain policy "sp=none": spoofed mail from subdomains is still delivered.');
  if (!tags.rua) problems.push('No "rua" address, so you receive no aggregate reports.');
  for (const key of ['rua', 'ruf'] as const) {
    const bad = (tags[key] ?? '').split(',').map((u) => u.trim()).filter((u) => u && !/^mailto:[^@\s]+@[^@\s]+$/i.test(u));
    if (bad.length) problems.push(`"${key}" contains ${bad.map((u) => `"${u}"`).join(', ')}, which is not a mailto: address; receivers send reports only to mailto: URIs.`);
  }
  if (tags.pct !== undefined) {
    const pct = /^\d{1,3}$/.test(tags.pct) ? Number(tags.pct) : NaN;
    if (!(pct >= 0 && pct <= 100)) problems.push(`Invalid "pct=${tags.pct}"; it must be a number from 0 to 100.`);
    else if (pct < 100) problems.push(`The policy applies to only ${pct}% of failing mail.`);
  }
  for (const key of ['adkim', 'aspf'] as const) {
    if (tags[key] !== undefined && !/^[rs]$/i.test(tags[key]!)) problems.push(`Invalid "${key}=${tags[key]}"; use r (relaxed) or s (strict).`);
  }
  return { record, tags, problems };
}

const POLICIES = new Set(['none', 'quarantine', 'reject']);

/** Splits a "k=v; k=v" tag list (DKIM, BIMI, TLS-RPT, MTA-STS TXT). Keys are lower-cased. */
export function tagList(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  return tags;
}

export interface DkimKey {
  keyType: string;
  revoked: boolean;
  /** RSA modulus length or 256 for ed25519; null if the key cannot be decoded. */
  bits: number | null;
}

// Minimal DER reader: returns [tag, contentStart, contentEnd] of the element at pos.
function der(b: Uint8Array, pos: number): [number, number, number] | null {
  if (pos + 2 > b.length) return null;
  const tag = b[pos]!;
  let len = b[pos + 1]!;
  let start = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > b.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[start + i]!;
    start += n;
  }
  return start + len <= b.length ? [tag, start, start + len] : null;
}

// Bit length of the modulus in an RSAPublicKey (PKCS#1) or SubjectPublicKeyInfo structure.
function rsaBits(b: Uint8Array): number | null {
  const outer = der(b, 0);
  if (!outer || outer[0] !== 0x30) return null;
  const first = der(b, outer[1]);
  if (!first) return null;
  if (first[0] === 0x30) {
    // SubjectPublicKeyInfo: AlgorithmIdentifier, then BIT STRING wrapping RSAPublicKey.
    const bits = der(b, first[2]);
    if (!bits || bits[0] !== 0x03) return null;
    return rsaBits(b.subarray(bits[1] + 1, bits[2]));
  }
  if (first[0] !== 0x02) return null;
  let i = first[1];
  while (i < first[2] && b[i] === 0) i++;
  if (i === first[2]) return 0;
  return (first[2] - i - 1) * 8 + (32 - Math.clz32(b[i]!));
}

/** Key type and strength of a DKIM key record (RFC 6376 3.6.1, RFC 8463). */
export function dkimKey(record: string): DkimKey {
  const tags = tagList(record);
  const keyType = (tags.k || 'rsa').toLowerCase();
  const p = (tags.p ?? '').replace(/\s+/g, '');
  if (!p) return { keyType, revoked: true, bits: null };
  let raw: Uint8Array;
  try {
    raw = Uint8Array.from(atob(p), (c) => c.charCodeAt(0));
  } catch {
    return { keyType, revoked: false, bits: null };
  }
  if (keyType === 'ed25519') return { keyType, revoked: false, bits: raw.length === 32 ? 256 : null };
  return { keyType, revoked: false, bits: keyType === 'rsa' ? rsaBits(raw) : null };
}

export interface MtaStsPolicy {
  mode: string | null;
  maxAge: number | null;
  mx: string[];
  problems: string[];
}

/** Parses an RFC 8461 policy file ("key: value" lines). */
export function parseMtaStsPolicy(text: string): MtaStsPolicy {
  const fields: Record<string, string> = {};
  const mx: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*:\s*(.*?)\s*$/);
    if (!m) continue;
    const key = m[1]!.toLowerCase();
    if (key === 'mx') mx.push(m[2]!.toLowerCase().replace(/\.$/, ''));
    else if (!(key in fields)) fields[key] = m[2]!;
  }
  const problems: string[] = [];
  if (fields.version !== 'STSv1') problems.push('The policy file does not start with "version: STSv1".');
  const mode = fields.mode?.toLowerCase() ?? null;
  if (!mode) problems.push('The policy file has no "mode".');
  else if (!['enforce', 'testing', 'none'].includes(mode)) problems.push(`Invalid policy mode "${fields.mode}".`);
  const maxAge = fields.max_age !== undefined && /^\d{1,10}$/.test(fields.max_age) ? Number(fields.max_age) : null;
  if (maxAge === null) problems.push('The policy file has no valid "max_age".');
  else if (maxAge > 31557600) problems.push('"max_age" is above the allowed maximum of 31557600 seconds (one year).');
  if (mode && mode !== 'none' && !mx.length) problems.push('The policy lists no "mx" hosts, so no mail server can match it.');
  return { mode, maxAge, mx, problems };
}

/** RFC 8461 4.1: "*.example.net" matches exactly one extra leftmost label. */
export function mxMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const p = pattern.toLowerCase().replace(/\.$/, '');
  if (!p.startsWith('*.')) return h === p;
  const dot = h.indexOf('.');
  return dot > 0 && h.slice(dot + 1) === p.slice(2);
}
