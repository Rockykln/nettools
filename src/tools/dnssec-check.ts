import { mapLimit } from '../core/async';
import { cachedJson } from '../core/cache';
import { RR_TYPES, dnskeyTag } from '../core/dns';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { normalizeDomain } from '../core/net';
import type { Tool } from '../core/tool';
import { RESOLVERS, resolve } from '../core/transport';

const ALGORITHMS: Record<number, [string, boolean]> = {
  // [name, still recommended]
  5: ['RSA/SHA-1', false], 7: ['RSASHA1-NSEC3', false], 8: ['RSA/SHA-256', true], 10: ['RSA/SHA-512', true],
  13: ['ECDSA P-256', true], 14: ['ECDSA P-384', true], 15: ['Ed25519', true], 16: ['Ed448', true],
};
const DIGESTS: Record<number, string> = { 1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384' };

interface Key { tag: number | null; flags: number; algorithm: number }
interface Ds { tag: number; algorithm: number; digestType: number }

interface ZoneReport {
  zone: string;
  ds: Ds[];
  keys: Key[];
  /** DS at the parent matches a key-signing key in the zone. */
  linked: boolean;
}

type Verdict = 'secure' | 'insecure' | 'bogus' | 'broken' | 'missing' | 'unknown';

interface Report {
  name: string;
  verdict: Verdict;
  zones: ZoneReport[];
  notes: string[];
}

const resolver = RESOLVERS[0]!;

async function zoneReport(zone: string): Promise<ZoneReport> {
  const [dsRes, keyRes] = await Promise.all([
    resolve(resolver, zone, RR_TYPES.DS, 4000, { cd: true }).catch(() => null),
    resolve(resolver, zone, RR_TYPES.DNSKEY, 4000, { cd: true }).catch(() => null),
  ]);
  // A CNAME at the name makes the resolver return the target's records, which belong to another zone.
  const owned = (a: { name: string }) => a.name.toLowerCase() === `${zone.toLowerCase()}.`;
  const ds = (dsRes?.message.answers ?? []).filter((a) => a.type === RR_TYPES.DS && owned(a)).map((a) => {
    const [t, alg, dt] = a.data.split(' ').map(Number);
    return { tag: t!, algorithm: alg!, digestType: dt! };
  });
  const keys = (keyRes?.message.answers ?? []).filter((a) => a.type === RR_TYPES.DNSKEY && owned(a)).map((a) => {
    const [flags, , alg] = a.data.split(' ').map(Number);
    return { tag: dnskeyTag(a.data), flags: flags!, algorithm: alg! };
  });
  const linked = ds.some((d) => keys.some((k) => k.tag === d.tag && k.algorithm === d.algorithm));
  return { zone, ds, keys, linked };
}

// The zones from the TLD down to the name itself, e.g. com., example.com.
function zones(name: string): string[] {
  const labels = name.split('.');
  // Only the last few levels can be delegated zones in practice; this also bounds the number of queries.
  return labels.map((_, i) => labels.slice(i).join('.')).reverse().slice(0, 5);
}

function check(name: string): Promise<Report> {
  return cachedJson(`dnssec:${name}`, (r) => (r.verdict === 'unknown' ? 0 : 300), () => checkUncached(name));
}

async function checkUncached(name: string): Promise<Report> {
  const [normal, unchecked, reports] = await Promise.all([
    resolve(resolver, name, RR_TYPES.SOA).catch(() => null),
    resolve(resolver, name, RR_TYPES.SOA, 4000, { cd: true }).catch(() => null),
    mapLimit(zones(name), 3, zoneReport),
  ]);
  const notes: string[] = [];
  // Zone cuts only: the TLD, the registered domain, and deeper names that have their own DS or keys.
  const relevant = reports.filter((z, i) => i <= 1 || z.ds.length || z.keys.length);
  const last = relevant[relevant.length - 1]!;
  if (!normal || !unchecked) {
    // Without both answers the verdict would be a guess; report it instead of calling the domain unsigned.
    return { name, verdict: 'unknown', zones: [], notes: [`${resolver.name} did not answer, so the check could not run. Please try again.`] };
  }
  let verdict: Verdict;
  if (unchecked.message.rcodeName === 'NXDOMAIN') {
    verdict = 'missing';
    notes.push(`${name} does not exist in DNS, so there is nothing to validate.`);
  } else if (normal.message.rcodeName === 'SERVFAIL' && unchecked.message.rcodeName !== 'SERVFAIL') {
    verdict = 'bogus';
    notes.push('Validating resolvers return SERVFAIL, but the data exists without validation: the signatures or keys are broken. Visitors using validating resolvers cannot reach this domain.');
  } else if (normal.message.ad) {
    verdict = 'secure';
  } else if (last.keys.length && !last.ds.length) {
    verdict = 'broken';
    notes.push(`${last.zone} is signed (it publishes DNSKEY records) but its parent has no DS record, so the signatures are not used. Add the DS record at your registrar.`);
  } else {
    verdict = 'insecure';
    // If the deepest zone found is signed, the name's own zone (e.g. below a public suffix like co.uk) is the unsigned one.
    notes.push(`${last.keys.length ? name : last.zone} is not signed with DNSSEC. Answers cannot be verified, but the domain works normally.`);
  }
  for (const z of relevant) {
    if (z.ds.length && z.keys.length && !z.linked) notes.push(`The DS record for ${z.zone} does not match any of its keys. This breaks the chain of trust.`);
    for (const k of z.keys) {
      const alg = ALGORITHMS[k.algorithm];
      if (alg && !alg[1]) notes.push(`${z.zone} uses ${alg[0]} (algorithm ${k.algorithm}), which is deprecated. Switch to ECDSA P-256 (13) or Ed25519 (15).`);
    }
    if (z.ds.some((d) => d.digestType === 1)) notes.push(`${z.zone} has a DS record with a SHA-1 digest, which is deprecated.`);
  }
  return { name, verdict, zones: relevant, notes: [...new Set(notes)] };
}

const VERDICT: Record<Verdict, [string, string]> = {
  secure: ['ok', 'DNSSEC is set up correctly and answers validate.'],
  insecure: ['warn', 'DNSSEC is not enabled for this domain.'],
  broken: ['bad', 'DNSSEC is only partly set up.'],
  bogus: ['bad', 'DNSSEC validation fails.'],
  missing: ['warn', 'The domain does not exist.'],
  unknown: ['bad', 'The check failed.'],
};

const algName = (n: number) => `${ALGORITHMS[n]?.[0] ?? 'unknown'} (${n})`;

function zoneRow(z: ZoneReport): SafeHtml {
  const ksk = z.keys.filter((k) => k.flags === 257);
  const zsk = z.keys.filter((k) => k.flags === 256);
  return html`<tr><td><code>${z.zone}.</code></td>
<td>${z.ds.length ? z.ds.map((d, i) => html`${i ? html`<br>` : ''}tag ${d.tag}, ${algName(d.algorithm)}, ${DIGESTS[d.digestType] ?? d.digestType}`) : html`<span class="muted">none</span>`}</td>
<td>${z.keys.length ? html`${ksk.length} KSK${ksk.length ? html` (tag ${ksk.map((k) => k.tag).join(', ')})` : ''}, ${zsk.length} ZSK<br><span class="muted">${[...new Set(z.keys.map((k) => algName(k.algorithm)))].join(', ')}</span>` : html`<span class="muted">none</span>`}</td>
<td>${z.ds.length && z.keys.length ? (z.linked ? html`<span class="status ok">linked</span>` : html`<span class="status bad">mismatch</span>`) : html`<span class="status info">unsigned</span>`}</td></tr>`;
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/dnssec-check">
<div class="field grow"><label for="name">Domain</label>
<input id="name" name="name" type="text" value="${value}" placeholder="example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Check DNSSEC</button></div>
</form>`;
}

const INVALID = 'Enter a domain such as example.com.';

const tool: Tool = {
  slug: 'dnssec-check',
  name: 'DNSSEC check',
  icon: 'dnssec',
  category: 'dns',
  title: 'DNSSEC Checker – Validate the Chain of Trust',
  description:
    'Check whether a domain is signed with DNSSEC and whether the chain of trust from the TLD down is intact: DS records, keys, algorithms and errors.',
  h1: 'DNSSEC check',
  lead: 'See whether a domain is protected by DNSSEC and where the chain of trust breaks if it is not.',
  examples: [['cloudflare.com (signed)', 'name=cloudflare.com'], ['dnssec-failed.org (broken)', 'name=dnssec-failed.org']],
  related: ['dns-lookup', 'root-dns-servers', 'whois'],
  heavy: () => true,
  isQuery: (url) => url.searchParams.has('name'),

  async render(c) {
    const value = (c.url.searchParams.get('name') ?? '').trim();
    if (!c.url.searchParams.has('name')) return form('');
    const name = normalizeDomain(value);
    if (!name?.includes('.') || name.split('.').length > 10) return html`${form(value)}<p class="error">${INVALID}</p>`;
    const r = await check(name);
    const [cls, text] = VERDICT[r.verdict];
    return html`${form(value)}
<div class="verdict ${cls}"><strong>${text}</strong> ${r.notes[0] ?? ''}</div>
${r.notes.length > 1 ? html`<ul>${r.notes.slice(1).map((n) => html`<li>${n}</li>`)}</ul>` : ''}
${r.zones.length ? html`<h2>Chain of trust</h2>
<p class="muted">The root zone (.) is signed and trusted by every validating resolver. Each zone below must have a DS record in its parent that matches one of its keys.</p>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>Zone</th><th>DS in parent</th><th>Keys (DNSKEY)</th><th>Link</th></tr></thead>
<tbody>${r.zones.map(zoneRow)}</tbody></table></div>` : ''}`;
  },

  apiDoc: 'GET /api/dnssec-check?name=example.com',

  async api(c) {
    const name = normalizeDomain(c.url.searchParams.get('name') ?? '');
    if (!name?.includes('.') || name.split('.').length > 10) return json({ error: INVALID }, { status: 400 });
    const r = await check(name);
    return json(r, r.verdict === 'unknown' ? { status: 502 } : undefined);
  },

  article: html`<h2>What DNSSEC does</h2>
<p>DNSSEC (DNS Security Extensions, RFC 4033 to 4035) adds digital signatures to DNS records. A validating resolver
checks them and refuses forged or altered answers, which protects against cache poisoning and redirection attacks. It
does not encrypt anything and does not hide which names you look up; for that, DNS-over-HTTPS or DNS-over-TLS is used
between you and your resolver. DNSSEC also does not protect the website itself, only the DNS data that leads to it.</p>

<h2>The chain of trust</h2>
<p>Trust starts at the root zone, whose key-signing key every validating resolver has built in as a trust anchor and
updates when ICANN rolls it over. The root publishes a DS (delegation signer) record for <code>com</code>, which is a
hash of a key of <code>com</code>; <code>com</code> publishes a DS record for <code>example.com</code>, and so on down the
tree. Each zone signs its own records with RRSIG records, and its DNSKEY set must contain the key the parent's DS record
points to.</p>
<ul>
<li>If a link is missing (no DS record at the parent), the domain is <em>insecure</em>: unsigned, but working
normally.</li>
<li>If a link is wrong, for example a DS record that no longer matches after a key change, or signatures have expired,
the domain is <em>bogus</em>. Validating resolvers then return SERVFAIL, and the domain becomes unreachable for everyone
who uses them.</li>
</ul>

<h2>How this DNSSEC checker works</h2>
<p>The check queries Cloudflare's validating resolver twice for the domain's SOA record: once normally and once with the
CD (checking disabled) bit set. If the normal query fails with SERVFAIL but the unchecked one succeeds, the data exists
but does not validate, so the domain is bogus. If the normal answer carries the AD (authenticated data) flag, the domain
is secure.</p>
<p>For each zone from the top-level domain down to your domain, the tool also fetches the DS records at the parent and
the DNSKEY records in the zone, computes the key tag of every DNSKEY and compares it, together with the algorithm, with
the key tags in the DS records. The table shows for each zone whether the DS and the keys are <em>linked</em> or a
<em>mismatch</em>.</p>
<table class="data">
<thead><tr><th>Result</th><th>Meaning</th><th>What to do</th></tr></thead>
<tbody>
<tr><td>Set up correctly</td><td>Answers validate, the chain is complete.</td><td>Nothing; recheck after key changes.</td></tr>
<tr><td>Not enabled</td><td>No DS record and no keys. Most domains are in this state.</td><td>Enable DNSSEC if your provider supports it.</td></tr>
<tr><td>Only partly set up</td><td>The zone publishes DNSKEY records but the parent has no DS record.</td><td>Add the DS record at your registrar.</td></tr>
<tr><td>Validation fails</td><td>Bogus: the DS does not match, or signatures are broken or expired.</td><td>Fix the DS record or the signing immediately, or remove the DS record.</td></tr>
</tbody>
</table>

<h2>Enabling DNSSEC</h2>
<ol>
<li>Turn on DNSSEC at your DNS provider; it signs the zone and shows you a DS record (or the DNSKEY it is based on).</li>
<li>Add that DS record at your registrar, the company where you registered the domain. Copy key tag, algorithm, digest
type and digest exactly.</li>
<li>Run this check again once the registry has published the record, usually within a few hours.</li>
</ol>
<p>Some registries and registrars read CDS and CDNSKEY records from the zone and update the DS record automatically
(RFC 7344, RFC 8078). If yours does, step 2 happens on its own.</p>

<h2>DNSSEC algorithms</h2>
<p>Every DNSKEY and DS record names its algorithm by number. RFC 8624 lists which ones should be used.</p>
<table class="data">
<thead><tr><th>Number</th><th>Algorithm</th><th>Status</th></tr></thead>
<tbody>
<tr><td>5</td><td>RSA/SHA-1</td><td>Deprecated, do not use for signing</td></tr>
<tr><td>7</td><td>RSASHA1-NSEC3-SHA1</td><td>Deprecated, do not use for signing</td></tr>
<tr><td>8</td><td>RSA/SHA-256</td><td>Widely used, fine</td></tr>
<tr><td>10</td><td>RSA/SHA-512</td><td>Works, rarely used</td></tr>
<tr><td>13</td><td>ECDSA P-256 with SHA-256</td><td>Recommended, the most common modern choice</td></tr>
<tr><td>14</td><td>ECDSA P-384 with SHA-384</td><td>Works, rarely used</td></tr>
<tr><td>15</td><td>Ed25519</td><td>Recommended, not yet validated by every resolver</td></tr>
<tr><td>16</td><td>Ed448</td><td>Rarely supported</td></tr>
</tbody>
</table>
<p>DS records also carry a digest type: 2 (SHA-256) is the standard, 4 (SHA-384) is fine, and 1 (SHA-1) is deprecated.</p>

<h2>Proving that a name does not exist</h2>
<p>A signed zone must also be able to prove a negative answer, otherwise an attacker could simply claim that a name does
not exist. DNSSEC does this with NSEC records (RFC 4034), which list the next existing name in the zone and the record
types present, or with NSEC3 records (RFC 5155), which do the same with hashed names. Plain NSEC lets anyone walk the
zone and list all names; NSEC3 makes that harder. Many providers today generate minimal NSEC answers on the fly, which
avoids the problem altogether. Either way, the choice does not affect whether this check reports the domain as
secure.</p>
<h2>Checking DNSSEC from the command line</h2>
<ul>
<li><code>dig +dnssec example.com SOA</code> shows the RRSIG records and, from a validating resolver, the
<code>ad</code> flag in the header.</li>
<li><code>dig +cd example.com SOA</code> repeats the query without validation. If this works but the normal query
returns SERVFAIL, the domain is bogus.</li>
<li><code>dig DS example.com +short</code> shows the DS record at the parent; <code>dig DNSKEY example.com +multi</code>
shows the keys with their key tags as comments.</li>
<li><code>delv example.com</code> (from BIND) validates itself and prints <code>; fully validated</code> or the reason it
failed.</li>
</ul>

<h2>Common problems</h2>
<ul>
<li><strong>Moving to another DNS provider:</strong> remove the DS record first and wait until its TTL has expired
(often one day) before switching name servers, or use a provider that supports a coordinated key transfer. Otherwise
the domain goes bogus.</li>
<li><strong>Key rollover without updating the DS:</strong> a new KSK only works once the matching DS is published, and
the old key must stay in the zone until the old DS has expired from caches.</li>
<li><strong>Expired signatures:</strong> RRSIG records have a validity period. If the signer stops running, the zone
turns bogus days or weeks later.</li>
<li><strong>Wrong DS record at the registrar:</strong> a wrong digest shows up as “validation fails”; a wrong key tag or algorithm also shows as a mismatch in the chain table.</li>
</ul>
<p>Check individual records with the <a href="/dns-lookup">DNS lookup</a>, see the top of the chain on the
<a href="/root-dns-servers">root DNS servers</a> page, and confirm registrar and name servers with the
<a href="/whois">WHOIS lookup</a>.</p>`,

  faq: [
    { q: 'Which algorithm should I use?', a: 'ECDSA P-256 (algorithm 13) is the most common modern choice: small keys and signatures, supported everywhere. Ed25519 (15) is even smaller but not yet supported by every resolver. Avoid algorithms 5 and 7, which use SHA-1.' },
    { q: 'Is DNSSEC required?', a: 'No, but it is recommended, and some top-level domains such as .gov require it. It is also needed for DANE, which secures mail server certificates through DNS.' },
    { q: 'What do KSK and ZSK mean?', a: 'The key-signing key (KSK, flags 257) signs only the key set and is referenced by the DS record. The zone-signing key (ZSK, flags 256) signs all other records. Some setups use one key for both, called a combined signing key.' },
    { q: 'Why is my domain unreachable after enabling DNSSEC?', a: 'The DS record at the registrar does not match the keys the DNS provider publishes, usually because of a copy error or a provider change. Correct or remove the DS record; resolvers recover once the old DS has expired from their cache.' },
    { q: 'Does DNSSEC slow down my website?', a: 'Hardly. Signed answers are larger, and validating resolvers need a few extra lookups for keys, but those are cached like any other record. Visitors do not notice a difference in page load times.' },
    { q: 'What is the difference between insecure and bogus?', a: 'Insecure means the domain is not signed, so answers cannot be checked but work normally. Bogus means signatures exist but fail to validate, so validating resolvers refuse the answer and the domain stops working for their users.' },
  ],
};

export default tool;
