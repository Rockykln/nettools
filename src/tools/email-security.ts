import { mapLimit } from '../core/async';
import { readCapped } from '../core/body';
import { cachedJson } from '../core/cache';
import { checkTarget } from '../core/guard';
import { RR_TYPES } from '../core/dns';
import { analyzeDmarc, analyzeSpf, dkimKey, mxMatches, parseMtaStsPolicy, tagList, txtValue, type DmarcResult, type MtaStsPolicy, type SpfNode, type SpfResult } from '../core/email';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { normalizeDomain } from '../core/net';
import type { Tool } from '../core/tool';
import { RESOLVERS, resolve } from '../core/transport';

// Selectors used by common providers (Google, Microsoft 365, Mailchimp, Proton, Fastmail, generic setups).
const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2', 'dkim', 'mail', 'protonmail', 'fm1'];

type Level = 'ok' | 'warn' | 'bad' | 'info';

interface Row {
  check: string;
  level: Level;
  summary: string;
}

export interface Report {
  domain: string;
  mx: { pref: number; host: string }[];
  spf: SpfResult;
  dmarc: DmarcResult;
  dkim: { selector: string; record: string; valid: boolean; keyType: string; bits: number | null }[];
  mtaSts: { record: string | null; mode: string | null; policy: MtaStsPolicy | null };
  tlsRpt: string | null;
  bimi: string | null;
  rows: Row[];
}

async function txt(name: string): Promise<string[]> {
  const { message } = await resolve(RESOLVERS[0]!, name, RR_TYPES.TXT);
  // SERVFAIL and similar must not look like "no record".
  if (message.rcodeName !== 'NOERROR' && message.rcodeName !== 'NXDOMAIN') throw new Error(message.rcodeName);
  return message.answers.filter((a) => a.type === RR_TYPES.TXT).map((a) => txtValue(a.data));
}

// RFC 8461: the policy is fetched over HTTPS without following redirects. Size-capped and SSRF-guarded.
async function mtaStsPolicy(domain: string, env: Env): Promise<MtaStsPolicy | null> {
  try {
    const host = `mta-sts.${domain}`;
    if (!(await checkTarget(host, env)).ok) return null;
    const res = await fetch(`https://${host}/.well-known/mta-sts.txt`, { redirect: 'manual', signal: AbortSignal.timeout(5000) });
    if (res.status !== 200) return null;
    const text = new TextDecoder().decode(await readCapped(res.body, 64 * 1024));
    return parseMtaStsPolicy(text);
  } catch {
    return null;
  }
}

export function analyze(domain: string, extraSelector: string | null, env: Env): Promise<Report> {
  return cachedJson(`mail:${domain}:${extraSelector ?? ''}`, () => 300, () => analyzeUncached(domain, extraSelector, env));
}

async function analyzeUncached(domain: string, extraSelector: string | null, env: Env): Promise<Report> {
  const selectors = [...new Set([...(extraSelector ? [extraSelector] : []), ...DKIM_SELECTORS])];
  const [mxRes, spf, dmarcTxt, stsTxt, tlsTxt, bimiTxt, dkimRaw] = await Promise.all([
    resolve(RESOLVERS[0]!, domain, RR_TYPES.MX).catch(() => null),
    analyzeSpf(domain, txt),
    txt(`_dmarc.${domain}`).catch(() => null),
    txt(`_mta-sts.${domain}`).catch(() => []),
    txt(`_smtp._tls.${domain}`).catch(() => []),
    txt(`default._bimi.${domain}`).catch(() => []),
    mapLimit(selectors, 4, async (s) => ({ selector: s, records: await txt(`${s}._domainkey.${domain}`).catch(() => []) })),
  ]);
  const mx = (mxRes?.message.answers ?? [])
    .filter((a) => a.type === RR_TYPES.MX)
    .map((a) => { const [p, h] = a.data.split(' '); return { pref: Number(p), host: h === '.' ? '' : (h ?? '').replace(/\.$/, '') }; })
    .sort((a, b) => a.pref - b.pref);
  const dmarc = dmarcTxt ? analyzeDmarc(dmarcTxt) : { record: null, tags: {}, problems: [`The DNS lookup for _dmarc.${domain} failed, so DMARC could not be checked. Try again later.`] };
  const dkim = dkimRaw.flatMap(({ selector, records }) =>
    records.filter((r) => /(^|;)\s*(v=DKIM1|p=)/i.test(r)).map((r) => {
      const k = dkimKey(r);
      return { selector, record: r, valid: !k.revoked, keyType: k.keyType, bits: k.bits };
    }),
  );
  const stsRecords = stsTxt.filter((t) => /^v=STSv1\s*(;|$)/i.test(t));
  const stsRecord = stsRecords[0] ?? null;
  const policy = stsRecord ? await mtaStsPolicy(domain, env) : null;
  const mtaSts = { record: stsRecord, mode: policy?.mode ?? null, policy };
  const tlsRecords = tlsTxt.filter((t) => /^v=TLSRPTv1\s*(;|$)/i.test(t));
  const tlsRpt = tlsRecords[0] ?? null;
  const bimi = bimiTxt.find((t) => /^v=BIMI1\s*(;|$)/i.test(t)) ?? null;

  const rows: Row[] = [];
  const nullMx = mx.length === 1 && mx[0]!.host === '';
  const sendsNoMail = /^v=spf1\s+-all\s*$/i.test(spf.record ?? '');
  rows.push(nullMx
    ? { check: 'MX', level: 'ok', summary: 'Null MX (RFC 7505): this domain explicitly accepts no email.' }
    : mx.length
      ? { check: 'MX', level: 'ok', summary: `${mx.length} mail server${mx.length > 1 ? 's' : ''}: ${mx.map((m) => m.host).join(', ')}` }
      : { check: 'MX', level: 'info', summary: 'No MX records. Senders may fall back to the A record; publish a null MX ("0 .") if the domain receives no email.' });
  rows.push(sendsNoMail
    ? { check: 'SPF', level: 'ok', summary: '"v=spf1 -all": this domain sends no email. Good protection against spoofing.' }
    : !spf.record
    ? { check: 'SPF', level: spf.problems[0]!.includes('lookup for the domain failed') ? 'warn' : 'bad', summary: spf.problems[0]! }
    : { check: 'SPF', level: spf.problems.length ? 'warn' : 'ok', summary: spf.problems.length ? spf.problems.join(' ') : `Valid, ${spf.totalLookups} of 10 DNS lookups, ${spf.allQualifier ? `ends with "${spf.allQualifier}all"` : 'ends with a redirect'}.` });
  const validKeys = dkim.filter((d) => d.valid);
  const weakKeys = validKeys.filter((d) => d.keyType === 'rsa' && d.bits !== null && d.bits < 1024);
  const keyInfo = (d: Report['dkim'][number]) => `${d.selector}${d.bits ? ` (${d.keyType === 'rsa' ? `${d.bits}-bit RSA` : d.keyType})` : ''}`;
  rows.push(dkim.length && !validKeys.length
    ? { check: 'DKIM', level: 'info', summary: `Only revoked keys (empty "p=") under ${dkim.map((d) => d.selector).join(', ')}. ${sendsNoMail || nullMx ? 'Expected for a domain that sends no email.' : 'No active DKIM key found.'}` }
    : dkim.length
    ? { check: 'DKIM', level: weakKeys.length ? 'warn' : 'ok', summary: `Found selector${validKeys.length > 1 ? 's' : ''} ${validKeys.map(keyInfo).join(', ')}${dkim.length > validKeys.length ? ` (revoked: ${dkim.filter((d) => !d.valid).map((d) => d.selector).join(', ')})` : ''}.${weakKeys.length ? ' RSA keys shorter than 1024 bits are insecure and rejected by many receivers; use 2048 bits.' : validKeys.some((d) => d.keyType === 'rsa' && d.bits === 1024) ? ' 1024-bit keys are weak; prefer 2048 bits.' : ''}` }
    : { check: 'DKIM', level: 'info', summary: 'No key found under common selectors. DKIM may still be set up with a custom selector; enter it above.' });
  rows.push(!dmarc.record
    ? { check: 'DMARC', level: dmarcTxt ? 'bad' : 'warn', summary: dmarc.problems[0]! }
    : { check: 'DMARC', level: dmarc.problems.length ? 'warn' : 'ok', summary: dmarc.problems.length ? `p=${dmarc.tags.p ?? '?'}. ${dmarc.problems.join(' ')}` : `Policy "${dmarc.tags.p}" with reports to ${reportAddresses(dmarc.tags.rua!)}.` });
  rows.push(mtaStsRow(mtaSts, stsRecords.length, nullMx ? [] : mx.map((m) => m.host)));
  rows.push(!tlsRpt
    ? { check: 'TLS-RPT', level: 'info', summary: 'Not configured. Optional companion to MTA-STS.' }
    : tlsRecords.length > 1
    ? { check: 'TLS-RPT', level: 'warn', summary: 'More than one TLS-RPT record; senders ignore all of them.' }
    : !tagList(tlsRpt).rua
    ? { check: 'TLS-RPT', level: 'warn', summary: 'The record has no "rua" tag, so no reports are sent.' }
    : { check: 'TLS-RPT', level: 'ok', summary: 'Reports about TLS delivery problems are requested.' });
  rows.push(bimiRow(bimi, dmarc));
  return { domain, mx, spf, dmarc, dkim, mtaSts, tlsRpt, bimi, rows };
}

function mtaStsRow(sts: Report['mtaSts'], records: number, mxHosts: string[]): Row {
  if (!sts.record) return { check: 'MTA-STS', level: 'info', summary: 'Not configured. Optional: forces TLS for mail delivered to this domain.' };
  if (records > 1) return { check: 'MTA-STS', level: 'warn', summary: 'More than one v=STSv1 TXT record; senders treat MTA-STS as not configured.' };
  if (!sts.policy) return { check: 'MTA-STS', level: 'warn', summary: 'TXT record found, but the policy file could not be loaded.' };
  const problems = [...sts.policy.problems];
  if (!tagList(sts.record).id) problems.unshift('The TXT record has no "id" tag.');
  const unmatched = sts.policy.mode === 'none' ? [] : mxHosts.filter((h) => h && !sts.policy!.mx.some((p) => mxMatches(h, p)));
  if (unmatched.length) problems.push(`MX ${unmatched.join(', ')} not covered by the policy's mx patterns; ${sts.policy.mode === 'enforce' ? 'senders that enforce MTA-STS will not deliver to it' : 'delivery would fail once the mode is enforce'}.`);
  const head = `Policy mode "${sts.policy.mode ?? '?'}"${sts.policy.maxAge !== null ? `, max_age ${sts.policy.maxAge}` : ''}.`;
  return { check: 'MTA-STS', level: sts.policy.mode === 'enforce' && !problems.length ? 'ok' : 'warn', summary: problems.length ? `${head} ${problems.join(' ')}` : head };
}

function bimiRow(bimi: string | null, dmarc: DmarcResult): Row {
  if (!bimi) return { check: 'BIMI', level: 'info', summary: 'Not configured. Optional: shows your logo in supporting mail clients; requires DMARC enforcement.' };
  const tags = tagList(bimi);
  if (!tags.l && !tags.a) return { check: 'BIMI', level: 'info', summary: 'BIMI record with an empty logo (l=): the domain declines to show a logo.' };
  const p = dmarc.tags.p?.toLowerCase();
  const pct = dmarc.tags.pct === undefined ? 100 : Number(dmarc.tags.pct);
  if ((p !== 'quarantine' && p !== 'reject') || pct !== 100) return { check: 'BIMI', level: 'warn', summary: 'Brand logo published, but mail clients ignore it: BIMI requires a DMARC policy of quarantine or reject at pct=100.' };
  return { check: 'BIMI', level: 'ok', summary: 'Brand logo published.' };
}

// "mailto:a@x.com!10m,mailto:b@y.com" -> "a@x.com, b@y.com"
function reportAddresses(rua: string): string {
  return rua.split(',').map((u) => u.trim().replace(/^mailto:/i, '').replace(/![0-9]+[kmgt]?$/i, '')).filter(Boolean).join(', ');
}

const LABEL: Record<Level, string> = { ok: 'pass', warn: 'warning', bad: 'fail', info: 'info' };
const badge = (l: Level) => html`<span class="status ${l}">${LABEL[l]}</span>`;

function spfTree(n: SpfNode): SafeHtml {
  return html`<li><code>${n.domain}</code> <span class="muted">${n.lookups} lookup${n.lookups === 1 ? '' : 's'}${n.error ? ` · ${n.error}` : ''}</span>
${n.record ? html`<br><code class="wrap-any">${n.record}</code>` : ''}
${n.includes.length ? html`<ul>${n.includes.map(spfTree)}</ul>` : ''}</li>`;
}

function form(value: string, selector: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/email-security">
<div class="field grow"><label for="domain">Domain or email address</label>
<input id="domain" name="domain" type="text" value="${value}" placeholder="example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><label for="selector">DKIM selector (optional)</label>
<input id="selector" name="selector" type="text" value="${selector}" placeholder="selector1" autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Check</button></div>
</form>`;
}

const INVALID = 'Enter a domain such as example.com or an email address.';

const tool: Tool = {
  slug: 'email-security',
  name: 'Email security',
  icon: 'mail',
  category: 'email',
  title: 'Email Security Check – SPF, DKIM, DMARC, MTA-STS & BIMI',
  description:
    'Check the email security of any domain: SPF with DNS lookup count, DKIM, DMARC policy, MTA-STS, TLS-RPT and BIMI, with clear explanations of every problem.',
  h1: 'Email security check',
  lead: 'Check whether a domain is protected against email spoofing and why mail might land in spam.',
  examples: [['gmail.com', 'domain=gmail.com'], ['github.com', 'domain=github.com']],
  related: ['spf-checker', 'dkim-checker', 'dmarc-checker', 'mx-lookup', 'blacklist-check'],
  heavy: () => true,
  isQuery: (url) => url.searchParams.has('domain'),

  async render(c) {
    const value = (c.url.searchParams.get('domain') ?? '').trim();
    const selectorRaw = (c.url.searchParams.get('selector') ?? '').trim();
    if (!c.url.searchParams.has('domain')) return form('', '');
    const domain = normalizeDomain(value);
    if (!domain?.includes('.')) return html`${form(value, selectorRaw)}<p class="error">${INVALID}</p>`;
    const selector = /^[a-z0-9._-]{1,63}$/i.test(selectorRaw) ? selectorRaw : null;
    const r = await analyze(domain, selector, c.env);
    return html`${form(value, selectorRaw)}
<p class="result-head">Results for <code>${r.domain}</code></p>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>Check</th><th>Result</th><th>Details</th></tr></thead>
<tbody>${r.rows.map((row) => html`<tr><td><strong>${row.check}</strong></td><td>${badge(row.level)}</td><td class="wrap-any">${row.summary}</td></tr>`)}</tbody></table></div>
${r.spf.tree ? html`<h2>SPF record and includes</h2><ul class="spf-tree">${spfTree(r.spf.tree)}</ul>` : ''}
${r.dmarc.record ? html`<h2>DMARC record</h2><pre class="raw">${r.dmarc.record}</pre>` : ''}
${r.dkim.length ? html`<h2>DKIM keys</h2>${r.dkim.map((d) => html`<h3><code>${d.selector}._domainkey.${r.domain}</code></h3><pre class="raw">${d.record}</pre>`)}` : ''}`;
  },

  apiDoc: 'GET /api/email-security?domain=example.com&selector=optional',

  async api(c) {
    const domain = normalizeDomain(c.url.searchParams.get('domain') ?? '');
    if (!domain?.includes('.')) return json({ error: INVALID }, { status: 400 });
    const sel = (c.url.searchParams.get('selector') ?? '').trim();
    return json(await analyze(domain, /^[a-z0-9._-]{1,63}$/i.test(sel) ? sel : null, c.env));
  },

  article: html`<h2>What this email security test checks</h2>
<p>Anyone can put any address in the <code>From:</code> line of an email. SPF, DKIM and DMARC are the DNS records that
let receiving mail servers tell real mail from forged mail. This tool looks up all of them for a domain, plus the
records that protect mail in transit and the brand logo record:</p>
<table class="data">
<thead><tr><th>Check</th><th>DNS name queried</th><th>What it does</th></tr></thead>
<tbody>
<tr><td>MX</td><td><code>example.com</code> (MX)</td><td>Mail servers that receive mail for the domain. A null MX (<code>0 .</code>, RFC 7505) declares that the domain accepts no mail.</td></tr>
<tr><td>SPF</td><td><code>example.com</code> (TXT)</td><td>Which servers may send mail for the domain</td></tr>
<tr><td>DKIM</td><td><code>selector._domainkey.example.com</code> (TXT)</td><td>Public key used to verify message signatures</td></tr>
<tr><td>DMARC</td><td><code>_dmarc.example.com</code> (TXT)</td><td>Policy for mail that fails authentication, and where to send reports</td></tr>
<tr><td>MTA-STS</td><td><code>_mta-sts.example.com</code> (TXT)</td><td>Requires TLS for mail delivered to the domain (RFC 8461)</td></tr>
<tr><td>TLS-RPT</td><td><code>_smtp._tls.example.com</code> (TXT)</td><td>Address for reports about TLS delivery failures (RFC 8460)</td></tr>
<tr><td>BIMI</td><td><code>default._bimi.example.com</code> (TXT)</td><td>Logo shown next to authenticated mail in supporting inboxes</td></tr>
</tbody>
</table>
<p>Results are cached for 5 minutes. After changing a record, wait for the cache and the record's TTL to expire before
testing again. You can query single records yourself with <code>dig TXT example.com</code> or
<code>dig TXT _dmarc.example.com</code>, or use the <a href="/txt-lookup">TXT record lookup</a> and
<a href="/mx-lookup">MX lookup</a>.</p>

<h2>SPF: which servers may send</h2>
<p>SPF is a single TXT record on the domain that lists the servers allowed to send its mail, for example
<code>v=spf1 ip4:192.0.2.10 include:_spf.google.com ~all</code>. Only one SPF record per domain is allowed, and
evaluation may use at most 10 DNS lookups across all nested includes; this tool follows the includes and shows the
total. Syntax, qualifiers, the lookup limits and flattening are explained on the <a href="/spf-checker">SPF checker</a>
page.</p>

<h2>DKIM: signed messages and selectors</h2>
<p>DKIM signs each outgoing message with a private key. The public key is published in DNS under a selector, for example
<code>selector1._domainkey.example.com</code>, as a record like <code>v=DKIM1; k=rsa; p=MIIBIjANBgkq...</code>. A record with an
empty <code>p=</code> means the key has been revoked. Use 2048-bit RSA keys; 1024-bit keys are still accepted but weak.</p>
<p>Selectors cannot be listed through DNS, so no tool can find every DKIM key of a domain. This check tries 12 selectors
used by common providers: <code>default</code>, <code>google</code>, <code>selector1</code>, <code>selector2</code>,
<code>k1</code>, <code>k2</code>, <code>s1</code>, <code>s2</code>, <code>dkim</code>, <code>mail</code>,
<code>protonmail</code> and <code>fm1</code>. If you use a different one, find it in the <code>DKIM-Signature</code> header
of a message you sent (the <code>s=</code> tag; <code>d=</code> is the signing domain) and enter it in the custom selector field.</p>

<h2>DMARC: policy and reports</h2>
<p>DMARC ties SPF and DKIM to the domain in the visible <code>From:</code> address. A message passes if SPF or DKIM
passes for a domain aligned with the <code>From:</code> domain, for example with
<code>v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com</code> at <code>_dmarc.example.com</code>. The policy
<code>p</code> decides what happens to failing mail, and <code>rua</code> collects daily aggregate reports. Every tag,
alignment modes, external report authorization and a rollout plan are covered on the
<a href="/dmarc-checker">DMARC checker</a> page.</p>

<h2>MTA-STS, TLS-RPT and BIMI</h2>
<p>SMTP between mail servers uses opportunistic TLS, which an attacker on the network path can strip. MTA-STS (RFC 8461)
lets a domain require TLS with a valid certificate. It needs two parts: a TXT record at <code>_mta-sts.example.com</code>
such as <code>v=STSv1; id=20260101</code>, and a policy file served at
<code>https://mta-sts.example.com/.well-known/mta-sts.txt</code> with <code>mode: testing</code> or <code>mode: enforce</code>,
the allowed <code>mx:</code> hosts and a <code>max_age</code>. Change the <code>id</code> whenever the policy changes. This tool checks both the TXT record and the policy file.</p>
<p>TLS-RPT (RFC 8460) asks sending servers to report TLS problems: <code>v=TLSRPTv1; rua=mailto:tlsrpt@example.com</code>
at <code>_smtp._tls.example.com</code>. Set it up before switching MTA-STS to <code>enforce</code>.</p>
<p>BIMI shows your logo in inboxes such as Gmail and Yahoo. It requires DMARC at <code>p=quarantine</code> or
<code>p=reject</code> without a <code>pct</code> below 100, a logo in SVG Tiny PS format, and for Gmail a Verified Mark Certificate or Common Mark Certificate.</p>

<h2>Google, Yahoo and Microsoft sender requirements</h2>
<p>Since February 2024, Google and Yahoo require all senders to authenticate with SPF or DKIM and to have valid forward
and reverse DNS for their sending IPs. Bulk senders (Google's threshold is about 5,000 messages a day to Gmail
addresses) must have SPF and DKIM, a DMARC record with at least <code>p=none</code>, alignment of the
<code>From:</code> domain with SPF or DKIM, one-click unsubscribe for marketing mail, and a spam complaint rate below 0.3% (Google recommends under 0.1%).
Since May 2025, Microsoft applies similar rules to high-volume senders to Outlook.com, Hotmail and Live addresses.</p>

<h2>Example setup for example.com</h2>
<p>A complete, minimal set of records for a domain that sends through one provider could look like this:</p>
<ul>
<li><code>example.com TXT "v=spf1 include:_spf.google.com -all"</code></li>
<li><code>google._domainkey.example.com TXT "v=DKIM1; k=rsa; p=..."</code> (value from the provider)</li>
<li><code>_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"</code></li>
<li><code>_smtp._tls.example.com TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"</code></li>
</ul>

<h2>Why does my mail land in spam? A checklist</h2>
<ol>
<li>Every service that sends as your domain (mail server, newsletter tool, CRM, ticket system) is covered by SPF or signs with DKIM.</li>
<li>SPF stays at or below 10 lookups and exists only once.</li>
<li>DKIM signatures use your own domain (<code>d=example.com</code>), not only the provider's.</li>
<li>A DMARC record exists. Start with <code>p=none</code> and a <code>rua</code> address, read the reports for a few weeks,
then move to <code>quarantine</code> and <code>reject</code>.</li>
<li>The sending IP has a matching <a href="/reverse-dns-lookup">reverse DNS (PTR) record</a>.</li>
<li>The sending IP is not on a spam list; test it with the <a href="/blacklist-check">IP blacklist check</a>.</li>
</ol>`,

  faq: [
    { q: 'What does "too many DNS lookups" mean for SPF?', a: 'SPF evaluation may trigger at most 10 DNS lookups. Each include, a, mx, ptr, exists and redirect counts, plus everything nested inside includes. Remove services you no longer use, replace a and mx with ip4 ranges where possible, or flatten includes to stay at or below the limit.' },
    { q: 'Should I use ~all or -all?', a: '-all (fail) is stricter. Once DMARC is in place, ~all (softfail) is common and safe; the DMARC policy decides what happens to failing mail.' },
    { q: 'Does a DMARC policy of none protect my domain?', a: 'No. p=none only collects reports. Spoofed mail is still delivered until you move to quarantine or reject. It does, however, meet the minimum DMARC requirement of Google and Yahoo for bulk senders.' },
    { q: 'Why is no DKIM record found although I use DKIM?', a: 'DKIM keys can only be found if the selector is known. Look up the s= tag in the DKIM-Signature header of a sent message and enter it as a custom selector.' },
    { q: 'Do I need SPF and DMARC on a domain that sends no email?', a: 'Yes, it prevents others from sending mail in its name. Publish v=spf1 -all, a DMARC record with p=reject, and optionally a null MX record (0 .) if the domain receives no mail either.' },
    { q: 'How long do DNS changes take to show up?', a: 'Until the old record’s TTL expires at the resolvers, often 1 hour or less. This tool caches results for 5 minutes.' },
  ],
};

export default tool;
