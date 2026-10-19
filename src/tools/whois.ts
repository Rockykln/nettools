import { readJsonCapped } from '../core/body';
import { cachedJson } from '../core/cache';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { cidrContains, isIP, normalizeDomain } from '../core/net';
import type { Tool } from '../core/tool';
import { whoisQuery, withTimeout } from '../core/transport';

type Kind = 'domain' | 'ip' | 'asn';

export interface Query {
  input: string;
  kind: Kind;
  value: string;
}

interface Bootstrap {
  services: [string[], string[]][];
}

const BOOTSTRAP: Record<Kind | 'ipv6', string> = {
  domain: 'https://data.iana.org/rdap/dns.json',
  ip: 'https://data.iana.org/rdap/ipv4.json',
  ipv6: 'https://data.iana.org/rdap/ipv6.json',
  asn: 'https://data.iana.org/rdap/asn.json',
};

const bootstrapCache = new Map<string, Promise<Bootstrap>>();

function bootstrap(url: string): Promise<Bootstrap> {
  let p = bootstrapCache.get(url);
  if (!p) {
    p = fetch(url, { cf: { cacheTtl: 86400, cacheEverything: true } }).then((r) => {
      if (!r.ok) throw new Error(`IANA bootstrap returned HTTP ${r.status}`);
      return r.json<Bootstrap>();
    });
    p.catch(() => bootstrapCache.delete(url));
    bootstrapCache.set(url, p);
  }
  return p;
}

export function parseQuery(raw: string): Query | null {
  const input = raw.trim();
  const asn = input.match(/^(?:asn?\s*)?(\d{1,10})$/i);
  if (asn && Number(asn[1]) <= 4294967295) return { input, kind: 'asn', value: asn[1]! };
  if (isIP(input)) return { input, kind: 'ip', value: input };
  const domain = normalizeDomain(input);
  if (domain && domain.includes('.')) return { input, kind: 'domain', value: domain };
  return null;
}

async function rdapBase(q: Query): Promise<string | null> {
  if (q.kind === 'domain') {
    const tld = q.value.split('.').pop()!;
    const data = await bootstrap(BOOTSTRAP.domain);
    return data.services.find(([tlds]) => tlds.includes(tld))?.[1][0] ?? null;
  }
  if (q.kind === 'asn') {
    const n = Number(q.value);
    const data = await bootstrap(BOOTSTRAP.asn);
    return (
      data.services.find(([ranges]) =>
        ranges.some((r) => {
          const [lo, hi = lo] = r.split('-').map(Number);
          return n >= lo! && n <= hi!;
        }),
      )?.[1][0] ?? null
    );
  }
  const data = await bootstrap(q.value.includes(':') ? BOOTSTRAP.ipv6 : BOOTSTRAP.ip);
  let best: { bits: number; url: string } | null = null;
  for (const [cidrs, urls] of data.services) {
    for (const cidr of cidrs) {
      const bits = Number(cidr.split('/')[1] ?? 0);
      if (cidrContains(cidr, q.value) && (!best || bits > best.bits)) best = { bits, url: urls[0]! };
    }
  }
  return best?.url ?? null;
}

type Rdap = Record<string, any>;

async function fetchRdap(url: string, lenient: boolean): Promise<{ status: number; data: Rdap | null }> {
  const res = await withTimeout(fetch(url, { headers: { accept: 'application/rdap+json, application/json' } }), 8000);
  // Some registries answer 400/422 instead of 404 for names below the registrable level.
  if (res.status === 404 || (lenient && (res.status === 400 || res.status === 422))) {
    await res.body?.cancel();
    return { status: res.status, data: null };
  }
  if (!res.ok) throw new Error(`RDAP server returned HTTP ${res.status}`);
  return { status: res.status, data: await readJsonCapped<Rdap>(res, 2 * 1024 * 1024) };
}

/** Wording plain WHOIS servers use for unregistered names. */
export const WHOIS_NOT_FOUND =
  /status:\s*(free|available)\b|no match\b|not found|no entries found|no data found|no matching record|object does not exist|no information available about domain|nothing found|we do not have an entry|is available for (registration|purchase)|^[ \t]*\S+ is free\b|not registered/im;

// Answers that mean the server refused the query, not that the name is free or taken.
const WHOIS_REFUSED = /limit exceeded|access control limit|quota exceeded|too many (requests|queries)|rate limit/i;

export function whoisNotFound(text: string): boolean {
  return WHOIS_NOT_FOUND.test(text);
}

/** Throws if a WHOIS answer is empty or a refusal, so it is not mistaken for a registered name. */
export function checkWhoisAnswer(server: string, text: string): void {
  if (!text.trim() || (WHOIS_REFUSED.test(text) && !whoisNotFound(text))) throw new Error(`No response from ${server}`);
}

export interface Lookup {
  query: Query;
  source: string;
  rdap: Rdap | null;
  whoisText: string | null;
  notFound: boolean;
}

// Common second-level labels under country code TLDs (example.co.uk, example.com.au).
const GENERIC_SLDS = new Set(['co', 'com', 'net', 'org', 'ac', 'edu', 'gov', 'ltd', 'plc', 'ne', 'or', 'go', 'gv', 'nom']);

// Registries only know registered names: try sub.example.co.uk, then example.co.uk, never co.uk.
// At most three names, always ending with the shortest registrable one.
export function candidateNames(domain: string): string[] {
  const labels = domain.split('.');
  const tld = labels[labels.length - 1]!;
  const sld = labels[labels.length - 2];
  const minLabels = tld.length === 2 && sld && GENERIC_SLDS.has(sld) ? 3 : 2;
  const out: string[] = [];
  for (let n = Math.min(labels.length, minLabels + 2); n >= minLabels; n--) out.push(labels.slice(-n).join('.'));
  return out.length ? out : [domain];
}

const whoisServerCache = new Map<string, Promise<string>>();

function whoisServer(tld: string): Promise<string> {
  let p = whoisServerCache.get(tld);
  if (!p) {
    p = whoisQuery('whois.iana.org', tld).then((iana) => {
      // [ \t] instead of \s: an empty "whois:" line must not capture the next line.
      const server = iana.match(/^whois:[ \t]*(\S+)/m)?.[1];
      if (!server) throw new Error(`No RDAP or WHOIS service is published for .${tld}`);
      return server.toLowerCase();
    });
    p.catch(() => whoisServerCache.delete(tld));
    whoisServerCache.set(tld, p);
  }
  return p;
}

async function whoisFallback(domain: string): Promise<{ server: string; text: string; notFound: boolean }> {
  const server = await whoisServer(domain.split('.').pop()!);
  const names = candidateNames(domain);
  let last = { server, text: '', notFound: true };
  for (const [i, name] of names.entries()) {
    // DENIC only returns registration data with these flags.
    const text = await whoisQuery(server, server === 'whois.denic.de' ? `-T dn,ace ${name}` : name);
    checkWhoisAnswer(server, text);
    last = { server, text, notFound: whoisNotFound(text) };
    // Subdomains are "invalid" at some registries (DENIC); keep going to the registered name.
    if (!last.notFound && !(i < names.length - 1 && /status:\s*invalid/i.test(text))) break;
  }
  return last;
}

async function lookupUncached(q: Query): Promise<Lookup> {
  const base = await rdapBase(q);
  if (!base) {
    if (q.kind !== 'domain') throw new Error('No RDAP service found for this address range.');
    const { server, text, notFound } = await whoisFallback(q.value);
    return { query: q, source: `whois://${server}`, rdap: null, whoisText: text, notFound };
  }
  const path = q.kind === 'domain' ? 'domain' : q.kind === 'ip' ? 'ip' : 'autnum';
  const prefix = base.endsWith('/') ? base : `${base}/`;
  const names = q.kind === 'domain' ? candidateNames(q.value) : [q.value];
  let url = '';
  for (const [i, name] of names.entries()) {
    url = `${prefix}${path}/${name}`;
    const res = await fetchRdap(url, i < names.length - 1);
    if (res.data) return { query: q, source: url, rdap: res.data, whoisText: null, notFound: false };
  }
  return { query: q, source: url, rdap: null, whoisText: null, notFound: true };
}

// Registration data changes rarely; "not found" is cached briefly so new registrations show up soon.
export function lookup(q: Query): Promise<Lookup> {
  return cachedJson(`whois:${q.kind}:${q.value}`, (l) => (l.notFound ? 600 : 3600), () => lookupUncached(q));
}

// --- RDAP rendering -------------------------------------------------------

function vcardValue(entity: Rdap, field: string): string | null {
  const props: unknown[] = entity?.vcardArray?.[1] ?? [];
  for (const p of props) {
    if (Array.isArray(p) && p[0] === field) {
      const v = p[3];
      return Array.isArray(v) ? v.filter(Boolean).join(' ') : typeof v === 'string' ? v : null;
    }
  }
  return null;
}

function entitiesWithRole(entities: Rdap[] | undefined, role: string, out: Rdap[] = []): Rdap[] {
  for (const e of entities ?? []) {
    if (e.roles?.includes(role)) out.push(e);
    entitiesWithRole(e.entities, role, out);
  }
  return out;
}

// RIPE lists several registrants (maintainer, role and organisation objects); prefer the organisation.
function findEntity(entities: Rdap[] | undefined, role: string): Rdap | null {
  const all = entitiesWithRole(entities, role);
  return all.find((e) => vcardValue(e, 'kind') === 'org') ?? all[0] ?? null;
}

function eventDate(data: Rdap, action: string): string | null {
  const ev = (data.events ?? []).find((e: Rdap) => e.eventAction === action);
  const t = ev?.eventDate ? Date.parse(String(ev.eventDate)) : NaN;
  // Some registries use the Unix epoch as "unknown".
  if (!Number.isFinite(t) || t <= 0) return null;
  return new Date(t).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

type Row = [string, unknown];

export interface IpOwner {
  network: string | null;
  range: string | null;
  organization: string | null;
  country: string | null;
  abuse: string | null;
}

/** The owner fields of an IP network RDAP record. */
export function ipOwner(d: Rdap): IpOwner {
  const registrant = findEntity(d.entities, 'registrant');
  const abuse = findEntity(d.entities, 'abuse');
  const str = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim() : null);
  return {
    network: str(d.name),
    range: d.startAddress && d.endAddress ? `${d.startAddress} – ${d.endAddress}` : null,
    organization: registrant ? str(vcardValue(registrant, 'fn')) : null,
    country: d.country ? String(d.country).toUpperCase() : null,
    abuse: abuse ? str(vcardValue(abuse, 'email')) : null,
  };
}

function summaryRows(kind: Kind, d: Rdap): Row[] {
  const registrar = findEntity(d.entities, 'registrar');
  const registrant = findEntity(d.entities, 'registrant');
  const abuse = findEntity(d.entities, 'abuse');
  const abuseMail = abuse ? vcardValue(abuse, 'email') : null;
  if (kind === 'domain') {
    return [
      ['Domain', d.ldhName ? String(d.ldhName).toLowerCase() : d.unicodeName],
      ['Registrar', registrar ? vcardValue(registrar, 'fn') : null],
      ['Registered', eventDate(d, 'registration')],
      ['Expires', eventDate(d, 'expiration')],
      ['Last changed', eventDate(d, 'last changed')],
      ['Status', (d.status ?? []).join(', ')],
      ['Name servers', (d.nameservers ?? []).map((n: Rdap) => String(n.ldhName ?? '').toLowerCase().replace(/\.$/, '')).join('\n')],
      ['DNSSEC', d.secureDNS ? (d.secureDNS.delegationSigned ? 'signed' : 'unsigned') : null],
      ['Abuse contact', abuseMail],
    ];
  }
  if (kind === 'ip') {
    const cidrs = (d.cidr0_cidrs ?? []).map((c: Rdap) => `${c.v4prefix ?? c.v6prefix}/${c.length}`).join(', ');
    return [
      ['Network name', d.name],
      ['Range', d.startAddress && d.endAddress ? `${d.startAddress} – ${d.endAddress}` : null],
      ['CIDR', cidrs || null],
      ['Organization', registrant ? vcardValue(registrant, 'fn') : null],
      ['Country', d.country ? String(d.country).toUpperCase() : null],
      ['Type', d.type],
      ['Registered', eventDate(d, 'registration')],
      ['Last changed', eventDate(d, 'last changed')],
      ['Abuse contact', abuseMail],
    ];
  }
  return [
    ['AS number', d.startAutnum == null ? null : d.endAutnum == null || d.startAutnum === d.endAutnum ? `AS${d.startAutnum}` : `AS${d.startAutnum} – AS${d.endAutnum}`],
    ['Name', d.name],
    ['Organization', registrant ? vcardValue(registrant, 'fn') : null],
    ['Country', d.country ? String(d.country).toUpperCase() : null],
    ['Registered', eventDate(d, 'registration')],
    ['Last changed', eventDate(d, 'last changed')],
    ['Abuse contact', abuseMail],
  ];
}

// Drops the terms-of-use comment blocks most WHOIS servers prepend.
function stripComments(text: string): string {
  const body = text.split('\n').filter((line) => !/^\s*[%#]/.test(line)).join('\n').trim();
  return body || text;
}

function renderLookup(l: Lookup): SafeHtml {
  const label = l.query.kind === 'asn' ? `AS${l.query.value}` : l.query.value;
  const head = html`<p class="result-head">Results for <code>${label}</code> · source <code class="wrap-any">${l.source}</code></p>`;
  if (l.notFound) return html`${head}<p class="muted">Not found. The ${l.query.kind === 'domain' ? 'domain is probably not registered' : 'registry has no record for it'}.</p>`;
  if (l.whoisText !== null) {
    return html`${head}<p class="muted">This registry does not offer RDAP, so the plain WHOIS answer is shown.</p><pre class="raw">${stripComments(l.whoisText)}</pre>`;
  }
  const rows = summaryRows(l.query.kind, l.rdap!).filter(([, v]) => v !== null && v !== undefined && v !== '');
  return html`${head}<table class="kv"><tbody>${rows.map(([k, v]) => html`<tr><th scope="row">${k}</th><td class="pre-line">${String(v)}</td></tr>`)}</tbody></table>
${l.query.kind === 'domain' ? html`<p class="hint">Next: <a href="/dns-lookup?name=${encodeURIComponent(l.query.value)}">DNS records</a> · <a href="/email-security?domain=${encodeURIComponent(l.query.value)}">email security</a> · <a href="/is-it-down?url=${encodeURIComponent(l.query.value)}">is it down?</a></p>` : ''}
<details class="raw-details"><summary>Raw RDAP response</summary><pre class="raw">${JSON.stringify(l.rdap, null, 2)}</pre></details>`;
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/whois">
<div class="field grow"><label for="q">Domain, IP address or AS number</label>
<input id="q" name="q" type="text" value="${value}" placeholder="example.com, 8.8.8.8 or AS13335" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Look up</button></div>
</form>`;
}

// Our own errors are safe to show; runtime/network errors are replaced by a generic message.
function publicError(e: unknown): string {
  const msg = e instanceof Error ? e.message : '';
  if (/^(No RDAP|No response|RDAP server returned|IANA bootstrap)/.test(msg)) return msg;
  return 'The registry did not answer. Please try again later.';
}

const INVALID = 'Enter a domain (example.com), an IP address (192.0.2.1) or an AS number (AS13335).';

const tool: Tool = {
  slug: 'whois',
  name: 'WHOIS lookup',
  icon: 'whois',
  category: 'domain',
  title: 'WHOIS Lookup – Domain Registrar, Expiry & Owner (RDAP)',
  description:
    'Free WHOIS lookup for domains, IP addresses and AS numbers. Shows registrar, expiry date, name servers, network owner and abuse contact via RDAP.',
  h1: 'WHOIS lookup',
  lead: 'Find out who a domain, IP address or autonomous system is registered to.',
  examples: [['example.com', 'q=example.com'], ['8.8.8.8', 'q=8.8.8.8'], ['AS13335', 'q=AS13335']],
  related: ['ip-lookup', 'domain-availability', 'asn-lookup', 'ns-lookup'],
  isQuery: (url) => url.searchParams.has('q') || url.searchParams.has('name'),

  async render(c) {
    const input = (c.url.searchParams.get('q') ?? c.url.searchParams.get('name') ?? '').trim();
    if (!c.url.searchParams.has('q') && !c.url.searchParams.has('name')) return form('');
    const q = parseQuery(input);
    if (!q) return html`${form(input)}<p class="error">${INVALID}</p>`;
    try {
      return html`${form(input)}${renderLookup(await lookup(q))}`;
    } catch (e) {
      return html`${form(input)}<p class="error">${publicError(e)}</p>`;
    }
  },

  apiDoc: 'GET /api/whois?q=example.com|192.0.2.1|AS13335',

  async api(c) {
    const q = parseQuery(c.url.searchParams.get('q') ?? '');
    if (!q) return json({ error: INVALID }, { status: 400 });
    try {
      const l = await lookup(q);
      return json(
        { query: q.value, kind: q.kind, source: l.source, notFound: l.notFound, rdap: l.rdap, whois: l.whoisText },
        { status: l.notFound ? 404 : 200 },
      );
    } catch (e) {
      const msg = publicError(e);
      return json({ error: msg }, { status: msg.startsWith('No RDAP') ? 404 : 502 });
    }
  },

  article: html`<h2>WHOIS and RDAP</h2>
<p>WHOIS is the traditional way to look up who registered a domain name, an IP address block or an autonomous
system number. The original protocol is plain text over TCP port 43: you send a name, the server sends back a block
of text whose format differs from registry to registry.</p>
<p>Its successor, RDAP (Registration Data Access Protocol, RFC 9082 and RFC 9083), returns the same information as
structured JSON over HTTPS. RDAP has fixed field names, supports internationalized names and lets registries
control access to sensitive data. ICANN has required RDAP from generic top-level domain (gTLD) registries and
registrars since 2019, and since 28 January 2025 RDAP is the authoritative source for gTLD registration data. From
that date, gTLD registries and registrars may switch off their port-43 WHOIS services, and many have done so.
Country code domains such as <code>.de</code> or <code>.uk</code> set their own rules.</p>

<h2>How this lookup works</h2>
<ol>
<li>The tool detects whether you entered a domain, an IPv4 or IPv6 address, or an AS number such as
<code>AS64496</code>.</li>
<li>It reads the IANA RDAP bootstrap files (RFC 9224) at <code>data.iana.org/rdap/</code>, which list the RDAP
server responsible for each top-level domain, IP range and AS number range.</li>
<li>It queries that server directly and shows the result as a table, with the raw JSON available.</li>
<li>If a registry has no RDAP service in the bootstrap file, the tool asks <code>whois.iana.org</code> for the
registry's WHOIS server and queries it on port 43. For <code>.de</code>, for example, the answer comes from DENIC's
WHOIS service and is shown as plain text.</li>
</ol>
<p>Results are cached for up to one hour, and "not found" answers for 10 minutes, so a fresh registration may take a
few minutes to appear.</p>

<h2>Running the same lookups on the command line</h2>
<pre class="raw">whois example.com
whois -h whois.iana.org com
curl -s https://rdap.verisign.com/com/v1/domain/example.com
curl -s https://rdap.org/domain/example.com
curl -s https://rdap.org/ip/192.0.2.1
curl -s https://rdap.org/autnum/64496</pre>
<p>The <code>whois</code> client picks a server based on built-in rules; the IANA query shows which registry runs a
top-level domain. <code>rdap.org</code> is a public redirector that uses the same IANA bootstrap data as this tool.
Pipe the JSON through <code>jq</code> to read single fields, for example
<code>jq '.events'</code> for the registration and expiry dates.</p>

<h2>Reading a domain record</h2>
<table class="data">
<thead><tr><th>Field</th><th>Meaning</th></tr></thead>
<tbody>
<tr><td>Registrar</td><td>The company the domain was registered through. Changes to the domain are made there.</td></tr>
<tr><td>Registered</td><td>Date of first registration. It stays the same after transfers between registrars.</td></tr>
<tr><td>Expires</td><td>End of the current registration period. Most registrars renew automatically before this date.</td></tr>
<tr><td>Last changed</td><td>Last update of the registry record, for example new name servers or a renewal.</td></tr>
<tr><td>Status</td><td>EPP status codes, see below.</td></tr>
<tr><td>Name servers</td><td>The servers that answer DNS queries for the domain.</td></tr>
<tr><td>DNSSEC</td><td>Whether a DS record is published, meaning the domain is signed.</td></tr>
</tbody>
</table>
<p>Name servers in the registry record should match what the domain actually serves. A
<a href="/dns-lookup">DNS lookup of the NS records</a> shows the live state, and the
<a href="/dnssec-check">DNSSEC check</a> confirms that a published DS record matches the domain's keys.</p>

<h2>Common EPP status codes</h2>
<p>Status codes come from EPP, the protocol registrars use to talk to registries (RFC 5731; grace-period statuses from RFC 3915). RDAP shows them in
plain words, for example <code>client transfer prohibited</code> instead of <code>clientTransferProhibited</code>.
Codes starting with <code>client</code> are set by the registrar, codes starting with <code>server</code> by the
registry.</p>
<table class="data">
<thead><tr><th>Status</th><th>What it means</th></tr></thead>
<tbody>
<tr><td><code>ok</code> / <code>active</code></td><td>No restrictions and no pending operations.</td></tr>
<tr><td><code>clientTransferProhibited</code></td><td>Registrar lock against transfers. Normal for most domains; unlock it at your registrar before a transfer.</td></tr>
<tr><td><code>clientUpdateProhibited</code>, <code>clientDeleteProhibited</code></td><td>Registrar lock against changes or deletion.</td></tr>
<tr><td><code>serverTransferProhibited</code> and similar</td><td>Registry lock, often a paid security service, or set during a dispute.</td></tr>
<tr><td><code>clientHold</code>, <code>serverHold</code></td><td>The domain is not published in DNS and does not resolve. Often caused by an unpaid renewal or an unverified contact email address.</td></tr>
<tr><td><code>autoRenewPeriod</code></td><td>The domain was renewed automatically at expiry; it can still be deleted for a refund during this grace period.</td></tr>
<tr><td><code>redemptionPeriod</code></td><td>The domain was deleted. The previous holder can restore it, usually for a fee, for 30 days in most gTLDs.</td></tr>
<tr><td><code>pendingDelete</code></td><td>The domain will be released within about five days and then becomes available again.</td></tr>
</tbody>
</table>

<h2>Why is the owner hidden?</h2>
<p>Since the GDPR took effect in May 2018, most registries and registrars no longer publish personal data of domain
holders. You will usually see the registrar, dates, status and name servers, but the holder's name, address and
email are replaced with text such as <code>REDACTED FOR PRIVACY</code> or omitted entirely. Many registrars also
offer privacy services that replace the holder's details with those of a proxy, even for companies.</p>
<p>To reach a domain holder, use the contact form or anonymized email address that the registrar provides, or the
registrar's abuse contact for spam, phishing and malware. Parties with a legitimate interest, such as law
enforcement or trademark holders, can request the hidden data from the registrar.</p>

<h2>IP addresses and AS numbers</h2>
<p>IP address blocks and AS numbers are assigned by the five Regional Internet Registries (RIRs): ARIN (North
America), RIPE NCC (Europe, Middle East, Central Asia), APNIC (Asia-Pacific), LACNIC (Latin America and Caribbean)
and AFRINIC (Africa). Their records show which organization holds a network, the allocated range, the country and
an abuse contact.</p>
<p>The holder is not always the user. A cloud provider or hosting company holds the block, and its customer runs the
server. For the routing view, use the <a href="/asn-lookup">ASN lookup</a>; for the host name an address points back
to, use the <a href="/reverse-dns-lookup">reverse DNS lookup</a>. If you are checking an address that sent you
spam, the <a href="/blacklist-check">blacklist check</a> shows whether it is already listed.</p>

<h2>Troubleshooting</h2>
<ul>
<li><strong>"Not found" for a domain that works:</strong> check the spelling and the ending. Subdomains such as
<code>www.example.com</code> have no record of their own; the tool looks up the registered domain.</li>
<li><strong>No expiry date:</strong> some country code registries, including DENIC for <code>.de</code>, do not
publish one. Ask the registrar.</li>
<li><strong>Registry did not answer:</strong> some registries rate-limit or block lookups from cloud networks. Try
again later or use the registry's own web lookup.</li>
<li><strong>Old data:</strong> results can be up to one hour old because of caching.</li>
</ul>`,

  faq: [
    {
      q: 'How can I tell when a domain expires?',
      a: 'Look at the "Expires" date. Most registrars renew domains automatically before it. Registries for some country code domains, such as .de, do not publish an expiry date at all.',
    },
    {
      q: 'What do statuses like clientTransferProhibited mean?',
      a: 'They are EPP status codes. clientTransferProhibited is a normal registrar lock that prevents unauthorized transfers to another registrar. Codes starting with server are set by the registry, for example during a dispute.',
    },
    {
      q: 'Why can I not see who owns a domain?',
      a: 'Since the GDPR took effect in 2018, registries and registrars redact personal data of domain holders. Use the registrar contact form or abuse contact to reach the holder.',
    },
    {
      q: 'Is WHOIS still available?',
      a: 'For gTLDs such as .com, .net and .org, RDAP replaced port-43 WHOIS as the authoritative service in January 2025, and many registries and registrars have turned WHOIS off. Many country code registries still run WHOIS. This tool uses RDAP first and falls back to WHOIS when needed.',
    },
    {
      q: 'Who do I contact about abuse from a domain or IP?',
      a: 'Use the abuse contact shown for the IP address. It belongs to the network operator responsible for that address, which may be a hosting or cloud provider rather than the person running the server.',
    },
    {
      q: 'Can I look up an AS number?',
      a: 'Yes. Enter it with or without the AS prefix, for example AS64496. The result shows the organization the number is registered to and the responsible Regional Internet Registry.',
    },
  ],
};

export default tool;
