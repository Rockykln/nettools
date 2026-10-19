import { mapLimit } from '../core/async';
import { RR_TYPES, type DnsMessage, type RrTypeName } from '../core/dns';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { isIP, normalizeDomain, reverseName } from '../core/net';
import type { Tool } from '../core/tool';
import { COMPARE_RESOLVERS, RESOLVERS, resolve, type Resolver } from '../core/transport';

const TYPES: RrTypeName[] = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'SRV', 'PTR', 'DS', 'DNSKEY', 'HTTPS'];
const ALL: RrTypeName[] = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];

interface LookupResult {
  type: RrTypeName;
  ms: number | null;
  message: DnsMessage | null;
  error: string | null;
}

interface Lookup {
  input: string;
  name: string;
  resolver: Resolver;
  results: LookupResult[];
}

function parseInput(url: URL): Lookup | { error: string; input: string } {
  const input = (url.searchParams.get('name') ?? '').trim();
  const resolver = RESOLVERS.find((r) => r.id === url.searchParams.get('resolver')) ?? RESOLVERS[0]!;
  const typeParam = (url.searchParams.get('type') ?? 'ALL').toUpperCase();
  if (isIP(input)) {
    return { input, name: reverseName(input)!, resolver, results: [{ type: 'PTR', ms: null, message: null, error: null }] };
  }
  const name = normalizeDomain(input);
  if (!name) return { error: 'Enter a valid domain name such as example.com, or an IP address for a reverse lookup.', input };
  const types = typeParam === 'ALL' ? ALL : TYPES.includes(typeParam as RrTypeName) ? [typeParam as RrTypeName] : ALL;
  return { input, name, resolver, results: types.map((type) => ({ type, ms: null, message: null, error: null })) };
}

async function run(lookup: Lookup): Promise<Lookup> {
  await mapLimit(
    lookup.results,
    6,
    async (r) => {
      try {
        const { message, ms } = await resolve(lookup.resolver, lookup.name, RR_TYPES[r.type]);
        r.message = message;
        r.ms = ms;
      } catch (e) {
        r.error = e instanceof Error ? e.message : String(e);
      }
    },
  );
  return lookup;
}

// --- Compare mode: one record type across all resolvers -----------------------

interface CompareRow {
  resolver: Resolver;
  ms: number | null;
  message: DnsMessage | null;
  error: string | null;
}

async function compareAll(name: string, type: RrTypeName): Promise<CompareRow[]> {
  return mapLimit(COMPARE_RESOLVERS, 6, async (resolver) => {
    try {
      const { message, ms } = await resolve(resolver, name, RR_TYPES[type]);
      return { resolver, ms, message, error: null };
    } catch (e) {
      return { resolver, ms: null, message: null, error: e instanceof Error ? e.message : String(e) };
    }
  });
}

function answerKey(row: CompareRow, type: RrTypeName): string | null {
  if (!row.message) return null;
  const data = row.message.answers.filter((a) => a.typeName === type).map((a) => a.data.toLowerCase()).sort();
  return `${row.message.rcodeName}|${data.join(',')}`;
}

function compareTable(rows: CompareRow[], type: RrTypeName): SafeHtml {
  const counts = new Map<string, number>();
  for (const r of rows) {
    const k = answerKey(r, type);
    if (k) counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  const majority = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  const agreeing = majority ? counts.get(majority)! : 0;
  const answered = rows.filter((r) => r.message).length;
  const summary =
    counts.size <= 1
      ? html`All ${answered} resolvers that answered return the same ${type} records.`
      : html`<strong>${counts.size} different answers.</strong> ${agreeing} of ${answered} resolvers agree; differences are highlighted. This is normal while a change propagates or for domains with geo DNS.`;
  return html`<p class="result-head">${summary}</p>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data compare">
<thead><tr><th>Resolver</th><th>Status</th><th>${type} answer</th><th>TTL</th><th>Time</th></tr></thead>
<tbody>${rows.map((r) => {
    const k = answerKey(r, type);
    const answers = r.message ? r.message.answers.filter((a) => a.typeName === type) : [];
    const ttl = answers.length ? Math.min(...answers.map((a) => a.ttl)) : null;
    const diff = k !== null && counts.size > 1 && k !== majority;
    return html`<tr${diff ? html` class="diff"` : ''}><td><strong>${r.resolver.name}</strong>${diff ? html`<span class="diff-tag">differs</span>` : ''}<br><span class="muted">${r.resolver.location}</span></td>
<td>${r.error ? html`<span class="status bad" title="${r.error}">error</span>` : html`<span class="status ${r.message!.rcodeName === 'NOERROR' ? 'ok' : 'bad'}">${r.message!.rcodeName}</span>`}</td>
<td class="wrap-any">${r.error ? html`<span class="muted">${r.error}</span>` : answers.length ? answers.map((a) => html`<code>${a.data}</code><br>`) : html`<span class="muted">none</span>`}</td>
<td>${ttl ?? '—'}</td><td>${r.ms !== null ? `${r.ms} ms` : '—'}</td></tr>`;
  })}</tbody></table></div>`;
}

function compareType(url: URL): RrTypeName {
  const t = (url.searchParams.get('type') ?? 'A').toUpperCase();
  return TYPES.includes(t as RrTypeName) ? (t as RrTypeName) : 'A';
}

const RCODE_HELP: Record<string, string> = {
  NXDOMAIN: 'the domain does not exist.',
  SERVFAIL: 'the domain’s DNS is broken, often because of failing DNSSEC or unreachable name servers.',
  REFUSED: 'the server refused to answer this query.',
  FORMERR: 'the query was rejected as malformed.',
};

function resultTable(r: LookupResult): SafeHtml {
  if (r.error) return html`<section class="result"><h3>${r.type}</h3><p class="error">${r.error}</p></section>`;
  const m = r.message!;
  // Answers include any CNAME chain the resolver followed, which is useful context.
  const rows = m.answers;
  const status = html`<span class="status ${m.rcodeName === 'NOERROR' ? 'ok' : 'bad'}" title="${RCODE_HELP[m.rcodeName] ?? ''}">${m.rcodeName}</span>`;
  const help = m.rcodeName !== 'NOERROR' && RCODE_HELP[m.rcodeName] ? html`<p class="muted">${m.rcodeName}: ${RCODE_HELP[m.rcodeName]}</p>` : '';
  const meta = html`${status} <span class="muted">${r.ms} ms${m.ad ? ' · DNSSEC validated' : ''}</span>`;
  if (!rows.length) {
    return html`<section class="result"><h3>${r.type} ${meta}</h3>${help || html`<p class="muted">No ${r.type} records.</p>`}</section>`;
  }
  return html`<section class="result"><h3>${r.type} ${meta}</h3>
<table class="data records">
<colgroup><col class="c-name"><col class="c-ttl"><col class="c-type"><col></colgroup>
<thead><tr><th>Name</th><th>TTL</th><th>Type</th><th>Data</th></tr></thead>
<tbody>${rows.map((a) => html`<tr><td data-label="Name"><code>${a.name}</code></td><td data-label="TTL">${a.ttl}</td><td data-label="Type">${a.typeName}</td><td data-label="Data" class="wrap-any"><code>${a.data}</code></td></tr>`)}</tbody>
</table></section>`;
}

function form(input: string, type: string, resolver: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/dns-lookup">
<div class="field grow"><label for="name">Domain or IP address</label>
<input id="name" name="name" type="text" value="${input}" placeholder="example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><label for="type">Record type</label>
<select id="type" name="type"><option value="ALL"${type === 'ALL' ? ' selected' : ''}>All common</option>
${TYPES.map((t) => html`<option${t === type ? html` selected` : ''}>${t}</option>`)}</select></div>
<div class="field"><label for="resolver">Resolver</label>
<select id="resolver" name="resolver"><option value="all"${resolver === 'all' ? html` selected` : ''}>Compare all resolvers</option>
${RESOLVERS.map((r) => html`<option value="${r.id}"${r.id === resolver ? html` selected` : ''}>${r.name}</option>`)}</select></div>
<div class="field"><button type="submit">Look up</button></div>
</form>`;
}

const tool: Tool = {
  slug: 'dns-lookup',
  name: 'DNS lookup',
  icon: 'dns',
  category: 'dns',
  title: 'DNS Lookup – Query Any Record Type, Compare Resolvers',
  description:
    `Look up A, AAAA, MX, TXT, NS, CAA and more for any domain, or compare the answers from ${COMPARE_RESOLVERS.length} public resolvers. Shows TTL and DNSSEC.`,
  h1: 'DNS lookup',
  lead: `Query the DNS records of any domain, or compare the answers from ${COMPARE_RESOLVERS.length} public resolvers.`,
  examples: [['MX of gmail.com', 'name=gmail.com&type=MX'], ['Compare A of github.com', 'name=github.com&type=A&resolver=all'], ['Reverse 1.1.1.1', 'name=1.1.1.1']],
  related: ['dns-propagation-checker', 'nslookup-online', 'ns-lookup', 'mx-lookup', 'cname-lookup', 'caa-lookup'],
  heavy: (url) => url.searchParams.get('resolver') === 'all',
  isQuery: (url) => url.searchParams.has('name'),

  async render(c) {
    const type = (c.url.searchParams.get('type') ?? 'ALL').toUpperCase();
    const resolver = c.url.searchParams.get('resolver') ?? RESOLVERS[0]!.id;
    if (!c.url.searchParams.has('name')) return form('', type, resolver);
    const parsed = parseInput(c.url);
    if ('error' in parsed) return html`${form(parsed.input, type, resolver)}<p class="error">${parsed.error}</p>`;
    if (resolver === 'all') {
      const t = parsed.results.length === 1 ? parsed.results[0]!.type : compareType(c.url);
      const rows = await compareAll(parsed.name, t);
      return html`${form(parsed.input, type, resolver)}
<p class="muted">Comparing <code>${parsed.name}</code> ${t} across ${COMPARE_RESOLVERS.length} public resolvers${type === 'ALL' ? ' (choose a record type to compare others)' : ''}.</p>
${compareTable(rows, t)}`;
    }
    const lookup = await run(parsed);
    return html`${form(lookup.input, type, resolver)}
<h2 class="result-head">Results for <code>${lookup.name}</code> from ${lookup.resolver.name}</h2>
${lookup.results.map(resultTable)}
<p class="hint">Next: <a href="/whois?q=${encodeURIComponent(lookup.name.replace(/\.$/, ''))}">WHOIS</a> ·
<a href="/dns-lookup?name=${encodeURIComponent(lookup.input)}&amp;type=A&amp;resolver=all">compare across resolvers</a> ·
<a href="/email-security?domain=${encodeURIComponent(lookup.input)}">email security</a></p>`;
  },

  apiDoc: `GET /api/dns-lookup?name=example.com&type=ALL|A|AAAA|MX|TXT|...&resolver=all|${RESOLVERS.map((r) => r.id).join('|')}`,

  async api(c) {
    const t = (c.url.searchParams.get('type') ?? 'ALL').toUpperCase();
    const res = c.url.searchParams.get('resolver');
    if (t !== 'ALL' && !TYPES.includes(t as RrTypeName)) return json({ error: `Unknown record type. Use ALL or one of ${TYPES.join(', ')}.` }, { status: 400 });
    if (res && res !== 'all' && !RESOLVERS.some((r) => r.id === res)) return json({ error: `Unknown resolver. Use all or one of ${RESOLVERS.map((r) => r.id).join(', ')}.` }, { status: 400 });
    const parsed = parseInput(c.url);
    if ('error' in parsed) return json({ error: parsed.error }, { status: 400 });
    if (c.url.searchParams.get('resolver') === 'all') {
      const t = parsed.results.length === 1 ? parsed.results[0]!.type : compareType(c.url);
      const rows = await compareAll(parsed.name, t);
      return json({
        name: parsed.name,
        type: t,
        results: rows.map((r) => ({ resolver: r.resolver.id, ms: r.ms, error: r.error, ...r.message })),
      });
    }
    const lookup = await run(parsed);
    return json({
      name: lookup.name,
      resolver: lookup.resolver.id,
      results: lookup.results.map((r) => ({ type: r.type, ms: r.ms, error: r.error, ...r.message })),
    });
  },

  article: html`<h2>What a DNS lookup shows</h2>
<p>The Domain Name System translates names such as <code>example.com</code> into the data computers need: IP addresses,
mail servers, verification strings and more. A DNS lookup asks a recursive resolver for one or more record types of a
name and shows the answer, the TTL (how many seconds the answer may be cached) and how long the resolver took. This tool
sends the query over an encrypted connection (DNS-over-HTTPS, RFC 8484, or DNS-over-TLS for Quad9) to the public resolver
you choose, so the result does not depend on your local network or your provider's DNS.</p>

<h2>How to use the DNS lookup</h2>
<ol>
<li>Enter a domain or host name, for example <code>example.com</code> or <code>www.example.com</code>. Enter an IPv4 or
IPv6 address instead to get its PTR record (reverse DNS).</li>
<li>Pick a record type, or keep the default, which queries A, AAAA, CNAME, MX, NS, TXT, SOA and CAA at once.</li>
<li>Pick a resolver, or choose <em>Compare all resolvers</em> to send the same query to every public
resolver in the list below except AliDNS and see the answers side by side. Comparison works for one record type at a time (A if you chose all types).</li>
<li>Read the answer. An empty section means the name exists but has no record of that type; NXDOMAIN means the name
does not exist at all.</li>
</ol>

<h2>What the record types mean</h2>
<table class="data">
<thead><tr><th>Type</th><th>Purpose</th><th>Example value</th></tr></thead>
<tbody>
<tr><td>A / AAAA</td><td>IPv4 / IPv6 address of the host name.</td><td><code>192.0.2.10</code>, <code>2001:db8::10</code></td></tr>
<tr><td><a href="/cname-lookup">CNAME</a></td><td>Alias that points to another host name. A name with a CNAME cannot have other records, so the zone apex cannot use one.</td><td><code>www.example.com. CNAME example.com.</code></td></tr>
<tr><td><a href="/mx-lookup">MX</a></td><td>Mail servers that accept email for the domain, with priority (lower is preferred).</td><td><code>10 mail.example.com.</code></td></tr>
<tr><td><a href="/ns-lookup">NS</a></td><td>Authoritative name servers for the zone.</td><td><code>ns1.example.com.</code></td></tr>
<tr><td><a href="/txt-lookup">TXT</a></td><td>Free text, used for SPF, DKIM, DMARC and domain verification.</td><td><code>"v=spf1 mx -all"</code></td></tr>
<tr><td>SOA</td><td>Zone metadata: primary name server, contact, serial number and timers, including the negative TTL.</td><td><code>ns1.example.com. hostmaster.example.com. 2026101501 ...</code></td></tr>
<tr><td><a href="/caa-lookup">CAA</a></td><td>Which certificate authorities may issue TLS certificates for the domain (RFC 8659).</td><td><code>0 issue "letsencrypt.org"</code></td></tr>
<tr><td>SRV</td><td>Host and port of a service (RFC 2782).</td><td><code>_sip._tcp.example.com</code></td></tr>
<tr><td><a href="/reverse-dns-lookup">PTR</a></td><td>Reverse DNS: host name for an IP address, stored under <code>10.2.0.192.in-addr.arpa</code> for 192.0.2.10.</td><td><code>host.example.com.</code></td></tr>
<tr><td><a href="/dnssec-check">DS / DNSKEY</a></td><td>DNSSEC keys, and the delegation signer that links them to the parent zone.</td><td>key tag, algorithm, digest</td></tr>
<tr><td>HTTPS</td><td>Connection hints for browsers, such as HTTP/3 support and alternative endpoints (RFC 9460).</td><td><code>1 . alpn="h3,h2"</code></td></tr>
</tbody>
</table>
<p>For email-related records there are dedicated tools: <a href="/mx-lookup">MX lookup</a>,
<a href="/spf-checker">SPF checker</a> and <a href="/email-security">email security check</a>.</p>

<h2>Reading the answer</h2>
<p>Each record is shown with its name, TTL and value. Host names end with a dot in DNS notation
(<code>mail.example.com.</code>), which marks them as fully qualified; the dot is not a typo. Several records of the same
type form a set: a domain with two A records is answered with both, and clients pick one. The response time shows how
fast the resolver answered from this site's location; a cached answer usually comes back in a few milliseconds, while
an uncached one includes the round trips to the authoritative servers.</p>
<p>If the answer for a host name is a CNAME, the resolver follows it and returns the target's records in the same
response. The chain is shown in order, so you can see which provider (for example a CDN) the name finally points to.</p>
<h2>Which resolvers are queried</h2>
<p>The resolver list covers Cloudflare, Google, Quad9, OpenDNS, AdGuard (unfiltered), Control D, NextDNS, DNS.SB,
Wikimedia DNS, IIJ (Japan) and AliDNS (China). AliDNS can be selected on its own but is left out of the comparison.
Filtering resolvers can block or rewrite names that are listed as malware or ads, which is one reason answers may
differ.</p>

<h2>Why do resolvers show different results?</h2>
<p>Each resolver caches answers for the record's TTL, so after a change some resolvers keep serving the old value
until their copy expires; geo DNS, negative caching and filtering cause differences as well. Choose <em>Compare all
resolvers</em> to see the answers of all ${COMPARE_RESOLVERS.length} resolvers side by side. How long changes take, how to
plan them and how to flush local caches is explained on the <a href="/dns-propagation-checker">DNS propagation
checker</a> page.</p>

<h2>Command-line equivalents</h2>
<table class="data">
<thead><tr><th>Task</th><th>Command</th></tr></thead>
<tbody>
<tr><td>A record</td><td><code>dig example.com A</code></td></tr>
<tr><td>Short answer only</td><td><code>dig +short example.com MX</code></td></tr>
<tr><td>Ask a specific resolver</td><td><code>dig @1.1.1.1 example.com AAAA</code></td></tr>
<tr><td>Follow the delegation from the root</td><td><code>dig +trace example.com</code></td></tr>
<tr><td>Reverse lookup</td><td><code>dig -x 192.0.2.10</code></td></tr>
<tr><td>Windows / nslookup</td><td><code>nslookup -type=TXT example.com 1.1.1.1</code></td></tr>
<tr><td>PowerShell</td><td><code>Resolve-DnsName example.com -Type MX</code></td></tr>
</tbody>
</table>
<p>The TTL in a resolver's answer counts down while the record sits in its cache. To see the original TTL, query one of
the authoritative name servers directly: <code>dig @ns1.example.com example.com A</code>.</p>

<h2>DNSSEC validated</h2>
<p>When the resolver confirms the answer with DNSSEC signatures (the AD flag in the response), the result is marked
“DNSSEC validated”. Unsigned domains are not marked; that is normal for most domains. To see where a signed domain's
chain of trust breaks, use the <a href="/dnssec-check">DNSSEC checker</a>.</p>

<h2>Troubleshooting checklist</h2>
<ul>
<li><strong>NXDOMAIN:</strong> check the spelling, whether the domain is registered and not expired, and whether the
parent zone lists name servers for it (<code>dig NS example.com</code>).</li>
<li><strong>SERVFAIL:</strong> the authoritative servers did not answer, answered incorrectly, or DNSSEC validation failed.</li>
<li><strong>Old value still shown:</strong> wait for the TTL; lower it to 300 seconds at least one full old TTL before planned changes.</li>
<li><strong>Works here, not on your PC:</strong> flush the local cache (<code>ipconfig /flushdns</code> on Windows,
<code>resolvectl flush-caches</code> on Linux with systemd-resolved) and check the hosts file.</li>
<li><strong>DNS resolves but the site is unreachable:</strong> test the address with the
<a href="/port-checker">port checker</a> or check whether the site <a href="/is-it-down">is down</a>.</li>
</ul>`,

  faq: [
    {
      q: 'How long does a DNS change take to show up?',
      a: 'Until the old record expires from resolver caches, which is at most its TTL: a TTL of 3600 means up to one hour. Names that were cached as non-existent follow the SOA negative TTL, and name server changes depend on the parent zone, often up to two days.',
    },
    {
      q: 'What does NXDOMAIN mean?',
      a: 'The domain name does not exist. Check the spelling, or whether the domain is registered and has name servers. If the name exists but has no record of the requested type, the answer is empty instead (often called NODATA).',
    },
    {
      q: 'Why are there no MX records?',
      a: 'The domain does not receive email, or senders fall back to its A/AAAA record (implicit MX). A null MX record ("0 .", RFC 7505) states explicitly that the domain accepts no mail.',
    },
    {
      q: 'Can I look up reverse DNS?',
      a: 'Yes. Enter an IPv4 or IPv6 address and the tool queries the PTR record automatically.',
    },
    {
      q: 'Which DNS resolver should I use for the lookup?',
      a: 'For a neutral view, use Cloudflare, Google or Quad9. If a user reports a problem with a specific provider, query that resolver, or compare all resolvers to see whether only some of them return the old or a blocked answer.',
    },
    {
      q: 'What is a TTL in DNS?',
      a: 'Time to live: the number of seconds a resolver may cache a record. Typical values range from 300 (5 minutes) to 86400 (one day). Lower values make changes visible faster but cause more queries.',
    },
  ],
};

export default tool;
