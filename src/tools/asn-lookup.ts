import { readJsonCapped } from '../core/body';
import { cachedJson } from '../core/cache';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { isIP } from '../core/net';
import { parseSubnet, toIp } from '../core/subnet';
import type { Tool } from '../core/tool';

const RIPESTAT = 'https://stat.ripe.net/data';
const SHOW_PREFIXES = 100;
const SHOW_NEIGHBOURS = 12;

async function ripestat<T>(endpoint: string, resource: string): Promise<T> {
  const res = await fetch(`${RIPESTAT}/${endpoint}/data.json?resource=${encodeURIComponent(resource)}&sourceapp=nettools`, {
    signal: AbortSignal.timeout(12000),
    cf: { cacheTtl: 3600, cacheEverything: true },
  });
  if (!res.ok) throw new Error(`RIPEstat returned HTTP ${res.status}`);
  const body = await readJsonCapped<{ status?: string; data?: T }>(res, 8 * 1024 * 1024);
  // RIPEstat reports some failures (maintenance, internal errors) with HTTP 200 and a status field.
  if (body.status && body.status !== 'ok') throw new Error(`RIPEstat returned status ${body.status}`);
  if (!body.data) throw new Error('RIPEstat returned no data');
  return body.data;
}

interface Neighbour { asn: number; power: number }

interface AsReport {
  asn: number;
  holder: string | null;
  announced: boolean;
  v4: string[];
  v6: string[];
  upstreams: Neighbour[];
  downstreams: Neighbour[];
  counts: { left: number; right: number };
}

export interface PrefixReport {
  query: string;
  prefix: string;
  origins: { asn: number; holder: string }[];
  announced: boolean;
}

async function asReport(asn: number): Promise<AsReport> {
  // Large networks return about 1 MB of JSON that takes several ms of CPU to parse; routing changes slowly.
  return cachedJson(`asn:${asn}`, () => 6 * 3600, async () => {
    const [overview, prefixes, neighbours] = await Promise.all([
      ripestat<{ holder?: string; announced?: boolean }>('as-overview', `AS${asn}`),
      ripestat<{ prefixes: { prefix: string }[] }>('announced-prefixes', `AS${asn}`),
      ripestat<{ neighbours: { asn: number; type: string; power: number }[]; neighbour_counts: { left: number; right: number } }>('asn-neighbours', `AS${asn}`),
    ]);
    const all = (prefixes.prefixes ?? []).map((p) => p.prefix);
    const top = (type: string) => (neighbours.neighbours ?? []).filter((n) => n.type === type).sort((a, b) => b.power - a.power).slice(0, SHOW_NEIGHBOURS).map(({ asn: a, power }) => ({ asn: a, power }));
    return {
      asn,
      holder: overview.holder ?? null,
      announced: !!overview.announced,
      v4: all.filter((p) => !p.includes(':')),
      v6: all.filter((p) => p.includes(':')),
      upstreams: top('left'),
      downstreams: top('right'),
      counts: { left: neighbours.neighbour_counts?.left ?? 0, right: neighbours.neighbour_counts?.right ?? 0 },
    };
  });
}

export async function prefixReport(resource: string): Promise<PrefixReport> {
  return cachedJson(`prefix:${resource}`, () => 6 * 3600, async () => {
    const d = await ripestat<{ resource: string; asns: { asn: number; holder: string }[]; announced: boolean }>('prefix-overview', resource);
    return { query: resource, prefix: d.resource ?? resource, origins: (d.asns ?? []).map((a) => ({ asn: a.asn, holder: a.holder ?? '' })), announced: !!d.announced };
  });
}

type Parsed = { kind: 'asn'; asn: number } | { kind: 'prefix'; resource: string };

export function parse(raw: string): Parsed | null {
  const s = raw.trim();
  const asn = s.match(/^(?:asn?\s*)?(\d{1,10})$/i);
  if (asn && Number(asn[1]) > 0 && Number(asn[1]) <= 4294967295) return { kind: 'asn', asn: Number(asn[1]) };
  if (isIP(s)) return { kind: 'prefix', resource: s };
  const sub = s.includes('/') ? parseSubnet(s) : null;
  // Canonical network/length form: RIPEstat rejects masks (/255.255.255.0) and host bits.
  return sub ? { kind: 'prefix', resource: `${toIp(sub.network, sub.version)}/${sub.prefix}` } : null;
}

function prefixList(list: string[], label: string): SafeHtml {
  if (!list.length) return html``;
  return html`<h3>${list.length.toLocaleString('en-US')} ${label} prefixes</h3>
<p class="prefix-list">${list.slice(0, SHOW_PREFIXES).map((p) => html`<a href="/subnet-calculator?cidr=${encodeURIComponent(p)}"><code>${p}</code></a> `)}</p>
${list.length > SHOW_PREFIXES ? html`<p class="muted">Showing ${SHOW_PREFIXES} of ${list.length.toLocaleString('en-US')}. The API returns all of them.</p>` : ''}`;
}

function neighbourTable(title: string, list: Neighbour[], total: number): SafeHtml {
  return html`<div><h3>${title} <span class="muted">(${total})</span></h3>
${list.length ? html`<ul class="plain">${list.map((n) => html`<li><a href="/asn-lookup?q=AS${n.asn}">AS${n.asn}</a></li>`)}</ul>` : html`<p class="muted">None seen.</p>`}</div>`;
}

// RFC 6996 private use, RFC 5398 and RFC 7300 reserved/documentation ranges.
function specialAsn(asn: number): string | null {
  if ((asn >= 64512 && asn <= 65534) || (asn >= 4200000000 && asn <= 4294967294)) return 'Private use (RFC 6996), not routed on the internet.';
  if ((asn >= 64496 && asn <= 64511) || (asn >= 65536 && asn <= 65551)) return 'Reserved for documentation (RFC 5398).';
  if (asn === 23456) return 'AS_TRANS placeholder for 4-byte ASNs (RFC 6793).';
  if (asn === 65535 || asn === 4294967295) return 'Reserved (RFC 7300).';
  return null;
}

function renderAs(r: AsReport): SafeHtml {
  const special = specialAsn(r.asn);
  return html`<table class="kv"><tbody>
<tr><th scope="row">AS number</th><td><strong>AS${r.asn}</strong></td></tr>
${special ? html`<tr><th scope="row">Range</th><td>${special}${r.announced ? ' Routes seen for it in BGP are leaks from private networks.' : ''}</td></tr>` : ''}
<tr><th scope="row">Holder</th><td>${r.holder || '—'}</td></tr>
<tr><th scope="row">Announced in BGP</th><td>${r.announced ? 'yes' : 'no'}</td></tr>
<tr><th scope="row">Prefixes</th><td>${r.v4.length.toLocaleString('en-US')} IPv4 · ${r.v6.length.toLocaleString('en-US')} IPv6</td></tr>
<tr><th scope="row">Registration</th><td><a href="/whois?q=AS${r.asn}">WHOIS for AS${r.asn}</a></td></tr>
</tbody></table>
<h2>Neighbors</h2>
<p class="muted">Upstreams appear before this network in BGP paths (usually transit providers); downstreams appear after it (customers). Strongest first.</p>
<div class="two-col">${neighbourTable('Upstreams', r.upstreams, r.counts.left)}${neighbourTable('Downstreams', r.downstreams, r.counts.right)}</div>
<h2>Announced prefixes</h2>
${prefixList(r.v4, 'IPv4')}${prefixList(r.v6, 'IPv6')}`;
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/asn-lookup">
<div class="field grow"><label for="q">AS number, IP address or prefix</label>
<input id="q" name="q" type="text" value="${value}" placeholder="AS13335, 1.1.1.1 or 8.8.8.0/24" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Look up</button></div>
</form>`;
}

const INVALID = 'Enter an AS number (AS13335), an IP address or a prefix (192.0.2.0/24).';

const tool: Tool = {
  slug: 'asn-lookup',
  name: 'ASN & BGP lookup',
  icon: 'asn',
  category: 'ip',
  title: 'ASN Lookup – BGP Prefixes, Upstreams & Peers of Any AS',
  description:
    'Look up any autonomous system or IP address: AS holder, announced IPv4 and IPv6 prefixes, upstream providers and downstream customers from live BGP data.',
  h1: 'ASN and BGP lookup',
  lead: 'Which network an IP belongs to, which prefixes an AS announces, and who its upstreams are.',
  examples: [['AS13335', 'q=AS13335'], ['1.1.1.1', 'q=1.1.1.1'], ['AS3320', 'q=AS3320']],
  related: ['ip-lookup', 'whois', 'ip-range-to-cidr'],
  isQuery: (url) => url.searchParams.has('q'),

  async render(c) {
    const value = (c.url.searchParams.get('q') ?? '').trim();
    if (!c.url.searchParams.has('q')) return form('');
    const p = parse(value);
    if (!p) return html`${form(value)}<p class="error">${INVALID}</p>`;
    try {
      if (p.kind === 'asn') return html`${form(value)}${renderAs(await asReport(p.asn))}`;
      const pr = await prefixReport(p.resource);
      if (!pr.origins.length) return html`${form(value)}<p class="muted">No BGP route covers <code>${p.resource}</code>. The address is probably not in use on the public internet.</p>`;
      const origin = pr.origins[0]!;
      return html`${form(value)}
<p class="result-head"><code>${pr.query}</code> is routed as part of <a href="/subnet-calculator?cidr=${encodeURIComponent(pr.prefix)}"><code>${pr.prefix}</code></a>,
originated by ${pr.origins.map((o, i) => html`${i ? ', ' : ''}<strong>AS${o.asn}</strong> (${o.holder})`)}.</p>
${renderAs(await asReport(origin.asn))}`;
    } catch {
      return html`${form(value)}<p class="error">The routing data service did not answer. Please try again later.</p>`;
    }
  },

  apiDoc: 'GET /api/asn-lookup?q=AS13335 (or an IP address or prefix)',

  async api(c) {
    const p = parse(c.url.searchParams.get('q') ?? '');
    if (!p) return json({ error: INVALID }, { status: 400 });
    try {
      if (p.kind === 'asn') return json({ ...(await asReport(p.asn)), special: specialAsn(p.asn) });
      const pr = await prefixReport(p.resource);
      return json({ ...pr, as: pr.origins[0] ? await asReport(pr.origins[0].asn) : null });
    } catch {
      return json({ error: 'The routing data service did not answer.' }, { status: 502 });
    }
  },

  article: html`<h2>What is an AS number?</h2>
<p>The internet is a network of networks. Each independently run network, such as an internet provider, a cloud
platform, a university or a large company, is an autonomous system (AS) with its own number, the ASN. Networks tell
each other with BGP (Border Gateway Protocol, RFC 4271) which IP prefixes they can reach, and every route carries the
AS path: the list of AS numbers it has passed through. Routers use that path to pick a route and to avoid loops.</p>
<p>AS numbers are handed out by the five regional internet registries (ARIN, RIPE NCC, APNIC, LACNIC and AFRINIC), which
receive blocks of numbers from IANA. A network usually needs its own ASN when it connects to more than one provider
(multihoming) or wants to announce its own address space.</p>

<h2>How to use this ASN lookup</h2>
<ol>
<li>Enter an AS number, with or without the prefix: <code>AS13335</code> or <code>13335</code>.</li>
<li>Or enter an IP address or prefix, such as <code>1.1.1.1</code> or <code>2001:db8::/32</code>. The tool finds the most
specific routed prefix that contains it, the AS that originates that prefix, and then shows the report for that AS.</li>
<li>Read the result: the AS holder name, whether the AS is currently announcing anything, its IPv4 and IPv6 prefixes,
and its most frequently seen upstream and downstream neighbors.</li>
</ol>
<p>To find the AS of your own connection, open <a href="/what-is-my-ip">What is my IP</a>; it shows your ASN and links
back here.</p>

<h2>Where the data comes from</h2>
<p>Routing data comes from <a href="https://stat.ripe.net/" rel="noopener">RIPEstat</a>, which is built on the RIPE
NCC Routing Information Service (RIS). RIS runs route collectors at internet exchanges around the world that receive full
or partial BGP tables from hundreds of peering networks. The result reflects what the internet actually routes, which can
differ from what is registered. Results on this site are cached for up to six hours.</p>
<p>For the registration record of an AS or address block, including the organization and the abuse contact, use the
<a href="/whois">WHOIS lookup</a>. Registration and routing are separate: a block can be registered to one company and
announced by its provider, or registered but not announced at all.</p>

<h2>ASN number ranges</h2>
<p>AS numbers were originally 16 bits (0 to 65535). Because those ran out, RFC 6793 introduced 32-bit ASNs, which go up
to 4,294,967,295. Some ranges have a special purpose:</p>
<table class="data">
<thead><tr><th>Range</th><th>Use</th></tr></thead>
<tbody>
<tr><td>0</td><td>Reserved, may not appear in routes (RFC 7607)</td></tr>
<tr><td>1 – 64495</td><td>Public 16-bit ASNs assigned by the registries</td></tr>
<tr><td>23456</td><td><code>AS_TRANS</code>, a placeholder for 32-bit ASNs on old routers (RFC 6793)</td></tr>
<tr><td>64496 – 64511</td><td>Documentation and examples (RFC 5398)</td></tr>
<tr><td>64512 – 65534</td><td>Private use (RFC 6996)</td></tr>
<tr><td>65536 – 65551</td><td>Documentation, 32-bit (RFC 5398)</td></tr>
<tr><td>65552 – 131071</td><td>Reserved (IANA)</td></tr>
<tr><td>4200000000 – 4294967294</td><td>Private use, 32-bit (RFC 6996)</td></tr>
<tr><td>65535 and 4294967295</td><td>Reserved, the last number of each range (RFC 7300)</td></tr>
</tbody>
</table>
<p>Private ASNs are used inside data centers and between a customer and a single provider. They should not appear in
the global routing table; if you see one in a public AS path, someone has leaked an internal route.</p>

<h2>Prefixes, origin AS and more-specifics</h2>
<p>The origin AS is the last AS in the path: the network that announces the prefix. A typical provider announces a few
large blocks, for example a /16, and sometimes more-specific prefixes such as /24s inside them for traffic engineering.
Routers always prefer the most specific matching prefix. The smallest prefixes widely accepted on the internet are /24
for IPv4 and /48 for IPv6; longer announcements are usually filtered.</p>
<p>A prefix announced by two different origin ASes at the same time is called a MOAS conflict. It can be legitimate, for
example during a migration or with anycast, but it is also what a route hijack looks like. Many networks now filter
announcements with RPKI route origin validation (RFC 6811), which checks the origin AS against a signed ROA published by
the address holder.</p>
<p>To turn a provider's address range into prefixes, or to merge a long prefix list, use the
<a href="/ip-range-to-cidr">IP range to CIDR converter</a>.</p>

<h2>Upstreams and downstreams</h2>
<p>An AS that appears directly before another one in BGP paths is usually its transit provider (upstream); one that
appears after it is usually a customer (downstream). The lists show the neighbors seen most often across the
collected paths. Large networks peer with each other directly and settlement-free, so for them the direction is less
clear-cut, and a well-known transit network can show up on both sides. An AS with only one upstream is single-homed: if
that link fails, the whole network is cut off.</p>

<h2>Command-line alternatives</h2>
<p>Team Cymru runs a public IP-to-ASN mapping service that works from any shell:</p>
<ul>
<li><code>whois -h whois.cymru.com " -v 1.1.1.1"</code> returns AS number, prefix, country, registry and AS name.</li>
<li><code>dig +short 1.1.1.1.origin.asn.cymru.com TXT</code> does the same over DNS. The address must be written in
reverse order, which for <code>1.1.1.1</code> happens to look identical.</li>
<li><code>whois AS13335</code> shows the registration record of an AS from the responsible registry.</li>
</ul>
<p>On a router with a full table, <code>show ip bgp 1.1.1.1</code> (Cisco) or <code>show route 1.1.1.1 detail</code>
(Juniper) shows the AS paths that router actually uses.</p>

<h2>Troubleshooting</h2>
<ul>
<li><strong>“Announced in BGP: no”:</strong> the AS exists but has no routes right now. It may be new, decommissioned, or
used only internally.</li>
<li><strong>No origin for an IP:</strong> the address is private (<code>10.0.0.0/8</code>, <code>192.168.0.0/16</code>),
reserved for documentation, or simply not routed.</li>
<li><strong>Unexpected company:</strong> a hosting, cloud or CDN provider announces the block on behalf of the site you
are checking. Use <a href="/reverse-dns-lookup">reverse DNS</a> for more hints about the host.</li>
<li><strong>Fresh change not visible:</strong> new announcements can take a while to show up in collected data, and
cached results here are up to six hours old.</li>
</ul>`,

  faq: [
    { q: 'How do I find the AS number of my provider?', a: 'Open “What is my IP”: it shows the AS number of your connection, linked to this lookup. You can also enter any IP address here to see which AS announces it.' },
    { q: 'Why does an IP belong to a different company than expected?', a: 'Address blocks can be routed by a provider on behalf of a customer, or belong to a cloud or CDN that hosts the website. The origin AS is the network announcing the route, not necessarily the organization using the address.' },
    { q: 'How current is the data?', a: 'RIPEstat updates routing data several times a day. Results here are cached for up to six hours.' },
    { q: 'What is the difference between a 16-bit and a 32-bit ASN?', a: 'Only the size of the number. ASNs up to 65535 fit in 16 bits; larger ones need 32-bit support, which all current routers have. Older notation sometimes writes 32-bit ASNs as two numbers with a dot, for example 1.10 for 65546.' },
    { q: 'How do I get my own AS number?', a: 'Apply at the regional internet registry for your region, usually through a member or sponsoring provider. You generally need a technical reason, such as connecting to two or more upstream providers.' },
    { q: 'Is an ASN the same as an IP address block?', a: 'No. The ASN identifies the network operator in routing; the IP blocks are the addresses it announces. One AS can announce hundreds of prefixes, and a prefix can move from one AS to another.' },
  ],
};

export default tool;
