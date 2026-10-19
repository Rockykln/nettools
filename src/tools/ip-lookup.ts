import { cachedJson } from '../core/cache';
import { RR_TYPES } from '../core/dns';
import { countryOf, GEO_CREDIT, type GeoResult } from '../core/geo';
import { isPublicAddress } from '../core/guard';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { isIP, isIPv4, normalizeDomain } from '../core/net';
import type { Tool, ToolContext } from '../core/tool';
import { RESOLVERS, resolve } from '../core/transport';
import { prefixReport, type PrefixReport } from './asn-lookup';
import { checkLists, type ListResult } from './blacklist-check';
import { countryName, ptr } from './what-is-my-ip';
import { ipOwner, lookup, type IpOwner } from './whois';

interface Report {
  ip: string;
  version: 4 | 6;
  /** Set when a host name was entered. */
  host: string | null;
  hostname: string | null;
  country: GeoResult | null;
  routing: PrefixReport | null;
  owner: IpOwner | null;
  ownerSource: string | null;
  /** IPv4 only; null for IPv6 or when the check failed. */
  blocklists: { listed: string[]; answered: number; total: number } | null;
}

const INVALID = 'Enter an IP address such as 8.8.8.8 or 2606:4700:4700::1111, or a host name.';

async function target(input: string): Promise<{ ip: string; host: string | null } | { error: string }> {
  const v = input.trim().replace(/^\[|\]$/g, '');
  if (isIP(v)) return isPublicAddress(v) ? { ip: v, host: null } : { error: 'Private, local and reserved addresses have no public owner or location.' };
  const host = normalizeDomain(v);
  if (!host?.includes('.')) return { error: INVALID };
  for (const type of [RR_TYPES.A, RR_TYPES.AAAA]) {
    const r = await resolve(RESOLVERS[0]!, host, type).catch(() => null);
    const ip = r?.message.answers.find((a) => a.type === type)?.data;
    if (ip) return isPublicAddress(ip) ? { ip, host } : { error: `${host} points to a private or reserved address.` };
  }
  return { error: `${host} does not resolve to an IP address.` };
}

// Each source is optional: one slow or failing service leaves its rows empty instead of failing the page.
const settle = <T>(p: Promise<T>): Promise<T | null> => p.catch(() => null);

async function report(c: ToolContext, ip: string, host: string | null): Promise<Report> {
  const [hostname, country, routing, whois, lists] = await Promise.all([
    settle(cachedJson(`ptr:${ip}`, (h) => (h ? 3600 : 0), () => ptr(ip))),
    settle(countryOf(c.env.ASSETS, ip)),
    settle(prefixReport(ip)),
    settle(lookup({ input: ip, kind: 'ip', value: ip })),
    isIPv4(ip) ? settle(checkLists(ip)) : Promise.resolve(null),
  ]);
  return {
    ip,
    version: isIPv4(ip) ? 4 : 6,
    host,
    hostname,
    country,
    routing,
    owner: whois?.rdap ? ipOwner(whois.rdap) : null,
    ownerSource: whois?.rdap ? whois.source : null,
    blocklists: lists ? summarize(lists) : null,
  };
}

function summarize(results: ListResult[]): Report['blocklists'] {
  const answered = results.filter((r) => r.state !== 'unavailable');
  return { listed: results.filter((r) => r.state === 'listed').map((r) => r.list.name), answered: answered.length, total: results.length };
}

const dash = (v: string | null | undefined) => (v ? v : '—');

function countryCell(g: GeoResult | null): SafeHtml | string {
  if (!g) return '—';
  if (!g.code) return html`<span class="muted">not assigned to a country</span>`;
  return html`${countryName(g.code) ?? g.code} <span class="muted">(${g.code})</span>`;
}

function render(r: Report): SafeHtml {
  const origin = r.routing?.origins[0];
  const enc = encodeURIComponent(r.ip);
  return html`<p class="result-head"><code>${r.ip}</code> <span class="badge">IPv${r.version}</span>${r.host ? html` · resolved from <code>${r.host}</code>` : ''}
<button type="button" class="btn-small" data-copy="${r.ip}">Copy</button></p>
<table class="kv"><tbody>
<tr><th scope="row">Reverse DNS</th><td><code>${dash(r.hostname)}</code></td></tr>
<tr><th scope="row">Country</th><td>${countryCell(r.country)}</td></tr>
<tr><th scope="row">Owner</th><td>${dash(r.owner?.organization)}</td></tr>
<tr><th scope="row">Network</th><td>${r.owner?.network || r.owner?.range ? html`${dash(r.owner?.network)}${r.owner?.range ? html`<br><span class="muted">${r.owner.range}</span>` : ''}` : '—'}</td></tr>
<tr><th scope="row">Abuse contact</th><td>${r.owner?.abuse ? html`<a href="mailto:${r.owner.abuse}">${r.owner.abuse}</a>` : '—'}</td></tr>
<tr><th scope="row">Announced prefix</th><td>${r.routing ? (r.routing.announced ? html`<a href="/subnet-calculator?cidr=${encodeURIComponent(r.routing.prefix)}"><code>${r.routing.prefix}</code></a>` : html`<span class="status warn">not announced in BGP</span>`) : '—'}</td></tr>
<tr><th scope="row">Origin AS</th><td>${origin ? html`<a href="/asn-lookup?q=AS${origin.asn}">AS${origin.asn}</a> ${origin.holder}` : '—'}</td></tr>
<tr><th scope="row">Blocklists</th><td>${r.version === 6 ? html`<span class="muted">not checked; most lists cover IPv4 only</span>`
    : !r.blocklists?.answered ? html`<span class="muted">no list answered; try the <a href="/blacklist-check?q=${enc}">blacklist check</a> later</span>`
    : r.blocklists.listed.length ? html`<span class="status bad">listed on ${r.blocklists.listed.length} of ${r.blocklists.answered}</span> ${r.blocklists.listed.join(', ')}`
    : html`<span class="status ok">not listed</span> <span class="muted">on any of ${r.blocklists.answered} lists that answered</span>`}</td></tr>
</tbody></table>
<p class="hint">Details: <a href="/whois?q=${enc}">WHOIS</a> · ${origin ? html`<a href="/asn-lookup?q=AS${origin.asn}">ASN and BGP</a> · ` : ''}${r.version === 4 ? html`<a href="/blacklist-check?q=${enc}">all blocklists</a> · ` : ''}<a href="/port-checker?host=${enc}&amp;preset=web">open ports</a> · <a href="/tcp-ping?host=${enc}">TCP ping</a></p>
<p class="hint">Country data: <a href="${GEO_CREDIT.url}" rel="noopener">IP Geolocation by DB-IP</a> (${GEO_CREDIT.license}${r.country ? `, ${r.country.month}` : ''}). Owner from the regional registry via RDAP, routing from RIPEstat.</p>`;
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/ip-lookup">
<div class="field grow"><label for="q">IP address or host name</label>
<input id="q" name="q" type="text" value="${value}" placeholder="8.8.8.8, 2606:4700:4700::1111 or example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Look up</button></div>
</form>`;
}

const tool: Tool = {
  slug: 'ip-lookup',
  name: 'IP lookup',
  icon: 'iplookup',
  category: 'ip',
  title: 'IP Lookup – Owner, Country, ASN & Abuse Contact of Any IP',
  description:
    'Look up any IPv4 or IPv6 address: country, owner and abuse contact, announced prefix and origin AS, reverse DNS and spam blocklist status in one view.',
  h1: 'IP address lookup',
  lead: 'Who owns an IP address, where it is registered, which network announces it and whether it is on a blocklist.',
  examples: [['8.8.8.8', 'q=8.8.8.8'], ['2606:4700:4700::1111', 'q=2606:4700:4700::1111'], ['wikipedia.org', 'q=wikipedia.org']],
  related: ['what-is-my-ip', 'whois', 'asn-lookup', 'blacklist-check'],
  heavy: () => true,
  isQuery: (url) => url.searchParams.has('q'),

  async render(c) {
    const value = (c.url.searchParams.get('q') ?? '').trim();
    if (!c.url.searchParams.has('q')) return form('');
    const t = await target(value);
    if ('error' in t) return html`${form(value)}<p class="error">${t.error}</p>`;
    return html`${form(value)}${render(await report(c, t.ip, t.host))}`;
  },

  apiDoc: 'GET /api/ip-lookup?q=8.8.8.8 (IPv4, IPv6 or a host name)',

  async api(c) {
    const t = await target(c.url.searchParams.get('q') ?? '');
    if ('error' in t) return json({ error: t.error }, { status: 400 });
    const r = await report(c, t.ip, t.host);
    return json({
      ip: r.ip,
      version: r.version,
      host: r.host,
      hostname: r.hostname,
      country: r.country?.code ?? null,
      countryName: r.country?.code ? countryName(r.country.code) : null,
      owner: r.owner,
      prefix: r.routing?.announced ? r.routing.prefix : null,
      origins: r.routing?.origins ?? [],
      blocklists: r.blocklists,
      sources: {
        country: `${GEO_CREDIT.name} IP to Country Lite${r.country ? ` ${r.country.month}` : ''} (${GEO_CREDIT.license}, ${GEO_CREDIT.url})`,
        owner: r.ownerSource,
        routing: 'RIPEstat',
      },
    });
  },

  article: html`<h2>What an IP lookup shows</h2>
<p>An IP address on its own says little. This lookup combines several public sources to answer the usual questions
about an address seen in a log file, a firewall alert or a mail header:</p>
<table class="data">
<thead><tr><th>Row</th><th>Source</th><th>What it tells you</th></tr></thead>
<tbody>
<tr><td>Reverse DNS</td><td>PTR record</td><td>The host name the network operator assigned, often hinting at the provider or the purpose, e.g. <code>dns.google</code>.</td></tr>
<tr><td>Country</td><td>DB-IP Lite database</td><td>The country where the address is most likely used.</td></tr>
<tr><td>Owner, network, abuse contact</td><td>Regional internet registry (RDAP)</td><td>The organization the block is registered to and where to report misuse.</td></tr>
<tr><td>Announced prefix, origin AS</td><td>Global BGP routing table (RIPEstat)</td><td>Which network actually routes the address on the internet today.</td></tr>
<tr><td>Blocklists</td><td>12 DNS blocklists</td><td>Whether the address is known for sending spam (IPv4 only).</td></tr>
</tbody>
</table>

<h2>Owner and routing can differ</h2>
<p>The registry shows who holds the address block; BGP shows who announces it. Usually that is the same company,
but not always. A provider may assign part of its space to a customer that announces it with its own AS number, a
hosting company may lease addresses from a broker, and large content networks announce space on behalf of their
customers. If you want to report abuse, the abuse contact of the registry entry is the right address in almost all
cases, because that organization can act on the customer behind the address.</p>

<h2>How accurate is IP geolocation?</h2>
<p>At country level, IP geolocation is right for the vast majority of addresses of home and mobile connections.
It is less reliable for addresses of companies with offices in many countries, satellite and mobile networks that
route traffic through a central gateway, VPN and proxy services, and anycast addresses such as public DNS
resolvers, which are served from many locations at once. The country shown here is where the address is most likely
used, which is not necessarily the country in the registry entry: a German provider can use its addresses in
Austria, for example. City-level data is far less accurate and is not shown.</p>

<h2>Reporting abuse</h2>
<ol>
<li>Write to the abuse contact shown above, not to the organization's general address.</li>
<li>Include the exact time with time zone, the source IP and port, and the relevant log lines or full mail headers.</li>
<li>Keep it factual and short. Abuse desks process many reports, often automatically.</li>
</ol>
<p>For spam, the <a href="/email-headers">email header analyzer</a> shows which server really sent a message.
The <a href="/blacklist-check">blacklist check</a> lists every blocklist with its removal page.</p>

<h2>The same lookups on the command line</h2>
<pre class="raw">dig +short -x 8.8.8.8                       # reverse DNS (PTR)
whois 8.8.8.8                               # registry entry with owner and abuse contact
curl -s https://rdap.arin.net/registry/ip/8.8.8.8   # the same as JSON via RDAP
whois -h whois.cymru.com " -v 8.8.8.8"      # origin AS and announced prefix
curl -s "https://net.rockykln.com/api/ip-lookup?q=8.8.8.8"   # everything at once</pre>
<p>The plain <code>whois</code> client asks the registry that holds the block; it follows referrals from ARIN to
RIPE, APNIC, LACNIC or AFRINIC on its own. RDAP returns the same data as structured JSON and is what this page uses.</p>

<h2>Private and special addresses</h2>
<p>Addresses such as <code>10.0.0.0/8</code>, <code>192.168.0.0/16</code>, <code>172.16.0.0/12</code>,
<code>100.64.0.0/10</code> (carrier-grade NAT) and IPv6 unique local addresses (<code>fc00::/7</code>) are not
routed on the internet and have no public owner or location; their meaning depends on the local network. The
<a href="/subnet-calculator">subnet calculator</a> shows which range an address belongs to.</p>`,

  faq: [
    {
      q: 'Can I find out who is behind an IP address?',
      a: 'You can see which organization the address block is registered to, usually an internet provider, hosting company or large company. The provider knows which customer used the address at a given time, but only shares that with law enforcement.',
    },
    {
      q: 'Why does the country differ from other IP lookup sites?',
      a: 'Every geolocation database is built from different sources and updated at different times. Results differ most for VPNs, mobile networks, satellite internet and addresses that recently moved to another provider.',
    },
    {
      q: 'Where does the country data come from?',
      a: 'From the free DB-IP IP to Country Lite database, licensed under Creative Commons Attribution 4.0 and updated monthly.',
    },
    {
      q: 'Why is there no blocklist result for IPv6?',
      a: 'The IPv6 address space is too large for per-address blocklists to work like they do for IPv4, and most lists do not publish IPv6 data.',
    },
    {
      q: 'Can I look up my own IP?',
      a: 'Yes. What is my IP shows your address together with the details Cloudflare sees for your connection; you can then enter it here for the registry and blocklist data.',
    },
  ],
};

export default tool;
