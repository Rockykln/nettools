import { mapLimit } from '../core/async';
import { buildQuery, RR_TYPES } from '../core/dns';
import { html, type SafeHtml } from '../core/html';
import { bar } from '../core/ui';
import { json } from '../core/http';
import { normalizeDomain } from '../core/net';
import type { Tool, ToolContext } from '../core/tool';
import { COMPARE_RESOLVERS, dohByIp, dotSequential, isAnswer, resolve, type Resolver } from '../core/transport';

const REPEATS = 3;

interface Row {
  resolver: Resolver;
  first: number | null;
  repeat: number | null;
  failures: number;
}

function median(sorted: number[]): number | null {
  if (!sorted.length) return null;
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid]! : Math.round((sorted[mid - 1]! + sorted[mid]!) / 2);
}

// The first query may miss the resolver's cache; the median of the following ones shows the cached speed.
async function bench(name: string): Promise<Row[]> {
  const rows = await mapLimit(COMPARE_RESOLVERS, 5, async (resolver) => {
    const times: (number | null)[] = [];
    if (resolver.transport === 'dot') {
      // One TLS connection for all repeats, like the reused HTTPS connection of the DoH resolvers.
      const queries = Array.from({ length: REPEATS }, () => buildQuery(name, RR_TYPES.A, { ad: true }));
      times.push(...(await dotSequential(dohByIp() ? resolver.ip : resolver.host, queries, 3000)));
    } else {
      for (let i = 0; i < REPEATS; i++) {
        times.push(await resolve(resolver, name, RR_TYPES.A, 3000).then((r) => (isAnswer(r.message) ? r.ms : null)).catch(() => null));
      }
    }
    const repeats = times.slice(1).filter((t): t is number => t !== null).sort((a, b) => a - b);
    return {
      resolver,
      first: times[0] ?? null,
      repeat: median(repeats),
      failures: times.filter((t) => t === null).length,
    };
  });
  return rows.sort((a, b) => (a.repeat ?? Infinity) - (b.repeat ?? Infinity));
}

function colo(c: ToolContext): string {
  const cf = c.req.cf as IncomingRequestCfProperties | undefined;
  return typeof cf?.colo === 'string' ? cf.colo : 'unknown';
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/dns-benchmark">
<div class="field grow"><label for="name">Domain</label>
<input id="name" name="name" type="text" value="${value}" placeholder="example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Run benchmark</button></div>
</form>`;
}

const INVALID = 'Enter a domain such as example.com.';

const tool: Tool = {
  slug: 'dns-benchmark',
  name: 'DNS speed benchmark',
  icon: 'benchmark',
  category: 'performance',
  title: 'DNS Speed Benchmark – Compare Public DNS Resolvers',
  description: `Compare how fast ${COMPARE_RESOLVERS.length} public DNS resolvers answer, including Cloudflare, Google, Quad9 and OpenDNS: first query and cached response time.`,
  h1: 'DNS speed benchmark',
  lead: `Compare the response times of ${COMPARE_RESOLVERS.length} public DNS resolvers for a domain, uncached and cached.`,
  heavy: () => true,
  examples: [['example.com', 'name=example.com'], ['wikipedia.org', 'name=wikipedia.org']],
  related: ['dns-lookup', 'dns-propagation-checker', 'response-time'],
  isQuery: (url) => url.searchParams.has('name'),

  async render(c) {
    const value = (c.url.searchParams.get('name') ?? '').trim();
    if (!c.url.searchParams.has('name')) return form('');
    const name = normalizeDomain(value);
    if (!name?.includes('.')) return html`${form(value)}<p class="error">${INVALID}</p>`;
    const rows = await bench(name);
    const max = Math.max(1, ...rows.map((r) => Math.max(r.first ?? 0, r.repeat ?? 0)));
    return html`${form(value)}
<p class="result-head">${REPEATS} A queries for <code>${name}</code> per resolver from Cloudflare <strong>${colo(c)}</strong>, fastest first</p>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data num bench"><thead><tr><th>Resolver</th><th>First query</th><th>Cached</th><th></th></tr></thead>
<tbody>${rows.map((r) => html`<tr><td><strong>${r.resolver.name}</strong><br><span class="muted">${r.resolver.transport === 'dot' ? 'DNS-over-TLS' : 'DNS-over-HTTPS'}</span></td>
<td>${r.first !== null ? `${r.first} ms` : html`<span class="status bad">failed</span>`}</td><td>${r.repeat !== null ? `${r.repeat} ms` : '—'}</td>
<td class="bar-cell">${bar(((r.repeat ?? 0) / max) * 100)}</td></tr>`)}</tbody></table></div>
<p class="hint">Times include the encrypted transport (HTTPS or TLS) and are measured from Cloudflare's network, not from your device.</p>`;
  },

  apiDoc: 'GET /api/dns-benchmark?name=example.com',

  async api(c) {
    const name = normalizeDomain(c.url.searchParams.get('name') ?? '');
    if (!name?.includes('.')) return json({ error: INVALID }, { status: 400 });
    const rows = await bench(name);
    return json({ name, from: colo(c), results: rows.map((r) => ({ resolver: r.resolver.id, firstMs: r.first, cachedMs: r.repeat, failures: r.failures })) });
  },

  article: html`<h2>What this benchmark measures</h2>
<p>For each of the ${COMPARE_RESOLVERS.length} resolvers the same A record is queried three times in a row. The first
query may have to be resolved from the authoritative name servers if the resolver has not cached the name yet; the
following queries are usually answered from the resolver's cache. “Cached” is the median of those repeats and shows
the raw speed of the resolver and the network path to it. The table is sorted by that value.</p>
<p>All queries are encrypted. Most resolvers are queried over DNS-over-HTTPS (DoH); Quad9 is queried over DNS-over-TLS
(DoT) on port 853. In both cases the connection is kept open between the repeats, so the first query includes the
connection setup and the cached value shows the resolver on an open connection.</p>
<p>A query that fails or takes longer than three seconds is marked as failed. A single failure can be a network hiccup;
repeated failures for the same resolver usually mean it is overloaded or not reachable from that location.</p>

<h2>What makes a resolver fast</h2>
<table class="data">
<thead><tr><th>Factor</th><th>Effect</th></tr></thead>
<tbody>
<tr><td>Anycast and distance</td><td>The large public resolvers announce the same IP addresses from many locations, and
routing sends you to a nearby one. Round-trip time to that site sets the lower limit for every answer.</td></tr>
<tr><td>Cache hit rate</td><td>A cached answer needs one round trip. A miss adds queries to the root, TLD and
authoritative servers. Busy resolvers have more names cached, but large ones split traffic across many servers with
separate caches, so a popular name can still miss.</td></tr>
<tr><td>TTL of the record</td><td>Records with a TTL of 60 seconds or less expire quickly and cause more misses than
records that live for hours.</td></tr>
<tr><td>Distance to the authoritative servers</td><td>On a miss, the resolver's path to the domain's name servers
matters. A domain hosted on a single name server far away is slow on every resolver.</td></tr>
<tr><td>Load and rate limits</td><td>Some resolvers throttle clients that send many queries, which shows up as
timeouts rather than slow answers.</td></tr>
</tbody>
</table>

<h3>EDNS Client Subnet and CDNs</h3>
<p>Raw resolver speed is only half of the picture. Content delivery networks pick the server they return based on
where the query comes from. With EDNS Client Subnet (ECS, RFC 7871) the resolver passes a shortened form of your IP
address, typically a /24 network, to the authoritative server, so the CDN can choose a server near you. Google Public
DNS sends ECS to name servers that support it. Cloudflare's 1.1.1.1 does not send ECS for privacy reasons, and Quad9
offers ECS only on a separate address (9.9.9.11). Without ECS the CDN sees the location of the resolver's site instead.
Usually that is close to you anyway, but if your resolver site is in another region, a resolver that answers in 5 ms
can still send you to a distant CDN node and make the actual download slower.</p>

<h2>Why results here differ from your home</h2>
<p>The queries run from the Cloudflare data center that handled your request, shown above the table. Resolvers with
servers in the same location, including Cloudflare's own 1.1.1.1, therefore look very fast; for Cloudflare the query
may not even leave the data center. From your home network the ranking can be different: what counts there is the
path from your provider to the nearest site of each resolver, and your provider's own resolver, which this tool cannot
reach, is often the closest of all. Use the table as a comparison of the resolvers' global networks, then measure from
your own machine before switching.</p>

<h2>Benchmarking from your own network</h2>
<p><code>dig</code> prints the query time of each lookup. Query the same name twice to see an uncached and a cached
answer:</p>
<pre class="raw">$ dig @1.1.1.1 example.com +noall +stats | grep "Query time"
;; Query time: 23 msec
$ dig @1.1.1.1 example.com +noall +stats | grep "Query time"
;; Query time: 9 msec</pre>
<p>A short loop compares several resolvers at once. Run it a few times and at different times of day, since single
measurements vary:</p>
<pre class="raw">for r in 1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222; do
  printf '%-16s' "$r"
  dig @"$r" example.com +noall +stats | awk '/Query time/ {print $4, "ms"}'
done</pre>
<p>This uses plain DNS on port 53. To test the encrypted transports, BIND 9.18 and later accept <code>+tls</code> and
<code>+https</code>, and <code>kdig</code> from Knot DNS does the same. Pick a domain that you actually use and one that
is rarely visited, so you see both cached and uncached behaviour. On Windows, GRC's DNS Benchmark runs a longer series
of tests against many resolvers, including the one your router hands out. Older tools such as namebench are no longer
maintained.</p>

<h2>Encrypted DNS and its overhead</h2>
<p>DoH and DoT protect queries from anyone on the network path, but the first query has to set up a TCP connection and
a TLS session, which costs one or two extra round trips. Clients keep the connection open afterwards, so later queries
are about as fast as plain DNS. DNS-over-QUIC (DoQ, RFC 9250) combines the transport and TLS handshakes and avoids
head-of-line blocking; it is supported by fewer resolvers and clients, AdGuard DNS being one of them. In practice the
handshake cost matters most on mobile devices that drop idle connections often.</p>

<h2>Changing your resolver</h2>
<ul>
<li><strong>Router:</strong> set the DNS servers in the WAN or DHCP settings so every device in the network uses them.
Many routers cache answers themselves, which makes repeated lookups fast for all clients.</li>
<li><strong>Windows 11:</strong> Settings, Network &amp; internet, the adapter, <em>DNS server assignment</em>,
<em>Edit</em>. For known resolvers Windows can enable DNS over HTTPS there.</li>
<li><strong>macOS:</strong> System Settings, Network, the connection, <em>Details</em>, <em>DNS</em>, or
<code>networksetup -setdnsservers Wi-Fi 1.1.1.1 1.0.0.1</code>.</li>
<li><strong>Linux with systemd-resolved:</strong> <code>DNS=</code> and optionally <code>DNSOverTLS=yes</code> in
<code>/etc/systemd/resolved.conf</code>; <code>resolvectl status</code> shows what is in use.</li>
<li><strong>Browsers:</strong> Firefox and Chromium-based browsers have their own secure DNS setting that can override
the system resolver.</li>
</ul>
<p>After a change, check what your clients actually see with the <a href="/dns-lookup">DNS lookup</a>, and use the
<a href="/dns-propagation-checker">DNS propagation checker</a> to see whether all resolvers return the same answer for
your own records.</p>

<h2>Choosing a resolver</h2>
<ul>
<li><strong>Speed:</strong> differences of a few milliseconds are rarely noticeable; failures and slow uncached answers
matter more.</li>
<li><strong>Privacy:</strong> encryption hides queries from the network, not from the resolver operator. Read the
logging policy and check where the operator is based. Your provider still sees which IP addresses you connect to.</li>
<li><strong>Filtering:</strong> several operators offer separate addresses that block malware or adult content. This
benchmark uses their standard endpoints, not the filtering ones.</li>
<li><strong>DNSSEC:</strong> a validating resolver refuses answers whose signatures do not check out. The large public
resolvers validate; the <a href="/dnssec-check">DNSSEC check</a> shows whether a domain is signed at all.</li>
</ul>`,

  faq: [
    { q: 'Which DNS resolver is the fastest?', a: 'It depends on where you are. Large anycast resolvers such as Cloudflare, Google and Quad9 are fast almost everywhere; your provider’s resolver can be faster because it is closer, but often caches fewer names. Measure from your own network before switching.' },
    { q: 'Why is the first query slower?', a: 'If the resolver has not cached the name, it has to ask the root, TLD and authoritative name servers first, which adds one or more round trips. The cached value shows what you get for names that are looked up often.' },
    { q: 'Does a faster resolver make my internet faster?', a: 'Only the first connection to each name gets faster, typically by a few milliseconds, and your system caches answers afterwards. Download speed is not affected, and a resolver without EDNS Client Subnet can occasionally lead to a more distant CDN server.' },
    { q: 'Why does Cloudflare always come out on top here?', a: 'The benchmark runs inside Cloudflare’s network, so the path to 1.1.1.1 is very short. From your home network the result can be different.' },
    { q: 'Is DNS over HTTPS slower than plain DNS?', a: 'The first query needs a TCP and TLS handshake and is slower. Once the connection is open, later queries reuse it and are about as fast as plain DNS over UDP.' },
    { q: 'Does the benchmark use my own DNS settings?', a: 'No. The queries are sent from the Cloudflare data center that handled your request, not from your device, so your configured resolver and your provider’s network play no part in the result.' },
  ],
};

export default tool;
