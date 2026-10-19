import { CLASS_CH, RR_TYPES, buildQuery } from '../core/dns';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import type { Tool, ToolContext } from '../core/tool';
import { mapLimit } from '../core/async';
import { cachedJson } from '../core/cache';
import { dnsOverTcp } from '../core/transport';
import { rootHistory, sparkline, type RootHistory } from '../jobs/root-monitor';

interface RootServer {
  letter: string;
  operator: string;
  ipv4: string;
  ipv6: string;
}

// https://www.iana.org/domains/root/servers
export const ROOT_SERVERS: RootServer[] = [
  { letter: 'A', operator: 'Verisign', ipv4: '198.41.0.4', ipv6: '2001:503:ba3e::2:30' },
  { letter: 'B', operator: 'USC-ISI', ipv4: '170.247.170.2', ipv6: '2801:1b8:10::b' },
  { letter: 'C', operator: 'Cogent Communications', ipv4: '192.33.4.12', ipv6: '2001:500:2::c' },
  { letter: 'D', operator: 'University of Maryland', ipv4: '199.7.91.13', ipv6: '2001:500:2d::d' },
  { letter: 'E', operator: 'NASA Ames Research Center', ipv4: '192.203.230.10', ipv6: '2001:500:a8::e' },
  { letter: 'F', operator: 'Internet Systems Consortium', ipv4: '192.5.5.241', ipv6: '2001:500:2f::f' },
  { letter: 'G', operator: 'US Department of Defense (NIC)', ipv4: '192.112.36.4', ipv6: '2001:500:12::d0d' },
  { letter: 'H', operator: 'US Army Research Lab', ipv4: '198.97.190.53', ipv6: '2001:500:1::53' },
  { letter: 'I', operator: 'Netnod', ipv4: '192.36.148.17', ipv6: '2001:7fe::53' },
  { letter: 'J', operator: 'Verisign', ipv4: '192.58.128.30', ipv6: '2001:503:c27::2:30' },
  { letter: 'K', operator: 'RIPE NCC', ipv4: '193.0.14.129', ipv6: '2001:7fd::1' },
  { letter: 'L', operator: 'ICANN', ipv4: '199.7.83.42', ipv6: '2001:500:9f::42' },
  { letter: 'M', operator: 'WIDE Project', ipv4: '202.12.27.33', ipv6: '2001:dc3::35' },
];

export interface RootResult {
  server: RootServer;
  connectMs: number | null;
  queryMs: number | null;
  serial: number | null;
  instance: string | null;
  error: string | null;
  /** The instance sits in Cloudflare's network, which Workers sockets cannot reach: not a failure of the root. */
  untestable: boolean;
}

const UNTESTABLE = 'Not testable from Cloudflare Workers here: the nearest instance is served from Cloudflare’s own network';

async function testRoot(server: RootServer): Promise<RootResult> {
  const result: RootResult = { server, connectMs: null, queryMs: null, serial: null, instance: null, error: null, untestable: false };
  try {
    const soa = buildQuery('.', RR_TYPES.SOA, { rd: false, id: 0x1001 });
    const ident = buildQuery('id.server', RR_TYPES.TXT, { rd: false, cls: CLASS_CH, id: 0x1002 });
    const res = await dnsOverTcp(server.ipv4, [soa, ident], 4000);
    result.connectMs = res.connectMs;
    result.queryMs = res.totalMs - res.connectMs;
    const soaMsg = res.messages[0]!;
    const soaRec = soaMsg.answers.find((a) => a.type === RR_TYPES.SOA);
    if (soaRec) result.serial = Number(soaRec.data.split(' ')[2]);
    else result.error = `No root zone SOA in the answer (${soaMsg.rcodeName})`;
    const txt = res.messages[1]!.answers.find((a) => a.type === RR_TYPES.TXT);
    if (txt) result.instance = txt.data.replace(/^"|"$/g, '');
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    // Workers cannot open sockets to addresses served from Cloudflare's own network (some root instances are).
    result.untestable = /proxy request failed|cannot connect to the specified address/i.test(message);
    result.error = result.untestable ? UNTESTABLE : message;
  }
  return result;
}

export async function runAll(): Promise<RootResult[]> {
  return mapLimit(ROOT_SERVERS, 5, testRoot);
}

function runAllCached(c: ToolContext): Promise<RootResult[]> {
  return cachedJson(`rootall:${colo(c)}`, () => 30, runAll);
}

function colo(c: ToolContext): string {
  const cf = c.req.cf as IncomingRequestCfProperties | undefined;
  return typeof cf?.colo === 'string' ? cf.colo : 'unknown';
}

function ago(ts: number): string {
  const min = Math.max(0, Math.round((Date.now() / 1000 - ts) / 60));
  return min < 1 ? 'just now' : min === 1 ? '1 minute ago' : `${min} minutes ago`;
}

const pct = (v: number | null) => (v === null ? '—' : `${(v * 100).toFixed(v === 1 ? 0 : 1)} %`);

// One table for everything: identity, latest check (live or from the cron job) and the 24-hour history.
function rootTable(results: RootResult[] | null, history: RootHistory | null, from: string): SafeHtml {
  const live = new Map(results?.map((r) => [r.server.letter, r]));
  const latestTs = history ? Math.max(0, ...Object.values(history.latest).map((l) => l.ts)) : 0;
  const latestColo = history ? Object.values(history.latest)[0]?.colo : undefined;
  const okCount = results ? results.filter((r) => !r.error).length : Object.values(history?.latest ?? {}).filter((l) => l.ok).length;
  // Untestable roots are not stored by the cron job, so the history only counts the testable ones.
  const tested = results ? results.filter((r) => !r.untestable).length : Object.keys(history?.latest ?? {}).length;
  const serials = new Set(
    (results ? results.map((r) => r.serial) : Object.values(history?.latest ?? {}).map((l) => l.serial)).filter((s): s is number => s !== null),
  );
  const timed = results ? results.map((r) => r.queryMs) : ROOT_SERVERS.map((s) => history?.latest[s.letter]?.queryMs ?? null);
  const fastest = Math.min(...timed.map((v) => v ?? Infinity));
  const max = history ? Math.max(10, ...history.roots.flatMap((r) => r.series.filter((v): v is number => v !== null && v > 0))) : 10;

  let summary: SafeHtml | string = html`No measurements yet. The servers are checked every 10 minutes.`;
  if (results) summary = html`Tested just now from Cloudflare <strong>${from}</strong>: ${okCount} of ${tested} testable roots answered`;
  else if (latestTs) summary = html`Last automatic check ${ago(latestTs)} from Cloudflare <strong>${latestColo ?? ''}</strong>: ${okCount} of ${tested} testable roots answered`;
  const serialNote =
    serials.size === 1 ? html`, root zone serial <code>${[...serials][0]}</code>.` : serials.size > 1 ? html`. Different zone serials (${[...serials].join(', ')}): an update is propagating.` : '.';

  return html`<p class="result-head" data-summary aria-live="polite">${summary}${results || latestTs ? serialNote : ''}</p>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data num roots">
<thead><tr><th>Root server</th><th>Operator</th><th>Address</th><th>Status</th><th>Query</th><th>Answering instance</th><th>Uptime, 24 h</th><th>Query time, 24 h</th></tr></thead>
<tbody>${ROOT_SERVERS.map((s, i) => {
    const r = live.get(s.letter);
    const l = history?.latest[s.letter];
    const h = history?.roots.find((x) => x.letter === s.letter);
    const ok = r ? !r.error : l?.ok;
    const ms = r ? r.queryMs : (l?.queryMs ?? null);
    return html`<tr data-root="${s.letter}">
<td><strong>${s.letter}</strong> <code class="muted">${s.letter.toLowerCase()}.root-servers.net</code></td>
<td>${s.operator}</td>
<td><code>${s.ipv4}</code><br><code class="muted">${s.ipv6}</code></td>
<td data-cell="status">${r?.untestable ? html`<span class="status info" title="${UNTESTABLE}">Not testable</span>` : ok === undefined ? '—' : ok ? html`<span class="status ok">OK</span>` : html`<span class="status bad" title="${r?.error ?? 'Failed in the last automatic check'}">Failed</span>`}</td>
<td data-cell="query"${ms !== null && ms === fastest ? html` class="best" title="Fastest"` : ''}>${ms === null ? '—' : ms < 1 ? '<1 ms' : `${ms} ms`}</td>
<td data-cell="instance"><code>${r ? (r.instance ?? r.error ?? '—') : (l?.instance ?? '—')}</code></td>
<td>${pct(h?.availability ?? null)}</td>
<td>${h && h.series.filter((v) => v !== null).length >= 3 ? sparkline(h.series, max) : html`<span class="muted">Collecting data…</span>`}</td></tr>`;
  })}</tbody>
</table></div>`;
}

const tool: Tool = {
  slug: 'root-dns-servers',
  name: 'Root DNS servers',
  icon: 'root',
  category: 'dns',
  title: 'Root DNS Server Test – Latency & Status of All 13 Roots',
  description:
    'Test all 13 DNS root servers (a.root-servers.net to m.root-servers.net) live: response time, root zone serial and which anycast instance answers.',
  h1: 'Root DNS server test',
  lead: 'Status, response time and history of the 13 DNS root servers, checked every 10 minutes and on demand.',
  related: ['dns-lookup', 'whois', 'speed-test'],
  // Only the full live test (13 connections) is heavy; history reads stored samples and single tests have their own limit.
  heavy: (url) => url.searchParams.has('run') || /^\/api\/root-dns-servers\/?$/.test(url.pathname),
  isQuery: (url) => url.searchParams.has('run'),

  async render(c) {
    const run = c.url.searchParams.has('run');
    const [results, history] = await Promise.all([
      run ? runAllCached(c) : Promise.resolve(null),
      rootHistory(c.env).catch(() => null),
    ]);
    return html`<form class="tool-form" method="get" action="/root-dns-servers" data-root-test>
<input type="hidden" name="run" value="1"><div class="field"><button type="submit">Test all 13 now</button></div>
</form>
${rootTable(results, history, colo(c))}`;
  },

  script: 'root-dns.js',

  apiDoc: 'GET /api/root-dns-servers (live test of all 13); GET /api/root-dns-servers/test/a (one root); GET /api/root-dns-servers/history (last 24 h)',

  async api(c, sub) {
    if (sub === 'history') {
      const history = await rootHistory(c.env).catch(() => null);
      return history ? json(history) : json({ error: 'History is not available right now.' }, { status: 503 });
    }
    const single = sub.match(/^test\/([a-m])$/i);
    if (sub !== '' && !single) return json({ error: 'Not found' }, { status: 404 });
    if (sub === '' ) {
      const results = await runAllCached(c);
      return json({ from: colo(c), results: results.map((r) => ({ root: `${r.server.letter.toLowerCase()}.root-servers.net`, ipv4: r.server.ipv4, connectMs: r.connectMs, queryMs: r.queryMs, serial: r.serial, instance: r.instance, error: r.error, untestable: r.untestable })) });
    }
    const server = ROOT_SERVERS.find((s) => s.letter === single![1]!.toUpperCase())!;
    const r = await cachedJson(`root:${colo(c)}:${server.letter}`, () => 30, () => testRoot(server));
    return json({ root: server.letter, from: colo(c), connectMs: r.connectMs, queryMs: r.queryMs, serial: r.serial, instance: r.instance, error: r.error, untestable: r.untestable });
  },

  article: html`<h2>What are the root servers?</h2>
<p>The root servers are the starting point of every DNS lookup. When a recursive resolver, such as the one run by
your ISP or a public service like <code>1.1.1.1</code>, does not yet know where to find <code>example.com</code>, it
asks a root server. The root server does not know the answer either, but it refers the resolver to the name servers
for <code>.com</code>, which in turn refer it to the name servers for <code>example.com</code>.</p>
<p>The data the root servers publish is the root zone: a small file that lists the name servers and DNSSEC keys
of every top-level domain, more than 1,400 of them. IANA (operated by ICANN) manages the content of the root zone,
and Verisign, as root zone maintainer, compiles, signs and distributes it to the root server operators.</p>

<h2>Why are there 13 root servers?</h2>
<p>There are 13 root server identities, <code>a.root-servers.net</code> through <code>m.root-servers.net</code>, run by
12 independent organizations (Verisign operates both A and J). The number goes back to the original DNS rule that a
UDP response must fit in 512 bytes: 13 names and their IPv4 addresses were the most that fit into one priming
response.</p>
<p>Thirteen identities does not mean thirteen machines. Each identity is announced from many locations using
anycast: the same IP address is routed to whichever instance is closest in network terms. In total there are about
2,000 root server instances worldwide, and new ones are added every year.</p>

<table class="data">
<thead><tr><th>Root</th><th>Operator</th><th>IPv4</th></tr></thead>
<tbody>
<tr><td>A, J</td><td>Verisign</td><td><code>198.41.0.4</code>, <code>192.58.128.30</code></td></tr>
<tr><td>B</td><td>USC Information Sciences Institute</td><td><code>170.247.170.2</code></td></tr>
<tr><td>C</td><td>Cogent Communications</td><td><code>192.33.4.12</code></td></tr>
<tr><td>D</td><td>University of Maryland</td><td><code>199.7.91.13</code></td></tr>
<tr><td>E</td><td>NASA Ames Research Center</td><td><code>192.203.230.10</code></td></tr>
<tr><td>F</td><td>Internet Systems Consortium</td><td><code>192.5.5.241</code></td></tr>
<tr><td>G</td><td>US Department of Defense (NIC)</td><td><code>192.112.36.4</code></td></tr>
<tr><td>H</td><td>US Army Research Lab</td><td><code>198.97.190.53</code></td></tr>
<tr><td>I</td><td>Netnod</td><td><code>192.36.148.17</code></td></tr>
<tr><td>K</td><td>RIPE NCC</td><td><code>193.0.14.129</code></td></tr>
<tr><td>L</td><td>ICANN</td><td><code>199.7.83.42</code></td></tr>
<tr><td>M</td><td>WIDE Project</td><td><code>202.12.27.33</code></td></tr>
</tbody>
</table>
<p>B-root changed its IPv4 address to <code>170.247.170.2</code> in 2023. Old root hints files still list the
previous address; resolvers learn the current set automatically through priming, but it is worth updating static
hints files from <code>https://www.internic.net/domain/named.root</code>.</p>

<h2>What this test measures</h2>
<p>For each of the 13 roots, the tool opens a TCP connection to port 53 on the IPv4 address and sends two queries
over it. The test runs from the Cloudflare data center that handled your request, not from your device, so the
results show how well that region is served. A background job repeats the same test every 10 minutes and keeps
24 hours of history.</p>
<ul>
<li><strong>Status:</strong> OK when the root answered both queries within the timeout, Failed otherwise. Hover
over a failure to see the error. Not testable means the nearest instance of that root is served from Cloudflare’s own
network, which Workers cannot open sockets to; it says nothing about the root itself, and such checks are not counted.</li>
<li><strong>Query:</strong> the time from sending the queries to receiving the answers, without the TCP handshake.
The fastest root in the current run is highlighted.</li>
<li><strong>Root zone serial:</strong> the serial number from the SOA record of the root zone, in the format
<code>YYYYMMDDNN</code>. It normally changes about twice a day. If roots report different serials, a new version is
still being distributed; this usually resolves within minutes.</li>
<li><strong>Answering instance:</strong> the <code>id.server</code> CHAOS TXT record (RFC 4892), which names the
anycast instance that answered. Many operators include an airport or city code, so you can see which site your
traffic reached.</li>
<li><strong>24 h and query time, 24 h:</strong> availability over the last day and a sparkline of response times
from the scheduled checks.</li>
</ul>

<h2>How to test a root server yourself</h2>
<p>With <code>dig</code> (part of BIND utilities on Linux and macOS) you can run the same queries from your own
network. Use <code>+norecurse</code>, because root servers only answer authoritatively and do not resolve names for
you.</p>
<pre class="raw">dig @a.root-servers.net . SOA +norecurse
dig @k.root-servers.net id.server CH TXT
dig @198.41.0.4 . SOA +tcp +norecurse
dig +trace example.com</pre>
<ol>
<li>The first command returns the SOA record of the root zone. The first number after the two host names in the answer is the serial.</li>
<li>The second asks K-root which instance is answering.</li>
<li>The third forces TCP, like this tool does. If UDP works but TCP fails, a firewall is likely blocking TCP on
port 53, which breaks large responses and DNSSEC.</li>
<li><code>dig +trace</code> follows the whole delegation chain: root, then <code>.com</code>, then the domain's own
name servers. It is the quickest way to see where a resolution problem starts.</li>
</ol>

<h2>Reading the results</h2>
<p>Because of anycast, response times from a large data center are usually low, often in the single-digit
milliseconds for roots with an instance in the same city. Higher values for some roots are normal: not every
operator has an instance in every region, and routing does not always pick the geographically closest site.</p>
<p>Do not compare these numbers directly with what you see at home. Your resolver talks to the root servers only
occasionally, because answers are cached. The referrals for top-level domains carry a TTL of two days, and the root
NS records themselves six days. For the delay that actually affects your browsing, test your
<a href="/dns-lookup">DNS resolver and records with a DNS lookup</a> or run a <a href="/speed-test">connection speed
and latency test</a>.</p>

<h2>Root servers and DNSSEC</h2>
<p>The root zone has been signed with DNSSEC since 2010. Validating resolvers trust the root key signing key
(KSK) and build a chain of trust down to each signed domain. The first KSK rollover took place on 11 October 2018,
when KSK-2017 replaced the original 2010 key; the second rollover, to KSK-2024, took place on 11 October 2026, and KSK-2017 is revoked in January 2027. Resolvers
that do not pick up a new key automatically fail to validate every signed name, which is why the rollovers are
announced years in advance. IANA publishes the current trust anchors at data.iana.org. To check that the chain works for a specific domain, use
the <a href="/dnssec-check">DNSSEC validation check</a>.</p>

<h2>Troubleshooting checklist</h2>
<ul>
<li><strong>One root fails once:</strong> usually a transient routing issue between the test location and the
nearest instance. Run the test again.</li>
<li><strong>One root fails repeatedly:</strong> check the 24 h column. If availability drops only from one data
center, the problem is local to that path, not the root server.</li>
<li><strong>All roots fail:</strong> outbound TCP to port 53 is blocked on the testing side. On your own network,
check firewall rules for TCP and UDP port 53.</li>
<li><strong>Different serials:</strong> an update is propagating. Wait a few minutes and test again.</li>
<li><strong>Your own lookups fail but roots are fine:</strong> the problem is further down the chain, at the
top-level domain, the domain's name servers or your resolver. Use <code>dig +trace</code> or compare resolvers with
the <a href="/dns-propagation-checker">DNS propagation checker</a>.</li>
</ul>`,

  faq: [
    {
      q: 'Who controls the DNS root servers?',
      a: 'IANA, operated by ICANN, manages the content of the root zone, and Verisign compiles, signs and distributes it. The 13 server identities are operated by 12 independent organizations, including Verisign, RIPE NCC, Netnod, NASA, ICANN and several universities and research networks.',
    },
    {
      q: 'How many root server instances are there?',
      a: 'About 2,000 worldwide. Each of the 13 identities, a.root-servers.net to m.root-servers.net, is announced from many locations with anycast, and your resolver reaches the nearest instance.',
    },
    {
      q: 'What happens if a root server goes down?',
      a: 'Nothing noticeable. Resolvers automatically use the other root servers, every identity has many anycast instances, and resolvers cache top-level domain referrals for up to two days.',
    },
    {
      q: 'Why does one root server fail in the test?',
      a: 'Occasional failures usually come from routing between the test location and the nearest instance. Run the test again and check the 24-hour availability column; persistent failures for one root are rare.',
    },
    {
      q: 'Why is the test run from Cloudflare and not from my computer?',
      a: 'Browsers cannot send raw DNS queries over TCP port 53, so the queries are sent from the Cloudflare data center that handled your request. To test from your own network, use dig, for example dig @a.root-servers.net . SOA +norecurse.',
    },
    {
      q: 'How often does the root zone change?',
      a: 'The root zone is usually published about twice a day. Each version has a new serial number in the format YYYYMMDDNN, which this test shows for every root server.',
    },
  ],
};

export default tool;
