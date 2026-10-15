import { socketHost } from '../core/net';
import { connect } from 'cloudflare:sockets';
import { checkTarget, isCloudflareAddress } from '../core/guard';
import { html, type SafeHtml } from '../core/html';
import { bar } from '../core/ui';
import { json } from '../core/http';
import { normalizeUrl } from '../core/http-probe';
import type { Tool, ToolContext } from '../core/tool';
import { TimeoutError, withTimeout } from '../core/transport';

const RUNS = 3;
const MAX_BODY = 2 * 1024 * 1024;

interface Run {
  tcpMs: number | null;
  tlsMs: number | null;
  ttfbMs: number | null;
  totalMs: number | null;
  bytes: number;
  status: string | null;
  error: string | null;
}

interface Report {
  url: string;
  host: string;
  https: boolean;
  dnsMs: number;
  addresses: string[];
  /** Behind Cloudflare: Workers cannot open sockets there, so runs use fetch() and TCP/TLS are not separable. */
  cloudflare: boolean;
  runs: Run[];
}

/** URL host names keep IPv6 literals in brackets; sockets need the plain address. */
const bare = (host: string) => host.replace(/^\[|\]$/g, '');

async function tcpTime(host: string, port: number): Promise<number> {
  const start = Date.now();
  const s = connect({ hostname: socketHost(host), port }, { secureTransport: 'off', allowHalfOpen: false });
  try {
    await withTimeout(s.opened, 5000);
    return Date.now() - start;
  } finally {
    s.close().catch(() => {});
  }
}

// One fresh connection: (TLS handshake), then a GET request read to the end or MAX_BODY.
async function httpRun(u: URL, tcpMs: number): Promise<Run> {
  const https = u.protocol === 'https:';
  const start = Date.now();
  const s = connect({ hostname: socketHost(bare(u.hostname)), port: Number(u.port) || (https ? 443 : 80) }, { secureTransport: https ? 'on' : 'off', allowHalfOpen: false });
  const run: Run = { tcpMs, tlsMs: null, ttfbMs: null, totalMs: null, bytes: 0, status: null, error: null };
  try {
    await withTimeout(s.opened, 8000);
    const opened = Date.now();
    // TCP time comes from a separate connection just before; cap it so TCP + TLS add up to this connection's setup time.
    run.tcpMs = Math.min(tcpMs, opened - start);
    if (https) run.tlsMs = opened - start - run.tcpMs;
    const w = s.writable.getWriter();
    const path = u.pathname + u.search;
    await w.write(new TextEncoder().encode(`GET ${path} HTTP/1.1\r\nHost: ${u.host}\r\nUser-Agent: nettools/1.0 (+https://net.rockykln.com)\r\nAccept: */*\r\nAccept-Encoding: gzip, br\r\nConnection: close\r\n\r\n`));
    const sent = Date.now();
    const r = s.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
    const read = async () => {
      for (;;) {
        const { value, done } = await r.read();
        if (done) break;
        if (run.ttfbMs === null) {
          run.ttfbMs = Date.now() - sent;
          run.status = new TextDecoder().decode(value.subarray(0, 64)).split('\r\n')[0] ?? null;
        }
        run.bytes += value.byteLength;
        if (run.bytes > MAX_BODY) break;
      }
    };
    await withTimeout(read(), 10000);
    run.totalMs = Date.now() - start;
  } catch (e) {
    run.error = e instanceof TimeoutError ? 'Timed out' : https ? 'Connection or TLS handshake failed' : 'Connection failed';
  } finally {
    s.close().catch(() => {});
  }
  return run;
}

// Fallback for sites on Cloudflare: time to response headers (connection included) and to the end of the body.
async function fetchRun(url: string): Promise<Run> {
  const run: Run = { tcpMs: null, tlsMs: null, ttfbMs: null, totalMs: null, bytes: 0, status: null, error: null };
  const start = Date.now();
  try {
    const res = await fetch(url, {
      redirect: 'manual',
      headers: { 'user-agent': 'nettools/1.0 (+https://net.rockykln.com)', accept: '*/*' },
      signal: AbortSignal.timeout(10000),
    });
    run.ttfbMs = Date.now() - start;
    run.status = `HTTP ${res.status} ${res.statusText}`.trim();
    const reader = res.body?.getReader();
    while (reader) {
      const { value, done } = await reader.read();
      if (done) break;
      run.bytes += value.byteLength;
      if (run.bytes > MAX_BODY) {
        await reader.cancel();
        break;
      }
    }
    run.totalMs = Date.now() - start;
  } catch (e) {
    run.error = e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError') ? 'Timed out' : 'Request failed';
  }
  return run;
}

async function measure(c: ToolContext, url: string): Promise<Report | { error: string }> {
  const u = new URL(url);
  const t0 = Date.now();
  const target = await checkTarget(u.hostname, c.env);
  const dnsMs = Date.now() - t0;
  if (!target.ok) return { error: target.reason };
  if (target.addresses.some(isCloudflareAddress)) {
    const runs: Run[] = [];
    for (let i = 0; i < RUNS; i++) runs.push(await fetchRun(url));
    return { url, host: bare(u.hostname), https: u.protocol === 'https:', dnsMs, addresses: target.addresses, cloudflare: true, runs };
  }
  const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
  const runs: Run[] = [];
  for (let i = 0; i < RUNS; i++) {
    let tcp: number;
    try {
      tcp = await tcpTime(bare(u.hostname), port);
    } catch {
      runs.push({ tcpMs: null, tlsMs: null, ttfbMs: null, totalMs: null, bytes: 0, status: null, error: 'TCP connection failed' });
      continue;
    }
    runs.push(await httpRun(u, tcp));
  }
  return { url, host: bare(u.hostname), https: u.protocol === 'https:', dnsMs, addresses: target.addresses, cloudflare: false, runs };
}

const median = (xs: (number | null)[]): number | null => {
  const v = xs.filter((x): x is number => x !== null).sort((a, b) => a - b);
  if (!v.length) return null;
  const mid = v.length >> 1;
  return v.length % 2 ? v[mid]! : Math.round((v[mid - 1]! + v[mid]!) / 2);
};

function waterfall(r: Report): SafeHtml {
  const tcp = median(r.runs.map((x) => x.tcpMs)), tls = median(r.runs.map((x) => x.tlsMs)), ttfb = median(r.runs.map((x) => x.ttfbMs)), total = median(r.runs.map((x) => x.totalMs));
  const download = total !== null && ttfb !== null ? Math.max(0, total - (tcp ?? 0) - (tls ?? 0) - ttfb) : null;
  const phases: [string, number | null, string][] = [
    ['DNS lookup', r.dnsMs, 'dns'],
    ...(r.cloudflare ? [] : [['TCP connect', tcp, 'tcp'], ...(r.https ? [['TLS handshake', tls, 'tls']] : [])] as [string, number | null, string][]),
    [r.cloudflare ? 'Connect + first byte' : 'Time to first byte', ttfb, 'ttfb'], ['Download', download, 'dl'],
  ];
  const sum = phases.reduce((a, [, v]) => a + (v ?? 0), 0) || 1;
  let offset = 0;
  return html`<div class="waterfall">${phases.map(([label, v, cls]) => {
    const left = (offset / sum) * 100, width = Math.max(((v ?? 0) / sum) * 100, 0.8);
    offset += v ?? 0;
    return html`<div class="wf-row"><span class="wf-label">${label}</span>${bar(width, cls, left)}<span class="wf-ms">${v === null ? '—' : `${v} ms`}</span></div>`;
  })}</div>`;
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/response-time">
<div class="field grow"><label for="url">Website</label>
<input id="url" name="url" type="text" value="${value}" placeholder="example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Measure</button></div>
</form>`;
}

const INVALID = 'Enter a website such as example.com or https://example.com/page.';

function colo(c: ToolContext): string {
  const cf = c.req.cf as IncomingRequestCfProperties | undefined;
  return typeof cf?.colo === 'string' ? cf.colo : 'unknown';
}

const tool: Tool = {
  slug: 'response-time',
  name: 'Response time',
  icon: 'ttfb',
  category: 'performance',
  title: 'Website Response Time Test – DNS, TLS & TTFB',
  description: 'Measure how fast a website responds: DNS lookup, TCP connect, TLS handshake, time to first byte and download time, averaged over three fresh connections.',
  h1: 'Website response time test',
  lead: 'Break down how long a website takes to answer: DNS, connection, TLS handshake and time to first byte.',
  heavy: () => true,
  examples: [['wikipedia.org', 'url=wikipedia.org'], ['github.com', 'url=github.com']],
  related: ['is-it-down', 'http-headers', 'tcp-ping'],
  isQuery: (url) => url.searchParams.has('url'),

  async render(c) {
    const value = (c.url.searchParams.get('url') ?? '').trim();
    if (!c.url.searchParams.has('url')) return form('');
    const url = normalizeUrl(value);
    if (!url) return html`${form(value)}<p class="error">${INVALID}</p>`;
    const r = await measure(c, url);
    if ('error' in r) return html`${form(value)}<p class="error">${r.error}</p>`;
    const ok = r.runs.filter((x) => !x.error);
    return html`${form(value)}
<p class="result-head">Median of ${RUNS} fresh connections to <code>${r.host}</code> from Cloudflare <strong>${colo(c)}</strong>${ok[0]?.status ? html` · <code>${ok[0].status}</code>` : ''}</p>
${r.cloudflare ? html`<p class="hint">${r.host} is served by Cloudflare, which cannot be reached with raw TCP connections from here. The runs use regular HTTPS requests, so connection setup and time to first byte are measured together; the first run includes the connection, later runs may reuse it.</p>` : ''}
${ok.length ? waterfall(r) : html`<p class="error">${r.runs[0]?.error ?? 'No response.'}</p>`}
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data num"><thead><tr><th>Run</th><th>TCP</th>${r.https ? html`<th>TLS</th>` : ''}<th>TTFB</th><th>Total</th><th>Received</th><th>Result</th></tr></thead>
<tbody>${r.runs.map((x, i) => html`<tr><td>${i + 1}</td><td>${x.tcpMs ?? '—'}${x.tcpMs !== null ? ' ms' : ''}</td>${r.https ? html`<td>${x.tlsMs ?? '—'}${x.tlsMs !== null ? ' ms' : ''}</td>` : ''}<td>${x.ttfbMs ?? '—'}${x.ttfbMs !== null ? ' ms' : ''}</td><td>${x.totalMs ?? '—'}${x.totalMs !== null ? ' ms' : ''}</td><td>${x.bytes ? `${(x.bytes / 1024).toFixed(1)} KB` : '—'}</td><td>${x.error ? html`<span class="status bad">${x.error}</span>` : html`<span class="status ok">OK</span>`}</td></tr>`)}</tbody></table></div>
<p class="hint">Measured from Cloudflare's network, not from your device. Redirects are not followed; check them with the <a href="/http-headers?url=${encodeURIComponent(url)}">HTTP header checker</a>.</p>`;
  },

  apiDoc: 'GET /api/response-time?url=wikipedia.org',

  async api(c) {
    const url = normalizeUrl(c.url.searchParams.get('url') ?? '');
    if (!url) return json({ error: INVALID }, { status: 400 });
    const r = await measure(c, url);
    if ('error' in r) return json(r, { status: 400 });
    return json({ ...r, from: colo(c) });
  },

  article: html`<h2>How the measurement works</h2>
<p>Enter a host name or a full URL, for example <code>wikipedia.org</code> or <code>https://your-domain.tld/login</code>.
The tool resolves the name once, then opens three fresh connections one after another. For each run it measures the TCP
connect, performs the TLS handshake for HTTPS URLs, sends a single HTTP/1.1 GET request and reads the response until
the server closes the connection or 2 MB have arrived. Nothing is reused between runs: no keep-alive, no TLS session
resumption, no cache on our side. The waterfall shows the median of the three runs, and the table below it lists every
run, so you can see whether the values are stable or one attempt was an outlier.</p>
<p>The measurement runs from the Cloudflare data center that handled your request, usually the one closest to you. Its
code is shown above the result. Redirects are not followed: if the URL answers with a 301 or 302, you see the timing of
that redirect response, not of the final page. Sites served by Cloudflare cannot be reached with raw
connections from here; for them the tool falls back to regular HTTPS requests and reports connection setup and time to
first byte as one value.</p>

<h2>What the phases mean</h2>
<table class="data"><thead><tr><th>Phase</th><th>What happens</th><th>Typical</th></tr></thead><tbody>
<tr><td>DNS lookup</td><td>The host name is resolved to an IP address.</td><td>1–50 ms when cached, up to a few hundred ms otherwise</td></tr>
<tr><td>TCP connect</td><td>The three-way handshake; roughly one round trip to the server.</td><td>1–20 ms nearby, 80–200 ms across continents</td></tr>
<tr><td>TLS handshake</td><td>Certificates and keys are exchanged; one round trip with TLS 1.3, two with TLS 1.2.</td><td>about one to two times the TCP time</td></tr>
<tr><td>Time to first byte</td><td>The request travels to the server, the server builds the response and the first byte comes back.</td><td>under 200 ms is good, over 600 ms is slow</td></tr>
<tr><td>Download</td><td>The rest of the response arrives.</td><td>depends on page size and compression</td></tr>
</tbody></table>
<p>Time to first byte here is counted from the moment the request is sent, so it contains one network round trip plus
the server's processing time. Subtract the TCP connect time from it to estimate how long the server itself worked on
the request. The request asks for gzip or Brotli compression, so the received size is usually the compressed size.</p>

<h2>How to read the result</h2>
<p>The phases point to different causes, so look at which one dominates.</p>
<ul>
<li><strong>TCP connect is high:</strong> the server is far away from the test location or the path is congested. The TLS
handshake then grows with it, because it needs the same round trips. A CDN or a server closer to your visitors helps;
faster code does not.</li>
<li><strong>TLS is much slower than TCP:</strong> the server may only offer TLS 1.2, send a long certificate chain, or be
short on CPU. Check the certificate setup with the <a href="/ssl-check">SSL certificate check</a>.</li>
<li><strong>TTFB is high, TCP and TLS are fast:</strong> the server itself is slow. Typical causes are application code,
slow database queries, calls to external APIs during the request, an exhausted worker pool (PHP-FPM, application server
threads) or a page cache that is missing or bypassed.</li>
<li><strong>Download is high:</strong> the response is large or uncompressed, or the server streams it slowly. Check the
<code>Content-Encoding</code> and <code>Content-Length</code> with the <a href="/http-headers">HTTP header checker</a>.</li>
<li><strong>Runs differ a lot:</strong> the first run warms up caches, a load balancer spreads the requests over
servers in different states, or the server is under load.</li>
</ul>
<p>To separate network from server, compare against the pure connection time with <a href="/tcp-ping">TCP ping</a>. If
the round trip is 20 ms and TTFB is 900 ms, the time is spent on the server.</p>

<h2>CDNs and caching</h2>
<p>Behind a CDN, the connection ends at the nearest edge server. TCP and TLS are then fast almost everywhere, and the
TTFB depends on whether the edge has the page in its cache. A cache hit typically comes back within a few milliseconds
of processing time; a miss adds the trip from the edge to your origin server and the origin's processing. Response
headers such as <code>Age</code>, <code>X-Cache</code> or <code>CF-Cache-Status</code> show which case you hit. Pages that set
cookies or send <code>Cache-Control: private</code> or <code>no-store</code> are usually not cached at the edge, so their TTFB
reflects the origin.</p>

<h2>HTTP/1.1, HTTP/2 and HTTP/3</h2>
<p>This test speaks HTTP/1.1 with one request per connection. Browsers mostly use HTTP/2 or HTTP/3 for HTTPS. For a single
request on a fresh connection the difference in TTFB is small: HTTP/2 mainly helps when many requests share one
connection. HTTP/3 runs over QUIC and combines the transport and TLS handshakes, which saves one round trip on a new
connection; that saving does not show up here.</p>

<h2>Measure it yourself with curl</h2>
<p>curl reports the same phases as cumulative times since the start of the request:</p>
<pre class="raw">$ curl -s -o /dev/null -w 'dns %{time_namelookup}  connect %{time_connect}  tls %{time_appconnect}  ttfb %{time_starttransfer}  total %{time_total}\\n' https://www.wikipedia.org/</pre>
<p>All values are in seconds and add up: <code>time_connect</code> includes the DNS time, <code>time_appconnect</code> marks
the end of the TLS handshake, and <code>time_starttransfer</code> is the first byte. To get the duration of a single phase,
subtract the previous value. Run the command a few times, because the first run often includes an uncached DNS lookup.
Add <code>--http1.1</code> to match this tool, or <code>--http2</code> to compare.</p>

<h2>Response time versus page load and Core Web Vitals</h2>
<p>This test measures how quickly the server answers one request. A browser does far more: it downloads styles,
scripts, fonts and images, runs JavaScript and renders the page. Core Web Vitals such as Largest Contentful Paint,
Interaction to Next Paint and Cumulative Layout Shift are measured in real browsers on real devices and networks, and
TTFB is only the first part of LCP. A fast server is a precondition for a fast page, but it does not guarantee one.
For the speed of your own connection, use the <a href="/speed-test">speed test</a>; to see whether a site is reachable
at all, use <a href="/is-it-down">is it down</a>.</p>`,

  faq: [
    { q: 'What is a good time to first byte?', a: 'Under 200 ms is good, 200–600 ms is acceptable, above 600 ms is slow. Google’s guidance for TTFB is 800 ms or less at the 75th percentile of real visits, measured in the browser and including redirects and connection setup.' },
    { q: 'Why is the first run slower?', a: 'The server may have to wake up a worker, compile code or fill its caches on the first request, and a CDN edge may not have the page cached yet. That is why the result uses the median of three runs.' },
    { q: 'Why does my browser feel slower than this result?', a: 'A browser also downloads images, styles and scripts and runs JavaScript. This test measures only the server’s response to the URL itself, from a Cloudflare data center rather than your own connection.' },
    { q: 'Why are my results different from another location?', a: 'TCP, TLS and part of the TTFB depend on the distance between the test location and the server. The test runs in the Cloudflare data center that handled your request, so a colleague in another country may see different values for the same site.' },
    { q: 'Why does the test show a redirect instead of my page?', a: 'Redirects are not followed, so the timing belongs to the 301 or 302 response. Enter the final URL, for example with https:// and the www prefix if the site uses it, to measure the actual page.' },
    { q: 'Can I measure a site that uses Cloudflare?', a: 'Yes, with less detail. The tool runs on Cloudflare Workers, which cannot open raw TCP connections to Cloudflare’s own network, so it uses regular HTTPS requests instead. You get the time to the first byte including connection setup and the download time, but no separate TCP and TLS values. For those, run curl with the -w timing options from your own machine.' },
  ],
};

export default tool;
