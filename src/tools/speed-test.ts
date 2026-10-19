import { html } from '../core/html';
import { json, text } from '../core/http';
import type { Tool, ToolContext } from '../core/tool';

const MAX_DOWNLOAD = 50 * 1024 * 1024;
const CHUNK = 64 * 1024;

function download(c: ToolContext): Response {
  const requested = Number(c.url.searchParams.get('bytes') ?? 0);
  const total = Number.isFinite(requested) ? Math.min(Math.max(Math.floor(requested), 0), MAX_DOWNLOAD) : 0;
  // Random data defeats compression on the way; one chunk is reused to keep CPU time low.
  const chunk = new Uint8Array(CHUNK);
  crypto.getRandomValues(chunk);
  let sent = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= total) {
        controller.close();
        return;
      }
      const len = Math.min(CHUNK, total - sent);
      controller.enqueue(len === CHUNK ? chunk : chunk.subarray(0, len));
      sent += len;
    },
  });
  return new Response(body, {
    headers: {
      'content-type': 'application/octet-stream',
      'content-length': String(total),
      'cache-control': 'no-store',
      'content-encoding': 'identity',
    },
  });
}

const MAX_UPLOAD = 17 * 1024 * 1024;

async function upload(c: ToolContext): Promise<Response> {
  if (Number(c.req.headers.get('content-length') ?? 0) > MAX_UPLOAD) return json({ error: 'Too large' }, { status: 413 });
  let bytes = 0;
  if (c.req.body) {
    const reader = c.req.body.getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_UPLOAD) {
        await reader.cancel();
        return json({ error: 'Too large' }, { status: 413 });
      }
    }
  }
  return json({ bytes });
}

const tool: Tool = {
  slug: 'speed-test',
  name: 'Speed test',
  icon: 'speed',
  category: 'performance',
  title: 'Internet Speed Test – Download, Upload, Ping & Jitter',
  description:
    'Test your internet speed for free: download and upload in Mbit/s, ping and jitter. Runs against the nearest Cloudflare data center, without ads.',
  h1: 'Internet speed test',
  lead: 'Measure download, upload, ping and jitter of your connection.',
  personal: true,
  script: 'speed-test.js',
  related: ['what-is-my-ip', 'dns-lookup', 'root-dns-servers'],

  render(c) {
    const cf = c.req.cf as IncomingRequestCfProperties | undefined;
    return html`<div class="speed" id="speed" data-colo="${typeof cf?.colo === 'string' ? cf.colo : ''}">
<div class="speed-grid">
<div class="metric"><span class="label">Download</span><span class="value" data-metric="down">—</span><span class="unit">Mbit/s</span></div>
<div class="metric"><span class="label">Upload</span><span class="value" data-metric="up">—</span><span class="unit">Mbit/s</span></div>
<div class="metric"><span class="label">Ping</span><span class="value" data-metric="ping">—</span><span class="unit">ms</span></div>
<div class="metric"><span class="label">Jitter</span><span class="value" data-metric="jitter">—</span><span class="unit">ms</span></div>
</div>
<div class="progress" aria-hidden="true"><div class="progress-bar" data-progress></div></div>
<p class="speed-status" data-status aria-live="polite">Ready.</p>
<p class="hint speed-volume" data-volume hidden></p>
<div class="share-bar" data-speed-share hidden><span class="muted">Share this result:</span>
<code class="share-url" data-share-url></code>
<button type="button" class="btn-small" data-copy="">Copy link</button>
<button type="button" class="btn-small" data-share="" data-share-title="My internet speed" hidden>Share…</button></div>
<button type="button" data-start>Start test</button>
<p class="hint">Uses about 1 MB of data per Mbit/s of your line speed in each direction, up to about 2 GB on a fast line. On mobile data, consider Wi-Fi.</p>
<noscript><p class="error">The speed test needs JavaScript to measure your connection.</p></noscript>
<table class="kv compact"><tbody>
<tr><th scope="row">Your IP</th><td><code>${c.clientIp}</code></td></tr>
<tr><th scope="row">Provider</th><td>${typeof cf?.asOrganization === 'string' ? cf.asOrganization : '—'}</td></tr>
<tr><th scope="row">Test server</th><td>Cloudflare data center ${typeof cf?.colo === 'string' ? cf.colo : ''}</td></tr>
</tbody></table>
</div>`;
  },

  async api(c, sub) {
    // Browsers send Sec-Fetch-Site; refusing cross-site requests stops other sites from using visitors as load generators.
    const site = c.req.headers.get('sec-fetch-site');
    if (site && site !== 'same-origin') return json({ error: 'Forbidden' }, { status: 403 });
    if (sub === 'ping') return text('', { headers: { 'cache-control': 'no-store' } });
    if (sub === 'down' && c.req.method !== 'POST') return download(c);
    if (sub === 'up' && c.req.method === 'POST') return upload(c);
    if (sub === 'up' || sub === 'down') return json({ error: 'Method not allowed' }, { status: 405, headers: { allow: sub === 'up' ? 'POST' : 'GET, HEAD' } });
    return json({ error: 'Not found' }, { status: 404 });
  },

  article: html`<h2>How the speed test works</h2>
<p>The test runs in your browser against the nearest Cloudflare data center, the same network that serves a large
part of the web. It runs in three phases:</p>
<ol>
<li><strong>Latency:</strong> 21 small HTTP requests. The first one is discarded because it includes the connection
setup; ping is the median of the other 20, and jitter is the average difference between consecutive requests, leaving
out the largest 10 % so a single hiccup does not dominate.</li>
<li><strong>Download:</strong> four parallel connections fetch random data for about eight seconds.</li>
<li><strong>Upload:</strong> three parallel connections send random data for about eight seconds.</li>
</ol>
<p>The first second of each throughput phase is ignored so that TCP slow start, where a new connection begins slowly
and speeds up as it learns the path, does not lower the result. Random data is used because it cannot be compressed
on the way, so every byte counted actually crossed your line.</p>

<h2>What the numbers mean</h2>
<ul>
<li><strong>Download / upload</strong> in megabits per second (Mbit/s). Providers advertise speeds in Mbit/s, while
browsers and download managers usually show megabytes per second (MB/s). Divide by 8 to convert: 100 Mbit/s is about
12.5 MB/s.</li>
<li><strong>Ping</strong> is the median round-trip time of an HTTP request to the server. It includes a little browser
overhead, so it is often a few milliseconds higher than the <code>ping</code> command.</li>
<li><strong>Jitter</strong> is how much the ping varies. High jitter causes choppy calls and lag spikes even when the
speed is high.</li>
</ul>

<h2>What speed do you need?</h2>
<p>These are rough figures per active use. Add them up for a household where several people stream, call and
download at the same time.</p>
<table class="data"><thead><tr><th>Use</th><th>Download</th><th>Upload</th><th>Latency</th></tr></thead><tbody>
<tr><td>Web browsing, email</td><td>5 Mbit/s</td><td>1 Mbit/s</td><td>not critical</td></tr>
<tr><td>HD video streaming (1080p)</td><td>5–8 Mbit/s</td><td>not critical</td><td>not critical</td></tr>
<tr><td>4K video streaming</td><td>15–25 Mbit/s</td><td>not critical</td><td>not critical</td></tr>
<tr><td>Video call (HD, one person)</td><td>2–4 Mbit/s</td><td>2–4 Mbit/s</td><td>below 100 ms, low jitter</td></tr>
<tr><td>Online gaming</td><td>5 Mbit/s</td><td>1 Mbit/s</td><td>below 50 ms, jitter below 10 ms</td></tr>
<tr><td>Cloud backup, uploading video</td><td>not critical</td><td>20 Mbit/s or more</td><td>not critical</td></tr>
</tbody></table>
<p>Games and video calls need very little bandwidth. If they stutter on a fast line, look at ping, jitter and what
else is using the connection, not at the download figure.</p>

<h2>Reading your result</h2>
<table class="data"><thead><tr><th>Ping</th><th>Rating</th><th>Typical cause</th></tr></thead><tbody>
<tr><td>below 20 ms</td><td>excellent</td><td>fiber or cable, data center nearby</td></tr>
<tr><td>20–50 ms</td><td>good</td><td>DSL, Wi-Fi, or a data center further away</td></tr>
<tr><td>50–100 ms</td><td>usable, noticeable in games</td><td>mobile networks, busy Wi-Fi, long distance</td></tr>
<tr><td>above 100 ms</td><td>poor for real-time use</td><td>satellite, overloaded line, VPN to another continent</td></tr>
</tbody></table>
<p>Low-earth-orbit satellite services usually land between 25 and 60 ms; geostationary satellite links typically measure
600 ms or more because of the distance the signal travels.</p>

<h2>Getting a reliable result</h2>
<ol>
<li>Connect the computer to the router with a cable. Wi-Fi is the most common reason for results below the contract
speed; a cheap gigabit Ethernet cable rules it out.</li>
<li>Pause downloads, cloud sync, streaming and game updates on all devices in the household.</li>
<li>Disconnect from VPNs. A VPN sends your traffic through another server, so you measure that path, not your line.</li>
<li>Close other browser tabs and use a current browser. On slow laptops the browser itself can become the limit on
gigabit connections.</li>
<li>Run the test three times, and once again at a different time of day. Evening results that are much lower than
morning results point to congestion at your provider.</li>
</ol>

<h2>Troubleshooting slow speeds</h2>
<ul>
<li><strong>Fast on cable, slow on Wi-Fi:</strong> move closer to the router, use the 5 GHz or 6 GHz band, and check
whether neighbors use the same channel. Thick walls and floors cost a lot of throughput.</li>
<li><strong>Slow on cable as well:</strong> restart the router and modem, check the link speed of the network card
(a cable or port that negotiates 100 Mbit/s caps every test), and compare with the sync rate on the router's status
page.</li>
<li><strong>Download fine, upload very low:</strong> most cable and DSL lines are asymmetric, so check the upload figure
in your contract before suspecting a fault.</li>
<li><strong>High ping or jitter only while the line is busy:</strong> this is bufferbloat. Large buffers in the router
fill up during uploads and downloads and delay every other packet. Routers with smart queue management (SQM, for
example fq_codel or CAKE) fix this.</li>
<li><strong>Specific websites are slow, the test is fine:</strong> the problem is on the server side or on the path to
it. Check whether the site is reachable with <a href="/is-it-down">is it down</a>, or measure the latency to the
server with a <a href="/tcp-ping">TCP ping</a>.</li>
<li><strong>Pages take long to start loading:</strong> slow name resolution can feel like a slow line. Compare
resolvers with the <a href="/dns-lookup">DNS lookup</a>.</li>
</ul>

<h2>Why results differ between speed tests</h2>
<p>Each service measures against different servers, with a different number of connections and a different way of
averaging. A test hosted inside your provider's network often shows a higher number than one that crosses into
another network. This test measures to Cloudflare, which is close to what you get when loading the many websites
served through Cloudflare. The page also shows which data center handled the test and the provider and
<a href="/what-is-my-ip">IP address</a> your connection used.</p>

<h2>Data usage and privacy</h2>
<p>The test transfers about 1 MB per Mbit/s of line speed in each direction: about 200 MB on a 100 Mbit/s line and up
to about 2 GB on symmetric gigabit, because the faster the line, the more data fits into the eight seconds of each
phase. On a metered mobile plan, use Wi-Fi instead. The measurement happens in your browser and
nothing is stored on the server. If you share a result, the numbers are encoded in the link itself.</p>`,

  faq: [
    {
      q: 'Why is my result lower than my contract speed?',
      a: 'Wi-Fi, other devices using the connection, VPNs and congestion at peak times all reduce the result. Test over a cable to see the speed your line actually delivers. Contracts also often state a maximum speed, not a guaranteed one.',
    },
    {
      q: 'How much data does the test use?',
      a: 'About 1 MB per Mbit/s of line speed in each direction: roughly 50 MB at 25 Mbit/s, 200 MB at 100 Mbit/s and up to about 2 GB on a symmetric gigabit line, because each phase runs for eight seconds.',
    },
    {
      q: 'Is the result stored?',
      a: 'No. The measurement happens in your browser and nothing is saved on the server. A shared result link contains the numbers in the URL itself.',
    },
    {
      q: 'What is a good ping?',
      a: 'Below 20 ms is excellent, below 50 ms is fine for video calls and gaming. Above 100 ms you will notice delays in real-time applications.',
    },
    {
      q: 'What is the difference between Mbit/s and MB/s?',
      a: 'Mbit/s is megabits per second, MB/s is megabytes per second. One byte has 8 bits, so 100 Mbit/s equals about 12.5 MB/s.',
    },
    {
      q: 'Why is my upload so much slower than my download?',
      a: 'Most cable and DSL lines are asymmetric and give more capacity to downloads. Fiber is often symmetric. Check the upload speed listed in your contract.',
    },
  ],
};

export default tool;
