import { connect } from 'cloudflare:sockets';
import { checkTarget } from '../core/guard';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { isIP, normalizeDomain, socketHost } from '../core/net';
import type { Tool, ToolContext } from '../core/tool';
import { TimeoutError, withTimeout } from '../core/transport';

const COUNT = 8;
const TIMEOUT_MS = 2000;

interface Probe {
  seq: number;
  ms: number | null;
  error: string | null;
}

interface Stats {
  sent: number;
  received: number;
  loss: number;
  min: number | null;
  avg: number | null;
  max: number | null;
  jitter: number | null;
}

async function probe(host: string, port: number, seq: number): Promise<Probe> {
  const start = Date.now();
  const socket = connect({ hostname: socketHost(host), port }, { secureTransport: 'off', allowHalfOpen: false });
  try {
    await withTimeout(socket.opened, TIMEOUT_MS);
    return { seq, ms: Date.now() - start, error: null };
  } catch (e) {
    const msg = e instanceof Error ? e.message : '';
    const error = e instanceof TimeoutError ? 'timeout' : /cloudflare|prohibited|not allowed|blocked/i.test(msg) ? 'not testable' : /refused|reset|closed/i.test(msg) ? 'refused' : 'unreachable';
    return { seq, ms: null, error };
  } finally {
    socket.close().catch(() => {});
  }
}

export function stats(probes: Probe[]): Stats {
  const t = probes.map((p) => p.ms).filter((v): v is number => v !== null);
  const avg = t.length ? t.reduce((a, b) => a + b, 0) / t.length : null;
  let jitter: number | null = null;
  if (t.length > 1) {
    let sum = 0;
    for (let i = 1; i < t.length; i++) sum += Math.abs(t[i]! - t[i - 1]!);
    jitter = sum / (t.length - 1);
  }
  return {
    sent: probes.length,
    received: t.length,
    loss: probes.length ? Math.round(((probes.length - t.length) / probes.length) * 100) : 0,
    min: t.length ? Math.min(...t) : null,
    avg: avg === null ? null : Math.round(avg * 10) / 10,
    max: t.length ? Math.max(...t) : null,
    jitter: jitter === null ? null : Math.round(jitter * 10) / 10,
  };
}

type Parsed = { host: string; port: number } | { error: string };

export function parse(url: URL): Parsed {
  let raw = (url.searchParams.get('host') ?? '').trim();
  let portRaw = (url.searchParams.get('port') ?? '').trim();
  // Accept "host:port", "[v6]:port" and URLs; an explicit port field wins.
  const withPort = raw.replace(/^[a-z]+:\/\//i, '').split('/')[0]!.match(/^(\[[^\]]+\]|[^:]+):(\d+)$/);
  if (withPort) {
    raw = withPort[1]!;
    if (!portRaw) portRaw = withPort[2]!;
  } else if (/^https?:\/\//i.test(raw)) {
    if (!portRaw) portRaw = raw.toLowerCase().startsWith('http:') ? '80' : '443';
    raw = raw.replace(/^[a-z]+:\/\//i, '').split('/')[0]!;
  }
  portRaw ||= '443';
  const host = isIP(raw.replace(/^\[|\]$/g, '')) ? raw.replace(/^\[|\]$/g, '') : normalizeDomain(raw);
  // Digits only: Number() would also accept "1e3", "0x50" or "80.0".
  const port = /^\d{1,5}$/.test(portRaw) ? Number(portRaw) : NaN;
  if (!host) return { error: 'Enter a host name or IP address, such as example.com.' };
  if (!Number.isInteger(port) || port < 1 || port > 65535 || port === 25) return { error: 'Enter a TCP port between 1 and 65535 (port 25 cannot be tested).' };
  return { host, port };
}

async function run(c: ToolContext, p: { host: string; port: number }): Promise<{ probes: Probe[]; error: string | null }> {
  const target = await checkTarget(p.host, c.env, { sockets: true });
  if (!target.ok) return { probes: [], error: target.reason };
  const probes: Probe[] = [];
  // Sequential on purpose: parallel connections would measure each other.
  const addr = target.addresses[0]!;
  for (let i = 1; i <= COUNT; i++) probes.push(await probe(addr, p.port, i));
  return { probes, error: null };
}

function colo(c: ToolContext): string {
  const cf = c.req.cf as IncomingRequestCfProperties | undefined;
  return typeof cf?.colo === 'string' ? cf.colo : 'unknown';
}

function form(host: string, port: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/tcp-ping">
<div class="field grow"><label for="host">Host name or IP address</label>
<input id="host" name="host" type="text" value="${host}" placeholder="example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><label for="port">TCP port</label>
<input id="port" name="port" type="text" inputmode="numeric" value="${port}" placeholder="443" autocomplete="off"></div>
<div class="field"><button type="submit">Ping</button></div>
</form>`;
}

const ms = (v: number | null) => (v === null ? '—' : `${v} ms`);

const tool: Tool = {
  slug: 'tcp-ping',
  name: 'TCP ping',
  icon: 'ping',
  category: 'ip',
  title: 'Online Ping Test (TCP) – Latency, Jitter & Packet Loss',
  description:
    'Ping any server online over TCP: connection time, jitter and loss from the nearest Cloudflare data center. Works where ICMP ping is blocked by firewalls.',
  h1: 'TCP ping',
  lead: 'Measure how fast a server accepts TCP connections, with latency, jitter and loss over several attempts.',
  examples: [['wikipedia.org:443', 'host=wikipedia.org&port=443'], ['9.9.9.9:53', 'host=9.9.9.9&port=53']],
  related: ['port-checker', 'is-it-down', 'speed-test'],
  heavy: () => true,
  isQuery: (url) => url.searchParams.has('host'),

  async render(c) {
    const hostRaw = (c.url.searchParams.get('host') ?? '').trim();
    const portRaw = (c.url.searchParams.get('port') ?? '443').trim();
    if (!c.url.searchParams.has('host')) return form('', '');
    const p = parse(c.url);
    if ('error' in p) return html`${form(hostRaw, portRaw)}<p class="error">${p.error}</p>`;
    const r = await run(c, p);
    if (r.error) return html`${form(hostRaw, portRaw)}<p class="error">${r.error}</p>`;
    const s = stats(r.probes);
    return html`${form(hostRaw, portRaw)}
<p class="result-head">${COUNT} TCP connections to <code>${socketHost(p.host)}:${p.port}</code> from Cloudflare <strong>${colo(c)}</strong></p>
<div class="speed-grid">
<div class="metric"><span class="label">Average</span><span class="value">${s.avg ?? '—'}</span><span class="unit">ms</span></div>
<div class="metric"><span class="label">Min / max</span><span class="value">${s.min ?? '—'}/${s.max ?? '—'}</span><span class="unit">ms</span></div>
<div class="metric"><span class="label">Jitter</span><span class="value">${s.jitter ?? '—'}</span><span class="unit">ms</span></div>
<div class="metric"><span class="label">Loss</span><span class="value">${s.loss}</span><span class="unit">%</span></div>
</div>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>#</th><th>Result</th><th>Time</th></tr></thead>
<tbody>${r.probes.map((pr) => html`<tr><td>${pr.seq}</td><td>${pr.error ? html`<span class="status bad">${pr.error}</span>` : html`<span class="status ok">connected</span>`}</td><td>${ms(pr.ms)}</td></tr>`)}</tbody></table></div>`;
  },

  apiDoc: 'GET /api/tcp-ping?host=wikipedia.org&port=443 (host:port and URLs work too)',

  async api(c) {
    const p = parse(c.url);
    if ('error' in p) return json({ error: p.error }, { status: 400 });
    const r = await run(c, p);
    if (r.error) return json({ error: r.error }, { status: 400 });
    return json({ host: p.host, port: p.port, from: colo(c), stats: stats(r.probes), probes: r.probes });
  },

  article: html`<h2>What is a TCP ping?</h2>
<p>A TCP ping measures latency by timing how long it takes to open a TCP connection to a service. The client sends a
SYN packet, the server answers with SYN-ACK, and the time between the two is roughly one round trip. The connection
is closed right after the handshake, so no data is exchanged with the application.</p>
<p>This tool makes 8 connection attempts, one after another, from the Cloudflare data center that handled your
request. Each attempt waits up to 2 seconds. Attempts run sequentially on purpose: parallel connections would compete
with each other and distort the timing.</p>

<h2>Why TCP instead of ICMP?</h2>
<p>The classic <code>ping</code> command uses ICMP echo packets. Many servers, cloud providers and firewalls drop ICMP,
so a normal ping reports a host as unreachable even though its web server works fine. A TCP ping measures how long it
takes to open a connection to a real service port, such as 443 for HTTPS or 22 for SSH. That is closer to what users
experience and works wherever the service itself is reachable.</p>
<table class="data"><thead><tr><th></th><th>ICMP ping</th><th>TCP ping</th></tr></thead><tbody>
<tr><td>Tests</td><td>the host's network stack</td><td>a specific service port</td></tr>
<tr><td>Blocked by firewalls</td><td>often</td><td>only if the service is blocked too</td></tr>
<tr><td>Shows if the service accepts connections</td><td>no</td><td>yes</td></tr>
<tr><td>Needs special permissions</td><td>raw sockets (root on some systems)</td><td>no</td></tr>
<tr><td>Typical tools</td><td><code>ping</code>, <code>mtr</code></td><td>this tool, <code>nping</code>, <code>hping3</code>, <code>tcping</code></td></tr>
</tbody></table>
<p>If you need to know whether a port is open at all, or want to test several ports at once, use the
<a href="/port-checker">port checker</a>.</p>

<h2>How to use it</h2>
<ol>
<li>Enter a host name such as <code>example.com</code> or an IP address such as <code>9.9.9.9</code>. IPv6 addresses
work too. Addresses in Cloudflare's network (including 1.1.1.1) cannot be tested from here.</li>
<li>Enter the port of the service you care about. The default is 443, which almost every website answers on.</li>
<li>Run the test and read the summary: average, minimum, maximum, jitter and loss over the 8 attempts.</li>
</ol>
<p>Examples: <code>wikipedia.org</code> on port 443 tests a website, <code>9.9.9.9</code> on port 53 tests a DNS
resolver over TCP, and a game server is tested on its TCP port, for example 25565 for Minecraft Java.</p>

<h2>How to read the result</h2>
<ul>
<li><strong>Average, min and max</strong> show the time for the TCP handshake, roughly one round trip between the
Cloudflare data center and the server. The minimum is the best indicator of distance; the gap to the maximum shows
how much the path or the server adds on top.</li>
<li><strong>Jitter</strong> is the average difference between consecutive measurements. Values above a few
milliseconds point to a busy or unstable path, or a server under load.</li>
<li><strong>Loss</strong> counts attempts that timed out after 2 seconds or were refused.</li>
</ul>
<p>Light in fiber covers about 200 km per millisecond, so every 1,000 km of cable adds about 10 ms of round-trip time
at best. Real paths are longer than the straight line, which gives these rough expectations:</p>
<table class="data"><thead><tr><th>Distance between data center and server</th><th>Typical handshake time</th></tr></thead><tbody>
<tr><td>Same city</td><td>1–5 ms</td></tr>
<tr><td>Same country or region</td><td>5–30 ms</td></tr>
<tr><td>Across Europe or across the US</td><td>20–80 ms</td></tr>
<tr><td>Transatlantic</td><td>70–120 ms</td></tr>
<tr><td>Europe to Asia or Australia</td><td>150–300 ms</td></tr>
</tbody></table>
<p>The measurement runs from the Cloudflare data center that handled your request, not from your computer. Its code is
shown above the result. To measure your own connection, use the <a href="/speed-test">speed test</a>.</p>

<h2>When a TCP ping is useful</h2>
<ul>
<li><strong>Checking a server that blocks ICMP:</strong> cloud instances and corporate firewalls often ignore ping, but
still answer on 443 or 22.</li>
<li><strong>After a firewall or DNS change:</strong> confirm that the new rule or the new address accepts connections
from the internet, not just from inside the network.</li>
<li><strong>Comparing locations:</strong> test the same service on two hosts, for example two mirrors or two game
servers, and pick the one with the lower minimum time.</li>
<li><strong>Spotting an overloaded service:</strong> a host that answers ICMP quickly but takes hundreds of
milliseconds to accept TCP connections has a full connection queue or a busy load balancer.</li>
</ul>

<h2>Timeouts vs. refused connections</h2>
<p>The two failure types mean different things:</p>
<ul>
<li><strong>Refused:</strong> the server, or a firewall in front of it, answered with a TCP reset. The host is
reachable, but nothing accepts connections on that port.</li>
<li><strong>Timeout:</strong> no answer within 2 seconds. Packets are dropped by a firewall, lost on the way, or the host
is offline. A single timeout among 8 attempts usually means packet loss; 8 out of 8 means the port is blocked or the
host is down.</li>
</ul>

<h2>Troubleshooting checklist</h2>
<ul>
<li><strong>Every attempt fails:</strong> check that the host name resolves with a <a href="/dns-lookup">DNS
lookup</a>, then try port 443 or 80. If those work, the service port is closed or firewalled.</li>
<li><strong>Some attempts time out:</strong> run the test again a few minutes later. Loss that persists points to an
overloaded link, a rate limit on the server, or a SYN flood protection that drops some new connections.</li>
<li><strong>High minimum time:</strong> the server is far away from the data center, or traffic takes a detour.
Check the network that announces the address with the <a href="/asn-lookup">ASN lookup</a>.</li>
<li><strong>Low minimum, high maximum:</strong> the path or the server is congested. Compare the result at a quieter time.</li>
<li><strong>"Cannot be checked" error:</strong> private and reserved addresses, and addresses that belong to Cloudflare,
cannot be reached from the test location. Port 25 cannot be tested either.</li>
</ul>

<h2>TCP ping from the command line</h2>
<p>To measure from your own network instead, these commands do the same:</p>
<ul>
<li><code>nping --tcp-connect -p 443 -c 8 example.com</code> (part of Nmap, Windows, macOS and Linux)</li>
<li><code>hping3 -S -p 443 -c 8 example.com</code> (Linux, needs root)</li>
<li><code>Test-NetConnection example.com -Port 443</code> (Windows PowerShell, a single attempt that reports success and
the remote address)</li>
<li><code>curl -o /dev/null -s -w '%{time_connect}\\n' https://example.com</code> (prints the connect time in seconds)</li>
</ul>`,

  faq: [
    { q: 'Why is this not a real ping?', a: 'Cloudflare Workers cannot send ICMP packets. A TCP connection time is a reliable replacement and works even where ICMP is blocked.' },
    { q: 'Which port should I use?', a: 'Use the port of the service you care about: 443 for websites, 22 for SSH, 3389 for Remote Desktop, 25565 for a Minecraft server.' },
    { q: 'Why does every attempt fail?', a: 'Nothing is listening on that port, or a firewall drops the connection. Try port 443 or check the port with the port checker.' },
    { q: 'Where is the test run from?', a: 'From the Cloudflare data center that handled your request, usually the one closest to you. The result shows its code, so the times are measured between that data center and the server, not from your computer.' },
    { q: 'Is a TCP ping slower than an ICMP ping?', a: 'Usually only slightly. Both take one round trip; the TCP handshake adds the time the server or a load balancer in front of it needs to accept the connection.' },
    { q: 'Can I test UDP services this way?', a: 'No. UDP has no handshake, so there is nothing to time without a reply from the application. Test a TCP port of the same server instead, if it has one.' },
  ],
};

export default tool;
