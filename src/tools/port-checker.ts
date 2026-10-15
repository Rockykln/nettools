import { connect } from 'cloudflare:sockets';
import { mapLimit } from '../core/async';
import { checkTarget } from '../core/guard';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { isIP, normalizeDomain, socketHost } from '../core/net';
import type { Tool, ToolContext } from '../core/tool';
import { TimeoutError, withTimeout } from '../core/transport';

// TCP ports grouped by topic. Each group is one click and stays within MAX_PORTS.
const PRESETS: { id: string; name: string; ports: [number, string][] }[] = [
  { id: 'web', name: 'Web', ports: [[80, 'HTTP'], [443, 'HTTPS'], [8080, 'HTTP alt'], [8443, 'HTTPS alt'], [8000, 'HTTP dev'], [3000, 'Node/Grafana']] },
  { id: 'remote', name: 'Remote access', ports: [[22, 'SSH'], [3389, 'RDP'], [5900, 'VNC'], [23, 'Telnet'], [5985, 'WinRM'], [5986, 'WinRM TLS']] },
  { id: 'email', name: 'Email', ports: [[25, 'SMTP'], [465, 'SMTPS'], [587, 'Submission'], [143, 'IMAP'], [993, 'IMAPS'], [110, 'POP3'], [995, 'POP3S']] },
  { id: 'files', name: 'Files', ports: [[21, 'FTP'], [990, 'FTPS'], [445, 'SMB'], [2049, 'NFS'], [873, 'rsync'], [548, 'AFP']] },
  { id: 'databases', name: 'Databases', ports: [[3306, 'MySQL'], [5432, 'PostgreSQL'], [1433, 'MS SQL'], [27017, 'MongoDB'], [6379, 'Redis'], [9200, 'Elasticsearch']] },
  { id: 'gaming', name: 'Game servers (TCP)', ports: [[25565, 'Minecraft Java'], [25575, 'Minecraft RCON'], [27015, 'Source RCON'], [30120, 'FiveM'], [7777, 'Terraria'], [10011, 'TeamSpeak query'], [64738, 'Mumble']] },
  { id: 'selfhosting', name: 'Self-hosting', ports: [[8123, 'Home Assistant'], [32400, 'Plex'], [8096, 'Jellyfin'], [9443, 'Portainer'], [8920, 'Jellyfin TLS'], [1883, 'MQTT'], [8883, 'MQTT TLS']] },
  { id: 'vpn', name: 'VPN & proxy', ports: [[1194, 'OpenVPN (TCP)'], [1723, 'PPTP'], [8388, 'Shadowsocks'], [1080, 'SOCKS'], [3128, 'Squid']] },
];

const SERVICE = new Map(PRESETS.flatMap((p) => p.ports));

// Your own IP and preset groups allow 10 ports; free-form lists on other hosts 5 (limits use as a scanner).
const MAX_PORTS_OWN = 10;
const MAX_PORTS_OTHER = 5;

type State = 'open' | 'closed' | 'filtered' | 'not testable' | 'error';

interface PortResult {
  port: number;
  state: State;
  ms: number | null;
  detail: string | null;
}

interface Check {
  host: string;
  own: boolean;
  ports: number[];
}

/** Parses "22, 80 443" and small ranges such as "20-25". Returns the ports or the first invalid token. */
export function parsePorts(raw: string, max: number): number[] | { bad: string } | { tooMany: true } {
  const out = new Set<number>();
  for (const tok of raw.split(/[\s,;]+/).filter(Boolean)) {
    const m = tok.match(/^(\d{1,5})(?:[-–](\d{1,5}))?$/);
    const lo = m ? Number(m[1]) : NaN;
    const hi = m?.[2] !== undefined ? Number(m[2]) : lo;
    if (!m || lo < 1 || hi > 65535 || hi < lo) return { bad: tok };
    // Checked before expanding so "1-65535" does not build a huge list.
    if (hi - lo + 1 > max) return { tooMany: true };
    for (let p = lo; p <= hi; p++) out.add(p);
    if (out.size > max) return { tooMany: true };
  }
  return [...out];
}

function parse(c: ToolContext): Check | { error: string } {
  // Brackets are common around IPv6 literals ("[2001:db8::1]").
  const hostRaw = (c.url.searchParams.get('host') ?? '').trim().replace(/^\[(.+)\]$/, '$1');
  const own = hostRaw === '';
  const host = own ? c.clientIp : isIP(hostRaw) ? hostRaw : normalizeDomain(hostRaw);
  if (!host) return { error: 'Enter an IP address or host name, or leave the field empty to check your own IP.' };
  const preset = PRESETS.find((p) => p.id === c.url.searchParams.get('preset'));
  // Groups of well-known ports are always allowed; free-form lists on other hosts are kept short.
  const max = own || preset ? MAX_PORTS_OWN : MAX_PORTS_OTHER;
  const parsed = preset ? preset.ports.map(([p]) => p) : parsePorts(c.url.searchParams.get('ports') ?? '', max);
  if ('bad' in parsed) return { error: `"${parsed.bad}" is not a TCP port. Use numbers between 1 and 65535 or ranges like 20-25, separated by commas.` };
  if ('tooMany' in parsed) return { error: own ? `Check at most ${max} ports at once.` : `Check at most ${max} ports at once on other hosts, or pick a group below.` };
  if (!parsed.length) return { error: 'Enter one or more TCP ports, separated by commas, or pick a group below.' };
  return { host, own, ports: parsed };
}

async function probe(host: string, port: number): Promise<PortResult> {
  // Workers do not allow outbound connections to port 25.
  if (port === 25) return { port, state: 'not testable', ms: null, detail: 'Port 25 cannot be tested from Cloudflare.' };
  const start = Date.now();
  const socket = connect({ hostname: socketHost(host), port }, { secureTransport: 'off', allowHalfOpen: false });
  try {
    await withTimeout(socket.opened, 5000);
    return { port, state: 'open', ms: Date.now() - start, detail: null };
  } catch (e) {
    if (e instanceof TimeoutError) return { port, state: 'filtered', ms: null, detail: 'No answer within 5 seconds (dropped by a firewall or host offline).' };
    const msg = e instanceof Error ? e.message : String(e);
    if (/cloudflare|prohibited|not allowed|blocked/i.test(msg)) return { port, state: 'not testable', ms: null, detail: 'Connections to Cloudflare addresses cannot be tested from Cloudflare Workers.' };
    if (/refused|reset|closed/i.test(msg)) return { port, state: 'closed', ms: Date.now() - start, detail: 'Connection refused or reset.' };
    return { port, state: 'error', ms: null, detail: 'Could not connect (host unreachable or not resolvable).' };
  } finally {
    socket.close().catch(() => {});
  }
}

const badge = (s: State) =>
  html`<span class="status ${s === 'open' ? 'ok' : s === 'not testable' || s === 'error' ? 'info' : s === 'filtered' ? 'warn' : 'bad'}">${s}</span>`;

function form(host: string, ports: string): SafeHtml {
  return html`<form class="tool-form" id="port-form" method="get" action="/port-checker">
<div class="field grow"><label for="host">IP address or host name</label>
<input id="host" name="host" type="text" value="${host}" placeholder="Empty = your own IP" autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><label for="ports">Ports</label>
<input id="ports" name="ports" type="text" value="${ports}" placeholder="22, 80, 443" required autocomplete="off" inputmode="numeric"></div>
<div class="field"><button type="submit">Check</button></div>
</form>
<p class="hint">Only check your own systems or hosts you are authorized to test.</p>
<div class="presets"><span class="muted">Or check a group:</span>
${PRESETS.map((g) => html`<button type="submit" form="port-form" class="chip" name="preset" value="${g.id}" formnovalidate title="${g.ports.map(([p, n]) => `${p} ${n}`).join(', ')}">${g.name}</button>`)}</div>`;
}

const tool: Tool = {
  slug: 'port-checker',
  name: 'Port checker',
  icon: 'port',
  category: 'ip',
  title: 'Open Port Checker – Test If a TCP Port Is Reachable',
  description:
    'Check whether TCP ports on your IP or any server are open, closed or filtered, tested from the internet. For port forwarding, firewalls and game servers.',
  h1: 'Open port checker',
  lead: 'Test from the internet whether TCP ports on your connection or a server are reachable.',
  related: ['what-is-my-ip', 'subnet-calculator', 'is-it-down'],
  heavy: (url) => (url.searchParams.get('host') ?? '').trim() !== '',
  isQuery: (url) => url.searchParams.has('ports') || url.searchParams.has('preset'),

  async render(c) {
    const hostRaw = (c.url.searchParams.get('host') ?? '').trim();
    const presetPorts = PRESETS.find((p) => p.id === c.url.searchParams.get('preset'))?.ports.map(([p]) => p).join(', ');
    const portsRaw = presetPorts ?? (c.url.searchParams.get('ports') ?? '').trim();
    if (!c.url.searchParams.has('ports') && !c.url.searchParams.has('preset')) return form('', '');
    const check = parse(c);
    if ('error' in check) return html`${form(hostRaw, portsRaw)}<p class="error">${check.error}</p>`;
    const target = check.own ? null : await checkTarget(check.host, c.env, { sockets: true });
    if (target && !target.ok) return html`${form(hostRaw, portsRaw)}<p class="error">${target.reason}</p>`;
    const addr = target ? target.addresses[0]! : check.host;
    const results = await mapLimit(check.ports, 5, (p) => probe(addr, p));
    return html`${form(hostRaw, portsRaw)}
<p class="result-head">Results for ${check.own ? html`your IP <code>${check.host}</code>` : html`<code>${check.host}</code>`}, tested from Cloudflare</p>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>Port</th><th>Service</th><th>State</th><th>Time</th><th>Details</th></tr></thead>
<tbody>${results.map((r) => html`<tr><td>${r.port}</td><td>${SERVICE.get(r.port) ?? '—'}</td><td>${badge(r.state)}</td><td>${r.ms !== null ? `${r.ms} ms` : '—'}</td><td class="wrap-any">${r.detail ?? ''}</td></tr>`)}</tbody></table></div>`;
  },

  apiDoc: `GET /api/port-checker?host=wikipedia.org&ports=80,443 (without host, your own IP is checked); GET /api/port-checker?host=wikipedia.org&preset=web (groups: ${PRESETS.map((p) => p.id).join(', ')})`,

  async api(c) {
    const check = parse(c);
    if ('error' in check) return json({ error: check.error }, { status: 400 });
    const target = check.own ? null : await checkTarget(check.host, c.env, { sockets: true });
    if (target && !target.ok) return json({ error: target.reason }, { status: 400 });
    const addr = target ? target.addresses[0]! : check.host;
    const results = await mapLimit(check.ports, 5, (p) => probe(addr, p));
    return json({ host: check.host, results });
  },

  article: html`<h2>What an open port checker does</h2>
<p>A port is a number between 1 and 65535 that identifies a service on a host: a web server usually listens on 443,
an SSH server on 22, a Minecraft server on 25565. This tool tries to open a TCP connection to each port you enter,
from a Cloudflare data center on the public internet. The result shows what a visitor from outside your network would
see, which is something you cannot test reliably from inside it: many routers do not loop connections to their own
public address back into the network (hairpin NAT), so a test from your own PC can fail even when everything works.</p>

<h2>Open, closed or filtered?</h2>
<ul>
<li><strong>Open:</strong> a program accepted the TCP connection. The port is reachable from the internet.</li>
<li><strong>Closed:</strong> the host answered but refused the connection with a TCP reset. Nothing is listening on the
port, or a firewall is actively rejecting the connection. Some routers send this reset themselves when no forwarding
rule exists.</li>
<li><strong>Filtered:</strong> no answer within 5 seconds. A firewall drops the packets, the router does not forward the
port, or the host is offline.</li>
<li><strong>Not testable:</strong> the port or address cannot be reached from Cloudflare's network (see Limits below).</li>
</ul>
<p>Closed is often good news while you troubleshoot: the packets reach the host, so the problem is the program, not
the path. Filtered means something along the way swallows the connection.</p>

<h2>How to check a port</h2>
<ol>
<li>Leave the host field empty to test your own public IP address, or enter a server's IP address or host name such as
<code>example.com</code>.</li>
<li>Enter up to 10 ports for your own IP, or up to 5 for other hosts, separated by commas: <code>22, 80, 443</code>.
Alternatively, click one of the groups to test the usual ports for a topic in one go.</li>
<li>Start the program you want to reach before you test. A port is only open while something listens on it.</li>
<li>Read the state per port and compare the time column: an open port answering in 15 ms is near the test location,
150 ms points to a server on another continent.</li>
</ol>
<p>The address this tool tests for your own connection is the one shown on <a href="/what-is-my-ip">what is my IP</a>.
If that is an IPv6 address, the test checks IPv6, and IPv4 port forwarding plays no part in the result.</p>

<h2>Port forwarding not working?</h2>
<p>Work through the chain from the program outward:</p>
<ol>
<li><strong>Is the program listening?</strong> On the machine itself, run <code>ss -tlnp</code> (Linux),
<code>netstat -ano | findstr LISTENING</code> (Windows) or <code>lsof -nP -iTCP -sTCP:LISTEN</code> (macOS). If the
port is bound to <code>127.0.0.1</code> only, the program accepts local connections and nothing else; configure it to
listen on <code>0.0.0.0</code> or the LAN address.</li>
<li><strong>Does the local firewall allow it?</strong> Windows Defender Firewall, <code>ufw</code> or
<code>firewalld</code> block incoming connections by default. Add a rule for the port and the TCP protocol.</li>
<li><strong>Does the router forward to the right device?</strong> The forwarding rule must point to the current LAN
address of the machine. Give it a DHCP reservation so the address does not change after a reboot.</li>
<li><strong>Does the router have a public IPv4 address?</strong> Compare the WAN address on the router's status page with
your public IP. If the router shows an address in <code>100.64.0.0/10</code> or a private range, your provider uses
carrier-grade NAT (CGNAT) or DS-Lite.</li>
<li><strong>Is the provider blocking the port?</strong> Some residential providers block incoming connections on ports
such as 80, 445 or 25. Try a high port like 8443 to compare.</li>
</ol>
<p>With CGNAT or DS-Lite you share a public IPv4 address with other customers and cannot receive incoming IPv4
connections at all. Ask your provider for a public IPv4 address, use IPv6, or use a tunnel or relay service. For IPv6
there is no port forwarding: every device has its own public address, and you open the port in the router's IPv6
firewall instead.</p>

<h2>Common ports by topic</h2>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>Topic</th><th>Ports</th></tr></thead>
<tbody>${PRESETS.map((g) => html`<tr><td>${g.name}</td><td class="wrap-any">${g.ports.map(([p, n], i) => html`${i ? ', ' : ''}<code>${p}</code> ${n}`)}</td></tr>`)}</tbody></table></div>

<h2>Ports that should not be open</h2>
<p>An open port is not a problem in itself, but some services attract constant automated attacks and should not face the
internet directly. If the checker shows any of these as open on your connection, put them behind a VPN or restrict
them to known addresses:</p>
<table class="data"><thead><tr><th>Port</th><th>Service</th><th>Risk</th></tr></thead><tbody>
<tr><td><code>23</code></td><td>Telnet</td><td>unencrypted logins, common target of IoT malware</td></tr>
<tr><td><code>445</code></td><td>SMB file sharing</td><td>used by worms such as WannaCry</td></tr>
<tr><td><code>3389</code></td><td>Remote Desktop</td><td>password guessing around the clock</td></tr>
<tr><td><code>5900</code></td><td>VNC</td><td>often configured with weak or no passwords</td></tr>
<tr><td><code>3306</code>, <code>5432</code>, <code>27017</code>, <code>6379</code></td><td>databases</td><td>data theft and ransom if exposed without authentication</td></tr>
</tbody></table>

<h2>Limits</h2>
<ul>
<li>The test uses TCP from Cloudflare's network. UDP ports (WireGuard, Valheim, most game and voice traffic) cannot be
tested this way, because UDP has no handshake that would confirm an open port.</li>
<li>Outbound connections to port 25 and to Cloudflare's own addresses are not possible from Cloudflare Workers, so
those show as not testable. Sites behind Cloudflare's proxy fall into this group.</li>
<li>Private, local and reserved addresses such as <code>192.168.1.10</code> are refused: they are not reachable from
the internet anyway.</li>
<li>Other hosts can be tested with up to 5 custom ports or one preset group per check. This keeps the tool useful for
diagnostics without turning it into a port scanner.</li>
<li>Rate limits or intrusion prevention on the target can make an open port look filtered after repeated tests.</li>
</ul>
<p>To measure how fast and how consistently a single port answers, use the <a href="/tcp-ping">TCP ping</a>. To check
whether a whole website is reachable over HTTP, use <a href="/is-it-down">is it down</a>, and to see which addresses a
host name points to, run a <a href="/dns-lookup">DNS lookup</a>.</p>`,

  faq: [
    { q: 'Is it legal to check ports?', a: 'Checking your own connection or servers you administer is fine. Only test systems you are allowed to test.' },
    { q: 'Why is my port filtered even though it is forwarded?', a: 'Often the program is not running, the local firewall blocks it, or your provider uses CGNAT so incoming IPv4 connections never reach your router.' },
    { q: 'Can I check UDP ports?', a: 'No. UDP has no connection handshake, so an open UDP port cannot be detected reliably from outside without a reply from the application.' },
    { q: 'What is the difference between closed and filtered?', a: 'Closed means the host answered and refused the connection, so the path works but nothing listens on the port. Filtered means no answer arrived within 5 seconds, usually because a firewall drops the packets.' },
    { q: 'Why can I not test port 25?', a: 'Cloudflare Workers do not allow outbound connections to port 25, which is used for server-to-server email. Ports 465 and 587 can be tested.' },
    { q: 'How do I know if my provider uses CGNAT?', a: 'Compare the WAN address on your router with the public IP shown on this site. If they differ, or the router shows an address in 100.64.0.0/10, your connection is behind carrier-grade NAT.' },
  ],
};

export default tool;
