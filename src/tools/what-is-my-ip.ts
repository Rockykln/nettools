import { html, secret, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { isIPv4, reverseName } from '../core/net';
import type { Tool, ToolContext } from '../core/tool';
import { RESOLVERS, resolve } from '../core/transport';
import { RR_TYPES } from '../core/dns';

export interface IpInfo {
  ip: string;
  version: 4 | 6;
  hostname: string | null;
  asn: number | null;
  isp: string | null;
  city: string | null;
  region: string | null;
  country: string | null;
  countryCode: string | null;
  timezone: string | null;
  colo: string | null;
  httpProtocol: string | null;
  tlsVersion: string | null;
  tlsCipher: string | null;
  tcpRttMs: number | null;
  userAgent: string | null;
}

export function countryName(code: string | null): string | null {
  if (!code || code === 'XX' || code === 'T1') return null;
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' }).of(code) ?? code;
  } catch {
    return code;
  }
}

// Not cached on purpose: the cache key would store the visitor's IP address.
export async function ptr(ip: string): Promise<string | null> {
  const name = reverseName(ip);
  if (!name) return null;
  try {
    const { message } = await resolve(RESOLVERS[0]!, name, RR_TYPES.PTR, 1500);
    const rec = message.answers.find((r) => r.type === RR_TYPES.PTR);
    return rec ? rec.data.replace(/\.$/, '') : null;
  } catch {
    return null;
  }
}

/** `ptr: false` skips the reverse DNS lookup where the host name is not shown (home page). */
export async function ipInfo(c: ToolContext, opts: { ptr?: boolean } = {}): Promise<IpInfo> {
  const cf = c.req.cf as IncomingRequestCfProperties | undefined;
  const str = (v: unknown) => (typeof v === 'string' && v ? v : null);
  return {
    ip: c.clientIp,
    version: isIPv4(c.clientIp) ? 4 : 6,
    hostname: opts.ptr === false ? null : await ptr(c.clientIp),
    asn: typeof cf?.asn === 'number' ? cf.asn : null,
    isp: str(cf?.asOrganization),
    city: str(cf?.city),
    region: str(cf?.region),
    country: countryName(str(cf?.country)),
    countryCode: str(cf?.country),
    timezone: str(cf?.timezone),
    colo: str(cf?.colo),
    httpProtocol: str(cf?.httpProtocol),
    tlsVersion: str(cf?.tlsVersion),
    tlsCipher: str(cf?.tlsCipher),
    tcpRttMs: typeof cf?.clientTcpRtt === 'number' && cf.clientTcpRtt > 0 ? cf.clientTcpRtt : null,
    userAgent: c.req.headers.get('user-agent'),
  };
}

const dash = (v: unknown) => (v === null || v === undefined || v === '' ? '—' : String(v));

/** `hidden` masks the address until hovered (used on the home page, which is often open on streams). */
export function ipHero(info: IpInfo, hidden = false): SafeHtml {
  return html`<div class="ip-hero">
<span class="label">Your public IP address${hidden ? html` <span class="secret-hint">hover, focus or tap to reveal</span>` : ''}</span>
<div class="ip-line">${hidden ? secret(info.ip, { code: true, cls: 'ip', strong: true }) : html`<code class="ip">${info.ip}</code>`}<span class="badge">IPv${info.version}</span>
<button type="button" class="btn-small" data-copy="${info.ip}">Copy</button></div>
</div>`;
}

const tool: Tool = {
  slug: 'what-is-my-ip',
  name: 'What is my IP',
  icon: 'ip',
  category: 'ip',
  title: 'What Is My IP Address? IPv4/IPv6, ISP & Location',
  description:
    'See your public IP address instantly, plus reverse DNS, ISP and ASN, approximate location and connection details. No ads, no cookies.',
  h1: 'What is my IP address?',
  lead: 'Your public IP address as the internet sees it, with ISP, reverse DNS and connection details.',
  personal: true,
  related: ['whois', 'dns-lookup', 'speed-test'],

  async render(c) {
    const info = await ipInfo(c);
    const location = [info.city, info.region, info.country].filter(Boolean).join(', ');
    return html`${ipHero(info)}
<table class="kv">
<tbody>
<tr><th scope="row">Reverse DNS</th><td><code>${dash(info.hostname)}</code></td></tr>
<tr><th scope="row">ISP / organization</th><td>${dash(info.isp)}</td></tr>
<tr><th scope="row">ASN</th><td>${info.asn ? html`<a href="/asn-lookup?q=AS${info.asn}" rel="nofollow">AS${info.asn}</a>` : '—'}</td></tr>
<tr><th scope="row">Approximate location</th><td>${dash(location)}</td></tr>
<tr><th scope="row">Time zone</th><td>${dash(info.timezone)}</td></tr>
<tr><th scope="row">HTTP protocol</th><td>${dash(info.httpProtocol)}</td></tr>
<tr><th scope="row">TLS</th><td>${dash([info.tlsVersion, info.tlsCipher].filter(Boolean).join(' · '))}</td></tr>
<tr><th scope="row">TCP round-trip time</th><td>${info.tcpRttMs ? `${info.tcpRttMs} ms` : '—'}</td></tr>
<tr><th scope="row">Served by data center</th><td>${dash(info.colo)}</td></tr>
<tr><th scope="row">Next steps</th><td><a href="/port-checker?preset=web" rel="nofollow">Check open ports on this IP</a> · <a href="/ip-lookup?q=${encodeURIComponent(info.ip)}" rel="nofollow">owner and blocklists</a> · <a href="/speed-test">speed test</a></td></tr>
<tr><th scope="row">User agent</th><td class="wrap-any"><code>${dash(info.userAgent)}</code></td></tr>
</tbody>
</table>`;
  },

  apiDoc: 'GET /api/what-is-my-ip (JSON); GET /ip (plain text)',

  async api(c) {
    return json(await ipInfo(c));
  },

  article: html`<h2>What is a public IP address?</h2>
<p>Every device that talks to the internet does so through a public IP address. At home this address usually
belongs to your router, and all devices on your network share it. Websites, game servers and mail servers see this
address, not the private address (such as <code>192.168.1.20</code>) your device has inside your network.</p>
<p>The router translates between the two with network address translation (NAT): outgoing connections leave with the
public address, and replies are mapped back to the device that started the connection. That is why two laptops in
the same household show the same result on this page.</p>

<h2>Public vs. private IP address</h2>
<p>Private addresses are reserved for local networks and are never routed on the internet. You can reuse them in
every home and office, which is why so many routers hand out <code>192.168.0.x</code> or <code>192.168.1.x</code>.
If the address you see in your network settings falls into one of the ranges below, it is not the address the rest
of the internet sees.</p>
<table class="data"><thead><tr><th>Range</th><th>Purpose</th></tr></thead><tbody>
<tr><td><code>10.0.0.0/8</code></td><td>Private (RFC 1918), common in companies</td></tr>
<tr><td><code>172.16.0.0/12</code></td><td>Private (RFC 1918), <code>172.16.0.0</code> to <code>172.31.255.255</code></td></tr>
<tr><td><code>192.168.0.0/16</code></td><td>Private (RFC 1918), typical home routers</td></tr>
<tr><td><code>100.64.0.0/10</code></td><td>Carrier-grade NAT between provider and customer (RFC 6598)</td></tr>
<tr><td><code>169.254.0.0/16</code></td><td>Link-local, assigned when no DHCP server answered</td></tr>
<tr><td><code>fc00::/7</code></td><td>IPv6 unique local addresses</td></tr>
<tr><td><code>fe80::/10</code></td><td>IPv6 link-local, present on every interface</td></tr>
</tbody></table>
<p>To see how large a range is or which addresses it contains, enter it in the
<a href="/subnet-calculator">subnet calculator</a>.</p>

<h2>IPv4 or IPv6?</h2>
<p>IPv4 addresses look like <code>203.0.113.7</code>. There are only about 4.3 billion of them, so many providers
share one address between several customers with carrier-grade NAT (CGNAT). IPv6 addresses look like
<code>2001:db8::1</code> and are plentiful enough for every device to have its own. If your connection supports
both, browsers normally prefer IPv6, so this page shows the IPv6 address. That does not mean you have no IPv4
address; it only means this connection used IPv6.</p>
<p>A typical home IPv6 setup gives the router a prefix, often a <code>/56</code> or <code>/64</code>, and each device
picks its own address from it. Many systems use temporary privacy addresses (RFC 8981) for outgoing connections, so
the last part of the IPv6 address shown here can change several times a day while the prefix stays the same.</p>

<h2>What the other fields mean</h2>
<table class="data"><thead><tr><th>Field</th><th>What it tells you</th></tr></thead><tbody>
<tr><td>Reverse DNS</td><td>The host name in the PTR record of your address, set by your provider. Look up other addresses with the <a href="/reverse-dns-lookup">reverse DNS lookup</a>.</td></tr>
<tr><td>ISP / organization</td><td>The network that announces your address on the internet, usually your provider, a mobile carrier, a VPN or a hosting company.</td></tr>
<tr><td>ASN</td><td>The autonomous system number of that network. The <a href="/asn-lookup">ASN lookup</a> lists its prefixes and owner.</td></tr>
<tr><td>Approximate location</td><td>City and region from a geolocation database (see below).</td></tr>
<tr><td>HTTP protocol, TLS</td><td>How your browser connected: HTTP/2 or HTTP/3, and the TLS version and cipher.</td></tr>
<tr><td>TCP round-trip time</td><td>Latency between your device and the Cloudflare data center that served the page.</td></tr>
<tr><td>Served by data center</td><td>The three-letter airport code of that data center, for example <code>FRA</code> or <code>ORD</code>.</td></tr>
</tbody></table>

<h2>How accurate is the location?</h2>
<p>The location comes from IP geolocation databases, not from your device. It usually points to your provider's
network hub and can be off by tens or hundreds of kilometers. Mobile connections are often placed in a different
city altogether, because carriers route traffic through a few central gateways. Nobody can find your street address
from your IP alone; only your provider can link the address to a customer, and in most countries it releases that
information only to authorities with a legal order.</p>

<h2>Finding your IP address on your device</h2>
<p>Your computer only knows its private address unless it is connected directly to the internet. These commands show
the local address:</p>
<ul>
<li><strong>Windows:</strong> run <code>ipconfig</code> in Command Prompt and look for "IPv4 Address".</li>
<li><strong>macOS:</strong> run <code>ipconfig getifaddr en0</code> in Terminal (<code>en0</code> is usually Wi-Fi or the built-in Ethernet port).</li>
<li><strong>Linux:</strong> run <code>ip -brief address</code>.</li>
</ul>
<p>To get the public address from a terminal, ask a DNS service that echoes it back:
<code>dig +short TXT CH whoami.cloudflare @1.1.1.1</code>. This site also returns the address as plain text at
<code>/ip</code> and as JSON at <code>/api/what-is-my-ip</code>, which is handy in scripts, for example
<code>curl -4</code> or <code>curl -6</code> against <code>/ip</code> to check each protocol separately.</p>

<h2>Common reasons to check your IP</h2>
<ul>
<li><strong>Remote access and port forwarding:</strong> you need the public address to reach a home server, camera or
game server. Test whether it is reachable from outside with the <a href="/port-checker">port checker</a>.</li>
<li><strong>Allowlists:</strong> firewalls, databases and admin panels often accept connections only from known
addresses. Check the address before you add it, and remember that a dynamic address will change.</li>
<li><strong>VPN check:</strong> with the VPN connected, this page should show the VPN provider as ISP. If you still see
your own provider, traffic is leaking around the tunnel, often over IPv6.</li>
<li><strong>Blocked email or websites:</strong> if mail servers reject your messages or sites show captchas, your address
may be on a spam list. The <a href="/blacklist-check">blacklist check</a> queries the common lists.</li>
</ul>

<h2>Troubleshooting</h2>
<ul>
<li><strong>The address does not match your router's status page.</strong> If the router shows an address in
<code>100.64.0.0/10</code> or a private range, your provider uses CGNAT. Incoming connections over IPv4 will not
work without a public address from the provider.</li>
<li><strong>The page shows IPv6 but a service needs IPv4.</strong> Your IPv4 address may be shared. Ask the service to
allow IPv6, or ask your provider for a dedicated IPv4 address.</li>
<li><strong>The location is in the wrong country.</strong> Check for a VPN, proxy or browser privacy relay. If none is
active, the geolocation database is out of date for your provider's address block; it usually corrects itself
within a few weeks.</li>
</ul>

<h2>How this page works</h2>
<p>The address is read from your connection to this server. The reverse DNS name is looked up live, everything else
comes from the connection metadata. Nothing is stored.</p>`,

  faq: [
    {
      q: 'Why is my IP address different on my phone?',
      a: 'On mobile data your phone uses the carrier network and gets an address from your mobile provider. On Wi-Fi it uses the public IP of that network.',
    },
    {
      q: 'Does my IP address change?',
      a: 'Most home connections get a dynamic address that can change after a router restart or every few days. Business lines often have a static address. IPv6 privacy addresses on your devices can change several times a day.',
    },
    {
      q: 'How do I hide my IP address?',
      a: 'A VPN or Tor routes your traffic through another server, so websites see that server\'s IP address instead of yours. Check this page after connecting to confirm it shows the VPN provider.',
    },
    {
      q: 'What is reverse DNS?',
      a: 'Reverse DNS maps an IP address back to a host name via a PTR record. Providers often use names that reveal the connection type or region.',
    },
    {
      q: 'Can someone find my home address from my IP?',
      a: 'No. Geolocation only narrows an address down to a city or region, often only to the provider\'s hub. Only your provider can link the IP to a customer account.',
    },
    {
      q: 'Why does this page show an IPv6 address instead of IPv4?',
      a: 'Your connection supports both, and your browser preferred IPv6. You still have an IPv4 address, which may be shared with other customers through carrier-grade NAT.',
    },
  ],
};

export default tool;
