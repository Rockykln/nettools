import { html } from '../core/html';
import { isIPv4 } from '../core/net';
import type { Tool } from '../core/tool';

// Endpoints that answer over one protocol only. Cloudflare serves every proxied name over both,
// so a single-stack test needs hosts outside this site.
export const IPV4_ONLY = 'https://api4.ipify.org/?format=json';
export const IPV6_ONLY = 'https://api6.ipify.org/?format=json';

const tool: Tool = {
  slug: 'ipv6-test',
  name: 'IPv6 test',
  icon: 'ipv6',
  category: 'ip',
  title: 'IPv6 Test – Does My Connection Support IPv6?',
  description: 'Test whether your internet connection works over IPv6 and IPv4, which protocol your browser prefers, and see both of your public IP addresses.',
  h1: 'IPv6 test',
  lead: 'Check whether your connection reaches the internet over IPv6, IPv4 or both, and which one your browser uses.',
  personal: true,
  script: 'ipv6-test.js',
  related: ['what-is-my-ip', 'port-checker', 'subnet-calculator'],

  render(c) {
    const v4 = isIPv4(c.clientIp);
    return html`<div class="ipv6-test" data-ipv6-test data-v4="${IPV4_ONLY}" data-v6="${IPV6_ONLY}">
<table class="kv compact"><tbody>
<tr><th scope="row">This page reached us over</th><td><span class="badge">IPv${v4 ? '4' : '6'}</span> <code>${c.clientIp}</code></td></tr>
<tr><th scope="row">IPv4</th><td data-k="v4">not tested yet</td></tr>
<tr><th scope="row">IPv6</th><td data-k="v6">not tested yet</td></tr>
</tbody></table>
<div class="verdict" data-k="verdict" hidden></div>
<p><button type="button" data-run>Start test</button></p>
<p class="hint">The test needs JavaScript. Your browser then contacts <code>api4.ipify.org</code> (IPv4 only) and
<code>api6.ipify.org</code> (IPv6 only), a public IP address service, which sees your addresses like any website.</p>
</div>`;
  },

  article: html`<h2>Why IPv6 exists</h2>
<p>IPv4 has about 4.3 billion addresses, far fewer than the number of devices online. IANA handed out its last
free IPv4 blocks in 2011, and the regional registries have since run out as well. Networks have stretched IPv4 with
NAT: your router shares one public address among all devices at home, and many providers add another layer, carrier-grade
NAT (CGNAT), so that many customers share a single public address.</p>
<p>IPv6 uses 128-bit addresses. A single home connection typically receives a whole prefix, often a /56 or a /48,
and every device gets its own globally routable address. No address sharing is needed, which makes incoming
connections, VoIP and peer-to-peer traffic simpler.</p>

<h2>What the test does</h2>
<p>The first row shows over which protocol your browser loaded this page. This site runs on Cloudflare, which answers
every hostname over both IPv4 and IPv6, so it cannot test each protocol on its own. When you start the test, your
browser therefore sends one request to <code>api4.ipify.org</code>, which has only an IPv4 address, and one to
<code>api6.ipify.org</code>, which has only an IPv6 address. Each service returns the public address it saw.</p>
<table class="data">
<thead><tr><th>Result</th><th>Meaning</th></tr></thead>
<tbody>
<tr><td>Dual stack</td><td>Both requests worked. Your connection has public IPv4 and IPv6 connectivity. This is the normal state for a modern connection.</td></tr>
<tr><td>IPv4 only</td><td>The IPv6 request failed. Your network has no working IPv6 path to the internet.</td></tr>
<tr><td>IPv6 only</td><td>Only the IPv6 request worked. Rare on home networks; IPv4-only sites will not load without a translation service.</td></tr>
<tr><td>Neither</td><td>Both requests failed, usually because a content blocker, proxy or firewall blocks the test service.</td></tr>
</tbody>
</table>
<p>The IPv4 and IPv6 addresses shown are usually different and unrelated. To see the address this site sees for you,
along with location and provider, use <a href="/what-is-my-ip">What is my IP</a>.</p>

<h2>How the browser chooses a protocol</h2>
<p>When a hostname has both an A (IPv4) and an AAAA (IPv6) record, the browser uses Happy Eyeballs (RFC 8305). It
tries IPv6 first and, if that does not succeed within a short delay (the RFC recommends 250 ms), starts an IPv4
connection in parallel and uses whichever completes first. A broken IPv6 setup therefore rarely causes visible
errors, only slightly slower connections, and the page above may have loaded over IPv4 even though IPv6 works.</p>

<h2>IPv6-only networks with NAT64</h2>
<p>Several large mobile carriers run their networks on IPv6 only. IPv4-only destinations are reached through
DNS64 and NAT64: the resolver synthesizes an IPv6 address from the IPv4 address, often in the prefix
<code>64:ff9b::/96</code>, and a gateway translates the traffic. Android phones additionally use 464XLAT so that apps
expecting IPv4 keep working. On such a network, the IPv4 test still succeeds and shows the gateway's IPv4 address,
so the result looks like dual stack.</p>

<h2>Common reasons for no IPv6</h2>
<ul>
<li>The provider does not offer IPv6 on your line, or only on newer contracts.</li>
<li>IPv6 is disabled on the router, or the router does not pass the delegated prefix to the LAN.</li>
<li>A VPN carries only IPv4. Good VPN clients then block IPv6 completely so that it cannot leak around the tunnel.</li>
<li>Different networks behave differently: the same phone may have IPv6 on mobile data but not on a Wi-Fi network.</li>
<li>IPv6 is disabled in the operating system or on the network adapter.</li>
</ul>

<h2>Checking IPv6 locally</h2>
<pre class="raw">ip -6 addr show scope global      # Linux: global IPv6 addresses
ipconfig                          # Windows: look for "IPv6 Address"
curl -6 https://api6.ipify.org    # public IPv6 address, fails without IPv6
ping -6 2001:4860:4860::8888      # Google Public DNS over IPv6</pre>
<p>An address starting with <code>fe80:</code> is link-local and exists on every interface with IPv6 enabled; it does
not mean you have internet access over IPv6. Addresses starting with <code>fd</code> are unique local addresses for
internal use. Public addresses currently start with <code>2</code> or <code>3</code>.</p>

<h2>Why your IPv6 address keeps changing</h2>
<p>Most operating systems use temporary addresses (privacy extensions, RFC 8981) for outgoing connections. The
interface identifier, the last 64 bits of the address, is random and replaced regularly, often daily, so websites
cannot track a device by a fixed address. The first 64 bits, your network prefix, stay the same unless your provider
assigns a new one. Some providers change the prefix on reconnect.</p>

<h2>IPv6 and firewalls</h2>
<p>Without NAT, every device with a global IPv6 address is reachable from the internet in principle. In practice
home routers block incoming IPv6 connections by default, just as NAT does for IPv4. If you open a port for a server,
open it for the device's IPv6 address in the router's firewall, ideally a stable address rather than a temporary one.
The <a href="/port-checker">port checker</a> shows whether a port is reachable from outside.</p>

<h2>IPv6 notation in brief</h2>
<p>An IPv6 address is written as eight groups of four hexadecimal digits. Leading zeros in a group may be dropped,
and one run of consecutive zero groups may be replaced by <code>::</code>. For example,
<code>2001:0db8:0000:0000:0000:0000:0000:0001</code> becomes <code>2001:db8::1</code>. Networks are written in CIDR
notation; a normal LAN is a <code>/64</code>. The <a href="/subnet-calculator">subnet calculator</a> splits and
expands IPv6 prefixes.</p>`,

  faq: [
    {
      q: 'Do I need IPv6?',
      a: 'Today almost every service is still reachable over IPv4, so you can use the internet without IPv6. IPv6 avoids address sharing through carrier-grade NAT, which helps with incoming connections, games and VoIP, and some networks already work over IPv6 only.',
    },
    {
      q: 'Why does the page say IPv4 although the test finds IPv6?',
      a: 'Browsers use Happy Eyeballs: they prefer IPv6 but fall back to IPv4 if the IPv6 connection is slower to start. A single page load can therefore use IPv4 even though IPv6 works.',
    },
    {
      q: 'How do I enable IPv6?',
      a: 'First check that your provider offers IPv6 on your connection. Then enable IPv6 on the router, usually with DHCPv6 prefix delegation on the WAN side and router advertisements on the LAN side. Operating systems enable IPv6 by default.',
    },
    {
      q: 'Is IPv6 less secure than IPv4?',
      a: 'Not inherently. The difference is that devices have globally routable addresses, so the router’s firewall, not NAT, keeps incoming connections out. Home routers block incoming IPv6 connections by default.',
    },
    {
      q: 'Why does my IPv6 address change every day?',
      a: 'Your operating system uses temporary addresses with a random interface identifier for privacy (RFC 8981). The network prefix in the first half of the address stays the same unless your provider changes it.',
    },
    {
      q: 'Does the IPv6 test send my data anywhere?',
      a: 'Your browser contacts api4.ipify.org and api6.ipify.org, a public IP address service that sees your IP addresses like any website you visit. The test starts only when you click the button.',
    },
  ],
};

export default tool;
