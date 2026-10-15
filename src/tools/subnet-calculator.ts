import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { binary, classify, formatCount, hostRange, netmask, parseSubnet, size, split, toIp, wildcard, type Subnet } from '../core/subnet';
import type { Tool } from '../core/tool';

const INVALID = 'Enter an address with prefix or netmask, e.g. 192.168.1.0/24, 10.0.0.1 255.255.0.0 or 2001:db8::/48.';

function details(s: Subnet): [string, string, boolean?][] {
  const v = s.version;
  const hosts = hostRange(s);
  const rows: [string, string, boolean?][] = [
    ['Network', `${toIp(s.network, v)}/${s.prefix}`, true],
    [v === 4 ? 'Broadcast' : 'Last address', toIp(s.last, v), true],
    ['Usable hosts', `${toIp(hosts.first, v)} – ${toIp(hosts.last, v)}`, true],
    ['Number of hosts', formatCount(hosts.count)],
    ['Total addresses', formatCount(size(s))],
  ];
  if (v === 4) {
    rows.push(['Netmask', netmask(s), true], ['Wildcard mask', wildcard(s), true]);
    rows.push(['Binary netmask', binary((((1n << 32n) - 1n) ^ ((1n << BigInt(32 - s.prefix)) - 1n)), 4), true]);
  } else if (s.prefix <= 64) {
    rows.push(['/64 networks', formatCount(1n << BigInt(64 - s.prefix))]);
  }
  rows.push(['Address type', classify(s)]);
  if (s.input !== s.network) rows.push(['You entered', toIp(s.input, v), true]);
  return rows;
}

function form(value: string, splitTo: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/subnet-calculator">
<div class="field grow"><label for="cidr">IP address with prefix or netmask</label>
<input id="cidr" name="cidr" type="text" value="${value}" placeholder="192.168.1.0/24" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><label for="split">Split into (optional)</label>
<input id="split" name="split" type="text" inputmode="numeric" value="${splitTo}" placeholder="/26" autocomplete="off"></div>
<div class="field"><button type="submit">Calculate</button></div>
</form>`;
}

const splitError = (s: Subnet) => `The split prefix must be between /${s.prefix + 1} and /${s.version === 4 ? 32 : 128}.`;

function splitPrefix(raw: string | null): number | null {
  const m = (raw ?? '').trim().match(/^\/?(\d{1,3})$/);
  return m ? Number(m[1]) : null;
}

const tool: Tool = {
  slug: 'subnet-calculator',
  name: 'Subnet calculator',
  icon: 'subnet',
  category: 'ip',
  title: 'Subnet Calculator – IPv4 & IPv6 CIDR, Netmask, Host Range',
  description:
    'Free IPv4 and IPv6 subnet calculator: network and broadcast address, host range, netmask, wildcard and host count. Split networks into smaller subnets.',
  h1: 'Subnet calculator',
  lead: 'Network, broadcast, host range and netmask for any IPv4 or IPv6 subnet, and how to split it.',
  examples: [['192.168.1.0/24', 'cidr=192.168.1.0/24'], ['10.0.0.0/22 into /24', 'cidr=10.0.0.0/22&split=24'], ['2001:db8::/48', 'cidr=2001:db8::/48']],
  related: ['what-is-my-ip', 'whois', 'port-checker'],
  isQuery: (url) => url.searchParams.has('cidr'),

  render(c) {
    const value = (c.url.searchParams.get('cidr') ?? '').trim();
    const splitRaw = (c.url.searchParams.get('split') ?? '').trim();
    if (!c.url.searchParams.has('cidr')) return form('', '');
    const s = parseSubnet(value);
    if (!s) return html`${form(value, splitRaw)}<p class="error">${INVALID}</p>`;
    const bare = !/[/\s]/.test(value);
    const guess = s.version === 4 ? `${value.split('.').slice(0, 3).join('.')}.0/24` : null;
    const to = splitPrefix(splitRaw);
    const parts = to !== null ? split(s, to, 256) : null;
    return html`${form(value, splitRaw)}
${bare ? html`<p class="hint">No prefix given, so /${s.prefix} was assumed.${guess ? html` Did you mean <a href="/subnet-calculator?cidr=${encodeURIComponent(guess)}">${guess}</a>?` : ''}</p>` : ''}
<table class="kv"><tbody>${details(s).map(([k, v, mono]) => html`<tr><th scope="row">${k}</th><td>${mono ? html`<code>${v}</code>` : v}</td></tr>`)}</tbody></table>
${parts && parts.blocks.length
      ? html`<h2>${formatCount(parts.total)} subnets of /${to}</h2>
${parts.total > BigInt(parts.blocks.length) ? html`<p class="muted">Showing the first ${parts.blocks.length}.</p>` : ''}
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>#</th><th>Network</th><th>Usable hosts</th><th>${s.version === 4 ? 'Broadcast' : 'Last address'}</th></tr></thead>
<tbody>${parts.blocks.map((b, i) => {
          const h = hostRange(b);
          return html`<tr><td>${i + 1}</td><td><code>${toIp(b.network, b.version)}/${b.prefix}</code></td><td><code>${toIp(h.first, b.version)} – ${toIp(h.last, b.version)}</code></td><td><code>${toIp(b.last, b.version)}</code></td></tr>`;
        })}</tbody></table></div>`
      : splitRaw ? html`<p class="error">${s.prefix >= (s.version === 4 ? 32 : 128) ? 'A single address cannot be split.' : splitError(s)}</p>` : ''}`;
  },

  apiDoc: 'GET /api/subnet-calculator?cidr=192.168.1.0/24&split=26 (split is optional, up to 256 subnets listed)',

  async api(c) {
    const s = parseSubnet(c.url.searchParams.get('cidr') ?? '');
    if (!s) return json({ error: INVALID }, { status: 400 });
    // Counts are formatted for people ("1,022", "2^80"); the API returns exact numbers, as digit strings beyond 2^53.
    const num = (n: bigint) => (n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n.toString());
    const counts: Record<string, bigint> = { number_of_hosts: hostRange(s).count, total_addresses: size(s) };
    if (s.version === 6 && s.prefix <= 64) counts._64_networks = 1n << BigInt(64 - s.prefix);
    const out: Record<string, unknown> = Object.fromEntries(details(s).map(([k, v]) => {
      const key = k.toLowerCase().replace(/[^a-z0-9]+/g, '_');
      return [key, key in counts ? num(counts[key]!) : v];
    }));
    const splitRaw = c.url.searchParams.get('split');
    if (splitRaw) {
      const to = splitPrefix(splitRaw);
      const parts = to !== null ? split(s, to, 256) : null;
      if (!parts?.blocks.length) return json({ error: splitError(s) }, { status: 400 });
      out.split = {
        prefix: to,
        total: num(parts.total),
        subnets: parts.blocks.map((b) => {
          const h = hostRange(b);
          return { network: `${toIp(b.network, b.version)}/${b.prefix}`, first: toIp(h.first, b.version), last: toIp(h.last, b.version) };
        }),
      };
    }
    return json(out);
  },

  article: html`<h2>How subnetting works</h2>
<p>An IP network is written as an address plus a prefix length, for example <code>192.168.1.0/24</code>. This is CIDR
notation (Classless Inter-Domain Routing, RFC 4632). The prefix says how many leading bits identify the network; the
remaining bits number the hosts. A /24 leaves 8 host bits, so it contains 2<sup>8</sup> = 256 addresses. Each bit you
add to the prefix halves the block: a /25 has 128 addresses, a /26 has 64.</p>
<p>The netmask expresses the same thing in dotted form. Every network bit is a 1, every host bit a 0, so /24 becomes
<code>255.255.255.0</code> and /26 becomes <code>255.255.255.192</code>. The calculator accepts all three common
inputs: <code>192.168.1.10/24</code>, <code>192.168.1.10/255.255.255.0</code> and
<code>192.168.1.10 255.255.255.0</code>. An address without a prefix is treated as a single host (/32 or /128).</p>

<h2>Network, broadcast and usable hosts</h2>
<p>In IPv4 the first address of a block is the network address and the last one the broadcast address, so a /24 has
254 usable hosts. Point-to-point links can use a /31, where both addresses are usable (RFC 3021), and a /32 describes
a single address, for example a loopback interface or a firewall rule for one host. IPv6 has no broadcast address,
and subnets for end devices are normally /64.</p>

<h2>Calculating a subnet by hand</h2>
<p>The quickest method uses the block size, which is 256 minus the netmask value in the octet where the prefix ends.</p>
<p><strong>Example 1:</strong> <code>192.168.10.77/27</code></p>
<ol>
<li>A /27 ends in the fourth octet with mask <code>224</code>. Block size: 256 &minus; 224 = 32.</li>
<li>The blocks start at 0, 32, 64, 96 and so on. 77 falls into the block that starts at 64.</li>
<li>Network address: <code>192.168.10.64</code>. Broadcast: the next block start minus one, <code>192.168.10.95</code>.</li>
<li>Usable hosts: <code>192.168.10.65</code> to <code>192.168.10.94</code>, 30 in total. Wildcard mask:
<code>0.0.0.31</code>.</li>
</ol>
<p><strong>Example 2:</strong> <code>172.16.45.200/20</code></p>
<ol>
<li>A /20 ends in the third octet with mask <code>240</code> (<code>255.255.240.0</code>). Block size: 16.</li>
<li>Blocks in the third octet start at 0, 16, 32, 48. 45 falls into the block that starts at 32.</li>
<li>Network: <code>172.16.32.0</code>. Broadcast: <code>172.16.47.255</code>.</li>
<li>Usable hosts: <code>172.16.32.1</code> to <code>172.16.47.254</code>, which is 4,094 addresses.</li>
</ol>
<p>Enter either example above to check the result, including the binary netmask.</p>

<h2>IPv4 prefix reference</h2>
<table class="data"><thead><tr><th>Prefix</th><th>Netmask</th><th>Addresses</th><th>Usable hosts</th></tr></thead><tbody>
<tr><td>/32</td><td><code>255.255.255.255</code></td><td>1</td><td>1 (single host)</td></tr>
<tr><td>/31</td><td><code>255.255.255.254</code></td><td>2</td><td>2 (point-to-point)</td></tr>
<tr><td>/30</td><td><code>255.255.255.252</code></td><td>4</td><td>2</td></tr>
<tr><td>/29</td><td><code>255.255.255.248</code></td><td>8</td><td>6</td></tr>
<tr><td>/28</td><td><code>255.255.255.240</code></td><td>16</td><td>14</td></tr>
<tr><td>/27</td><td><code>255.255.255.224</code></td><td>32</td><td>30</td></tr>
<tr><td>/26</td><td><code>255.255.255.192</code></td><td>64</td><td>62</td></tr>
<tr><td>/25</td><td><code>255.255.255.128</code></td><td>128</td><td>126</td></tr>
<tr><td>/24</td><td><code>255.255.255.0</code></td><td>256</td><td>254</td></tr>
<tr><td>/23</td><td><code>255.255.254.0</code></td><td>512</td><td>510</td></tr>
<tr><td>/22</td><td><code>255.255.252.0</code></td><td>1,024</td><td>1,022</td></tr>
<tr><td>/21</td><td><code>255.255.248.0</code></td><td>2,048</td><td>2,046</td></tr>
<tr><td>/20</td><td><code>255.255.240.0</code></td><td>4,096</td><td>4,094</td></tr>
<tr><td>/16</td><td><code>255.255.0.0</code></td><td>65,536</td><td>65,534</td></tr>
<tr><td>/8</td><td><code>255.0.0.0</code></td><td>16,777,216</td><td>16,777,214</td></tr>
</tbody></table>

<h2>Splitting a network into subnets</h2>
<p>Enter a larger prefix in the "Split into" field to divide a network into equal parts. Splitting
<code>10.0.0.0/22</code> into /24 gives four networks: <code>10.0.0.0/24</code>, <code>10.0.1.0/24</code>,
<code>10.0.2.0/24</code> and <code>10.0.3.0/24</code>. Each additional prefix bit doubles the number of subnets and
halves their size; the calculator lists up to the first 256.</p>
<p>When the parts need different sizes, assign the largest first so every block starts on a boundary of its own size.
This is called variable-length subnet masking (VLSM). For <code>192.168.50.0/24</code> with one LAN of 100 hosts, one
of 50, one of 20 and a router link:</p>
<table class="data"><thead><tr><th>Need</th><th>Prefix</th><th>Subnet</th><th>Usable range</th></tr></thead><tbody>
<tr><td>100 hosts</td><td>/25 (126)</td><td><code>192.168.50.0/25</code></td><td><code>.1</code> – <code>.126</code></td></tr>
<tr><td>50 hosts</td><td>/26 (62)</td><td><code>192.168.50.128/26</code></td><td><code>.129</code> – <code>.190</code></td></tr>
<tr><td>20 hosts</td><td>/27 (30)</td><td><code>192.168.50.192/27</code></td><td><code>.193</code> – <code>.222</code></td></tr>
<tr><td>Router link</td><td>/30 (2)</td><td><code>192.168.50.224/30</code></td><td><code>.225</code> – <code>.226</code></td></tr>
</tbody></table>
<p>That leaves <code>192.168.50.228</code> to <code>192.168.50.255</code> free for later. Plan some headroom: a
network that is exactly full on day one will need renumbering soon.</p>

<h2>IPv6 subnetting</h2>
<p>IPv6 works the same way, only with 128 bits. In practice the boundaries are fixed by convention:</p>
<ul>
<li>A <strong>/64</strong> is the standard size for one network segment. Stateless address autoconfiguration (SLAAC)
only works with /64, and the block contains 2<sup>64</sup>, about 18.4 quintillion, addresses.</li>
<li>Home connections usually receive a <strong>/56</strong> (256 networks of /64) or a single /64.</li>
<li>Businesses and sites commonly get a <strong>/48</strong>, which holds 65,536 networks of /64.</li>
</ul>
<p>For an IPv6 prefix the calculator shows how many /64 networks it contains. Try <code>2001:db8::/48</code> and split
it into /64 to see the first subnets.</p>

<h2>Wildcard masks and ACLs</h2>
<p>A wildcard mask is the netmask inverted: subtract each octet from 255. <code>255.255.255.224</code> becomes
<code>0.0.0.31</code>. Cisco IOS access lists and OSPF network statements use it, for example
<code>access-list 10 permit 192.168.10.64 0.0.0.31</code> matches the whole /27 from example 1.</p>

<h2>Common mistakes</h2>
<ul>
<li><strong>Host address instead of network address:</strong> <code>192.168.1.10/24</code> is a host in a network, not
the network itself. Many routers and cloud consoles reject it in a route or a firewall rule; use
<code>192.168.1.0/24</code>.</li>
<li><strong>Misaligned blocks:</strong> <code>10.0.1.0/23</code> is not a valid network start, because a /23 must begin at
an even third octet. The calculator shows the real network, <code>10.0.0.0/23</code>.</li>
<li><strong>Overlapping ranges:</strong> two sites or a VPN using the same private range cannot route to each other.
Pick less common ranges such as <code>10.37.0.0/16</code> instead of <code>192.168.0.0/24</code> for networks that may
be connected later.</li>
<li><strong>Forgetting reserved addresses:</strong> cloud providers often reserve more than two addresses per subnet
(AWS reserves five), so check the provider's documentation before sizing a small subnet.</li>
</ul>

<h2>Related tools</h2>
<p>To turn an arbitrary start and end address into a list of CIDR blocks, use the
<a href="/ip-range-to-cidr">IP range to CIDR converter</a>. To find out who owns a public network, run a
<a href="/whois">WHOIS lookup</a> or check the announcing network with the <a href="/asn-lookup">ASN lookup</a>. Your
own public address is shown on <a href="/what-is-my-ip">what is my IP</a>.</p>`,

  faq: [
    { q: 'What is a wildcard mask?', a: 'The inverted netmask. Cisco ACLs and OSPF use it: 0 bits must match, 1 bits are ignored. For a /24 it is 0.0.0.255.' },
    { q: 'How many hosts fit in a /24?', a: '254. The block has 256 addresses, minus the network and the broadcast address.' },
    { q: 'Which address ranges are private?', a: '10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16 (RFC 1918). 100.64.0.0/10 is used by providers for carrier-grade NAT (RFC 6598). In IPv6, fc00::/7 is the unique local range.' },
    { q: 'What does /24 mean?', a: 'The first 24 bits of the address identify the network and the remaining 8 bits number the hosts. It is the same as the netmask 255.255.255.0.' },
    { q: 'Which prefix do I need for 50 hosts?', a: 'A /26, which has 62 usable addresses. A /27 has only 30. Add headroom for growth, and check whether your cloud provider reserves extra addresses.' },
    { q: 'Why should IPv6 subnets be /64?', a: 'Stateless address autoconfiguration (SLAAC) requires a 64-bit interface identifier, and many devices and protocols assume /64 networks. Smaller IPv6 subnets are used mainly for point-to-point links.' },
  ],
};

export default tool;
