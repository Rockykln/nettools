import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { aggregate, formatCount, parseSubnet, size, toIp, type Subnet } from '../core/subnet';
import type { Tool } from '../core/tool';

const MAX_LINES = 500;
const MAX_BLOCKS = 2048;

interface Result {
  mode: 'range' | 'aggregate';
  cidrs: Subnet[];
  errors: string[];
}

// Each line is a range "a - b", a CIDR, or a single address. Ranges are converted, CIDR lists are merged.
export function convert(input: string): Result {
  const all = input.split(/[\n,;]+/).map((l) => l.trim()).filter(Boolean);
  const lines = all.slice(0, MAX_LINES);
  const errors: string[] = all.length > MAX_LINES ? [`Only the first ${MAX_LINES} of ${all.length} entries were converted.`] : [];
  const blocks: Subnet[] = [];
  let ranges = 0;
  for (const line of lines) {
    const range = line.match(/^(\S+?)\s*(?:-|–|to)\s*(\S+)$/i);
    if (range) {
      // "10.0.0.5-20" is shorthand for "10.0.0.5-10.0.0.20".
      const end = /^\d{1,3}$/.test(range[2]!) && /^\d+\.\d+\.\d+\.\d+$/.test(range[1]!) ? range[1]!.replace(/\d+$/, range[2]!) : range[2]!;
      const a = parseSubnet(range[1]!), b = parseSubnet(end);
      if (!a || !b || a.version !== b.version) {
        errors.push(`"${line}" is not a valid range.`);
        continue;
      }
      // Reversed ranges are accepted; a CIDR at either end counts with all of its addresses.
      const first = a.network < b.network ? a.network : b.network;
      const last = a.last > b.last ? a.last : b.last;
      // Kept as one interval: aggregate() merges by first/last address and splits into CIDR blocks only once,
      // so many overlapping ranges cannot blow up the intermediate list.
      blocks.push({ version: a.version, prefix: 0, network: first, last, input: first });
      ranges++;
      continue;
    }
    const s = parseSubnet(line);
    if (s) blocks.push(s);
    else errors.push(`"${line}" is not an IP address, CIDR block or range.`);
  }
  const versions = new Set(blocks.map((b) => b.version));
  const cidrs = [4, 6].flatMap((v) => (versions.has(v as 4 | 6) ? aggregate(blocks.filter((b) => b.version === v)) : []));
  if (cidrs.length > MAX_BLOCKS) return { mode: 'range', cidrs: [], errors: [`The result would have more than ${MAX_BLOCKS} blocks. Split the input into smaller ranges.`] };
  return { mode: ranges ? 'range' : 'aggregate', cidrs, errors };
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/ip-range-to-cidr">
<div class="field grow"><label for="input">IP ranges or CIDR blocks, one per line</label>
<textarea id="input" name="input" rows="5" required autocapitalize="off" autocomplete="off" spellcheck="false" placeholder="10.0.0.5 - 10.0.0.20&#10;192.168.0.0/25&#10;192.168.0.128/25">${value}</textarea></div>
<div class="field"><button type="submit">Convert</button></div>
</form>`;
}

const INVALID = 'Enter at least one range (10.0.0.5 - 10.0.0.20), CIDR block or IP address.';

const tool: Tool = {
  slug: 'ip-range-to-cidr',
  name: 'Range to CIDR',
  icon: 'range',
  category: 'ip',
  title: 'IP Range to CIDR Converter & CIDR Aggregator',
  description:
    'Convert any IPv4 or IPv6 address range into the smallest list of CIDR blocks, or merge a list of overlapping networks into a minimal set. Free, instant.',
  h1: 'IP range to CIDR converter',
  lead: 'Turn address ranges into CIDR blocks and merge lists of networks into the shortest possible set.',
  examples: [['10.0.0.5 – 10.0.0.20', 'input=10.0.0.5-10.0.0.20']],
  related: ['subnet-calculator', 'asn-lookup', 'whois'],
  heavy: (url) => (url.searchParams.get('input') ?? '').split(/[\n,;]+/).length > 20,
  isQuery: (url) => url.searchParams.has('input'),

  render(c) {
    const value = c.url.searchParams.get('input') ?? '';
    if (!c.url.searchParams.has('input')) return form('');
    const r = convert(value);
    if (!r.cidrs.length) return html`${form(value)}<p class="error">${r.errors[0] ?? INVALID}</p>`;
    const total = r.cidrs.reduce((a, s) => a + size(s), 0n);
    const list = r.cidrs.map((s) => `${toIp(s.network, s.version)}/${s.prefix}`).join('\n');
    return html`${form(value)}
${r.errors.map((e) => html`<p class="error">${e}</p>`)}
<p class="result-head">${r.cidrs.length} CIDR block${r.cidrs.length === 1 ? '' : 's'} covering ${formatCount(total)} addresses
<button type="button" class="btn-small" data-copy="${list}">Copy all</button></p>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>CIDR</th><th>First address</th><th>Last address</th><th>Addresses</th></tr></thead>
<tbody>${r.cidrs.map((s) => html`<tr><td><code>${toIp(s.network, s.version)}/${s.prefix}</code></td><td><code>${toIp(s.network, s.version)}</code></td><td><code>${toIp(s.last, s.version)}</code></td><td>${formatCount(size(s))}</td></tr>`)}</tbody></table></div>`;
  },

  apiDoc: 'GET /api/ip-range-to-cidr?input=10.0.0.5-10.0.0.20 (also 10.0.0.5-20, several entries separated by commas)',

  async api(c) {
    const r = convert(c.url.searchParams.get('input') ?? '');
    if (!r.cidrs.length) return json({ error: r.errors[0] ?? INVALID }, { status: 400 });
    return json({ cidrs: r.cidrs.map((s) => `${toIp(s.network, s.version)}/${s.prefix}`), errors: r.errors });
  },

  article: html`<h2>Why convert IP ranges to CIDR?</h2>
<p>Firewalls, routers, cloud security groups, web server allow lists and <code>.htaccess</code> files expect networks in
CIDR notation (Classless Inter-Domain Routing, RFC 4632), such as <code>203.0.113.0/24</code>. Providers, abuse reports
and WHOIS records, on the other hand, often list plain ranges such as <code>203.0.113.10 – 203.0.113.75</code>. This
converter turns any start–end range into the smallest set of CIDR blocks that covers it exactly: no address outside
the range is included and none inside it is left out.</p>
<p>The second job is the reverse direction: you paste a long list of networks and get back the shortest equivalent
list, with overlapping and adjacent blocks merged. This is often called CIDR aggregation or route summarization.</p>

<h2>How CIDR blocks work</h2>
<p>A CIDR block is written as a network address followed by a slash and a prefix length. The prefix length says how many
leading bits are fixed; the remaining bits can take any value. An IPv4 address has 32 bits, so a <code>/24</code> leaves
8 bits free and contains 2<sup>8</sup> = 256 addresses. Two rules follow from this:</p>
<ul>
<li>The size of a block is always a power of two: 1, 2, 4, 8, 16 and so on.</li>
<li>A block must start at a multiple of its own size. <code>203.0.113.64/26</code> is valid because 64 is a multiple of
64; <code>203.0.113.10/26</code> is not a proper network address.</li>
</ul>
<table class="data">
<thead><tr><th>Prefix</th><th>Netmask</th><th>Addresses</th></tr></thead>
<tbody>
<tr><td>/32</td><td><code>255.255.255.255</code></td><td>1</td></tr>
<tr><td>/31</td><td><code>255.255.255.254</code></td><td>2</td></tr>
<tr><td>/30</td><td><code>255.255.255.252</code></td><td>4</td></tr>
<tr><td>/29</td><td><code>255.255.255.248</code></td><td>8</td></tr>
<tr><td>/28</td><td><code>255.255.255.240</code></td><td>16</td></tr>
<tr><td>/27</td><td><code>255.255.255.224</code></td><td>32</td></tr>
<tr><td>/26</td><td><code>255.255.255.192</code></td><td>64</td></tr>
<tr><td>/25</td><td><code>255.255.255.128</code></td><td>128</td></tr>
<tr><td>/24</td><td><code>255.255.255.0</code></td><td>256</td></tr>
<tr><td>/22</td><td><code>255.255.252.0</code></td><td>1,024</td></tr>
<tr><td>/16</td><td><code>255.255.0.0</code></td><td>65,536</td></tr>
</tbody>
</table>
<p>For the network address, broadcast address and usable host range of a single block, use the
<a href="/subnet-calculator">subnet calculator</a>.</p>

<h2>Worked example: range to CIDR</h2>
<p>Take the range <code>203.0.113.10 – 203.0.113.75</code>, which contains 66 addresses. It does not start on a
boundary, so the converter walks from the start address and always takes the largest block that is correctly aligned
and does not run past the end:</p>
<table class="data">
<thead><tr><th>Block</th><th>Covers</th><th>Addresses</th></tr></thead>
<tbody>
<tr><td><code>203.0.113.10/31</code></td><td>.10 – .11</td><td>2</td></tr>
<tr><td><code>203.0.113.12/30</code></td><td>.12 – .15</td><td>4</td></tr>
<tr><td><code>203.0.113.16/28</code></td><td>.16 – .31</td><td>16</td></tr>
<tr><td><code>203.0.113.32/27</code></td><td>.32 – .63</td><td>32</td></tr>
<tr><td><code>203.0.113.64/29</code></td><td>.64 – .71</td><td>8</td></tr>
<tr><td><code>203.0.113.72/30</code></td><td>.72 – .75</td><td>4</td></tr>
</tbody>
</table>
<p>Six blocks, 66 addresses, nothing extra. A range that starts and ends on clean boundaries collapses to one block:
<code>198.51.100.0 – 198.51.100.127</code> is exactly <code>198.51.100.0/25</code>. The worst case for IPv4 is a range
like <code>0.0.0.1 – 255.255.255.254</code>, which needs 62 blocks.</p>

<h2>Worked example: merging a CIDR list</h2>
<p>Paste a list of networks, for example an exported allow list, and the tool merges what can be merged:</p>
<ul>
<li>Adjacent halves: <code>198.51.100.0/25</code> and <code>198.51.100.128/25</code> become <code>198.51.100.0/24</code>.</li>
<li>Overlaps: <code>203.0.113.0/24</code> already contains <code>203.0.113.64/26</code>, so the /26 disappears.</li>
<li>Duplicates and single addresses inside a listed block are removed.</li>
</ul>
<p>Two blocks are only merged when the result is a valid CIDR block. <code>198.51.100.128/25</code> and
<code>198.51.101.0/25</code> are adjacent, but together they do not start on a /24 boundary, so they stay separate.
Shorter lists make firewall rules easier to review and, on many devices, faster to evaluate. IPv4 and IPv6 can be mixed
in one input; each family is merged separately.</p>

<h2>Accepted input</h2>
<ul>
<li>Ranges: <code>10.0.0.5 - 10.0.0.20</code>, <code>10.0.0.5–10.0.0.20</code> or <code>10.0.0.5 to 10.0.0.20</code></li>
<li>CIDR blocks: <code>192.168.0.0/24</code>, or with a netmask: <code>192.168.0.0 255.255.255.0</code></li>
<li>IPv6 ranges and prefixes: <code>2001:db8::/48</code> or <code>2001:db8::10 - 2001:db8::ff</code></li>
<li>Single addresses, which become /32 (IPv4) or /128 (IPv6) blocks</li>
</ul>
<p>Entries can be separated by new lines, commas or semicolons; up to ${MAX_LINES} entries at once. Invalid lines are
reported and skipped, the rest is still converted.</p>

<h2>Using the result</h2>
<p>Most systems take the output as is. A few examples with the blocks from above:</p>
<ul>
<li>nftables: <code>ip saddr { 203.0.113.16/28, 203.0.113.32/27 } accept</code></li>
<li>iptables: one rule per block, <code>iptables -A INPUT -s 203.0.113.32/27 -j ACCEPT</code></li>
<li>nginx: <code>allow 203.0.113.32/27;</code> followed by <code>deny all;</code></li>
<li>Apache 2.4: <code>Require ip 203.0.113.32/27</code></li>
</ul>
<p>Some tools accept ranges directly, such as nftables (<code>203.0.113.10-203.0.113.75</code>) or the iptables
<code>iprange</code> module, but cloud security groups and most router ACLs do not. If you script this yourself,
Python's standard library has <code>ipaddress.summarize_address_range()</code> for ranges and
<code>ipaddress.collapse_addresses()</code> for merging.</p>

<h2>Common use cases</h2>
<ul>
<li><strong>WHOIS ranges:</strong> RIPE and other registries describe IPv4 assignments as an <code>inetnum</code> range
such as <code>192.0.2.0 - 192.0.2.255</code>. Paste it here to get <code>192.0.2.0/24</code> for a firewall rule.</li>
<li><strong>Published service ranges:</strong> SaaS and cloud providers publish lists of the addresses their servers use.
Merging those lists before importing them keeps allow lists short.</li>
<li><strong>Abuse blocking:</strong> an abuse report lists a range of scanning hosts; the converter gives you exactly
the blocks to deny, without blocking neighbors by rounding up to a /24.</li>
<li><strong>Cleaning up old rules:</strong> years of single-address entries often add up to whole blocks. Merging shows
where several rules can become one.</li>
</ul>
<h2>Troubleshooting</h2>
<ul>
<li><strong>Too many blocks:</strong> the range starts or ends on an odd address. That is expected; check whether the
provider really meant that range or a rounded network such as a /26.</li>
<li><strong>“Not a valid range”:</strong> an address is mistyped, or one side is IPv4 and the other IPv6. A reversed range
(end before start) is swapped automatically.</li>
<li><strong>Blocks did not merge:</strong> they are adjacent but not aligned, as in the merging example above.</li>
<li><strong>Range belongs to whom?</strong> Look up the owner of a block with the <a href="/whois">WHOIS lookup</a>, or
see which network announces it with the <a href="/asn-lookup">ASN and BGP lookup</a>.</li>
</ul>
<p>To check which address you are connecting from before adding it to an allow list, use
<a href="/what-is-my-ip">What is my IP</a>.</p>`,

  faq: [
    { q: 'Why does my range produce several blocks?', a: 'A CIDR block always has a size that is a power of two and starts at a multiple of that size. A range that does not start and end on such a boundary needs several blocks of different sizes to be covered exactly.' },
    { q: 'Can I convert IPv6 ranges?', a: 'Yes. IPv6 ranges and prefixes work the same way, with 128 instead of 32 bits. IPv4 and IPv6 can be mixed in one list; they are processed separately.' },
    { q: 'Is the result exact?', a: 'Yes. The blocks cover exactly the given addresses, without gaps and without extra addresses. Merging only combines blocks when the merged block contains no address that was not in the input.' },
    { q: 'How many IP addresses are in a /24, /16 or /8?', a: 'A /24 has 256 addresses, a /16 has 65,536 and a /8 has 16,777,216. In general, an IPv4 block with prefix length n contains 2 to the power of (32 minus n) addresses.' },
    { q: 'Do the blocks include network and broadcast addresses?', a: 'Yes. A CIDR block in a firewall rule or allow list simply means every address in it. Network and broadcast addresses only matter when the block is used as a subnet on a LAN interface.' },
    { q: 'Can I convert a netmask to a prefix length?', a: 'Yes. Enter the network with its mask, for example 192.168.0.0 255.255.255.0, and the result is shown as 192.168.0.0/24.' },
  ],
};

export default tool;
