import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import type { Tool } from '../core/tool';

const MAX = 50;

interface MacResult {
  input: string;
  mac: string | null;
  vendor: string | null;
  country: string | null;
  block: string | null;
  local: boolean;
  multicast: boolean;
  error: string | null;
}

/**
 * Normalizes "00:1A:2B:3C:4D:5E", "001a.2b3c.4d5e", "00-1A-2B", "0:1a:2b:3c:4d:5e" or a bare
 * OUI (24 bits), MA-M (28 bits) or MA-S (36 bits) prefix to upper-case hex.
 */
export function normalizeMac(input: string): string | null {
  const s = input.trim().replace(/\/(24|28|36|48)$/, '');
  const groups = s.split(/[\s:-]+/);
  let hex: string;
  if (groups.length === 6 && groups.every((g) => /^[0-9a-f]{1,2}$/i.test(g))) {
    // Full address as printed by arp/ifconfig on BSD and macOS, without leading zeros.
    hex = groups.map((g) => g.padStart(2, '0')).join('');
  } else if (/^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$/i.test(s)) {
    hex = s.replace(/\./g, '');
  } else if (groups.length > 1 && groups.slice(0, -1).every((g) => /^[0-9a-f]{2}$/i.test(g)) && /^[0-9a-f]{1,2}$/i.test(groups.at(-1)!)) {
    hex = groups.join('');
  } else if (groups.length === 1 && /^[0-9a-f]+$/i.test(s)) {
    hex = s;
  } else {
    return null;
  }
  hex = hex.toUpperCase();
  return hex.length >= 6 && hex.length <= 12 ? hex : null;
}

const format = (hex: string) => hex.match(/.{1,2}/g)!.join(':');

type Entry = [bits: number, vendor: string, country: string | null];

// IEEE registry from public/data/mac/XX.json (one file per first byte), refreshed monthly by
// scripts/update-mac-vendors.mjs. Files are kept per isolate; there are at most 256 of about 13 KB.
const files = new Map<string, Promise<Record<string, Entry>>>();

function vendorFile(assets: Fetcher, byte: string): Promise<Record<string, Entry>> {
  let p = files.get(byte);
  if (!p) {
    p = assets.fetch(new Request(`https://assets.local/data/mac/${byte}.json`)).then((r) => {
      if (!r.ok) throw new Error(`MAC data ${byte}: HTTP ${r.status}`);
      return r.json<Record<string, Entry>>();
    });
    p.catch(() => files.delete(byte));
    files.set(byte, p);
  }
  return p;
}

async function lookup(assets: Fetcher, inputs: string[]): Promise<MacResult[]> {
  const parsed = inputs.map((input) => ({ input, hex: normalizeMac(input) }));
  const valid = parsed.filter((p): p is { input: string; hex: string } => p.hex !== null);
  const bytes = [...new Set(valid.map((v) => v.hex.slice(0, 2)))];
  const tables = new Map(await Promise.all(bytes.map(async (b) => [b, await vendorFile(assets, b)] as const)));
  // The /36 block wins over /28 and /24.
  const rowFor = (hex: string) => {
    const table = tables.get(hex.slice(0, 2))!;
    for (const len of [9, 7, 6]) {
      const e = hex.length >= len ? table[hex.slice(0, len)] : undefined;
      if (e) return { prefix: hex.slice(0, len), bits: e[0], vendor: e[1], country: e[2] };
    }
    return undefined;
  };
  const byInput = new Map(valid.map((v) => [v.input, rowFor(v.hex)]));
  return parsed.map(({ input, hex }) => {
    if (!hex) return { input, mac: null, vendor: null, country: null, block: null, local: false, multicast: false, error: 'Not a MAC address' };
    const first = parseInt(hex.slice(0, 2), 16);
    const row = byInput.get(input);
    return {
      input,
      mac: format(hex),
      vendor: row?.vendor ?? null,
      country: row?.country ?? null,
      // IEEE notation (70-B3-D5-F2-6) also fits the odd-length /28 and /36 prefixes.
      block: row ? `${row.prefix.match(/.{1,2}/g)!.join('-')}/${row.bits}` : null,
      local: (first & 0b10) !== 0,
      multicast: (first & 0b1) !== 0,
      error: null,
    };
  });
}

function note(r: MacResult): SafeHtml | string {
  if (r.error) return html`<span class="error">${r.error}</span>`;
  if (r.multicast) return 'Multicast or broadcast address, not a device.';
  if (r.local) return 'Locally administered: usually a randomized “private” address (phones, laptops) or a virtual machine, so it has no vendor.';
  if (!r.vendor) return 'Not in the IEEE registry.';
  return '';
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/mac-lookup">
<div class="field grow"><label for="mac">MAC addresses, one per line (up to ${MAX})</label>
<textarea id="mac" name="mac" rows="4" required autocapitalize="off" autocomplete="off" spellcheck="false" placeholder="3C:22:FB&#10;00-00-5E-00-53-01">${value}</textarea></div>
<div class="field"><button type="submit">Look up vendors</button></div>
</form>`;
}

const tool: Tool = {
  slug: 'mac-lookup',
  name: 'MAC vendor lookup',
  icon: 'mac',
  category: 'ip',
  title: 'MAC Address Lookup – Find the Vendor of Any Device',
  description:
    'Find the manufacturer of a network device from its MAC address using the official IEEE registry (MA-L, MA-M, MA-S). Bulk lookup, detects random MACs.',
  h1: 'MAC address vendor lookup',
  lead: 'Find out which manufacturer a network device comes from, using the official IEEE registry.',
  examples: [['3C:22:FB (Apple block)', 'mac=3C:22:FB'], ['00:00:5E:00:53:01 (documentation)', 'mac=00:00:5E:00:53:01']],
  related: ['subnet-calculator', 'what-is-my-ip', 'port-checker'],
  isQuery: (url) => url.searchParams.has('mac'),

  async render(c) {
    const value = c.url.searchParams.get('mac') ?? '';
    if (!c.url.searchParams.has('mac')) return form('');
    const inputs = value.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean).slice(0, MAX);
    if (!inputs.length) return html`${form(value)}<p class="error">Enter at least one MAC address.</p>`;
    let results: MacResult[];
    try {
      results = await lookup(c.env.ASSETS, inputs);
    } catch {
      return html`${form(value)}<p class="error">The vendor database is not available right now.</p>`;
    }
    return html`${form(value)}
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>MAC address</th><th>Vendor</th><th>Country</th><th>Block</th><th>Note</th></tr></thead>
<tbody>${results.map((r) => html`<tr><td><code>${r.mac ?? r.input}</code></td><td>${r.vendor ?? '—'}</td><td>${r.country ?? '—'}</td><td><code>${r.block ?? '—'}</code></td><td class="wrap-any">${note(r)}</td></tr>`)}</tbody></table></div>`;
  },

  apiDoc: 'GET /api/mac-lookup?mac=00:00:5E:00:53:01 (several separated by commas)',

  async api(c) {
    const inputs = (c.url.searchParams.get('mac') ?? '').split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean).slice(0, MAX);
    if (!inputs.length) return json({ error: 'Enter at least one MAC address.' }, { status: 400 });
    try {
      const results = await lookup(c.env.ASSETS, inputs);
      if (results.every((r) => r.error)) return json({ error: 'Not a MAC address. Use a format like 00:00:5E:00:53:01.' }, { status: 400 });
      return json(results);
    } catch {
      return json({ error: 'The vendor database is not available right now.' }, { status: 503 });
    }
  },

  article: html`<h2>How MAC address lookup works</h2>
<p>Every Ethernet and Wi-Fi interface has a 48-bit MAC address (also called EUI-48 or hardware address), written as six
bytes such as <code>00:00:5E:00:53:01</code>. The IEEE Registration Authority sells blocks of these addresses to
manufacturers, and the first part of every address identifies the block. Looking that part up in the public IEEE
registry tells you which company made the network chip or the device, which helps to identify unknown entries in a
router's client list, a switch's MAC table or a DHCP log.</p>
<p>This tool uses a copy of the IEEE MA-L, MA-M and MA-S registries and always picks the longest matching block, so a
small MA-S assignment wins over the larger MA-L block it may sit in.</p>

<h2>OUI, MA-L, MA-M and MA-S</h2>
<p>The IEEE assigns blocks in three sizes. The term OUI (Organizationally Unique Identifier) is still used for the
24-bit prefix of the large block.</p>
<table class="data">
<thead><tr><th>Block</th><th>Fixed prefix</th><th>Addresses per block</th><th>Typical holder</th></tr></thead>
<tbody>
<tr><td>MA-L (OUI)</td><td>24 bits (6 hex digits)</td><td>16,777,216</td><td>Large manufacturers</td></tr>
<tr><td>MA-M</td><td>28 bits (7 hex digits)</td><td>1,048,576</td><td>Mid-size manufacturers</td></tr>
<tr><td>MA-S</td><td>36 bits (9 hex digits)</td><td>4,096</td><td>Small series, embedded products</td></tr>
</tbody>
</table>
<p>Because of the smaller blocks, the first three bytes are not always enough. If the result shows a /28 or /36 block,
enter the full address to get the right vendor. Large companies often hold dozens of MA-L blocks, and after
acquisitions the registry may still list the original company name.</p>

<h2>How to look up a MAC address</h2>
<ol>
<li>Find the address. On Linux, <code>ip link show</code> lists your own interfaces and <code>ip neigh</code> shows the
devices your machine has recently talked to. On Windows, use <code>getmac /v</code> or <code>ipconfig /all</code>, and
<code>arp -a</code> for neighbors. On macOS, <code>ifconfig en0</code>. On a Cisco switch,
<code>show mac address-table</code>.</li>
<li>Paste one address per line, up to 50 at once. Any common format works.</li>
<li>Read the vendor, country and the matching registry block. A note explains addresses that have no vendor.</li>
</ol>

<h2>Accepted formats</h2>
<p>Colons (<code>00:00:5e:00:53:01</code>), dashes (<code>00-00-5E-00-53-01</code>), Cisco dots
(<code>0000.5e00.5301</code>) or no separators (<code>00005E005301</code>). Upper and lower case are both fine. A prefix
of at least three bytes is enough for an MA-L lookup. The examples on this page use the range
<code>00:00:5E:00:53:00</code> to <code>00:00:5E:00:53:FF</code>, which is reserved for documentation (RFC 7042, now
RFC 9542) and belongs to no real device.</p>

<h2>The two special bits in the first byte</h2>
<p>The two lowest bits of the first byte change the meaning of the whole address:</p>
<table class="data">
<thead><tr><th>Bit</th><th>Value 0</th><th>Value 1</th></tr></thead>
<tbody>
<tr><td>I/G (bit 0)</td><td>Individual: a single interface</td><td>Group: multicast or broadcast</td></tr>
<tr><td>U/L (bit 1)</td><td>Universally administered, assigned from an IEEE block</td><td>Locally administered, set by software or an admin</td></tr>
</tbody>
</table>
<p>In practice: if the second hex digit is <code>2</code>, <code>6</code>, <code>A</code> or <code>E</code>, the address is
locally administered unicast and has no vendor. If the first byte is odd, it is a group address.
<code>FF:FF:FF:FF:FF:FF</code> is broadcast, <code>01:00:5E</code> starts IPv4 multicast and <code>33:33</code> starts IPv6
multicast.</p>

<h2>Randomized and virtual MAC addresses</h2>
<p>Phones and laptops now use a random “private” MAC address for each Wi-Fi network to prevent tracking. iOS and iPadOS
call it Private Wi-Fi Address, Android enables per-network randomization by default since Android 10, and Windows offers
Random hardware addresses in the Wi-Fi settings. These addresses have the locally administered bit set, so a lookup
cannot return a vendor. To identify such a device, check its host name in the router's DHCP list, or temporarily turn
off the private address for that one network on the device.</p>
<p>Virtual machines, containers, bridges and VPN interfaces also generate addresses. Some hypervisors use their own MA-L
block, so a VM can show up as the hypervisor vendor rather than the hardware vendor. Router redundancy protocols use
shared virtual addresses too; VRRP for IPv4, for example, uses <code>00:00:5E:00:01:xx</code>, where <code>xx</code> is
the virtual router ID.</p>

<h2>MAC addresses inside IPv6 addresses</h2>
<p>Older IPv6 setups build the interface identifier from the MAC address (modified EUI-64): <code>FF:FE</code> is
inserted in the middle and the U/L bit is flipped. The address <code>00:00:5E:00:53:01</code> becomes the interface ID
<code>200:5eff:fe00:5301</code>, as in <code>2001:db8::200:5eff:fe00:5301</code>. If you see <code>ff:fe</code> in the
middle of an IPv6 address, you can recover the MAC: remove <code>ff:fe</code> and flip the second-lowest bit of the first
byte back (<code>02</code> becomes <code>00</code>). Most current systems use random or stable private interface IDs
instead (RFC 8981, RFC 7217).</p>

<h2>Typical uses for admins</h2>
<ul>
<li><strong>Unknown devices:</strong> an entry in the DHCP lease list without a host name becomes easier to place once
you know it is, for example, a printer or camera manufacturer.</li>
<li><strong>Switch port tracing:</strong> combine the switch MAC table with a vendor lookup to see which kind of device
sits behind a port, or to spot an unmanaged switch that shows many MACs on one port.</li>
<li><strong>Inventory and NAC:</strong> network access control and asset tools group devices by vendor to apply
policies, such as placing IoT devices in a separate VLAN.</li>
<li><strong>Bulk checks:</strong> paste up to 50 addresses from a log export and review them in one table.</li>
</ul>
<h2>Troubleshooting</h2>
<ul>
<li><strong>“Not in the IEEE registry”:</strong> the vendor bought a private listing, the block was assigned very
recently, or the address was typed incorrectly.</li>
<li><strong>Locally administered:</strong> a randomized Wi-Fi address, a VM or a manually set address. The vendor
cannot be determined from the address.</li>
<li><strong>Wrong-looking vendor:</strong> the lookup shows the maker of the network chip or module, which is often not
the brand on the device. A smart TV can report the Wi-Fi module manufacturer.</li>
<li><strong>Same device, several MACs:</strong> Wi-Fi and Ethernet each have their own address, and a device may use a
different random address per network.</li>
</ul>
<p>MAC addresses only identify devices on the local network segment. For anything beyond it, work with IP addresses:
<a href="/what-is-my-ip">check your public IP address</a>, plan address ranges with the
<a href="/subnet-calculator">subnet calculator</a>, or find the host name of an IP with a
<a href="/reverse-dns-lookup">reverse DNS lookup</a>.</p>`,

  faq: [
    { q: 'Can I find a device or its owner from a MAC address?', a: 'No. A MAC address only reveals the manufacturer of the network chip. It is not passed on beyond the local network segment, so websites cannot see it, and there is no public directory that maps MAC addresses to people.' },
    { q: 'Why is the vendor unknown?', a: 'The address is randomized or locally administered, or it belongs to a manufacturer that registered its block privately, or the block was assigned after the last registry update.' },
    { q: 'Is my MAC address sent anywhere?', a: 'Only the addresses you enter are looked up in this site’s copy of the IEEE registry. They are not stored or passed on.' },
    { q: 'What is an OUI?', a: 'The Organizationally Unique Identifier is the first 24 bits (three bytes) of a MAC address assigned by the IEEE to one organization. Today the IEEE calls this block size MA-L; smaller blocks are MA-M (28 bits) and MA-S (36 bits).' },
    { q: 'Can two devices have the same MAC address?', a: 'Manufacturers should never assign the same universal address twice, but duplicates do occur with cheap hardware, cloned addresses and virtual machines. On the same network segment a duplicate causes connection drops for both devices.' },
    { q: 'How do I find the MAC address of a device on my network?', a: 'Check the client list in your router, or ping the device and then run ip neigh on Linux or arp -a on Windows and macOS to see the MAC address next to its IP address.' },
  ],
};

export default tool;
