// Landing pages for high-volume search terms. Each reuses a tool's form with preset options and has its own
// title, explanation and FAQ. Results are rendered by the underlying tool, so landing pages are never query pages.
import { html } from '../core/html';
import type { Faq, Tool } from '../core/tool';
import { COMPARE_RESOLVERS } from '../core/transport';
import dnsLookup from './dns-lookup';
import emailSecurity from './email-security';
import whois from './whois';

interface Landing {
  slug: string;
  name: string;
  title: string;
  description: string;
  h1: string;
  lead: string;
  /** Preset form values, e.g. { type: 'MX' }. */
  defaults: Record<string, string>;
  article: ReturnType<typeof html>;
  faq: Faq[];
  examples: [string, string][];
  related: string[];
}

function landing(base: Tool, l: Landing): Tool {
  return {
    ...base,
    ...l,
    querySlug: base.slug,
    queryDefaults: l.defaults,
    isQuery: () => false,
    heavy: undefined,
    api: undefined,
    apiDoc: undefined,
    script: base.script,
    render(c) {
      // Only the presets: a landing page never runs a lookup itself (no rate limit, would be indexed).
      const url = new URL(c.url.origin + c.url.pathname);
      for (const [k, v] of Object.entries(l.defaults)) url.searchParams.set(k, v);
      return base.render({ ...c, url });
    },
  };
}

const propagation = landing(dnsLookup, {
  slug: 'dns-propagation-checker',
  name: 'DNS propagation checker',
  title: 'DNS Checker – DNS Propagation Across Public Resolvers',
  description: `Check whether a DNS change has propagated: compare A, AAAA, MX, TXT, NS and CNAME answers from ${COMPARE_RESOLVERS.length} public resolvers side by side, with TTLs.`,
  h1: 'DNS propagation checker',
  lead: `See whether ${COMPARE_RESOLVERS.length} public DNS resolvers already return your new records.`,
  defaults: { resolver: 'all', type: 'A' },
  examples: [['github.com A', 'name=github.com&type=A&resolver=all'], ['gmail.com MX', 'name=gmail.com&type=MX&resolver=all']],
  related: ['dns-lookup', 'mx-lookup', 'whois'],
  article: html`<h2>What “DNS propagation” really means</h2>
<p>Nothing is pushed out when you change a DNS record. Your DNS provider's authoritative name servers answer with the
new value as soon as the zone is reloaded. Recursive resolvers, the servers your ISP, your company or a public service
like 1.1.1.1 runs, keep the previous answer in their cache until its TTL (time to live) has counted down to zero. Only
then do they ask the authoritative servers again. “Propagation” is nothing more than those cached copies expiring, one
resolver at a time.</p>
<p>That is also why the change looks random from the outside: each resolver cached the record at a different moment,
so each one picks up the new value at a different moment. Large resolvers run many independent cache nodes, and even
two queries to the same address can be answered by different nodes.</p>

<h2>Using this checker</h2>
<p>The form above sends the same query to ${COMPARE_RESOLVERS.length} public resolvers, among them Cloudflare, Google,
Quad9 and OpenDNS, and lists their answers side by side with the remaining TTL. Answers that differ from the majority
are highlighted. Pick the record type you actually changed: A or AAAA after moving a server, MX after switching mail
providers, TXT for SPF or a verification token, NS after moving the zone to another DNS provider.</p>
<p>The TTL column tells you how long a resolver will keep its current answer. If a resolver still shows the old value
with 1200 seconds left, it will switch in at most 20 minutes, no matter what you do.</p>

<h2>How long a change takes</h2>
<table class="data">
<thead><tr><th>Change</th><th>Worst case</th><th>Why</th></tr></thead>
<tbody>
<tr><td>Edit an existing record</td><td>Old TTL of that record</td><td>Resolvers serve the cached copy until it expires.</td></tr>
<tr><td>Add a new name</td><td>SOA negative TTL</td><td>A resolver that asked before the name existed caches the NXDOMAIN (RFC 2308).</td></tr>
<tr><td>Change name servers</td><td>TTL of the NS records in the parent zone</td><td>The delegation is served by the TLD, not by your provider.</td></tr>
</tbody>
</table>

<h3>Negative caching</h3>
<p>If anyone looked up a name before you created it, resolvers remember that it did not exist. The cache time is the
smaller of the SOA record's TTL and its last field (historically “minimum”, today the negative TTL). Check it with
<code>dig example.com SOA</code>. Values between 300 and 3600 seconds are common, but some zones use a day. Avoid
testing a new host name before the record is actually in place.</p>

<h3>Name server changes</h3>
<p>Moving a domain to another DNS provider changes the NS records at the registry, and those are cached under the
TTL the TLD sets, not yours. For <code>.com</code> and <code>.net</code> the delegation TTL is 172800 seconds, two days.
During that window some resolvers still ask the old provider, so keep the old zone online and identical until the
period has passed. <code>dig +trace example.com</code> shows the delegation the TLD currently hands out, and the
<a href="/whois">WHOIS lookup</a> shows the name servers registered for the domain.</p>

<h2>Planning a change</h2>
<ol>
<li>One to two days before the change, lower the TTL of the records you will touch to 300 seconds. The old, longer
TTL must expire first, so the waiting time is the old TTL, not the new one.</li>
<li>Make the change. Keep the old server, mail host or zone running in parallel.</li>
<li>Watch the comparison here until every resolver returns the new value.</li>
<li>Raise the TTL again, for example to 3600 or 86400, to reduce query load and make you less dependent on your DNS
provider's availability.</li>
</ol>

<h2>Still seeing the old value locally</h2>
<p>If the public resolvers here already show the new record but your own machine does not, the stale copy sits closer
to you: in the operating system, the browser, the router or your ISP's resolver. Flush the local caches:</p>
<pre class="raw">Windows:   ipconfig /flushdns
macOS:     sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
Linux:     resolvectl flush-caches        (systemd-resolved)
Chrome:    chrome://net-internals/#dns  -&gt; Clear host cache</pre>
<p>Also check the hosts file (<code>/etc/hosts</code> or <code>C:\\Windows\\System32\\drivers\\etc\\hosts</code>) for an old
entry. A home router that runs its own DNS cache can be restarted, or you can query a public resolver directly with
<code>dig @1.1.1.1 example.com A</code> to rule it out.</p>`,
  faq: [
    { q: 'Why do resolvers show different IP addresses for the same domain?', a: 'Large sites and CDNs answer differently depending on where the query comes from (geo DNS), and some rotate between several addresses. Different answers only mean incomplete propagation if the old value is still among them.' },
    { q: 'Can I force propagation?', a: 'No. Caches expire on their own. Cloudflare and Google offer purge pages that refresh their public resolver’s cache for a single name, but every other resolver keeps its copy until the TTL runs out.' },
    { q: 'I lowered the TTL right before the change. Why did it not help?', a: 'Resolvers had cached the record with the old, longer TTL and do not see the lower value until that copy expires. Lower the TTL at least one full old TTL in advance.' },
    { q: 'Why does a brand-new subdomain not resolve yet?', a: 'Probably negative caching. If the name was queried before it existed, resolvers cache the NXDOMAIN for the negative TTL from the zone’s SOA record. Wait for that time or test with a resolver that has not asked yet.' },
    { q: 'How long until new name servers are used everywhere?', a: 'Up to the TTL of the delegation in the parent zone. For .com and .net that is two days. Keep the old DNS provider’s zone active and unchanged until then.' },
    { q: 'Which record type should I check?', a: 'The one you changed: A or AAAA for a new server, MX for a new mail provider, TXT for SPF or a verification code, NS after moving DNS providers.' },
  ],
});

const mx = landing(dnsLookup, {
  slug: 'mx-lookup',
  name: 'MX lookup',
  title: 'MX Lookup – Find the Mail Servers of Any Domain',
  description: 'Look up the MX records of any domain: which mail servers receive its email, in which order, and with which TTL. Live from public DNS resolvers.',
  h1: 'MX lookup',
  lead: 'Find out which mail servers receive email for a domain, and in which order.',
  defaults: { type: 'MX' },
  examples: [['gmail.com', 'name=gmail.com&type=MX'], ['outlook.com', 'name=outlook.com&type=MX']],
  related: ['email-security', 'blacklist-check', 'dns-lookup'],
  article: html`<h2>What MX records do</h2>
<p>MX (mail exchanger) records tell other mail servers where to deliver email for a domain. A sending server that has a
message for <code>user@example.com</code> asks DNS for the MX records of <code>example.com</code>, sorts them and opens
an SMTP connection on port 25 to the first host that answers. The lookup above shows exactly what such a server sees:
every MX host, its preference and the remaining TTL.</p>

<h2>Syntax and preference</h2>
<pre class="raw">example.com.  3600  IN  MX  10 mx1.example.com.
example.com.  3600  IN  MX  20 mx2.example.com.</pre>
<p>The number is the preference. Lower values are tried first, the actual numbers do not matter, only their order.
In this example <code>mx1</code> receives all mail while it is reachable; <code>mx2</code> only gets mail when
<code>mx1</code> refuses connections or times out. Records with the same preference share the load: senders pick one
of them at random. The host name must have its own A or AAAA record, which the sender resolves in a second step.</p>
<p>Backup MX hosts were common when servers were less reliable. Today they are often a weak spot: spammers deliver to
the backup on purpose because it tends to have weaker filtering. If you keep one, it needs the same spam and
recipient checks as the primary.</p>

<h2>No MX record, and null MX</h2>
<p>If a domain has no MX records at all, RFC 5321 tells senders to treat the domain's own A or AAAA record as an
implicit MX with preference 0. So <code>example.com</code> without MX but with an A record pointing at a web server will
still receive delivery attempts on that web server's port 25, which usually fail slowly after retries.</p>
<p>A domain that accepts no mail should say so with a null MX (RFC 7505): a single record with preference 0 and the
root as host, <code>example.com. MX 0 .</code>. Senders then bounce the message immediately instead of queueing it.
Combine it with <code>v=spf1 -all</code> and a DMARC reject policy so the domain cannot be used for sending either.</p>

<h2>Typical MX hosts of large providers</h2>
<table class="data">
<thead><tr><th>Provider</th><th>MX records</th></tr></thead>
<tbody>
<tr><td>Google Workspace (current setups)</td><td><code>1 smtp.google.com.</code></td></tr>
<tr><td>Google Workspace (older setups)</td><td><code>aspmx.l.google.com</code> (1), <code>alt1</code> and <code>alt2.aspmx.l.google.com</code> (5), <code>alt3</code> and <code>alt4.aspmx.l.google.com</code> (10)</td></tr>
<tr><td>Microsoft 365</td><td><code>example-com.mail.protection.outlook.com</code>: the domain with dots replaced by hyphens</td></tr>
<tr><td>Zoho Mail</td><td><code>mx.zoho.com</code>, <code>mx2.zoho.com</code>, <code>mx3.zoho.com</code> (regional variants such as <code>zoho.eu</code>)</td></tr>
<tr><td>Proton Mail</td><td><code>mail.protonmail.ch</code>, <code>mailsec.protonmail.ch</code></td></tr>
<tr><td>Fastmail</td><td><code>in1-smtp.messagingengine.com</code>, <code>in2-smtp.messagingengine.com</code></td></tr>
</tbody>
</table>
<p>Both Google sets work; you do not need to switch an existing domain to <code>smtp.google.com</code>. If you see the
MX of a filtering service instead, mail passes through that service first and is relayed to the mailbox provider
afterwards.</p>

<h2>Common mistakes</h2>
<ul>
<li><strong>MX pointing to an IP address:</strong> <code>MX 10 192.0.2.25</code> is invalid. Create a host name such
as <code>mail.example.com</code> with an A record and point the MX at the name.</li>
<li><strong>MX pointing to a CNAME:</strong> forbidden by RFC 2181. Many senders tolerate it, some do not. Point the MX
directly at the name that holds the A/AAAA record.</li>
<li><strong>MX host without address record:</strong> the MX exists, but <code>mail.example.com</code> does not resolve,
so mail is deferred and bounces after a few days. Check the host with an A lookup.</li>
<li><strong>Missing trailing dot in a zone file:</strong> <code>mail.example.com</code> without the final dot becomes
<code>mail.example.com.example.com</code> in BIND-style zones.</li>
<li><strong>Old records left in place:</strong> after a provider change, a remaining MX of the old provider still
receives part of the mail.</li>
</ul>

<h2>Command line</h2>
<pre class="raw">dig +short example.com MX
dig @8.8.8.8 example.com MX
nslookup -type=MX example.com
Resolve-DnsName example.com -Type MX</pre>
<p>After changing mail providers, compare the new MX across resolvers with the
<a href="/dns-propagation-checker">resolver comparison</a>, then make sure SPF, DKIM and DMARC match the new
provider with the <a href="/email-security">email security check</a>. Whether the MX host accepts connections on port 25
can be tested with the <a href="/port-checker">port checker</a>.</p>`,
  faq: [
    { q: 'Can an MX record point to an IP address?', a: 'No. MX records must point to a host name that has its own A or AAAA record. Pointing to a CNAME is also not allowed by the standard, even though many senders tolerate it.' },
    { q: 'Why are there several MX records with the same priority?', a: 'Senders pick one of them at random, which spreads the load. They only fall back to a higher number when all hosts with the lowest number fail.' },
    { q: 'What happens if a domain has no MX record?', a: 'Senders fall back to the domain’s A or AAAA record and try to deliver there. To reject mail cleanly, publish a null MX record (0 .) instead.' },
    { q: 'Which MX records does Google Workspace use?', a: 'New setups use a single record, 1 smtp.google.com. Domains set up earlier often use aspmx.l.google.com with four alt hosts; both are valid.' },
    { q: 'How long until a new MX record takes effect?', a: 'Up to the TTL of the old MX records. Senders that still have the old records cached keep delivering to the old provider, so keep the old mailboxes active for that time.' },
    { q: 'My MX records are correct but mail does not arrive. What else?', a: 'Check whether port 25 on the MX host is reachable, whether the server is on a blocklist, and whether the mailbox provider has the domain verified and active.' },
  ],
});

const txt = landing(dnsLookup, {
  slug: 'txt-lookup',
  name: 'TXT lookup',
  title: 'TXT Record Lookup – Check Domain Verification Records',
  description: 'Look up the TXT records of any domain: SPF, domain verification codes for Google, Microsoft and others, and more. Shows every record with TTL.',
  h1: 'TXT record lookup',
  lead: 'Show all TXT records of a domain, such as SPF and domain verification codes.',
  defaults: { type: 'TXT' },
  examples: [['github.com', 'name=github.com&type=TXT'], ['_dmarc.github.com', 'name=_dmarc.github.com&type=TXT']],
  related: ['spf-checker', 'dkim-checker', 'dmarc-checker'],
  article: html`<h2>What TXT records are</h2>
<p>A TXT record holds arbitrary text attached to a DNS name. The original idea was human-readable notes; today almost
every TXT record carries a machine-readable setting that some service looks up: email authentication policies,
ownership proofs for cloud services, or pointers to security policies. A name can have any number of TXT records, and
a lookup returns all of them at once. The tool above lists each one with its TTL.</p>

<h2>Strings, length and quoting</h2>
<p>On the wire a TXT record is a list of character strings, each at most 255 bytes long. Values longer than that, such
as 2048-bit DKIM keys, must be split into several strings inside one record. Consumers join them without any
separator:</p>
<pre class="raw">sel1._domainkey.example.com. TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqh...first 255 bytes" "...rest of the key"</pre>
<p>That is a single record, not two. Two separate records with half a key each would be broken. Most DNS hosting
panels split long values automatically when you paste them in one piece; others expect you to enter the quoted
chunks yourself. Check the result after saving.</p>
<p>Quoting is the most common source of errors. Some panels add quotes automatically, so pasting
<code>"v=spf1 -all"</code> with quotes ends up as a value that literally contains quote characters. Others require the
quotes. If the lookup shows doubled or escaped quotes (<code>\\"</code>), remove the quotes in the panel. Spaces inside
a value are fine; a space accidentally placed between two chunks is not, because it becomes part of the joined text.</p>

<h2>What you will find in TXT records</h2>
<table class="data">
<thead><tr><th>Name</th><th>Typical content</th><th>Purpose</th></tr></thead>
<tbody>
<tr><td><code>example.com</code></td><td><code>v=spf1 ...</code></td><td>SPF: servers allowed to send mail for the domain</td></tr>
<tr><td><code>example.com</code></td><td><code>google-site-verification=...</code>, <code>MS=ms...</code>, <code>facebook-domain-verification=...</code></td><td>Ownership proof for Google, Microsoft 365, Meta and many other services</td></tr>
<tr><td><code>selector._domainkey.example.com</code></td><td><code>v=DKIM1; k=rsa; p=...</code></td><td>DKIM public key for one signing selector</td></tr>
<tr><td><code>_dmarc.example.com</code></td><td><code>v=DMARC1; p=...</code></td><td>DMARC policy and report addresses</td></tr>
<tr><td><code>_mta-sts.example.com</code></td><td><code>v=STSv1; id=...</code></td><td>Announces an MTA-STS policy (RFC 8461)</td></tr>
<tr><td><code>_smtp._tls.example.com</code></td><td><code>v=TLSRPTv1; rua=...</code></td><td>Where to send TLS delivery reports (RFC 8460)</td></tr>
<tr><td><code>default._bimi.example.com</code></td><td><code>v=BIMI1; l=...; a=...</code></td><td>Brand logo for supporting inboxes</td></tr>
</tbody>
</table>
<p>Only the records on the domain itself show up when you look up <code>example.com</code>. DKIM, DMARC, MTA-STS and
the others live on their own names: enter the full name, for example <code>_dmarc.example.com</code>, to see them.
DKIM selectors cannot be listed through DNS; take the <code>s=</code> value from the <code>DKIM-Signature</code> header
of a sent message.</p>
<p>To evaluate rather than just read these records, use the dedicated checks: the <a href="/spf-checker">SPF checker</a>
counts DNS lookups and validates the syntax, the <a href="/dmarc-checker">DMARC checker</a> explains the policy, and the
<a href="/email-security">email security check</a> tests SPF, DKIM, DMARC, MTA-STS, TLS-RPT and BIMI together.</p>

<h2>Domain verification records</h2>
<p>Services such as Google Search Console, Microsoft 365 or Atlassian ask you to publish a token to prove you control
the domain. Typical problems when the service says it cannot find it:</p>
<ul>
<li><strong>Wrong host name:</strong> many DNS panels append the domain automatically. Entering
<code>example.com</code> in the name field creates <code>example.com.example.com</code>. Use <code>@</code> or leave the
field empty for the domain itself.</li>
<li><strong>Token pasted into the wrong record type,</strong> for example as a CNAME, or into a different zone than the
one the domain's NS records actually point to. Check with a <a href="/ns-lookup">NS lookup</a> which provider
is authoritative.</li>
<li><strong>Negative caching:</strong> if the service checked before the record existed, its resolver may cache the
empty answer for the SOA negative TTL.</li>
</ul>
<p>Verification tokens can usually be removed once the service has confirmed ownership, but some services check
periodically and lose verification if the token disappears. Check the provider's documentation before cleaning up.</p>

<h2>Command line</h2>
<pre class="raw">dig +short example.com TXT
dig +short _dmarc.example.com TXT
nslookup -type=TXT example.com
Resolve-DnsName example.com -Type TXT</pre>`,
  faq: [
    { q: 'Can a domain have several TXT records?', a: 'Yes, and most do: SPF and several verification tokens usually sit side by side. Only SPF is special: there must be exactly one record starting with v=spf1 on a name.' },
    { q: 'What is the maximum length of a TXT record?', a: 'Each string inside a record is limited to 255 bytes, but a record may contain several strings that are joined together. In practice, keep records well below 1 to 2 KB so answers stay small.' },
    { q: 'Why does my DKIM key appear as several quoted parts?', a: 'Keys longer than 255 bytes are split into several strings within one record. Receivers join them without spaces, so this is correct as long as it is one record and no extra spaces were added.' },
    { q: 'Why does my new verification code not show up?', a: 'Check the exact host name your provider asked for, whether the panel appended the domain twice, and whether you edited the zone at the provider your NS records actually point to. Then wait for any cached negative answer to expire.' },
    { q: 'Why do I not see the DMARC record when I look up my domain?', a: 'DMARC is published at _dmarc.example.com, not on the domain itself. Enter that full name, or use the DMARC checker.' },
    { q: 'Are TXT records public?', a: 'Yes. Anyone can query them, so never put secrets, passwords or internal notes in TXT records.' },
  ],
});

const reverse = landing(dnsLookup, {
  slug: 'reverse-dns-lookup',
  name: 'Reverse DNS lookup',
  title: 'Reverse DNS Lookup – Find the Host Name of an IP',
  description: 'Reverse DNS (PTR) lookup for any IPv4 or IPv6 address: find the host name behind an IP, and check the PTR records of mail servers.',
  h1: 'Reverse DNS lookup',
  lead: 'Find the host name that belongs to an IPv4 or IPv6 address.',
  defaults: { type: 'PTR' },
  examples: [['8.8.8.8', 'name=8.8.8.8'], ['1.1.1.1', 'name=1.1.1.1'], ['2606:4700:4700::1111', 'name=2606:4700:4700::1111']],
  related: ['what-is-my-ip', 'whois', 'asn-lookup'],
  article: html`<h2>How reverse DNS works</h2>
<p>Forward DNS turns a name into an address. Reverse DNS answers the opposite question: which host name belongs to
this IP address? The answer is stored in a PTR record under one of two special zones, <code>in-addr.arpa</code> for
IPv4 and <code>ip6.arpa</code> for IPv6. Enter an address in the form above and the PTR name is built for you.</p>

<h2>Building the PTR name</h2>
<p>DNS names get more specific from right to left, IP addresses from left to right. To make the address fit the DNS
tree, it is written backwards. For IPv4 the four octets are reversed:</p>
<pre class="raw">192.0.2.1   -&gt;  1.2.0.192.in-addr.arpa.  PTR  mail.example.com.</pre>
<p>For IPv6 the address is first written out in full, then every hex digit (nibble) becomes its own label, in reverse
order. <code>2001:db8::1</code> expands to <code>2001:0db8:0000:0000:0000:0000:0000:0001</code>, which gives:</p>
<pre class="raw">1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.</pre>
<p>Because of this layout, a <code>/24</code> in IPv4 maps to exactly one reverse zone, and IPv6 delegation works on
4-bit boundaries such as <code>/48</code> or <code>/56</code>. Smaller IPv4 blocks than a /24 are delegated with CNAME
tricks described in RFC 2317, which is why some PTR lookups show a CNAME before the PTR record.</p>

<h2>Who controls PTR records</h2>
<p>The reverse zone belongs to whoever holds the address block, not to the owner of the domain in the PTR value.
Regional internet registries delegate <code>in-addr.arpa</code> and <code>ip6.arpa</code> zones to ISPs and hosting
providers, who in turn manage the records for their customers. In practice:</p>
<ul>
<li><strong>Cloud servers and VPS:</strong> set the reverse DNS name in the hosting provider's control panel or API,
often in the network or IP settings of the server.</li>
<li><strong>Dedicated servers and business lines:</strong> ask the provider, or have them delegate the reverse zone to
your own name servers if you hold a larger block.</li>
<li><strong>Home connections:</strong> usually not changeable; the provider assigns generic names.</li>
</ul>
<p>Your domain registrar and your DNS hosting provider cannot set a PTR record for an address they do not own. To find
out who holds an address, use the <a href="/whois">WHOIS lookup</a> or the <a href="/asn-lookup">ASN lookup</a>.</p>

<h2>Forward-confirmed reverse DNS</h2>
<p>Anyone who controls a reverse zone can put any name into a PTR record, including names of domains they do not own.
That is why mail servers check both directions: the PTR of the connecting IP must point to a name, and that name's A
or AAAA record must point back to the same IP. This is called forward-confirmed reverse DNS (FCrDNS).</p>
<pre class="raw">dig +short -x 192.0.2.1          -&gt; mail.example.com.
dig +short mail.example.com A    -&gt; 192.0.2.1</pre>
<p>If both lookups match, the check passes. Large mailbox providers such as Gmail and Yahoo require valid forward and
reverse DNS for sending IPs, and many smaller servers reject or heavily penalize mail from addresses without it. For a
mail server, use a dedicated name like <code>mail.example.com</code>, make it match the name the server announces in
its SMTP greeting (HELO/EHLO), and keep both records in sync after any IP change.</p>

<h2>Generic names</h2>
<p>Many ISPs fill their reverse zones automatically with names that encode the address, for example
<code>192-0-2-1.dyn.provider.example</code> or names containing <code>dsl</code>, <code>dynamic</code> or
<code>pool</code>. Spam filters treat such names as end-user connections that should not send mail directly. A server
sending mail needs a specific name, not a generic one, even if FCrDNS technically passes.</p>
<p>For troubleshooting, a PTR name often reveals the provider, region or even the router of an address. It is set by
the address owner, though, and can be out of date or misleading.</p>

<h2>Command line</h2>
<pre class="raw">dig -x 192.0.2.1
dig -x 2001:db8::1
nslookup 192.0.2.1
Resolve-DnsName 192.0.2.1</pre>
<p>Your own connection's reverse DNS name is shown on <a href="/what-is-my-ip">What is my IP</a>. If the IP belongs to a
mail server, also check it with the <a href="/blacklist-check">blacklist check</a>.</p>`,
  faq: [
    { q: 'Why does my IP have no reverse DNS name?', a: 'Not every provider sets PTR records, especially for IPv6. For servers, set one in the hosting provider’s panel; for home connections the provider decides.' },
    { q: 'Can I set the PTR record at my domain registrar?', a: 'No. PTR records live in the reverse zone of the IP block, which belongs to the provider that owns the addresses. Set it with your hosting or internet provider.' },
    { q: 'What is forward-confirmed reverse DNS?', a: 'The PTR record of an IP points to a host name, and that host name’s A or AAAA record points back to the same IP. Mail servers use this check to reject senders with forged or missing reverse DNS.' },
    { q: 'Can an IP address have several PTR records?', a: 'Technically yes, but it causes inconsistent results and some checks fail. Use exactly one PTR record per address.' },
    { q: 'Can reverse DNS show which websites run on an IP?', a: 'No. A PTR record contains one name chosen by the address owner, not the websites hosted there.' },
    { q: 'How do I see my own reverse DNS name?', a: 'Open What is my IP: it shows the reverse DNS name of your current connection.' },
  ],
});

const spf = landing(emailSecurity, {
  slug: 'spf-checker',
  name: 'SPF checker',
  title: 'SPF Checker – Validate SPF Records & DNS Lookup Limit',
  description: 'Check the SPF record of any domain: syntax, all qualifier, every include with its DNS lookup count against the limit of 10, plus DKIM and DMARC.',
  h1: 'SPF record checker',
  lead: 'Validate a domain’s SPF record and count its DNS lookups against the limit of 10.',
  defaults: {},
  examples: [['github.com', 'domain=github.com'], ['gmail.com', 'domain=gmail.com']],
  related: ['dkim-checker', 'dmarc-checker', 'email-security'],
  article: html`<h2>How SPF works</h2>
<p>SPF (Sender Policy Framework, RFC 7208) is a TXT record on your domain that lists the servers allowed to send its
email. A receiving server takes the domain from the envelope sender, the address given in <code>MAIL FROM</code> during
the SMTP session and later shown as <code>Return-Path</code>, fetches that domain's SPF record and checks whether the
connecting IP matches. It does not look at the <code>From:</code> header your users see. Tying the two together is the
job of <a href="/dmarc-checker">DMARC</a>.</p>
<p>The checker above fetches the record, validates the syntax, follows every <code>include</code> and counts the DNS
lookups, so you can see which part of the record uses up the budget.</p>

<h2>Syntax</h2>
<p>A record starts with <code>v=spf1</code>, followed by mechanisms that are evaluated left to right. The first one
that matches decides the result.</p>
<pre class="raw">v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 mx include:_spf.example.net -all</pre>
<table class="data">
<thead><tr><th>Mechanism</th><th>Matches if the sending IP</th><th>DNS lookups</th></tr></thead>
<tbody>
<tr><td><code>ip4:</code>, <code>ip6:</code></td><td>is inside the given address or range</td><td>0</td></tr>
<tr><td><code>a</code>, <code>a:host</code></td><td>is an A/AAAA address of the domain or host</td><td>1</td></tr>
<tr><td><code>mx</code></td><td>is an address of one of the domain's MX hosts</td><td>1 (more than 10 MX hosts cause a permerror)</td></tr>
<tr><td><code>include:domain</code></td><td>passes the SPF record of another domain</td><td>1 plus everything inside</td></tr>
<tr><td><code>exists:domain</code></td><td>(after macro expansion) the given name resolves to any A record</td><td>1</td></tr>
<tr><td><code>ptr</code></td><td>has a matching reverse DNS name; deprecated, do not use</td><td>1</td></tr>
<tr><td><code>all</code></td><td>always matches; goes last</td><td>0</td></tr>
</tbody>
</table>
<p>Each mechanism can carry a qualifier: <code>+</code> pass (the default), <code>-</code> fail, <code>~</code> softfail,
<code>?</code> neutral. The modifier <code>redirect=domain</code> hands evaluation over to another domain's record and
also costs a lookup.</p>

<h2>The lookup limits</h2>
<p>Evaluating a record may trigger at most 10 DNS-querying terms: <code>include</code>, <code>a</code>, <code>mx</code>,
<code>ptr</code>, <code>exists</code> and <code>redirect</code>, counted across all nested includes. A record that needs
more returns a permanent error (permerror), and receivers treat SPF as failed for every message, including legitimate
ones. Each additional SaaS tool you add with its own include eats into the same budget.</p>
<p>The second limit is the void lookup limit: RFC 7208 recommends that receivers stop after 2 lookups that return no
records or NXDOMAIN. An include that points to a domain without an SPF record, or to one that no longer exists, is
worse: it makes the whole evaluation return permerror (RFC 7208, section 5.2). Remove leftovers from services you
stopped using.</p>

<h2>Only one record</h2>
<p>A name may have only one TXT record that starts with <code>v=spf1</code>. When a new provider tells you to “add an
SPF record”, merge its include into the existing record instead of creating a second one. Two records cause a
permerror, just like too many lookups.</p>

<h2>~all or -all</h2>
<p><code>-all</code> tells receivers to reject mail from unlisted servers; <code>~all</code> asks them to accept it but
treat it as suspicious. With a DMARC policy in place, the DMARC result decides what happens, and many large senders
use <code>~all</code> so that forwarded mail is not rejected on SPF alone. Without DMARC, <code>-all</code> gives
stronger protection. <code>?all</code> provides no protection, and <code>+all</code> authorizes every IP on the
internet.</p>

<h2>Records for common providers</h2>
<table class="data">
<thead><tr><th>Provider</th><th>Include</th></tr></thead>
<tbody>
<tr><td>Google Workspace</td><td><code>include:_spf.google.com</code></td></tr>
<tr><td>Microsoft 365</td><td><code>include:spf.protection.outlook.com</code></td></tr>
</tbody>
</table>
<p>A domain using Microsoft 365 plus its own server at 192.0.2.10 would publish
<code>v=spf1 ip4:192.0.2.10 include:spf.protection.outlook.com -all</code>. Newsletter, CRM and ticket systems document
their own includes; some send with their own envelope domain and need no SPF entry from you at all, only DKIM.</p>

<h2>Flattening</h2>
<p>Flattening replaces includes with the <code>ip4</code> and <code>ip6</code> ranges they currently resolve to, which
brings the lookup count down. The catch: providers change their sending ranges without notice, and a flattened copy
silently goes stale, so mail from new provider IPs starts to fail. Only flatten with automation that refreshes the
list regularly, or for providers that publish stable ranges. Removing unused includes and using a subdomain for bulk
mail are safer first steps.</p>
<p>A domain that sends no email should publish <code>v=spf1 -all</code>, so nobody can pass SPF in its name.</p>`,
  faq: [
    { q: 'Should I use -all or ~all?', a: 'With DMARC in place, ~all is common and safe, because the DMARC policy decides. Without DMARC, -all gives stronger protection.' },
    { q: 'Does SPF check the From address I see in my mail program?', a: 'No. SPF checks the envelope sender (Return-Path). DMARC ties SPF and DKIM to the visible From domain.' },
    { q: 'What counts toward the 10-lookup limit?', a: 'include, a, mx, ptr, exists and redirect, including those inside included records. ip4, ip6 and all do not count.' },
    { q: 'Can I have two SPF records if I use two providers?', a: 'No. Two records starting with v=spf1 cause a permanent error. Merge both includes into one record, for example v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all.' },
    { q: 'What is SPF flattening?', a: 'Replacing includes with the IP ranges they contain to stay under 10 lookups. It works, but the list must be updated whenever the provider changes its addresses.' },
    { q: 'Why does SPF fail for forwarded mail?', a: 'The forwarding server sends from its own IP, which is not in your SPF record. DKIM survives forwarding in most cases, which is why DMARC passes if either SPF or DKIM is aligned.' },
  ],
});

const dmarc = landing(emailSecurity, {
  slug: 'dmarc-checker',
  name: 'DMARC checker',
  title: 'DMARC Checker – Check DMARC Policy & Reporting',
  description: 'Check the DMARC record of any domain: policy (none, quarantine, reject), reporting addresses, alignment and percentage, together with SPF and DKIM.',
  h1: 'DMARC record checker',
  lead: 'See whether a domain has a DMARC policy, how strict it is and where reports go.',
  defaults: {},
  examples: [['google.com', 'domain=google.com'], ['github.com', 'domain=github.com']],
  related: ['spf-checker', 'dkim-checker', 'email-security'],
  article: html`<h2>What DMARC does</h2>
<p>DMARC (Domain-based Message Authentication, Reporting and Conformance, RFC 9989, which replaced RFC 7489 in 2026) is a TXT record at
<code>_dmarc.example.com</code>. It closes the gap that SPF and DKIM leave open: both can pass for a domain that has
nothing to do with the address in the <code>From:</code> header. DMARC requires that at least one of them passes
<em>and</em> is aligned with the From domain, tells receivers what to do with mail that fails, and asks them to send
reports about everything they saw.</p>
<p>The checker above reads the record, explains each tag and shows SPF and DKIM next to it, since DMARC depends on
both.</p>

<h2>Tags</h2>
<pre class="raw">v=DMARC1; p=quarantine; sp=reject; rua=mailto:dmarc@example.com; adkim=r; aspf=r; fo=1</pre>
<table class="data">
<thead><tr><th>Tag</th><th>Meaning</th><th>Default</th></tr></thead>
<tbody>
<tr><td><code>v</code></td><td>Version, must be <code>DMARC1</code> and come first</td><td>required</td></tr>
<tr><td><code>p</code></td><td>Policy: <code>none</code>, <code>quarantine</code> or <code>reject</code></td><td>required</td></tr>
<tr><td><code>sp</code></td><td>Policy for subdomains</td><td>value of <code>p</code></td></tr>
<tr><td><code>rua</code></td><td>Addresses for aggregate reports, as <code>mailto:</code> URIs separated by commas</td><td>none</td></tr>
<tr><td><code>ruf</code></td><td>Addresses for failure (forensic) reports; few receivers send them</td><td>none</td></tr>
<tr><td><code>pct</code></td><td>Percentage of failing mail the policy applies to</td><td>100</td></tr>
<tr><td><code>adkim</code></td><td>DKIM alignment: <code>r</code> relaxed or <code>s</code> strict</td><td><code>r</code></td></tr>
<tr><td><code>aspf</code></td><td>SPF alignment: <code>r</code> relaxed or <code>s</code> strict</td><td><code>r</code></td></tr>
<tr><td><code>fo</code></td><td>When to send failure reports: <code>0</code> all fail, <code>1</code> any fails, <code>d</code> DKIM fails, <code>s</code> SPF fails</td><td><code>0</code></td></tr>
</tbody>
</table>
<p>DMARCbis, published in 2026 as RFC 9989, drops <code>pct</code> in favor of a simpler <code>t=y</code> (testing)
flag and adds <code>np</code> for subdomains that do not exist. Receivers still honor <code>pct</code> in existing
records, but new records should not rely on it.</p>

<h2>Alignment</h2>
<p>SPF authenticates the envelope sender domain, DKIM the <code>d=</code> domain in the signature. Alignment compares
those with the From domain. In relaxed mode, the organizational domains must match: mail from
<code>news.example.com</code> signed with <code>d=example.com</code> is aligned. In strict mode the names must be
identical. Relaxed is the right choice for nearly everyone. A message from <code>example.com</code> sent through a
newsletter service that signs only with its own domain passes DKIM, but not aligned, and therefore fails DMARC.
Configure custom DKIM for every such service.</p>

<h2>Rollout plan</h2>
<ol>
<li>Publish <code>p=none</code> with a <code>rua</code> address. Nothing is blocked; you start receiving reports.</li>
<li>For a few weeks, read the reports and list every source that sends as your domain: mail server, Microsoft 365 or
Google Workspace, newsletter tool, CRM, invoicing, ticket system. Fix SPF and DKIM for each legitimate one.</li>
<li>Move to <code>p=quarantine</code>. If you are unsure, add <code>t=y</code> first: receivers then report as before
but apply the next lower policy.</li>
<li>When the reports show only spoofed mail failing, switch to <code>p=reject</code>. Keep reading reports afterwards,
because new services get added without anyone telling IT.</li>
</ol>

<h2>Aggregate reports</h2>
<p>Receivers such as Google, Microsoft and Yahoo send aggregate reports, usually once a day, as gzip- or
zip-compressed XML attachments. Each report lists source IPs, message counts and the SPF, DKIM and alignment results.
They contain no message content. A busy domain receives many reports a day, so use a dedicated mailbox and a parser
or a DMARC report service instead of reading XML by hand.</p>
<p>If the <code>rua</code> address is on another domain, for example a report service, that domain must authorize it.
For reports about <code>example.com</code> sent to <code>example.net</code>, the receiving side publishes:</p>
<pre class="raw">example.com._report._dmarc.example.net.  TXT  "v=DMARC1"</pre>
<p>Without that record, receivers drop the external address. Report services set this up for their customers.</p>

<h2>Bulk sender requirements</h2>
<p>Since February 2024, Google and Yahoo require bulk senders to publish a DMARC record, at least <code>p=none</code>,
and to send with a From domain that aligns with SPF or DKIM. The <a href="/email-security">email security check</a>
covers the full list of requirements.</p>

<h2>Common mistakes</h2>
<ul>
<li>Record published on the domain instead of <code>_dmarc.example.com</code>, or more than one DMARC record.</li>
<li>Missing <code>mailto:</code> in front of the report address.</li>
<li>Jumping straight to <code>p=reject</code> without reading reports, which blocks your own invoices or newsletters.</li>
<li>Staying on <code>p=none</code> forever: it only monitors, spoofed mail is still delivered.</li>
<li>Forgetting parked domains: a domain that sends no mail should have <code>p=reject</code> and
<code>v=spf1 -all</code>.</li>
</ul>`,
  faq: [
    { q: 'Do I need DMARC?', a: 'Yes, if your domain sends email. Google and Yahoo require it for bulk senders, and without a policy anyone can spoof your From address with little resistance.' },
    { q: 'Is p=none enough?', a: 'No. p=none only collects reports; spoofed mail is still delivered. It is the right first step, not the goal.' },
    { q: 'Will p=reject break my email?', a: 'Only for services that send in your name without aligned SPF or DKIM. Read the reports under p=none first and fix those senders before tightening the policy.' },
    { q: 'What is the difference between relaxed and strict alignment?', a: 'Relaxed accepts any subdomain of the same organizational domain, for example mail.example.com for example.com. Strict requires an exact match. Relaxed is the default and fits most domains.' },
    { q: 'Where do DMARC reports go?', a: 'To the addresses in the rua tag. They are compressed XML files; a DMARC report service or a parser makes them readable.' },
    { q: 'Why do I receive no reports for my external rua address?', a: 'The receiving domain must authorize it with a TXT record v=DMARC1 at yourdomain._report._dmarc.reportdomain. Without it, receivers ignore the address.' },
  ],
});

const dkim = landing(emailSecurity, {
  slug: 'dkim-checker',
  name: 'DKIM checker',
  title: 'DKIM Checker – Find and Validate DKIM Records',
  description: 'Look up the DKIM keys of a domain: common selectors or your own, key type and length, revoked keys, plus the SPF and DMARC records it depends on.',
  h1: 'DKIM record checker',
  lead: 'Find a domain’s DKIM public keys by selector and check that they are valid.',
  defaults: {},
  examples: [['github.com', 'domain=github.com'], ['outlook.com', 'domain=outlook.com']],
  related: ['dmarc-checker', 'spf-checker', 'email-headers'],
  article: html`<h2>What DKIM proves</h2>
<p>DKIM (DomainKeys Identified Mail, RFC 6376) lets a sending server sign each message with a private key. The
signature covers selected header fields and the body and travels in a <code>DKIM-Signature</code> header. The receiver
fetches the matching public key from DNS and verifies the signature. A valid signature proves two things: the signing
domain took responsibility for the message, and the signed parts were not changed on the way.</p>
<p>Enter a domain above. The check tries a list of common selectors; enter your own selector in the second field to
look up one specific key.</p>

<h2>Selectors and where the key lives</h2>
<p>A domain can have many DKIM keys at the same time, one per selector. Every service that sends in your name usually
gets its own. The public key is a TXT record at a name built from the selector and the domain:</p>
<pre class="raw">selector._domainkey.example.com.  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."</pre>
<p>DNS offers no way to list the selectors of a domain, so no checker can find every key. Unknown selectors have to be
taken from a real message.</p>

<h3>Finding the selector in a received message</h3>
<p>Open the full headers of a message sent from the domain (“Show original” or “View source” in most mail programs)
and look for the signature header:</p>
<pre class="raw">DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;
 s=sel2024; h=from:to:subject:date:message-id; bh=...; b=...</pre>
<p><code>d=</code> is the signing domain and <code>s=</code> the selector, so this key lives at
<code>sel2024._domainkey.example.com</code>. A message can carry several signatures, for example one for your domain
and one for the sending service's own domain. The <a href="/email-headers">email header analyzer</a> extracts them.</p>

<h2>Key record tags</h2>
<table class="data">
<thead><tr><th>Tag</th><th>Meaning</th></tr></thead>
<tbody>
<tr><td><code>v</code></td><td>Version, <code>DKIM1</code>. Optional, but if present it must come first.</td></tr>
<tr><td><code>k</code></td><td>Key type: <code>rsa</code> (the default) or <code>ed25519</code> (RFC 8463).</td></tr>
<tr><td><code>p</code></td><td>The public key in base64. Empty means the key is revoked.</td></tr>
<tr><td><code>h</code></td><td>Accepted hash algorithms, for example <code>sha256</code>. Rarely set.</td></tr>
<tr><td><code>t</code></td><td>Flags. <code>y</code> marks a key in testing mode.</td></tr>
</tbody>
</table>

<h2>Key length</h2>
<p>RFC 8301 requires RSA signing keys of at least 1024 bits and recommends 2048; receivers must not treat signatures
with shorter keys as valid. 1024-bit keys still verify, but 2048 is the sensible choice for every new key.</p>
<p>A 2048-bit key is roughly 400 characters of base64, more than the 255-byte limit of a single TXT string. It must be
stored as several strings within one record, which receivers join without spaces. Most DNS panels split long values
automatically; some expect the chunks entered by hand. If a key shows up as invalid, look for an added space between
chunks or a key that ended up in two separate records.</p>
<p>Ed25519 keys are much shorter, but not every receiver verifies them, so they are used in addition to an RSA
signature, not instead of it.</p>

<h2>Selectors of large providers</h2>
<table class="data">
<thead><tr><th>Provider</th><th>Selector and record</th></tr></thead>
<tbody>
<tr><td>Google Workspace</td><td><code>google</code> by default; a TXT record generated in the Admin console</td></tr>
<tr><td>Microsoft 365</td><td><code>selector1</code> and <code>selector2</code>, both CNAMEs pointing to names under your tenant's <code>onmicrosoft.com</code> domain</td></tr>
</tbody>
</table>
<p>With CNAMEs, the provider keeps the key and can rotate it without any change to your zone. Copy the exact targets
from the provider's admin portal. The lookup follows the CNAME and shows the key at its end.</p>

<h2>DKIM and DMARC alignment</h2>
<p>A valid signature alone does not satisfy DMARC. The <code>d=</code> domain must also align with the domain in the
From header: the same organizational domain in relaxed mode, the identical name in strict mode. A newsletter tool that
signs with its own domain produces a valid but unaligned signature. Set up custom DKIM in every such service so that it
signs as your domain. The <a href="/dmarc-checker">DMARC checker</a> shows the policy and alignment settings.</p>

<h2>Rotating and revoking keys</h2>
<ol>
<li>Generate a new key pair and publish the public key under a new selector, for example one with a date in its
name.</li>
<li>Switch the signing server to the new selector once the record resolves everywhere.</li>
<li>Keep the old record published for a few days, so delayed messages can still be verified.</li>
<li>Revoke the old key by publishing the record with an empty <code>p=</code>, or delete it.</li>
</ol>
<p>An empty <code>p=</code> tells receivers that signatures made with this key must fail. The checker lists such
selectors as revoked. Domains that send no mail sometimes publish a revoked key on purpose.</p>`,
  faq: [
    { q: 'Why does the checker not find my DKIM key?', a: 'DKIM keys can only be found when the selector is known. If your provider uses a selector that is not on the common list, take the s= value from the DKIM-Signature header of a sent message and enter it in the selector field.' },
    { q: 'Where do I find my DKIM selector?', a: 'In the headers of a message sent from your domain: the DKIM-Signature header contains s= (the selector) and d= (the signing domain). The admin console of your mail provider usually shows it as well.' },
    { q: 'Should I use a 1024-bit or a 2048-bit key?', a: '2048 bits. 1024 is the minimum receivers still accept, and 2048 is the recommended size for new keys. The longer key has to be split into several strings within one TXT record.' },
    { q: 'What does an empty p= mean?', a: 'The key has been revoked. Receivers treat signatures made with that selector as failed. It is a normal final step of key rotation.' },
    { q: 'Can a domain have several DKIM keys?', a: 'Yes, one per selector. Each sending service usually gets its own selector, and during a rotation old and new keys exist side by side.' },
    { q: 'Does DKIM survive forwarding?', a: 'Usually, as long as the signed headers and the body stay unchanged. Mailing lists that add a footer or change the subject break the signature.' },
  ],
});

const ns = landing(dnsLookup, {
  slug: 'ns-lookup',
  name: 'NS lookup',
  title: 'NS Lookup – Find the Name Servers of a Domain',
  description: 'Look up the NS records of any domain: which authoritative name servers serve its zone, with TTL. Useful after moving DNS or for delegation errors.',
  h1: 'NS lookup',
  lead: 'Find out which authoritative name servers answer for a domain.',
  defaults: { type: 'NS' },
  examples: [['github.com', 'name=github.com&type=NS'], ['wikipedia.org', 'name=wikipedia.org&type=NS']],
  related: ['nslookup-online', 'dnssec-check', 'dns-propagation-checker'],
  article: html`<h2>What NS records do</h2>
<p>NS records name the authoritative name servers of a zone: the servers that hold the actual records and answer
queries for them. Every lookup for a name in the zone ends at one of these servers. If they are wrong or unreachable,
nothing in the zone resolves, however correct the A, MX or TXT records are.</p>
<p>The lookup above asks a public resolver for the NS records of a name. For a domain, that is the list of servers that
currently serve its zone.</p>

<h2>Delegation: parent and child</h2>
<p>NS records exist in two places. The parent zone, for example the <code>.com</code> registry, holds a copy that
delegates the domain to its name servers. The domain's own zone lists NS records at its apex as well. Resolvers find
the domain through the parent's copy and usually prefer the child's set once they reach the authoritative servers.</p>
<pre class="raw">; in the .com zone (parent)
example.com.  172800  IN  NS  ns1.example.net.
example.com.  172800  IN  NS  ns2.example.net.

; in the example.com zone (child)
example.com.   86400  IN  NS  ns1.example.net.
example.com.   86400  IN  NS  ns2.example.net.</pre>
<p>Both sets should list the same servers. The parent copy is set at your registrar, the child copy in your DNS
hosting panel. When they differ, some resolvers use one set and some the other, and answers start to depend on where
you ask.</p>

<h3>Glue records</h3>
<p>If a domain's name servers sit inside the domain itself, such as <code>ns1.example.com</code> for
<code>example.com</code>, resolvers face a loop: to reach the server they would need the zone it serves. The parent
therefore also publishes the servers' IP addresses, called glue records. You register them at the registrar, often
under a heading like “host records” or “child name servers”. Update them whenever such a server changes its IP.</p>

<h3>Lame delegation</h3>
<p>A delegation is lame when a listed server does not answer authoritatively for the zone: it refuses the query,
times out or simply does not have the zone configured. A typical cause is a move to a new DNS provider where an old
server stayed in the NS set, or the zone was deleted at the old provider too early. Resolvers retry other servers, so
lookups become slow and sometimes fail.</p>

<h2>How many name servers</h2>
<p>RFC 1034 requires at least two name servers per zone, and RFC 2182 advises placing them in different networks and
locations so that one outage does not take the whole zone down. Most DNS providers hand out two to four names, often
under different top-level domains. Extra servers only help if they are really independent; four names in the same
network add little.</p>

<h2>Changing name servers</h2>
<ol>
<li>Create the complete zone at the new provider and compare every record with the old one.</li>
<li>Change the name servers at the registrar. This updates the parent's NS set.</li>
<li>Keep the old zone online and unchanged until the parent's NS TTL has passed: two days for <code>.com</code> and
<code>.net</code>.</li>
<li>Check the result here and in the <a href="/dns-propagation-checker">propagation checker</a>.</li>
</ol>
<p>Signed domains need extra care. A DS record that no longer matches the keys at the new provider makes the domain
unresolvable for validating resolvers. The simple safe path is to remove the DS record, wait for its TTL, move the zone,
then sign it at the new provider and publish the new DS. The <a href="/dnssec-check">DNSSEC check</a> shows the current
state.</p>

<h2>Command line</h2>
<pre class="raw">dig +short example.com NS
dig +trace example.com
dig @a.gtld-servers.net example.com NS +norecurse
nslookup -type=NS example.com</pre>
<p><code>dig +trace</code> starts at the root servers and follows every delegation step, so you see what each level
hands out. The third command asks a <code>.com</code> server directly: the delegation appears in the authority
section, the glue in the additional section. The registered name servers are also listed in the
<a href="/whois">WHOIS lookup</a>.</p>`,
  faq: [
    { q: 'Why do the name servers in WHOIS differ from the NS lookup?', a: 'WHOIS shows the delegation stored at the registry, the NS lookup shows what resolvers get, usually the set from your own zone. Make both identical, at the registrar and in your DNS panel.' },
    { q: 'How many name servers should a domain have?', a: 'At least two, and they should be independent: different networks and ideally different locations, so a single outage does not stop resolution.' },
    { q: 'What is a glue record?', a: 'The IP address of a name server that lies inside the domain it serves, published in the parent zone. Without it resolvers could not reach a server like ns1.example.com for example.com.' },
    { q: 'What is a lame delegation?', a: 'A name server listed in the NS records that does not answer authoritatively for the zone. Remove it from the NS set at the registrar and in the zone.' },
    { q: 'How long does a name server change take?', a: 'Up to the TTL of the NS records in the parent zone, two days for .com and .net. Keep the old provider’s zone unchanged until then.' },
    { q: 'Can I use name servers from two DNS providers?', a: 'Yes, if both serve identical zone data, for example through zone transfers from a primary or automated updates to both. DNSSEC signing makes such setups more complex.' },
  ],
});

const cname = landing(dnsLookup, {
  slug: 'cname-lookup',
  name: 'CNAME lookup',
  title: 'CNAME Lookup – Check CNAME Records and Alias Chains',
  description: 'Look up the CNAME record of a host name and see where an alias points: CDN, SaaS or www targets, chains, and dangling records that risk takeover.',
  h1: 'CNAME lookup',
  lead: 'See whether a host name is an alias and which name it points to.',
  defaults: { type: 'CNAME' },
  examples: [['www.microsoft.com', 'name=www.microsoft.com&type=CNAME'], ['www.apple.com', 'name=www.apple.com&type=CNAME']],
  related: ['dns-lookup', 'subdomain-finder', 'ssl-check'],
  article: html`<h2>What a CNAME record does</h2>
<p>A CNAME (canonical name) record makes one name an alias of another. When a resolver looks up
<code>www.example.com</code> and finds a CNAME to <code>example.cdn.example.net</code>, it restarts the lookup at the
target and returns the whole chain together with the final answer. The tool above shows the CNAME record of a name,
or no answer if the name holds its records directly.</p>
<pre class="raw">www.example.com.          3600  IN  CNAME  example.cdn.example.net.
example.cdn.example.net.    60  IN  A      192.0.2.80</pre>
<p>The alias applies to every record type, not only to addresses. A query for the TXT or CAA records of
<code>www.example.com</code> is answered from the target as well.</p>

<h2>The rules</h2>
<ul>
<li><strong>Nothing else at the same name.</strong> A name with a CNAME may not hold any other record (RFC 1034,
RFC 2181), apart from DNSSEC records such as RRSIG and NSEC. A CNAME plus a TXT record on
<code>shop.example.com</code> is invalid, and most panels refuse to save it.</li>
<li><strong>Not at the zone apex.</strong> The domain itself always has SOA and NS records, so by the first rule
<code>example.com</code> cannot be a CNAME.</li>
<li><strong>One CNAME per name.</strong> Two aliases on the same name are an error.</li>
<li><strong>MX and NS must not point to an alias.</strong> Their targets need their own A or AAAA records.</li>
</ul>

<h3>ALIAS, ANAME and CNAME flattening</h3>
<p>Because a CNAME is not allowed at the apex, many DNS providers offer a substitute under names such as ALIAS, ANAME
or CNAME flattening, and AWS Route 53 has alias records. The provider resolves the target itself and serves the
resulting A and AAAA records at the apex. To resolvers and to this lookup they look like ordinary address records;
no CNAME appears on the wire. These are provider features, not a standard record type, so they do not survive a move
to a provider that lacks the same feature.</p>

<h2>Typical uses</h2>
<table class="data">
<thead><tr><th>Use</th><th>Example</th><th>Why an alias</th></tr></thead>
<tbody>
<tr><td>www</td><td><code>www.example.com CNAME example.com.</code></td><td>Addresses are maintained in one place.</td></tr>
<tr><td>CDN and hosting</td><td><code>www.example.com CNAME example.cdn.example.net.</code></td><td>The provider can change its IPs without you touching DNS.</td></tr>
<tr><td>SaaS on your own domain</td><td><code>help.example.com CNAME example.helpdesk.example.net.</code></td><td>The vendor routes requests and usually issues the certificate.</td></tr>
<tr><td>Ownership checks</td><td>A random label pointing to a vendor's verification host</td><td>Proves control of the zone without a TXT record.</td></tr>
<tr><td>Email</td><td>DKIM selectors as CNAMEs, as used by Microsoft 365</td><td>The provider can rotate keys on its side.</td></tr>
</tbody>
</table>

<h2>Chains</h2>
<p>A CNAME may point to another CNAME. CDNs often use two or three steps, from your name to a customer-specific name and
from there to an edge host name. Resolvers follow such chains, but each step can cost an extra query and has its own
TTL. Keep your own part of the chain short, and never build a loop: two names pointing at each other produce an
error, not an answer.</p>

<h2>Dangling CNAMEs and subdomain takeover</h2>
<p>A CNAME is dangling when its target no longer belongs to you: the cloud app, storage bucket or SaaS account was
deleted, but the DNS record stayed. On many platforms anyone can then create a resource with the same name and serve
their own content on your subdomain, from phishing pages to scripts that read cookies scoped to your domain. This is
called subdomain takeover.</p>
<p>Prevention is housekeeping: remove the CNAME before or together with the resource it points to, and review aliases
to external services regularly. Warning signs are a target that returns NXDOMAIN, or a provider page saying the site or
bucket does not exist. The <a href="/subdomain-finder">subdomain finder</a> lists known subdomains of a domain, a good
starting point for such a review.</p>

<h2>Command line</h2>
<pre class="raw">dig +short www.example.com CNAME
dig www.example.com A
nslookup -type=CNAME www.example.com</pre>
<p>The second command shows the complete chain followed by the final address in the answer section. If the alias
points to a CDN or SaaS host, the <a href="/ssl-check">SSL check</a> shows whether the certificate there covers your
host name.</p>`,
  faq: [
    { q: 'Can I put a CNAME on my root domain?', a: 'No. The root of a zone holds SOA and NS records, and a CNAME may not coexist with other records. Use A and AAAA records, or your provider’s ALIAS, ANAME or CNAME flattening feature.' },
    { q: 'Why can’t I add a TXT record next to a CNAME?', a: 'A name with a CNAME may not have any other records. Put the TXT record on a different name, or replace the CNAME with A and AAAA records.' },
    { q: 'Does a CNAME redirect visitors to another website?', a: 'No. It only changes where the name resolves to. The browser keeps the original host name, so the target server must accept that name and present a certificate for it.' },
    { q: 'What is CNAME flattening?', a: 'A provider feature that follows the CNAME on the DNS server and returns the final A and AAAA records instead. It allows alias behavior at the zone apex.' },
    { q: 'Is a long CNAME chain a problem?', a: 'Each step can add a lookup and a point of failure. Two or three steps through a CDN are normal; avoid adding your own extra hops.' },
    { q: 'What is a dangling CNAME?', a: 'An alias that points to a deleted cloud or SaaS resource. If someone else can claim that resource name, they control the content served on your subdomain.' },
  ],
});

const caa = landing(dnsLookup, {
  slug: 'caa-lookup',
  name: 'CAA lookup',
  title: 'CAA Lookup – Check Which CAs May Issue Certificates',
  description: 'Look up the CAA records of a domain: which certificate authorities may issue TLS certificates, wildcard rules and the iodef reporting address.',
  h1: 'CAA record lookup',
  lead: 'See which certificate authorities a domain allows to issue TLS certificates.',
  defaults: { type: 'CAA' },
  examples: [['google.com', 'name=google.com&type=CAA'], ['github.com', 'name=github.com&type=CAA']],
  related: ['ssl-check', 'dns-lookup', 'dnssec-check'],
  article: html`<h2>What CAA records do</h2>
<p>A CAA (Certification Authority Authorization) record lists the certificate authorities that may issue TLS
certificates for a domain. Before issuing, a publicly trusted CA must look up the CAA records of every name in the
certificate and refuse if it is not allowed. The CA/Browser Forum has required this check since September 2017; the
current specification is RFC 8659.</p>
<p>CAA only controls issuance. Browsers do not check it, and certificates issued before you published the record stay
valid until they expire.</p>

<h2>Record format</h2>
<pre class="raw">example.com.  3600  IN  CAA  0 issue "letsencrypt.org"
example.com.  3600  IN  CAA  0 issue "digicert.com"
example.com.  3600  IN  CAA  0 issuewild ";"
example.com.  3600  IN  CAA  0 iodef "mailto:security@example.com"</pre>
<p>Each record has three parts: a flags value, a tag and a value. The example allows Let's Encrypt and DigiCert to
issue normal certificates, allows no CA to issue wildcard certificates and names an address for reports.</p>
<table class="data">
<thead><tr><th>Tag</th><th>Meaning</th></tr></thead>
<tbody>
<tr><td><code>issue</code></td><td>A CA that may issue certificates for the name. Also covers wildcards unless <code>issuewild</code> is present. The value <code>";"</code> allows no CA.</td></tr>
<tr><td><code>issuewild</code></td><td>CAs that may issue wildcard certificates. If present, it replaces <code>issue</code> for wildcards.</td></tr>
<tr><td><code>iodef</code></td><td>Where a CA may report a request it refused, as a <code>mailto:</code> or <code>https:</code> URL. Not every CA sends such reports.</td></tr>
</tbody>
</table>
<p>The flags value is 0 in almost every record. 128 marks the record as critical: a CA that does not understand the
tag must not issue. Several <code>issue</code> records add up, each allowing one more CA.</p>
<p>A value can carry parameters after the CA identifier. RFC 8657 defines <code>accounturi</code>, which limits issuance
to one ACME account, and <code>validationmethods</code>, which limits how domain control may be proven:</p>
<pre class="raw">example.com.  CAA  0 issue "letsencrypt.org; validationmethods=dns-01"</pre>

<h2>Identifiers of common CAs</h2>
<table class="data">
<thead><tr><th>CA</th><th>Value for issue and issuewild</th></tr></thead>
<tbody>
<tr><td>Let's Encrypt</td><td><code>letsencrypt.org</code></td></tr>
<tr><td>Google Trust Services</td><td><code>pki.goog</code></td></tr>
<tr><td>DigiCert</td><td><code>digicert.com</code></td></tr>
<tr><td>Sectigo</td><td><code>sectigo.com</code></td></tr>
</tbody>
</table>
<p>Each CA documents its own identifier. Check what your hosting platform or CDN uses: some obtain certificates from
more than one CA, and the CAA records must allow all of them, or a renewal will fail.</p>

<h2>How CAs find the record</h2>
<p>A CA checks the exact name first. If it has no CAA records, the CA moves up one label at a time and uses the first
CAA set it finds. For <code>shop.eu.example.com</code> the order is:</p>
<pre class="raw">shop.eu.example.com  -&gt;  eu.example.com  -&gt;  example.com  -&gt;  com</pre>
<p>A record on <code>example.com</code> therefore covers all subdomains, unless a subdomain has its own CAA set, which
replaces the parent's completely rather than adding to it. If a name is a CNAME, the DNS query returns the CAA records
of the alias target, and those apply.</p>
<p>No CAA record anywhere up the tree means any CA may issue. A failed lookup is not the same as an empty answer: for a
DNSSEC-signed zone a CA must refuse when the lookup fails. For unsigned zones the CA/Browser Forum Baseline
Requirements let a CA treat a repeated lookup failure outside its own infrastructure as permission to issue.</p>

<h2>Effect on certificate issuance</h2>
<ul>
<li>A new CAA record that omits your current CA breaks the next renewal, often weeks or months later when nobody
remembers the change. List every CA in use before publishing.</li>
<li>Managed certificates from CDNs and hosting panels are affected just like the ones you request yourself.</li>
<li>Subdomains run by other teams or vendors inherit the parent's records. Give them their own CAA set if they need a
different CA.</li>
<li>A domain that never needs a certificate can publish <code>0 issue ";"</code> to block issuance entirely.</li>
</ul>
<p>After a change, check the deployed certificate and its issuer with the <a href="/ssl-check">SSL check</a>.</p>

<h2>Command line</h2>
<pre class="raw">dig +short example.com CAA
dig +short www.example.com CAA</pre>
<p>An empty answer for the subdomain means the CA climbs to the parent, so query both levels.</p>`,
  faq: [
    { q: 'Do I need a CAA record?', a: 'It is not required. Without one, any publicly trusted CA may issue for your domain. A CAA record limits that to the CAs you actually use.' },
    { q: 'Does a new CAA record affect existing certificates?', a: 'No. CAA is checked only when a certificate is issued. Existing certificates stay valid until they expire, and the record takes effect at the next renewal.' },
    { q: 'Do browsers check CAA records?', a: 'No. Only certificate authorities check them, before issuance.' },
    { q: 'What does issue ";" mean?', a: 'No CA may issue certificates for the name. It suits domains that never serve TLS, and as issuewild ";" it blocks wildcard certificates only.' },
    { q: 'Why does my certificate renewal fail after adding CAA?', a: 'The CA your hosting or CDN uses is not listed. Find out which CAs it uses and add an issue record for each one.' },
    { q: 'Do subdomains inherit CAA records?', a: 'Yes. A CA climbs from the requested name toward the root and uses the first CAA set it finds. A subdomain with its own records replaces the parent’s set.' },
  ],
});

const nslookup = landing(dnsLookup, {
  slug: 'nslookup-online',
  name: 'Online nslookup & dig',
  title: 'Online nslookup & dig – Run DNS Queries in the Browser',
  description: 'Run nslookup and dig style DNS queries online: any record type, any public resolver, no terminal needed. With a guide to both command-line tools.',
  h1: 'Online nslookup & dig',
  lead: 'Query DNS records like nslookup or dig would, directly in the browser.',
  defaults: { type: 'ALL' },
  examples: [['cloudflare.com', 'name=cloudflare.com&type=ALL'], ['wikipedia.org', 'name=wikipedia.org&type=ALL']],
  related: ['ns-lookup', 'dns-propagation-checker', 'reverse-dns-lookup'],
  article: html`<h2>nslookup and dig without a terminal</h2>
<p>nslookup and dig are the two classic command-line tools for querying DNS. This page runs the same kind of query
from our server against public resolvers and shows the answer as a table. Enter a name, pick a record type or keep
“All common” to fetch the usual types at once, and choose which resolver to ask. That covers what most people open a
terminal for, and it works on a locked-down work PC or a phone where neither tool is available.</p>

<h2>Where the tools come from</h2>
<table class="data">
<thead><tr><th>System</th><th>nslookup</th><th>dig</th></tr></thead>
<tbody>
<tr><td>Windows</td><td>Built in</td><td>Not included. Use <code>Resolve-DnsName</code> in PowerShell, or dig inside WSL.</td></tr>
<tr><td>macOS</td><td>Built in</td><td>Built in</td></tr>
<tr><td>Debian, Ubuntu</td><td colspan="2">Package <code>dnsutils</code> (<code>bind9-dnsutils</code> on newer releases)</td></tr>
<tr><td>Fedora, RHEL</td><td colspan="2">Package <code>bind-utils</code></td></tr>
</tbody>
</table>

<h2>The same query in both tools</h2>
<pre class="raw">nslookup -type=MX example.com
nslookup -type=MX example.com 1.1.1.1
dig example.com MX
dig @1.1.1.1 example.com MX
dig +short example.com MX</pre>
<p>Mind the argument order: nslookup takes the server as the last argument, dig expects it with an <code>@</code> in
front. On this page, the resolver dropdown does the same job.</p>

<h3>Reading nslookup output</h3>
<pre class="raw">Server:   one.one.one.one
Address:  1.1.1.1

Non-authoritative answer:
example.com     mail exchanger = 10 mail.example.com.</pre>
<p>The first block names the resolver that answered. “Non-authoritative answer” only means the response came from a
recursive resolver rather than from the zone's own name server; it is not an error. On Windows, “Server: UnKnown”
means the resolver's address has no reverse DNS name, which is harmless.</p>

<h3>Reading dig output</h3>
<pre class="raw">;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: NOERROR, id: 4242
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
example.com.        3600    IN      MX      10 mail.example.com.

;; Query time: 12 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)</pre>
<p>dig shows more detail. The status is NOERROR, NXDOMAIN for a name that does not exist, or SERVFAIL when the
resolver failed, for example on a DNSSEC validation error. In the flags, <code>aa</code> marks an authoritative answer
and <code>ad</code> a DNSSEC-validated one. The second column of each record is the remaining TTL in seconds, which
this page shows as well.</p>

<h2>Interactive nslookup</h2>
<p>Run <code>nslookup</code> without arguments to get a prompt where settings stay in effect between queries:</p>
<pre class="raw">&gt; server 9.9.9.9
&gt; set type=TXT
&gt; example.com
&gt; set type=NS
&gt; example.com
&gt; exit</pre>
<p>dig has no interactive mode. It accepts several queries on one command line instead, or a file of queries with
<code>-f</code>.</p>

<h2>Useful options</h2>
<table class="data">
<thead><tr><th>Purpose</th><th>nslookup</th><th>dig</th></tr></thead>
<tbody>
<tr><td>Record type</td><td><code>-type=AAAA</code></td><td><code>AAAA</code></td></tr>
<tr><td>Specific resolver</td><td>server as last argument</td><td><code>@8.8.8.8</code></td></tr>
<tr><td>Reverse lookup</td><td><code>nslookup 192.0.2.1</code></td><td><code>dig -x 192.0.2.1</code></td></tr>
<tr><td>Answer only</td><td>not available</td><td><code>+short</code></td></tr>
<tr><td>Follow delegation from the root</td><td>not available</td><td><code>+trace</code></td></tr>
</tbody>
</table>
<p>Avoid ANY queries: many servers answer them with a minimal response (RFC 8482). That is why “All common” here
sends one query per record type.</p>

<h2>Why results differ from your own machine</h2>
<ul>
<li><strong>Different resolver.</strong> Your computer asks the resolver set by DHCP or a VPN; this page asks public
resolvers. Each has its own cache, so after a change one may still return the old record until the TTL expires.</li>
<li><strong>Split DNS.</strong> Company networks often answer internal names, or different addresses for public names,
only to clients inside the network. From outside, such names do not exist.</li>
<li><strong>Location-based answers.</strong> CDNs return addresses close to the resolver or the client, so the IPs differ
by location.</li>
<li><strong>Hosts file and browser DNS.</strong> nslookup and dig ignore the hosts file, but browsers and ping use it.
Browsers with DNS over HTTPS enabled may also use a different resolver than the system.</li>
</ul>
<p>To compare many resolvers side by side, use the <a href="/dns-propagation-checker">DNS propagation checker</a>.</p>`,
  faq: [
    { q: 'What is the difference between nslookup and dig?', a: 'Both send DNS queries. nslookup ships with Windows and prints a short, simplified answer. dig shows the full response with status, flags, TTLs and sections, which makes it the better tool for troubleshooting.' },
    { q: 'Is dig available on Windows?', a: 'Not by default. Use Resolve-DnsName in PowerShell, install dig inside WSL, or use this page.' },
    { q: 'What does “Non-authoritative answer” mean?', a: 'The answer came from a recursive resolver, not directly from the domain’s own name server. That is the normal case and not an error.' },
    { q: 'Why does nslookup show a different address than my browser uses?', a: 'Browsers use the hosts file and sometimes their own DNS over HTTPS resolver, while nslookup asks the system’s DNS server directly. Caches on each path can also hold different answers.' },
    { q: 'How do I query a specific DNS server?', a: 'With nslookup, add the server as the last argument: nslookup example.com 1.1.1.1. With dig, put it first with an @: dig @1.1.1.1 example.com. On this page, choose it in the resolver list.' },
    { q: 'Why does a name resolve in my office but not here?', a: 'It is probably an internal name served only by your company’s DNS (split DNS). Public resolvers do not know it.' },
  ],
});

const ipWhois = landing(whois, {
  slug: 'ip-whois-lookup',
  name: 'IP WHOIS lookup',
  title: 'IP WHOIS Lookup – Find Who Owns an IP Address',
  description: 'Find out who owns an IP address: registry, network range, holder organization and abuse contact for any IPv4 or IPv6 address, via RDAP.',
  h1: 'IP WHOIS lookup',
  lead: 'Find the organization that holds an IP address and where to report abuse from it.',
  defaults: {},
  examples: [['8.8.8.8', 'q=8.8.8.8'], ['9.9.9.9', 'q=9.9.9.9']],
  related: ['ip-lookup', 'whois', 'asn-lookup'],
  article: html`<h2>Who owns an IP address</h2>
<p>Every public IP address belongs to a block registered with one of five regional internet registries (RIRs). Their
databases record which organization holds the block, how it is used and whom to contact about abuse. An IP WHOIS
lookup reads that record. Enter an IPv4 or IPv6 address above; the tool finds the responsible registry and shows the
registration.</p>
<p>The answer is rarely the person behind a connection. In most cases it names an ISP, a cloud platform or a hosting
company that holds the block and hands addresses to its customers, often dynamically. Which customer used an address at
a given time is known only to that provider, which discloses it to law enforcement or through legal process, not to
the public.</p>

<h2>The five registries</h2>
<table class="data">
<thead><tr><th>RIR</th><th>Region</th><th>Range object</th></tr></thead>
<tbody>
<tr><td>ARIN</td><td>USA, Canada, parts of the Caribbean</td><td><code>NetRange</code>, <code>CIDR</code></td></tr>
<tr><td>RIPE NCC</td><td>Europe, the Middle East, parts of Central Asia</td><td><code>inetnum</code>, <code>inet6num</code></td></tr>
<tr><td>APNIC</td><td>Asia-Pacific</td><td><code>inetnum</code>, <code>inet6num</code></td></tr>
<tr><td>LACNIC</td><td>Latin America, parts of the Caribbean</td><td><code>inetnum</code></td></tr>
<tr><td>AFRINIC</td><td>Africa</td><td><code>inetnum</code>, <code>inet6num</code></td></tr>
</tbody>
</table>
<p>IANA hands large blocks to the RIRs, and the RIRs distribute them to their members. Addresses from one region can
be used anywhere in the world, so the registry says little about where a device actually is.</p>

<h2>Reading the record</h2>
<pre class="raw">inetnum:   198.51.100.0 - 198.51.100.255
netname:   EXAMPLE-HOSTING-NET
country:   DE
status:    ASSIGNED PA
org:       ORG-EH1-RIPE
abuse-c:   AR1234-RIPE</pre>
<p>The range shows how large the registered block is. RIPE-style databases write it as a start and end address, ARIN
adds CIDR notation; the <a href="/ip-range-to-cidr">range to CIDR converter</a> translates between both. The country
field is what the holder entered, usually its own seat, not the location of the address.</p>

<h3>Allocation and assignment</h3>
<ul>
<li><strong>Allocation:</strong> a block given to a provider to distribute further. RIPE status
<code>ALLOCATED PA</code>, ARIN net types such as Direct Allocation or Reallocation.</li>
<li><strong>Assignment:</strong> a block used by one organization, taken from a provider's space or received directly
from the registry. RIPE <code>ASSIGNED PA</code> or <code>ASSIGNED PI</code> (provider independent), ARIN Reassignment
or Direct Assignment.</li>
</ul>
<p>A lookup returns the most specific registered block. If the provider registered a customer's sub-block, you see the
customer; otherwise you see the provider's allocation. Residential and small business addresses are usually not
registered separately.</p>

<h2>Abuse contacts</h2>
<p>To report spam, scans, attacks or phishing from an address, write to the abuse contact in the record, not to the
address itself and not to the registry: RIRs maintain registrations but do not handle abuse. Look for the
<code>abuse-mailbox</code> of the abuse-c object at RIPE NCC, <code>OrgAbuseEmail</code> at ARIN, or the entity with
the role “abuse” in RDAP output. A useful report contains:</p>
<ul>
<li>the source IP and, for shared addresses, the source port;</li>
<li>exact timestamps with time zone, ideally in UTC;</li>
<li>relevant log lines, or full message headers for spam;</li>
<li>a short, factual description of what happened.</li>
</ul>
<p>Providers using carrier-grade NAT share one IPv4 address among many customers and can only find the right one with
the source port and an exact time. For spam, the <a href="/email-headers">email header analyzer</a> shows which IP
actually delivered the message.</p>

<h2>RDAP for IP addresses</h2>
<p>This tool queries RDAP, the JSON-based successor of port-43 WHOIS. The IANA bootstrap files list which registry is
responsible for each address range, and the query goes straight to that registry's RDAP server. Classic WHOIS
clients often have to follow referrals from one registry to the next, especially for blocks that were transferred
between regions. RDAP returns the network object with its range, type and the entities attached to it, each with
roles such as registrant, technical or abuse.</p>
<pre class="raw">curl -s https://rdap.org/ip/203.0.113.7
whois 203.0.113.7
whois -h whois.ripe.net 2001:db8::1</pre>

<h2>Related lookups</h2>
<p>The <a href="/asn-lookup">ASN lookup</a> shows which network announces the prefix in BGP. That can differ from the
WHOIS holder, for example when a company's provider-independent block is routed by its ISP. The
<a href="/reverse-dns-lookup">reverse DNS lookup</a> shows the host name the provider set for the address, which often
hints at the service or region. For domains and AS numbers, use the general <a href="/whois">WHOIS lookup</a>.</p>`,
  faq: [
    { q: 'Can I find out who is using an IP address?', a: 'Usually not. WHOIS shows the organization that holds the address block, typically an ISP or hosting provider. Only the provider knows which customer used the address at a given time.' },
    { q: 'Why does the lookup show a cloud provider instead of the website owner?', a: 'The website runs on servers rented from that provider, so the address belongs to the provider’s block. The customer is not listed unless the provider registered a sub-block for it.' },
    { q: 'Is the country in the WHOIS record the location of the IP?', a: 'No. It is the country the holder entered, usually where the organization is registered. The address itself can be used anywhere.' },
    { q: 'Where do I report abuse from an IP address?', a: 'To the abuse contact in the WHOIS or RDAP record, with the IP, port, exact timestamps including the time zone, and log excerpts. Registries themselves do not handle abuse reports.' },
    { q: 'What is the difference between inetnum and NetRange?', a: 'Both describe a registered address range. RIPE NCC, APNIC, LACNIC and AFRINIC call it inetnum (inet6num for IPv6); ARIN uses NetRange with an additional CIDR field.' },
    { q: 'Why does the WHOIS holder differ from the ASN lookup?', a: 'WHOIS shows who holds the address block, the ASN lookup shows which network announces it in BGP. A provider can route a block registered to one of its customers.' },
  ],
});

export const LANDING_PAGES: Tool[] = [propagation, mx, txt, ns, cname, caa, nslookup, reverse, ipWhois, spf, dkim, dmarc];
