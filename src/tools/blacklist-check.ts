import { mapLimit } from '../core/async';
import { cachedJson } from '../core/cache';
import { RR_TYPES } from '../core/dns';
import { txtValue } from '../core/email';
import { isPublicAddress } from '../core/guard';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { isIPv4, isIPv6, normalizeDomain } from '../core/net';
import type { Tool } from '../core/tool';
import { RESOLVERS, resolve } from '../core/transport';

interface Dnsbl {
  zone: string;
  name: string;
  url: string;
}

const LISTS: Dnsbl[] = [
  { zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN', url: 'https://check.spamhaus.org/' },
  { zone: 'b.barracudacentral.org', name: 'Barracuda', url: 'https://www.barracudacentral.org/lookups' },
  { zone: 'bl.spamcop.net', name: 'SpamCop', url: 'https://www.spamcop.net/bl.shtml' },
  { zone: 'psbl.surriel.com', name: 'PSBL', url: 'https://psbl.org/' },
  { zone: 'dnsbl-1.uceprotect.net', name: 'UCEPROTECT Level 1', url: 'https://www.uceprotect.net/en/rblcheck.php' },
  { zone: 'dnsbl-2.uceprotect.net', name: 'UCEPROTECT Level 2', url: 'https://www.uceprotect.net/en/rblcheck.php' },
  { zone: 'bl.mailspike.net', name: 'Mailspike', url: 'https://mailspike.org/' },
  { zone: 'dnsbl.dronebl.org', name: 'DroneBL', url: 'https://dronebl.org/lookup' },
  { zone: 'ix.dnsbl.manitu.net', name: 'NiX Spam', url: 'https://www.dnsbl.manitu.net/' },
  { zone: 'truncate.gbudb.net', name: 'GBUdb Truncate', url: 'https://www.gbudb.com/' },
  { zone: 'db.wpbl.info', name: 'WPBL', url: 'http://www.wpbl.info/' },
  { zone: 'all.s5h.net', name: 's5h.net', url: 'https://www.usenix.org.uk/content/rbl.html' },
];

type State = 'listed' | 'clean' | 'unavailable';

export interface ListResult {
  list: Dnsbl;
  state: State;
  code: string | null;
  reason: string | null;
}

interface Report {
  input: string;
  ip: string;
  source: string;
  results: ListResult[];
}

/** Interprets a DNSBL answer: rcode plus all A records returned for the query name. */
export function classify(rcode: string, addrs: string[]): { state: State; code: string | null; reason: string | null } {
  if (rcode === 'NXDOMAIN') return { state: 'clean', code: null, reason: null };
  if (rcode !== 'NOERROR') return { state: 'unavailable', code: null, reason: `The list answered ${rcode}.` };
  if (!addrs.length) return { state: 'clean', code: null, reason: null };
  // 127.255.255.x and 127.0.0.1 are error codes (e.g. "queries via public resolvers are blocked"), not listings;
  // anything outside 127/8 is a hijacked or wildcard answer.
  const error = addrs.find((a) => !a.startsWith('127.') || a.startsWith('127.255.255.') || a === '127.0.0.1');
  if (error) return { state: 'unavailable', code: error, reason: 'This list does not answer queries from public DNS resolvers.' };
  return { state: 'listed', code: addrs.join(', '), reason: null };
}

async function query(ip: string, list: Dnsbl): Promise<ListResult> {
  const name = `${ip.split('.').reverse().join('.')}.${list.zone}`;
  try {
    const { message } = await resolve(RESOLVERS[0]!, name, RR_TYPES.A, 3000);
    const addrs = message.answers.filter((r) => r.type === RR_TYPES.A).map((r) => r.data);
    const verdict = classify(message.rcodeName, addrs);
    if (verdict.state !== 'listed') return { list, ...verdict };
    const a = verdict.code;
    const txt = await resolve(RESOLVERS[0]!, name, RR_TYPES.TXT, 3000).catch(() => null);
    const reason = txt?.message.answers.find((r) => r.type === RR_TYPES.TXT)?.data;
    return { list, state: 'listed', code: a, reason: reason ? txtValue(reason) : null };
  } catch {
    return { list, state: 'unavailable', code: null, reason: 'No answer.' };
  }
}

// Private addresses of a misconfigured domain cannot be on a public list; skip them.
async function firstIPv4(name: string): Promise<string | null> {
  const r = await resolve(RESOLVERS[0]!, name, RR_TYPES.A).catch(() => null);
  return r?.message.answers.find((a) => a.type === RR_TYPES.A && isPublicAddress(a.data))?.data ?? null;
}

// A domain is checked through its primary mail server, falling back to its web server address.
async function target(input: string): Promise<{ ip: string; source: string } | { error: string }> {
  const v = input.trim();
  if (isIPv6(v)) return { error: 'Most blocklists only cover IPv4. Enter an IPv4 address or a domain.' };
  if (isIPv4(v)) return isPublicAddress(v) ? { ip: v, source: 'IP address' } : { error: 'Private and reserved addresses cannot be listed.' };
  const domain = normalizeDomain(v);
  if (!domain?.includes('.')) return { error: 'Enter an IPv4 address or a domain such as example.com.' };
  const mx = await resolve(RESOLVERS[0]!, domain, RR_TYPES.MX).catch(() => null);
  const mxHost = mx?.message.answers
    .filter((a) => a.type === RR_TYPES.MX)
    .map((a) => { const [p, h] = a.data.split(' '); return { p: Number(p), h: (h ?? '').replace(/\.$/, '') }; })
    .filter((m) => m.h)
    .sort((a, b) => a.p - b.p)[0]?.h;
  if (mxHost) {
    const ip = await firstIPv4(mxHost);
    if (ip) return { ip, source: `mail server ${mxHost}` };
  }
  const ip = await firstIPv4(domain);
  return ip ? { ip, source: `web server ${domain}` } : { error: `${domain} has no IPv4 address.` };
}

/** IPv4 only; one DNS query per list, cached for 10 minutes. */
export function checkLists(ip: string): Promise<ListResult[]> {
  // An answer where no list responded is not cached, so a retry asks again.
  return cachedJson(`dnsbl:${ip}`, (r) => (r.some((x) => x.state !== 'unavailable') ? 600 : 0), () => mapLimit(LISTS, 6, (l) => query(ip, l)));
}

async function check(input: string): Promise<Report | { error: string }> {
  const t = await target(input);
  if ('error' in t) return t;
  const results = await checkLists(t.ip);
  return { input, ip: t.ip, source: t.source, results };
}

const BADGE: Record<State, SafeHtml> = {
  listed: html`<span class="status bad">listed</span>`,
  clean: html`<span class="status ok">not listed</span>`,
  unavailable: html`<span class="status info">unavailable</span>`,
};

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/blacklist-check">
<div class="field grow"><label for="q">IPv4 address or domain</label>
<input id="q" name="q" type="text" value="${value}" placeholder="203.0.113.10 or example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Check blocklists</button></div>
</form>`;
}

const tool: Tool = {
  slug: 'blacklist-check',
  name: 'Blacklist check',
  icon: 'blacklist',
  category: 'email',
  title: 'Email Blacklist Check – Is My IP or Domain Listed?',
  description:
    'Check whether an IP or a domain’s mail server is listed on 12 spam blocklists (DNSBL) such as SpamCop, Barracuda and UCEPROTECT, with removal links.',
  h1: 'IP and mail server blacklist check',
  lead: 'Find out whether a mail server is listed on common spam blocklists and where to request removal.',
  examples: [['gmail.com mail server', 'q=gmail.com']],
  related: ['email-security', 'whois', 'dns-lookup'],
  heavy: () => true,
  isQuery: (url) => url.searchParams.has('q'),

  async render(c) {
    const value = (c.url.searchParams.get('q') ?? '').trim();
    if (!c.url.searchParams.has('q')) return form('');
    const r = await check(value);
    if ('error' in r) return html`${form(value)}<p class="error">${r.error}</p>`;
    const listed = r.results.filter((x) => x.state === 'listed').length;
    const usable = r.results.filter((x) => x.state !== 'unavailable').length;
    return html`${form(value)}
<div class="verdict ${listed ? 'bad' : 'ok'}"><strong>${listed ? `Listed on ${listed} of ${usable} blocklists.` : `Not listed on any of the ${usable} blocklists that answered.`}</strong>
Checked <code>${r.ip}</code> (${r.source}).</div>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>Blocklist</th><th>Status</th><th>Details</th></tr></thead>
<tbody>${r.results.map((x) => html`<tr><td><a href="${x.list.url}" rel="noopener nofollow">${x.list.name}</a><br><code class="muted">${x.list.zone}</code></td><td>${BADGE[x.state]}</td>
<td class="wrap-any">${x.reason ?? (x.code ? html`<code>${x.code}</code>` : '')}</td></tr>`)}</tbody></table></div>`;
  },

  apiDoc: 'GET /api/blacklist-check?q=8.8.8.8 (or a domain)',

  async api(c) {
    const r = await check(c.url.searchParams.get('q') ?? '');
    if ('error' in r) return json({ error: r.error }, { status: 400 });
    return json({ ip: r.ip, source: r.source, results: r.results.map((x) => ({ list: x.list.zone, name: x.list.name, state: x.state, code: x.code, reason: x.reason })) });
  },

  article: html`<h2>What is a DNS blocklist?</h2>
<p>A DNS blocklist (DNSBL, also called RBL or simply "blacklist") is a list of IP addresses that sent spam, were part of a
botnet, or belong to ranges that should not send mail directly, such as dynamic home connections. Mail servers look up
every connecting IP in one or more lists and reject or score mail from listed addresses. A listing is the most common
reason why mail from a correctly configured server suddenly bounces with messages such as
<code>554 5.7.1 Service unavailable; Client host [203.0.113.25] blocked using zen.spamhaus.org</code>.</p>

<h2>How a DNSBL lookup works</h2>
<p>Blocklists are published through DNS, which makes lookups fast and cheap for every mail server. To check an IPv4 address,
the four octets are reversed and the list's zone is appended:</p>
<ol>
<li>Take the IP address, for example <code>203.0.113.25</code>.</li>
<li>Reverse the octets: <code>25.113.0.203</code>.</li>
<li>Append the zone: <code>25.113.0.203.zen.spamhaus.org</code>.</li>
<li>Query an A record. <code>NXDOMAIN</code> (no such name) means the address is not listed. An answer in
<code>127.0.0.0/8</code>, such as <code>127.0.0.2</code>, means it is listed.</li>
</ol>
<p>You can do this yourself with <code>dig +short 25.113.0.203.zen.spamhaus.org A</code>. Many lists also publish a TXT
record at the same name that explains the reason and links to the removal page:
<code>dig +short 25.113.0.203.zen.spamhaus.org TXT</code>. Per RFC 5782, lists answer for the test entry
<code>127.0.0.2</code>, so querying <code>2.0.0.127.zen.spamhaus.org</code> shows whether a list responds at all.</p>

<h3>Return codes</h3>
<p>The last octet of the answer often tells which sub-list matched. Spamhaus ZEN combines several lists:</p>
<table class="data">
<thead><tr><th>Answer</th><th>Spamhaus list</th><th>Meaning</th></tr></thead>
<tbody>
<tr><td><code>127.0.0.2</code></td><td>SBL</td><td>Known spam source or spam operation</td></tr>
<tr><td><code>127.0.0.3</code></td><td>SBL CSS</td><td>Low-reputation sender, often snowshoe spam</td></tr>
<tr><td><code>127.0.0.4</code>&ndash;<code>127.0.0.7</code></td><td>XBL</td><td>Infected or hijacked device, open proxy</td></tr>
<tr><td><code>127.0.0.9</code></td><td>DROP</td><td>Hijacked or criminal network range</td></tr>
<tr><td><code>127.0.0.10</code>, <code>127.0.0.11</code></td><td>PBL</td><td>Range that should not send mail directly, such as dynamic IPs</td></tr>
<tr><td><code>127.255.255.252</code>&ndash;<code>127.255.255.255</code></td><td>Error</td><td>Query refused, for example because it came through a public resolver</td></tr>
</tbody>
</table>
<p>Answers in <code>127.255.255.0/24</code>, <code>127.0.0.1</code> or outside <code>127.0.0.0/8</code> are error signals,
not listings. This tool reports them as "unavailable" instead of "listed".</p>

<h2>Which lists this tool checks</h2>
<p>The check queries 12 blocklists in parallel: Spamhaus ZEN, Barracuda, SpamCop, PSBL, UCEPROTECT Level 1 and Level 2,
Mailspike, DroneBL, NiX Spam, GBUdb Truncate, WPBL and s5h.net. Each result links to the list's own lookup and removal page.</p>
<ul>
<li>Only IPv4 addresses are checked. Most blocklists publish little or no IPv6 data.</li>
<li>If you enter a domain such as <code>example.com</code>, the tool looks up its MX records, takes the primary mail host
(lowest preference value) and checks that host's IPv4 address. This is the server that receives mail, which is often
but not always the server that sends it. If your outgoing mail leaves through a different IP, enter that IP directly.</li>
</ul>
<p>To find the sending IP, open a message you sent in the recipient's mailbox and look at the topmost
<code>Received:</code> header added by the receiving server. To check your current public address, see
<a href="/what-is-my-ip">what is my IP</a>; the <a href="/mx-lookup">MX lookup</a> lists all mail hosts of a domain.</p>

<h2>Why Spamhaus may show as unavailable</h2>
<p>Spamhaus and some other lists refuse queries that arrive through large public DNS resolvers such as 8.8.8.8 or 1.1.1.1,
because the volume would be impossible to attribute. They answer with an error code like <code>127.255.255.254</code>
instead. Since this tool resolves through public resolvers, such lists can appear as unavailable. In that case, check the
address on the list's own website. The same problem affects mail servers: if your server uses a public resolver for
DNSBL lookups, Spamhaus checks silently stop working. Run a local recursive resolver or use the Spamhaus Data Query
Service instead.</p>

<h2>I am listed. What now?</h2>
<ol>
<li>Read the reason on the list's lookup page. A PBL or dynamic-range listing is a policy listing, not a spam report.</li>
<li>Find and fix the cause: a compromised mailbox password, an infected device behind the same NAT, an open relay, or a web
contact form abused to send spam. Check the mail queue and logs for unusual volume. Delisting without fixing the cause
leads straight back onto the list.</li>
<li>Make sure the server has a <a href="/reverse-dns-lookup">reverse DNS (PTR) record</a> that matches its host name, and
valid <a href="/email-security">SPF, DKIM and DMARC records</a> for every domain it sends for.</li>
<li>Request removal through each list's own page. Removal is free on the major lists; do not pay third parties for it.</li>
<li>Wait. SpamCop listings expire on their own about 24 hours after reports stop. PSBL and UCEPROTECT Level 1 also expire
automatically after a period without new spam.</li>
<li>Check again after the listing is gone and keep an eye on the server's outgoing volume.</li>
</ol>

<h2>How to avoid being listed again</h2>
<p>Enforce strong passwords and multi-factor authentication for mailboxes, rate-limit outgoing mail per account, and alert on
queue growth. Block outbound port 25 from client networks so infected devices cannot deliver spam directly. Protect web forms
with a CAPTCHA and never let them send to arbitrary addresses. Process bounces and unsubscribe requests promptly so that
newsletters do not hit spam traps.</p>

<h2>About UCEPROTECT Level 2</h2>
<p>UCEPROTECT Level 2 lists whole network allocations when enough addresses in them are on Level 1, so a clean server can be
listed because of its neighbors at the same hosting provider. Few large mail providers use Level 2 to reject mail. A
Level 2 listing alone rarely explains delivery problems; ask your hosting provider about the range if it persists.</p>

<h2>Troubleshooting checklist</h2>
<ul>
<li>Bounce message names a list: check that list first, using the exact IP in the bounce.</li>
<li>All lists clean but mail still rejected: the receiver may use its own reputation data, as Gmail and Microsoft do.
Check authentication and complaint rates.</li>
<li>Home or office IP listed on a policy list: send through your provider's or mail host's SMTP relay on port 587 instead of
delivering directly on port 25. Test reachability with the <a href="/port-checker">port checker</a>.</li>
<li>New VPS listed on day one: the address had a previous owner. Request removal and, if needed, ask the provider for another IP.</li>
</ul>`,

  faq: [
    { q: 'Which blocklists matter most?', a: 'Spamhaus, Barracuda and SpamCop are used by the most mail servers. A listing there causes real delivery problems; smaller lists have less impact.' },
    { q: 'Why is my home IP listed?', a: 'Many lists, such as the Spamhaus PBL, include dynamic and residential address ranges, because mail should leave through your provider’s mail server. That is expected and only matters if you run your own mail server at home.' },
    { q: 'Can I check IPv6 addresses?', a: 'No. Most blocklists only publish IPv4 data, so this check covers IPv4. Enter a domain to check the IPv4 address of its primary mail server.' },
    { q: 'Why is Spamhaus shown as unavailable?', a: 'Spamhaus refuses queries that come through large public DNS resolvers and answers with an error code instead. Check the address on check.spamhaus.org using the link in the result.' },
    { q: 'How long does it take to be removed from a blocklist?', a: 'Many lists remove an entry automatically within a day to a week after the spam stops. Manual removal requests are often processed within hours, but only if the cause has been fixed.' },
    { q: 'I entered a domain. Which IP was checked?', a: 'The IPv4 address of the domain’s primary MX host, the server that receives its mail. If outgoing mail is sent from a different server, enter that server’s IP address instead.' },
  ],
};

export default tool;
