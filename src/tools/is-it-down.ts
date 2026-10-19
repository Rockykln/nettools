import { cachedJson } from '../core/cache';
import { RR_TYPES } from '../core/dns';
import { html, type SafeHtml } from '../core/html';
import { openLink } from '../core/ui';
import { json } from '../core/http';
import { fetchChain, normalizeUrl, type Chain } from '../core/http-probe';
import type { Tool } from '../core/tool';
import { COMPARE_RESOLVERS, RESOLVERS, resolve } from '../core/transport';
import { chainTable } from './http-headers';

type Verdict = 'up' | 'blocked' | 'error' | 'down' | 'refused';

interface Check {
  url: string;
  host: string;
  chain: Chain;
  addresses: string[];
  verdict: Verdict;
}

function check(url: string, env: Env, explicitScheme: boolean): Promise<Check> {
  return cachedJson(`down:${url}:${explicitScheme ? 1 : 0}`, () => 60, async () => {
    const first = await checkUncached(url, env);
    // Without a scheme we try HTTPS first; sites that only serve plain HTTP get a second chance.
    if (!explicitScheme && first.verdict === 'down' && url.startsWith('https://')) {
      const plain = await checkUncached(url.replace(/^https:/, 'http:'), env);
      if (plain.verdict !== 'down') return plain;
    }
    return first;
  });
}

async function checkUncached(url: string, env: Env): Promise<Check> {
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
  const [chain, a, aaaa] = await Promise.all([
    fetchChain(url, env),
    resolve(RESOLVERS[0]!, host, RR_TYPES.A).catch(() => null),
    resolve(RESOLVERS[0]!, host, RR_TYPES.AAAA).catch(() => null),
  ]);
  const addresses = [a, aaaa].flatMap((r) => r?.message.answers.filter((x) => x.type === RR_TYPES.A || x.type === RR_TYPES.AAAA).map((x) => x.data) ?? []);
  return { url, host, chain, addresses, verdict: verdictOf(chain) };
}

export function verdictOf(chain: Chain): Verdict {
  const last = chain.hops[chain.hops.length - 1];
  // The start URL itself is not allowed (private address, this site): not a statement about the site.
  if (chain.errorKind === 'refused' && !last) return 'refused';
  // The site answered, but its redirects lead somewhere that is not followed (loop, limit, private target).
  if (last && (chain.errorKind === 'redirect' || chain.errorKind === 'refused')) return 'error';
  // Many large sites answer automated requests with 401/403/429 or a 503 bot challenge although they work in browsers.
  const challenged = last && last.status === 503 && last.headers.some(([k]) => k === 'cf-mitigated');
  return chain.error || !last ? 'down'
    : [401, 403, 429].includes(last.status) || challenged ? 'blocked'
    : last.status >= 500 ? 'down'
    : last.status >= 400 ? 'error'
    : 'up';
}

function verdictBox(c: Check): SafeHtml {
  const last = c.chain.hops[c.chain.hops.length - 1];
  const total = c.chain.hops.reduce((a, h) => a + h.ms, 0);
  if (c.verdict === 'up') {
    return html`<div class="verdict ok"><strong>${c.host} is up.</strong> It answered with HTTP ${last!.status} in ${total} ms.
If it does not load for you, the problem is probably on your side: try another network, clear the DNS cache or disable extensions.</div>`;
  }
  if (c.verdict === 'blocked') {
    return html`<div class="verdict ok"><strong>${c.host} is up, but blocked our automated check</strong> (HTTP ${last!.status}).
The server answered, so it is online. It most likely works in a normal browser.</div>`;
  }
  if (c.verdict === 'error' && c.chain.error) {
    return html`<div class="verdict warn"><strong>${c.host} responds, but its redirects could not be followed.</strong> ${c.chain.error.replace(/\.$/, '')}.</div>`;
  }
  if (c.verdict === 'error') {
    return html`<div class="verdict warn"><strong>${c.host} responds, but with an error.</strong> HTTP ${last!.status} ${last!.statusText}:
the server is reachable but refuses or cannot find the page.</div>`;
  }
  return html`<div class="verdict bad"><strong>${c.host} looks down for everyone.</strong> ${c.chain.error?.replace(/\.$/, '') ?? `HTTP ${last?.status ?? ''}`}.
${c.addresses.length || /resolve/i.test(c.chain.error ?? '') ? '' : ' The host name does not resolve to an IP address.'}</div>`;
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/is-it-down">
<div class="field grow"><label for="url">Website</label>
<input id="url" name="url" type="text" value="${value}" placeholder="example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Check</button></div>
</form>`;
}

const INVALID = 'Enter a website such as example.com.';

const tool: Tool = {
  slug: 'is-it-down',
  name: 'Is it down?',
  icon: 'down',
  category: 'web',
  title: 'Is It Down? Check If a Website Is Down for Everyone',
  description:
    'Is a website down or is it just you? Check any site live from Cloudflare: HTTP status, response time, redirects and DNS, plus tips if it fails for you.',
  h1: 'Is it down or just me?',
  lead: 'Check from the internet whether a website is really down or only unreachable for you.',
  examples: [['github.com', 'url=github.com'], ['wikipedia.org', 'url=wikipedia.org']],
  related: ['http-headers', 'dns-lookup', 'speed-test'],
  isQuery: (url) => url.searchParams.has('url'),

  async render(c) {
    const value = (c.url.searchParams.get('url') ?? '').trim();
    if (!c.url.searchParams.has('url')) return form('');
    const url = normalizeUrl(value);
    if (!url) return html`${form(value)}<p class="error">${INVALID}</p>`;
    const r = await check(url, c.env, /^https?:\/\//i.test(value));
    if (r.verdict === 'refused') return html`${form(value)}<p class="error">${r.chain.error}</p>`;
    const cf = c.req.cf as IncomingRequestCfProperties | undefined;
    const when = new Date().toISOString().slice(11, 16);
    return html`${form(value)}${verdictBox(r)}
<p class="hint">Checked at ${when} UTC from Cloudflare ${typeof cf?.colo === 'string' ? cf.colo : ''} · <a href="/is-it-down?url=${encodeURIComponent(value)}">Check again</a></p>
<table class="kv compact"><tbody>
<tr><th scope="row">Checked URL</th><td class="wrap-any"><code>${r.url}</code>${openLink(r.url)}</td></tr>
<tr><th scope="row">IP addresses</th><td class="wrap-any">${r.addresses.length ? r.addresses.map((a, i) => html`${i ? ', ' : ''}<code>${a}</code>`) : '—'}</td></tr>
</tbody></table>
<h2>Requests</h2>${chainTable(r.chain)}
<p class="hint"><a href="/http-headers?url=${encodeURIComponent(url)}">Show all response headers</a> · <a href="/dns-lookup?name=${encodeURIComponent(r.host)}&amp;resolver=all&amp;type=A">Compare DNS across resolvers</a></p>`;
  },

  apiDoc: 'GET /api/is-it-down?url=example.com',

  async api(c) {
    const url = normalizeUrl(c.url.searchParams.get('url') ?? '');
    if (!url) return json({ error: INVALID }, { status: 400 });
    const r = await check(url, c.env, /^https?:\/\//i.test(c.url.searchParams.get('url') ?? ''));
    if (r.verdict === 'refused') return json({ error: r.chain.error }, { status: 400 });
    return json({ url: r.url, verdict: r.verdict, addresses: r.addresses, hops: r.chain.hops.map(({ headers: _h, ...rest }) => rest), error: r.chain.error });
  },

  article: html`<h2>Is the website down for everyone or just for me?</h2>
<p>When a page does not load, there are two very different possibilities: the site itself is offline, or something
between you and the site is broken. The second case is more common. Your Wi-Fi, your DNS resolver, a browser
extension, a VPN, a corporate proxy or your internet provider can all make a working site look dead. This tool
answers the first question by requesting the site from a neutral location on the public internet. If it loads here,
the site is up and the fault is somewhere on your side of the connection.</p>

<h2>How the check works</h2>
<p>The website is requested live from Cloudflare's network, much like a browser would request it, without cookies
and without running any JavaScript. In parallel, the host name is resolved in DNS to its IPv4 (A) and IPv6 (AAAA)
addresses. The check then:</p>
<ol>
<li>Follows up to 4 redirects (5 requests in total), for example from <code>http://example.com</code> to <code>https://www.example.com/</code>,
and shows every hop with its status code and response time.</li>
<li>Waits up to 8 seconds for each request and 15 seconds in total. A server that has not answered by then is treated as unreachable.</li>
<li>Refuses private and internal addresses such as <code>192.168.1.1</code>, <code>10.0.0.5</code> or
<code>localhost</code>. Only public websites can be checked.</li>
<li>Caches each result for 60 seconds, so repeated checks of the same URL within a minute show the same answer.</li>
</ol>

<h2>How to read the result</h2>
<table class="data">
<thead><tr><th>Verdict</th><th>When it is shown</th><th>What it means</th></tr></thead>
<tbody>
<tr><td>Up</td><td>Final response is 2xx or 3xx</td><td>The site works. If it fails for you, look at your own network.</td></tr>
<tr><td>Up, but blocked our automated check</td><td>401, 403 or 429, or a Cloudflare bot challenge</td><td>The server answered, so it is online. It refuses automated requests but usually works in a browser.</td></tr>
<tr><td>Responds with an error</td><td>Other 4xx codes, such as 404 or 410</td><td>The server runs, but the requested page does not exist or is refused.</td></tr>
<tr><td>Down</td><td>5xx code, timeout, DNS failure, refused connection or TLS error</td><td>The site is not working for anyone, at least not from this location.</td></tr>
</tbody>
</table>
<p>If the result says the host name does not resolve, there is no DNS record for it at all. That points to an expired
domain, a deleted record or a typo. Check the records with the <a href="/dns-lookup">DNS lookup tool</a> and the
registration status with a <a href="/whois">WHOIS lookup</a>.</p>

<h2>Common HTTP status codes during an outage</h2>
<table class="data">
<thead><tr><th>Code</th><th>Name</th><th>Typical cause</th></tr></thead>
<tbody>
<tr><td><code>200</code></td><td>OK</td><td>Everything works.</td></tr>
<tr><td><code>301</code>, <code>308</code></td><td>Moved Permanently, Permanent Redirect</td><td>Normal redirect, for example to HTTPS.</td></tr>
<tr><td><code>302</code>, <code>307</code></td><td>Found, Temporary Redirect</td><td>Temporary redirect, often to a login or maintenance page.</td></tr>
<tr><td><code>403</code></td><td>Forbidden</td><td>Access denied, often a firewall or bot protection that blocks data center traffic.</td></tr>
<tr><td><code>404</code></td><td>Not Found</td><td>The path does not exist. The server itself is fine.</td></tr>
<tr><td><code>429</code></td><td>Too Many Requests</td><td>Rate limiting.</td></tr>
<tr><td><code>500</code></td><td>Internal Server Error</td><td>Application crash or configuration error.</td></tr>
<tr><td><code>502</code></td><td>Bad Gateway</td><td>A proxy or CDN could not get a valid answer from the origin server.</td></tr>
<tr><td><code>503</code></td><td>Service Unavailable</td><td>Overload or planned maintenance.</td></tr>
<tr><td><code>504</code></td><td>Gateway Timeout</td><td>The origin server answered too slowly for the proxy or CDN.</td></tr>
</tbody>
</table>
<p>CDNs add their own codes. Cloudflare, for example, returns <code>521</code> when the origin refuses the connection,
<code>522</code> when the connection to the origin times out, and <code>525</code> or <code>526</code> for TLS problems
between Cloudflare and the origin. All of them mean the CDN is fine but the server behind it is not.</p>

<h2>It works here but not for me</h2>
<p>If the check shows the site as up, work through this list from top to bottom:</p>
<ol>
<li>Reload with the cache bypassed (<code>Ctrl+F5</code>, or <code>Cmd+Shift+R</code> on a Mac) and try a private window.</li>
<li>Disable browser extensions, ad blockers and VPNs one at a time.</li>
<li>Try another network, such as mobile data instead of Wi-Fi. If it works there, the problem is your local network or provider.</li>
<li>Clear the DNS cache: <code>ipconfig /flushdns</code> on Windows, <code>sudo resolvectl flush-caches</code> on Linux
with systemd-resolved, <code>sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder</code> on macOS.</li>
<li>Switch to a public DNS resolver such as 1.1.1.1 or 8.8.8.8, in case your provider's resolver is broken or filtering.</li>
<li>Compare the IP addresses shown here with what your computer resolves: <code>nslookup example.com</code>. A different or
outdated address can mean a recent DNS change has not reached your resolver yet. The
<a href="/dns-propagation-checker">DNS propagation checker</a> shows what ${COMPARE_RESOLVERS.length} public resolvers return.</li>
<li>Check whether a school, company or parental-control filter blocks the site.</li>
</ol>

<h2>Checking from the command line</h2>
<p>You can reproduce the test yourself. <code>curl -I https://example.com</code> prints only the status line and
headers; adding <code>-L</code> follows redirects. <code>curl -sS -o /dev/null -w "%{http_code} %{time_total}\\n" https://example.com</code>
prints just the status code and total time. If curl reports <code>Could not resolve host</code>, the problem is DNS;
<code>Connection refused</code> means nothing listens on the port; <code>Connection timed out</code> usually means a
firewall drops the packets or the host is offline. To test a port directly, use the
<a href="/port-checker">port checker</a> or measure TCP connect times with <a href="/tcp-ping">TCP ping</a>. For a full view
of the redirect chain and response headers, use the <a href="/http-headers">HTTP header checker</a>.</p>

<h2>Why websites go down</h2>
<p>Most outages fall into a few groups. Expired domains and expired TLS certificates are the easiest to rule out: the domain
stops resolving, or browsers show a certificate warning while the server itself runs fine. Overload during traffic peaks
or attacks typically shows up as <code>503</code> or timeouts. Failed deployments and database problems produce
<code>500</code> errors. DNS mistakes, such as a record pointing to an old server IP, make a site vanish for some users
and not others while caches expire. Hosting and CDN incidents can take down thousands of sites at once.</p>

<h2>Limits of a single check</h2>
<p>This is a snapshot from one network at one moment. A site can be reachable from Cloudflare but blocked in one country,
broken only for IPv6 users, or failing only for logged-in users. Large services also serve different regions from
different data centers, so a regional outage may not show up here. If the site is reported as up but many people
report problems, check the service's official status page as well.</p>`,

  faq: [
    { q: 'Why does a site show 403 here but work in my browser?', a: 'Many sites block requests from data centers or require a browser challenge before they serve content. A 401, 403 or 429 answer still proves the server is online, so the result is shown as up, but blocked our automated check.' },
    { q: 'How often should I check again?', a: 'Outages are often fixed within minutes. Results are cached for 60 seconds, so wait at least a minute before checking the same URL again.' },
    { q: 'Can I check a site on my local network?', a: 'No. The check runs on the public internet and refuses private and internal addresses such as 192.168.x.x, 10.x.x.x and localhost. Test local devices from inside your own network instead.' },
    { q: 'The site is up here but down for me. What is the most likely cause?', a: 'Usually DNS or the local network. Flush your DNS cache, try a public resolver such as 1.1.1.1, and test from mobile data. If it works on another network, contact your provider or network administrator.' },
    { q: 'What does a timeout mean?', a: 'The server did not answer within 8 seconds. Common causes are an overloaded server, a firewall dropping traffic, or a host that is switched off.' },
    { q: 'Does the check download the whole page?', a: 'No. It requests the URL and evaluates the status code and headers of each response. Scripts are not executed, so a page that loads but breaks in JavaScript can still show as up.' },
  ],
};

export default tool;
