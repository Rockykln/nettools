import { SITE } from './config';
import { html, secret, type SafeHtml } from './core/html';
import { icon, page } from './core/layout';
import { absolute, pageJsonLd, toolJsonLd, websiteJsonLd } from './core/seo';
import { normalizeDomain } from './core/net';
import { CATEGORIES, type Tool, type ToolContext } from './core/tool';
import { RESOLVERS } from './core/transport';
import { LANDING_PAGES, TOOLS, TOOLS_BY_SLUG } from './tools/registry';
import { ipHero, ipInfo } from './tools/what-is-my-ip';

function toolCard(t: Tool, showCategory: boolean): SafeHtml {
  const category = CATEGORIES.find((cat) => cat.id === t.category)!;
  return html`<a class="tool-card" href="/${t.slug}"><span class="tile">${icon(t.icon, '')}</span>
<span>${showCategory ? html`<span class="cat">${category.name}</span>` : ''}<span class="tc-name">${t.name}</span><span class="desc">${t.lead}</span></span><span class="arrow" aria-hidden="true">→</span></a>`;
}

function toolCards(tools: Tool[], showCategory = true): SafeHtml {
  return html`<ul class="card-grid">${tools.map((t) => html`<li>${toolCard(t, showCategory)}</li>`)}</ul>`;
}

/** Embed code for the grade badge of the checked domain (security headers, email security). */
function badgeBox(c: ToolContext, tool: Tool): SafeHtml {
  const kind = tool.slug === 'http-headers' ? 'headers' : tool.slug === 'email-security' ? 'email' : null;
  if (!kind) return html``;
  const raw = c.url.searchParams.get(kind === 'headers' ? 'url' : 'domain') ?? '';
  const domain = normalizeDomain(raw);
  if (!domain?.includes('.')) return html``;
  const img = absolute(c.env, `/badge/${kind}/${domain}.svg`);
  const link = absolute(c.env, kind === 'headers' ? `/http-headers?url=${encodeURIComponent(domain)}` : `/email-security?domain=${encodeURIComponent(domain)}`);
  const md = `[![${kind === 'headers' ? 'Security headers' : 'Email security'}](${img})](${link})`;
  return html`<div class="share-bar"><span class="muted">Badge for your README:</span>
<img src="/badge/${kind}/${domain}.svg" alt="${kind} grade badge" height="20">
<button type="button" class="btn-small" data-copy="${md}">Copy Markdown</button>
<button type="button" class="btn-small" data-copy="${`<a href="${link}"><img src="${img}" alt="${kind === 'headers' ? 'Security headers' : 'Email security'} grade"></a>`}">Copy HTML</button></div>`;
}

/** Copy/share controls for a result URL. The native share button is revealed by site.js where supported. */
export function shareBar(url: string, title: string): SafeHtml {
  return html`<div class="share-bar"><span class="muted">Share this result:</span>
<code class="share-url">${url}</code>
<button type="button" class="btn-small" data-copy="${url}">Copy link</button>
<button type="button" class="btn-small" data-share="${url}" data-share-title="${title}" hidden>Share…</button></div>`;
}

function toolList(tools: Tool[]): SafeHtml {
  return html`<ul class="tool-list">${tools.map((t) => html`<li><a href="/${t.slug}">${icon(t.icon)}${t.name}</a><span>${t.lead}</span></li>`)}</ul>`;
}

export async function toolPage(c: ToolContext, tool: Tool): Promise<Response> {
  const category = CATEGORIES.find((cat) => cat.id === tool.category)!;
  const isQuery = tool.isQuery?.(c.url) ?? false;
  const related = tool.related.map((s) => TOOLS_BY_SLUG.get(s)).filter((t): t is Tool => !!t);
  const rendered = await tool.render(c);
  // A query that only produced an error message is answered with 400 and is not offered for sharing.
  const failed = isQuery && /<p class="error">/.test(rendered.value) && !/class="(result|verdict|data|kv)/.test(rendered.value);
  const pageUrl = absolute(c.env, c.url.pathname + c.url.search);
  const body = html`<div class="wrap">
<nav class="crumbs" aria-label="Breadcrumb"><a href="/">${SITE.name}</a> <span aria-hidden="true">›</span> <a href="/#${category.id}">${category.name}</a> <span aria-hidden="true">›</span> <span aria-current="page">${tool.name}</span></nav>
<div class="tool-head"><span class="tile">${icon(tool.icon, '')}</span>
<div><h1>${tool.h1}</h1><p class="lead">${tool.lead}</p></div></div>
<section class="tool" aria-label="${tool.name}">
${rendered}
</section>
${isQuery && !failed ? shareBar(pageUrl, tool.h1) : ''}
${isQuery && !failed ? badgeBox(c, tool) : ''}
${!isQuery && tool.examples?.length ? html`<p class="examples"><span class="muted">Try:</span> ${tool.examples.map(([label, q]) => html`<a class="chip" href="/${tool.querySlug ?? tool.slug}?${q}" rel="nofollow">${label}</a>`)}</p>` : ''}
<div class="below-tool">
<article class="article">
${tool.article}
</article>
${tool.faq.length ? html`<section class="faq"><h2>Frequently asked questions</h2>
${tool.faq.map((f) => html`<h3>${f.q}</h3><p>${f.a}</p>`)}</section>` : ''}
${related.length ? html`<section class="related"><h2>Related tools</h2>${toolList(related)}</section>` : ''}
</div>
</div>`;
  return page(c.env, {
    title: tool.title,
    description: tool.description,
    path: `/${tool.slug}`,
    url: isQuery ? pageUrl : undefined,
    body,
    noindex: isQuery,
    personal: tool.personal,
    jsonLd: toolJsonLd(c.env, tool),
    image: `/og/${tool.slug}.png`,
    imageAlt: `${tool.h1} – ${tool.lead}`,
    scripts: tool.script ? [tool.script] : [],
    status: failed ? 400 : 200,
  });
}

export async function homePage(c: ToolContext): Promise<Response> {
  const info = await ipInfo(c, { ptr: false });
  const host = new URL(c.env.SITE_URL).host;
  const body = html`<section class="hero"><div class="wrap hero-grid">
<div>
<span class="eyebrow">Free network tools</span>
<h1>Free network tools for IP, DNS and speed – <em>without the ads.</em></h1>
<p class="lead">${SITE.name} is a set of fast network tools for admins, developers and the curious. Every lookup runs
live on Cloudflare's global network. No pop-ups, no cookies, no sign-up.</p>
<div class="hero-actions"><a class="btn" href="/speed-test">${icon('speed')}Run a speed test</a>
<a class="btn secondary" href="/dns-lookup">${icon('dns')}DNS lookup</a></div>
<ul class="trust">${['No ads', 'No cookies', 'No sign-up', 'Open source'].map((t) => html`<li>${icon('check')}${t}</li>`)}</ul>
</div>
<section class="tool" aria-label="Your IP address">
${ipHero(info, true)}
<p class="ip-meta">${info.isp ?? ''}${info.isp ? ' · ' : ''}${secret([info.city, info.country].filter(Boolean).join(', ') || '—')}</p>
<p class="ip-meta"><a href="/what-is-my-ip">See reverse DNS, ASN and connection details →</a></p>
</section>
</div></section>

<section class="section" id="tools"><div class="wrap">
<h2 class="section-title">All tools</h2>
<p class="section-intro">Most results render on the server, so they work without JavaScript and every result has a link you can share.</p>
${CATEGORIES.map((cat) => {
    const tools = TOOLS.filter((t) => t.category === cat.id);
    return tools.length ? html`<h3 class="cat-title" id="${cat.id}">${cat.name} <span class="cat-count">${tools.length}</span></h3>${toolCards(tools, false)}` : '';
  })}
<p class="examples"><span class="muted">Popular checks:</span> ${LANDING_PAGES.map((l) => html`<a class="chip" href="/${l.slug}">${l.name}</a>`)}</p>
</div></section>

<section class="section"><div class="wrap">
<h2 class="section-title">Why ${SITE.name}?</h2>
<div class="features">
<div class="feature"><span class="tile">${icon('shield', '')}</span><h3>Private by design</h3>
<p>No ads, no cookies, no profiles. What you enter is used for the lookup, not kept.</p></div>
<div class="feature"><span class="tile">${icon('code', '')}</span><h3>Built for admins</h3>
<p>Shareable result links, a free JSON API and plain-text output for scripts and terminals.</p></div>
<div class="feature"><span class="tile">${icon('github', '')}</span><h3>Open source</h3>
<p>MIT licensed on GitHub. Read the code, report an issue or suggest the next tool.</p></div>
</div>
</div></section>

<section class="section" id="api"><div class="wrap api-grid">
<div><h2 class="section-title">Use it from your terminal</h2>
<p class="section-intro">Every lookup tool has a JSON endpoint. No key, no account; requests are rate limited per IP address.</p>
<div class="hero-actions"><a class="btn secondary" href="/api">API documentation</a>
<a class="btn secondary" href="${SITE.github}" rel="noopener">${icon('github')}View on GitHub</a></div></div>
<pre class="terminal"><span class="comment"># Your public IP as plain text</span>
<span class="cmd"><span class="prompt">$ </span>curl ${host}/ip</span>
<span class="comment"># MX records via Google DNS</span>
<span class="cmd"><span class="prompt">$ </span>curl "${host}/api/dns-lookup<wbr>?name=example.com<wbr>&amp;type=MX<wbr>&amp;resolver=google"</span>
<span class="comment"># Who operates an IP address or network?</span>
<span class="cmd"><span class="prompt">$ </span>curl "${host}/api/whois<wbr>?q=AS13335"</span></pre>
</div></section>`;
  return page(c.env, {
    title: `Free Network Tools – IP, DNS, WHOIS & Speed Test | ${SITE.name}`,
    description:
      'Free network tools: what is my IP, speed test, port checker, DNS lookup, WHOIS, SPF/DMARC check, subnet calculator and more. No ads, no cookies.',
    path: '/',
    body,
    personal: true,
    jsonLd: [websiteJsonLd(c.env)],
  });
}

export function legalPage(c: ToolContext): Response {
  const o = SITE.operator;
  // "OpenDNS (Cisco)" already carries parentheses; the location is added inside them, not as a second pair.
  const resolvers = RESOLVERS.map((r) => (r.name.endsWith(')') ? `${r.name.slice(0, -1)}, ${r.location.replace(/^Global/, 'global')})` : `${r.name} (${r.location.replace(/^Global/, 'global')})`)).join(', ');
  const summary: [string, string][] = [
    ['Cookies', 'None. Only your light/dark choice is kept in your browser’s local storage.'],
    ['Advertising', 'None.'],
    ['Your inputs', 'Sent to the services needed for the lookup. Not stored by us, except in Cloudflare’s technical logs (up to 7 days) and a short-lived result cache (up to 6 hours).'],
    ['Your IP address', 'Processed by Cloudflare to deliver the site and kept in its technical logs for up to 7 days; counted for 60 seconds for rate limiting; never part of our statistics.'],
    ['Statistics', 'Server-side counts of page views and tool usage, without IP addresses or inputs. No tracking scripts.'],
  ];
  const body = html`<div class="wrap">
<h1>Legal notice &amp; privacy</h1>
<p class="lead">Who runs ${SITE.name} and exactly what happens with your data – in plain words.</p>
<div class="legal-grid">
<aside class="tool legal-card" aria-label="Legal notice">
<h2>Legal notice (Impressum)</h2>
<p class="muted">Information according to § 5 DDG and § 18 (1) MStV</p>
<address>${o.name}<br>${o.street}<br>${o.postBox}<br>${o.city}<br>${o.country}</address>
<p>Email: <a href="mailto:${o.email}">${o.email}</a></p>
<p class="muted">Responsible for content according to § 18 (2) MStV: ${o.name}, address as above.</p>
<p class="muted">Private, non-commercial project.</p>
</aside>
<div class="legal-body">
<h2 id="privacy">Privacy in short</h2>
<table class="kv"><tbody>${summary.map(([t, d]) => html`<tr><th scope="row">${t}</th><td>${d}</td></tr>`)}</tbody></table>

<h2>Controller</h2>
<p>The controller responsible for data processing on this website is ${o.name}, contact details as in the legal
notice. Providing data is neither legally nor contractually required, and there is no automated decision-making.</p>

<h2>Hosting and delivery</h2>
<p>The site runs on Cloudflare Workers (Cloudflare, Inc., 101 Townsend St, San Francisco, CA 94107, USA). Cloudflare
processes your IP address and request data to deliver the site and protect it from attacks (Art. 6 (1) (f) GDPR;
our interest is a secure and working website). Cloudflare acts as our processor under a data processing agreement
(Art. 28 GDPR). Transfers to the USA rely on the EU-U.S. Data Privacy Framework and Standard Contractual Clauses.
See <a href="https://www.cloudflare.com/privacypolicy/" rel="noopener">Cloudflare’s privacy policy</a>.</p>

<h2>Usage statistics and logs</h2>
<p>For each request the server records which tool was used, whether it succeeded, how long it took, the country
derived from your IP address and the Cloudflare data center that answered. These statistics contain neither your
IP address nor your inputs and are kept for up to three months. In addition, Cloudflare’s technical request logs
and traces contain the requested address including what you entered in a tool, your IP address, your browser’s user
agent and your approximate location. They are kept for up to 7 days to find errors and are then deleted
automatically (Art. 6 (1) (f) GDPR; our interest is operating and improving the service).</p>

<h2>What happens with your tool inputs</h2>
<p>Domains, IP addresses, URLs and other values you enter are used to run the lookup you asked for (Art. 6 (1) (b)
GDPR, or (f): providing the service you request). To do that, the server sends them to the services that hold the
answer:</p>
<ul>
<li><strong>DNS lookups</strong> go to the public resolver you choose: ${resolvers}. “Compare all resolvers” uses all
of them except AliDNS, which is only queried when you select it. China has no EU adequacy decision, and data there
may be accessed by authorities; do not select AliDNS for lookups you want to keep private.</li>
<li><strong>Registration data</strong> comes from the RDAP and WHOIS servers of the registries listed by IANA,
<strong>routing data</strong> from RIPEstat (RIPE NCC, Netherlands), <strong>certificate data</strong> from Cert Spotter (SSLMate, USA) and crt.sh
(Sectigo, UK/USA) and <strong>blocklist data</strong> from the DNS blocklists named in the tool, queried through Cloudflare’s resolver.</li>
<li><strong>IPv6 test:</strong> only when you start the test, your browser contacts ipify (api4.ipify.org and
api6.ipify.org, a public IP address service operated from the USA), which sees your IP addresses. Nothing is sent to
us.</li>
<li><strong>User agent page:</strong> screen size, time zone and similar values are read by a script in your browser
and only displayed there.</li>
<li><strong>Helper lookups</strong> (address checks before connecting, blocklists, email records, DNSSEC, the reverse
DNS of your own IP) use Cloudflare’s resolver 1.1.1.1. Registry lookups start at IANA (data.iana.org, whois.iana.org).</li>
<li><strong>Website, header, certificate, social preview, robots.txt, response time, port and ping checks,</strong> the
MTA-STS policy of the email check and grade badges connect from our server to the address you enter. That host sees a
request from Cloudflare’s network, not from your IP address, and may log it.</li>
</ul>
<p>Several of these services are outside the EU: Google, OpenDNS (Cisco), NextDNS and Wikimedia in the USA, Control D
in Canada, Quad9 in Switzerland, IIJ in Japan, Cloudflare (as resolver), Cert Spotter and ipify in the USA, crt.sh in the UK and USA and AliDNS in China;
DNS.SB and the DNS blocklists are run by operators in several countries, including the USA. The transfer happens
because you request that lookup (Art. 49 (1) (b) GDPR). Switzerland, Japan, Canada and the UK have EU adequacy
decisions; for the USA the Data Privacy Framework applies to certified companies.</p>
<p>Results may be cached for up to six hours to reduce load on these services. Your own IP address is not passed on,
except where a tool is about your own connection: “What is my IP” looks up the reverse DNS name of your address, and
the port checker connects to it if you leave the host empty. If you enter your own address into a lookup, for example
via the “owner and blocklists” link on “What is my IP”, it is treated like any other input: IP lookup sends it to the
regional registry (RDAP), RIPEstat and the DNS blocklists, and the results may be cached as described above.</p>

<h2>Grade badges</h2>
<p>Badges embedded on other websites are loaded from this site by those websites’ visitors. Their browsers send the
usual request data (IP address, user agent) to Cloudflare as described under hosting; nothing else is recorded.</p>

<h2>Email header analyzer</h2>
<p>Headers you paste into the email header analyzer are processed only in your browser and never sent to our server.</p>

<h2>Speed test</h2>
<p>The test data is random and discarded immediately. Results are calculated in your browser and only become part of
a link if you share it.</p>

<h2>Rate limiting</h2>
<p>To prevent abuse, the number of requests per IP address (per /64 network for IPv6) is counted for up to 60 seconds
and then discarded (Art. 6 (1) (f) GDPR; our interest is preventing abuse).</p>

<h2>Light and dark mode</h2>
<p>If you switch between light and dark mode, your choice is saved in your browser’s local storage so the site
remembers it. It is never sent to the server and is strictly necessary for the function you requested
(§ 25 (2) No. 2 TDDDG). You can delete it at any time in your browser settings.</p>

<h2>Contacting us by email</h2>
<p>If you email us, we process your message to reply (Art. 6 (1) (f) GDPR) and delete it when it is no longer needed.</p>

<h2>Your rights</h2>
<p>You have the right to access, rectification, erasure, restriction of processing and data portability. You may
object at any time to processing based on Art. 6 (1) (f) GDPR for reasons arising from your particular situation
(Art. 21 GDPR). You also have the right to lodge a complaint with a supervisory authority, for example the
Landesbeauftragte für Datenschutz und Informationsfreiheit Nordrhein-Westfalen, Kavalleriestraße 2–4,
40213 Düsseldorf, <a href="https://www.ldi.nrw.de/" rel="noopener">ldi.nrw.de</a>. As this site stores no data that
identifies you, there is usually nothing to disclose. Contact: <a href="mailto:${o.email}">${o.email}</a>.</p>

<h2>Acceptable use</h2>
<p>Only check hosts and networks you own or are authorized to test. Scanning third-party systems without permission
may be illegal and may violate the terms of their operator. Abuse is blocked and may be reported.</p>

<h2>Liability</h2>
<p>All tools and results are provided free of charge and without warranty of accuracy, completeness or availability.
Liability is limited to intent and gross negligence, except for injury to life, body or health; liability under
mandatory law, such as the Product Liability Act, and for breach of essential obligations remains unaffected. We are not
responsible for the content of external websites we link to; no unlawful content was apparent when the links were
set.</p>

<h2 id="licenses">Licenses &amp; credits</h2>
<ul>
<li>Source code: <a href="${SITE.license.url}" rel="noopener license">${SITE.license.name} License</a>, © 2026 ${SITE.author},
available on <a href="${SITE.github}" rel="noopener">GitHub</a>. The ${SITE.name} name and logo may not be used to imply
endorsement.</li>
<li>Icons: <a href="https://phosphoricons.com" rel="noopener">Phosphor Icons</a>, <a href="/assets/LICENSE-Phosphor.txt">MIT License</a>.</li>
<li>Font: <a href="https://rsms.me/inter/" rel="noopener">Inter</a> by The Inter Project Authors,
<a href="/assets/fonts/LICENSE-Inter.txt">SIL Open Font License 1.1</a>. Served from this site, not from a font service.</li>
<li>MAC vendor data: IEEE Registration Authority (standards-oui.ieee.org), used as published.</li>
<li>IP to country data: <a href="https://db-ip.com" rel="noopener">IP Geolocation by DB-IP</a>, <a href="https://creativecommons.org/licenses/by/4.0/" rel="noopener">CC BY 4.0</a>.</li>
<li>GitHub and the GitHub logo are trademarks of GitHub, Inc.; they are used only to link to the source code.</li>
</ul>
</div>
</div>
</div>`;
  return page(c.env, {
    title: `Legal notice & privacy – ${SITE.name}`,
    description: `Legal notice (Impressum) and privacy policy of ${SITE.name}.`,
    path: '/legal',
    jsonLd: pageJsonLd(c.env, '/legal', 'Legal notice & privacy', 'Legal notice and privacy information for nettools.'),
    body,
    noindex: true,
  });
}

/** Warning page before leaving the site through a link to a host found by a tool. */
export function goPage(c: ToolContext): Response {
  const raw = c.url.searchParams.get('url') ?? '';
  let target: URL | null = null;
  try {
    const u = new URL(raw);
    if ((u.protocol === 'https:' || u.protocol === 'http:') && u.hostname.includes('.')) target = u;
  } catch {
    target = null;
  }
  if (!target) return notFoundPage(c);
  const href = target.toString();
  const host = target.hostname;
  const body = html`<div class="wrap narrow">
<h1>You are leaving ${SITE.name}</h1>
<p class="lead">This link leads to an external website that ${SITE.name} has not checked.</p>
<section class="tool leave">
<p class="leave-host">${target.protocol === 'http:' ? html`<span class="status warn">no HTTPS</span> ` : ''}<strong>${host}</strong></p>
<p class="wrap-any"><code>${href}</code></p>
<p class="muted">Addresses found in DNS, certificate logs or redirects can belong to internal, unfinished or unsafe
systems. Only continue if you trust this site.</p>
<div class="hero-actions"><a class="btn" href="${href}" rel="noopener noreferrer nofollow">Continue to ${host}</a>
<button type="button" class="btn secondary" data-back>Go back</button></div>
<p class="hint">Check it first: <a href="/is-it-down?url=${encodeURIComponent(href)}">is it up?</a> ·
<a href="/http-headers?url=${encodeURIComponent(href)}">HTTP headers</a> ·
<a href="/whois?q=${encodeURIComponent(host)}">WHOIS</a></p>
</section>
</div>`;
  return page(c.env, { title: `Leaving ${SITE.name}`, description: 'External link warning.', path: '/go', body, noindex: true });
}

export function apiPage(c: ToolContext): Response {
  const host = new URL(c.env.SITE_URL).host;
  const tools = TOOLS.filter((t) => t.apiDoc);
  const body = html`<div class="wrap">
<h1>Free network API</h1>
<p class="lead">Every lookup tool has a JSON endpoint. No key, no account, no sign-up.</p>
<div class="below-tool"><article class="article">
<h2>Basics</h2>
<ul>
<li>All endpoints answer <code>GET</code> requests with JSON (<code>application/json</code>). Errors return a JSON object
with an <code>error</code> field and an HTTP status of 400 (invalid input), 403 (cross-site browser requests), 404 (nothing found, e.g. no RDAP record), 405 (wrong method), 429, 502 or 503.</li>
<li>Rate limits per IP address (per /64 for IPv6): 30 requests per minute; port checks of other hosts, TCP ping, DNSSEC, certificate, social preview, robots.txt, response time,
DNS benchmark, blocklist, IP lookup, subdomain, email, domain availability, compare-all DNS queries, the full root server test, range-to-CIDR with more than 20 entries
and uncached badges additionally 10 per minute; single root server tests allow 30 and the speed test 600 requests per minute. Over the limit you get
HTTP 429; wait a minute.</li>
<li>Please keep automated use moderate. For monitoring many domains, run your own copy from the
<a href="${SITE.github}" rel="noopener">source code</a> on the Cloudflare Workers free plan.</li>
<li>Plain text: <code>curl ${host}</code> or <code>curl ${host}/ip</code> prints only your IP address.</li>
<li>Badges: <code>/badge/headers/example.com.svg</code> and <code>/badge/email/example.com.svg</code> return an SVG grade badge (A–F), cached for 6 hours.</li>
</ul>
<h2>Endpoints</h2>
<div class="table-scroll" tabindex="0" role="region" aria-label="API endpoints"><table class="data"><thead><tr><th>Tool</th><th>Request</th></tr></thead>
<tbody>${tools.map((t) => html`<tr><td><a href="/${t.slug}">${t.name}</a></td><td class="wrap-any">${t.apiDoc!.split('; ').map((part, i) => {
    const m = part.match(/^(.*?)(?: \((.*)\))?$/)!;
    return html`${i ? html`<br>` : ''}<code>${m[1]}</code>${m[2] ? html` <span class="muted">${m[2]}</span>` : ''}`;
  })}</td></tr>`)}
<tr><td>Tool index</td><td><code>GET /api/tools</code></td></tr></tbody></table></div>
<h2>Example</h2>
<pre class="raw">curl "${host}/api/dns-lookup?name=example.com&amp;type=MX"</pre>
<p>A machine-readable overview for AI assistants is available at <a href="/llms.txt">/llms.txt</a>.</p>
</article></div>
</div>`;
  return page(c.env, {
    title: `Free Network API – DNS, WHOIS, IP & Port Check | ${SITE.name}`,
    description: 'Free JSON API for DNS lookups, WHOIS/RDAP, IP details, port checks, DNSSEC, email security and more. No key, no sign-up, documented examples.',
    path: '/api',
    jsonLd: pageJsonLd(c.env, '/api', 'Free network API', 'Free JSON API for DNS lookups, WHOIS/RDAP, IP details, port checks, DNSSEC, email security and more.', 'TechArticle'),
    body,
  });
}

export function notFoundPage(c: ToolContext): Response {
  const body = html`<div class="wrap">
<h1>Page not found</h1>
<p class="lead">There is nothing at <code>${c.url.pathname}</code>. Maybe one of these tools is what you were looking for:</p>
${toolList(TOOLS)}
</div>`;
  return page(c.env, { title: `Not found – ${SITE.name}`, description: 'Page not found.', path: c.url.pathname, body, noindex: true, status: 404 });
}

export function rateLimitedPage(c: ToolContext): Response {
  const body = html`<div class="wrap">
<h1>Too many requests</h1>
<p class="lead">You ran a lot of lookups in a short time. Please wait a minute and try again.</p>
<p><a class="btn secondary" href="${c.url.pathname}">Back to the tool</a></p>
</div>`;
  return page(c.env, { title: `Too many requests – ${SITE.name}`, description: 'Rate limit reached.', path: c.url.pathname, body, noindex: true, status: 429 });
}
