import { cachedJson } from '../core/cache';
import { html, type SafeHtml } from '../core/html';
import { openLink } from '../core/ui';
import { json } from '../core/http';
import { fetchChain, normalizeUrl, type Chain, type Hop } from '../core/http-probe';
import type { Tool } from '../core/tool';

type Level = 'ok' | 'warn' | 'bad' | 'info';

interface Finding {
  header: string;
  level: Level;
  note: string;
}

const get = (hop: Hop, name: string) => hop.headers.find(([k]) => k === name)?.[1] ?? null;

/** max-age of an HSTS header in seconds (quoted values and spaces around "=" are valid), or null if absent. */
export function hstsMaxAge(value: string): number | null {
  for (const directive of value.split(';')) {
    const m = directive.trim().match(/^max-age\s*=\s*"?(\d+)"?$/i);
    if (m) return Number(m[1]);
  }
  return null;
}

/** Sources of the frame-ancestors directive across all policies, or null if no policy sets it. */
export function frameAncestors(csp: string | null): string[][] | null {
  if (!csp) return null;
  const found: string[][] = [];
  // Several CSP headers arrive joined with ", "; each is an independent policy.
  for (const policy of csp.split(',')) {
    for (const directive of policy.split(';')) {
      const [name, ...sources] = directive.trim().split(/\s+/);
      if (name?.toLowerCase() === 'frame-ancestors') {
        found.push(sources.map((x) => x.toLowerCase()));
        break;
      }
    }
  }
  return found.length ? found : null;
}

function framingFinding(xfo: string | null, csp: string | null): Finding {
  const header = 'Clickjacking protection';
  const ancestors = frameAncestors(csp);
  if (ancestors) {
    // Every policy is enforced, so one that is restrictive is enough; "*" or bare schemes allow any site.
    const open = (src: string[]) => src.some((x) => x === '*' || /^(https?|wss?|data|blob):$/.test(x));
    return ancestors.some((src) => !open(src))
      ? { header, level: 'ok', note: `CSP frame-ancestors ${ancestors.find((src) => !open(src))!.join(' ') || "(empty, same as 'none')"}` }
      : { header, level: 'warn', note: 'CSP frame-ancestors allows any site to embed the page.' };
  }
  if (xfo) {
    const v = xfo.split(',')[0]!.trim().toUpperCase();
    return v === 'DENY' || v === 'SAMEORIGIN'
      ? { header, level: 'ok', note: `X-Frame-Options: ${xfo}` }
      : { header, level: 'warn', note: `X-Frame-Options: ${xfo} is not supported by modern browsers; use DENY, SAMEORIGIN or CSP frame-ancestors.` };
  }
  return { header, level: 'warn', note: 'Neither X-Frame-Options nor CSP frame-ancestors is set.' };
}

export function securityFindings(hop: Hop): Finding[] {
  const out: Finding[] = [];
  const https = hop.url.startsWith('https:');
  const hsts = get(hop, 'strict-transport-security');
  if (!https) out.push({ header: 'HTTPS', level: 'bad', note: 'The final page is served over plain HTTP.' });
  else if (!hsts) out.push({ header: 'Strict-Transport-Security', level: 'bad', note: 'Missing. Browsers may still try plain HTTP first.' });
  else {
    const age = hstsMaxAge(hsts) ?? 0;
    out.push(age >= 15552000
      ? { header: 'Strict-Transport-Security', level: 'ok', note: `max-age ${Math.round(age / 86400)} days${/includesubdomains/i.test(hsts) ? ', includes subdomains' : ''}${/preload/i.test(hsts) ? ', preload' : ''}.` }
      : { header: 'Strict-Transport-Security', level: 'warn', note: `max-age is only ${Math.round(age / 86400)} days; at least 180 days is recommended.` });
  }
  const csp = get(hop, 'content-security-policy');
  out.push(csp
    ? { header: 'Content-Security-Policy', level: 'ok', note: 'Present.' }
    : { header: 'Content-Security-Policy', level: 'warn', note: 'Missing. A CSP limits the damage of cross-site scripting.' });
  // Duplicate headers arrive joined with ", "; browsers still honour "nosniff, nosniff".
  out.push(get(hop, 'x-content-type-options')?.split(',')[0]?.trim().toLowerCase() === 'nosniff'
    ? { header: 'X-Content-Type-Options', level: 'ok', note: 'nosniff' }
    : { header: 'X-Content-Type-Options', level: 'warn', note: 'Should be "nosniff".' });
  out.push(framingFinding(get(hop, 'x-frame-options'), csp));
  const rp = get(hop, 'referrer-policy');
  // The last valid token wins; these two send the full URL to other sites.
  const rpLast = rp?.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean).pop();
  out.push(rp
    ? rpLast === 'unsafe-url' || rpLast === 'no-referrer-when-downgrade'
      ? { header: 'Referrer-Policy', level: 'warn', note: `${rp}: sends the full URL, including path and query, to other sites.` }
      : { header: 'Referrer-Policy', level: 'ok', note: rp }
    : { header: 'Referrer-Policy', level: 'info', note: 'Not set; browsers default to strict-origin-when-cross-origin.' });
  const pp = get(hop, 'permissions-policy');
  out.push(pp
    ? { header: 'Permissions-Policy', level: 'ok', note: 'Present.' }
    : { header: 'Permissions-Policy', level: 'info', note: 'Not set. Optional; restricts camera, microphone and other browser features.' });
  for (const h of ['server', 'x-powered-by']) {
    const v = get(hop, h);
    if (v && /\d/.test(v)) out.push({ header: h === 'server' ? 'Server' : 'X-Powered-By', level: 'info', note: `Reveals software versions: ${v}` });
  }
  return out;
}

const LABEL: Record<Level, string> = { ok: 'good', warn: 'improve', bad: 'missing', info: 'note' };
const badge = (l: Level) => html`<span class="status ${l}">${LABEL[l]}</span>`;

export function chainTable(chain: Chain): SafeHtml {
  return html`<div class="table-scroll" tabindex="0" role="region" aria-label="Redirect chain"><table class="data"><thead><tr><th>#</th><th>Status</th><th>URL</th><th>Time</th></tr></thead>
<tbody>${chain.hops.map((h, i) => html`<tr><td>${i + 1}</td><td><span class="status ${h.status < 400 ? 'ok' : 'bad'}">${h.status}</span> <span class="muted">${h.statusText}</span></td><td class="wrap-any"><code>${h.url}</code>${openLink(h.url)}</td><td>${h.ms} ms</td></tr>`)}
${chain.error ? html`<tr><td>${chain.hops.length + 1}</td><td><span class="status bad">error</span></td><td colspan="2">${chain.error}</td></tr>` : ''}</tbody></table></div>`;
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/http-headers">
<div class="field grow"><label for="url">URL</label>
<input id="url" name="url" type="text" value="${value}" placeholder="https://example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Check headers</button></div>
</form>`;
}

const INVALID = 'Enter a web address such as example.com or https://example.com/page.';

const tool: Tool = {
  slug: 'http-headers',
  name: 'HTTP headers',
  icon: 'headers',
  category: 'web',
  title: 'HTTP Header Checker – Security Headers, Redirects & Status',
  description:
    'Check the HTTP headers of any URL: redirect chain, status codes, HSTS, CSP, X-Frame-Options and other security headers, with clear recommendations.',
  h1: 'HTTP header checker',
  lead: 'See the redirect chain and response headers of any URL, and which security headers are missing.',
  examples: [['github.com', 'url=https://github.com'], ['http → https redirect', 'url=http://wikipedia.org']],
  related: ['is-it-down', 'dns-lookup', 'whois'],
  isQuery: (url) => url.searchParams.has('url'),

  async render(c) {
    const value = (c.url.searchParams.get('url') ?? '').trim();
    if (!c.url.searchParams.has('url')) return form('');
    const url = normalizeUrl(value);
    if (!url) return html`${form(value)}<p class="error">${INVALID}</p>`;
    const chain = await cachedJson(`hdr:${url}`, () => 60, () => fetchChain(url, c.env));
    const final = chain.hops[chain.hops.length - 1];
    // Nothing answered at all: show it as an error (no share bar, HTTP 400) rather than a one-row table.
    if (!final) return html`${form(value)}<p class="error">${chain.error ?? 'No response.'}</p>`;
    return html`${form(value)}
<h2>Redirect chain</h2>${chainTable(chain)}
${final ? html`<h2>Security headers</h2>
${final.status >= 400 ? html`<p class="hint">The final response is an error page (HTTP ${final.status}). Its headers may come from a proxy or CDN rather than the site itself.</p>` : ''}
<div class="table-scroll" tabindex="0" role="region" aria-label="Security header checks"><table class="data"><thead><tr><th>Check</th><th>Result</th><th>Details</th></tr></thead>
<tbody>${securityFindings(final).map((f) => html`<tr><td>${/\s/.test(f.header) ? f.header : html`<code>${f.header}</code>`}</td><td>${badge(f.level)}</td><td class="wrap-any">${f.note}</td></tr>`)}</tbody></table></div>
<h2>Response headers</h2>
<p class="muted">Final response from <code>${final.url}</code></p>
<table class="data records pairs"><colgroup><col class="c-name"><col></colgroup><thead><tr><th>Header</th><th>Value</th></tr></thead>
<tbody>${final.headers.map(([k, v]) => html`<tr><td data-label="Header"><code>${k}</code></td><td data-label="Value" class="wrap-any"><code>${v}</code></td></tr>`)}</tbody></table>` : ''}`;
  },

  apiDoc: 'GET /api/http-headers?url=https://example.com',

  async api(c) {
    const url = normalizeUrl(c.url.searchParams.get('url') ?? '');
    if (!url) return json({ error: INVALID }, { status: 400 });
    const chain = await cachedJson(`hdr:${url}`, () => 60, () => fetchChain(url, c.env));
    const final = chain.hops[chain.hops.length - 1];
    // A refused start URL (private address, this site) is an input error, like in the other tools.
    if (!final && chain.errorKind === 'refused') return json({ error: chain.error }, { status: 400 });
    return json({ ...chain, security: final ? securityFindings(final) : [] });
  },

  article: html`<h2>What an HTTP header check shows</h2>
<p>Every web page arrives with a set of HTTP response headers that the visitor never sees: the status code, caching
rules, cookies, the server software and instructions for the browser on how to handle the page. This checker
requests a URL, follows its redirect chain hop by hop, and lists the status code, response time and headers of every
step. It then rates the security headers of the final response, so you can see at a glance what is missing.</p>

<h2>How the check works</h2>
<ul>
<li>The URL is requested from Cloudflare's network with a browser-like request and without cookies.</li>
<li>Redirects are followed step by step, up to 5 hops, with a total time limit of 15 seconds.</li>
<li>Only the headers are evaluated; the page body is not downloaded.</li>
<li>Private and internal addresses are refused, and results are cached for 60 seconds.</li>
</ul>
<p>To get the same view on the command line, run <code>curl -I https://example.com</code> for one response, or
<code>curl -sIL http://example.com</code> to follow redirects and print the headers of every hop. Note that
<code>-I</code> sends a <code>HEAD</code> request, which some servers answer differently from <code>GET</code>.</p>

<h2>Security headers and recommended values</h2>
<p>Security headers tell the browser how to treat a page. They cost nothing to send and block whole classes of attacks.
This table lists the headers this tool evaluates, with a safe starting value for a typical site:</p>
<table class="data">
<thead><tr><th>Header</th><th>Purpose</th><th>Example value</th></tr></thead>
<tbody>
<tr><td><code>Strict-Transport-Security</code></td><td>Forces HTTPS for future visits</td><td><code>max-age=31536000; includeSubDomains</code></td></tr>
<tr><td><code>Content-Security-Policy</code></td><td>Limits where scripts, styles and frames may load from</td><td><code>default-src 'self'; frame-ancestors 'none'</code></td></tr>
<tr><td><code>X-Content-Type-Options</code></td><td>Stops MIME type sniffing</td><td><code>nosniff</code></td></tr>
<tr><td><code>X-Frame-Options</code></td><td>Prevents framing (clickjacking)</td><td><code>DENY</code> or <code>SAMEORIGIN</code></td></tr>
<tr><td><code>Referrer-Policy</code></td><td>Controls how much of the URL is sent to other sites</td><td><code>strict-origin-when-cross-origin</code></td></tr>
<tr><td><code>Permissions-Policy</code></td><td>Disables browser features the page does not use</td><td><code>camera=(), microphone=(), geolocation=()</code></td></tr>
</tbody>
</table>

<h3>Strict-Transport-Security (HSTS)</h3>
<p>HSTS tells the browser to use only HTTPS for the domain for the next <code>max-age</code> seconds, even if a user
types <code>http://</code> or follows an old link. Browsers ignore the header when it is sent over plain HTTP, so it must be
set on the HTTPS response. This tool rates a <code>max-age</code> of at least 15552000 seconds (180 days) as good.</p>
<p>To get a domain onto the browser preload list at hstspreload.org, the header on the bare domain must have
<code>max-age</code> of at least 31536000 (one year), include <code>includeSubDomains</code> and <code>preload</code>,
and the site must redirect HTTP to HTTPS on the same host. Every subdomain must then support HTTPS. Removal from the
preload list takes months, so test with a short <code>max-age</code> first and increase it once everything works.</p>
<p>Example: <code>Strict-Transport-Security: max-age=63072000; includeSubDomains; preload</code></p>

<h3>Content-Security-Policy (CSP)</h3>
<p>A CSP is an allowlist of sources for each type of content. If an attacker manages to inject a script tag, the browser
refuses to run it unless its source is allowed. A strict policy blocks inline scripts unless they carry a nonce or hash.
Useful directives include <code>default-src</code> (fallback for everything), <code>script-src</code>,
<code>style-src</code>, <code>img-src</code>, <code>connect-src</code>, <code>object-src 'none'</code>,
<code>base-uri 'self'</code> and <code>frame-ancestors</code>, which replaces <code>X-Frame-Options</code> in modern browsers.</p>
<p>Roll a new policy out with <code>Content-Security-Policy-Report-Only</code> first. The browser then reports violations
in the console without blocking anything, so you can fix the policy before enforcing it. A policy that contains
<code>'unsafe-inline'</code> in <code>script-src</code> offers little protection against cross-site scripting.</p>

<h3>X-Content-Type-Options, X-Frame-Options and Referrer-Policy</h3>
<p><code>X-Content-Type-Options: nosniff</code> has exactly one valid value and stops browsers from treating, for example,
an uploaded text file as a script. <code>X-Frame-Options</code> accepts <code>DENY</code> or <code>SAMEORIGIN</code>; the old
<code>ALLOW-FROM</code> value is not supported by current browsers, use CSP <code>frame-ancestors</code> instead. If no
<code>Referrer-Policy</code> is set, current browsers default to <code>strict-origin-when-cross-origin</code>, which is a
reasonable value.</p>

<h3>Headers you can drop</h3>
<p><code>X-XSS-Protection</code> controlled a filter that modern browsers have removed; it is safe to omit or set to
<code>0</code>. <code>Server</code> and <code>X-Powered-By</code> values with version numbers, such as
<code>Apache/2.4.41 (Ubuntu)</code> or <code>PHP/7.4.3</code>, tell attackers which known vulnerabilities to try. Hiding them
is not a fix for outdated software, but there is no reason to advertise it.</p>

<h2>Redirect chains</h2>
<p>Every redirect costs a full round trip before the page can start loading. A clean setup needs at most one hop, for example
<code>http://example.com</code> &rarr; <code>301</code> &rarr; <code>https://www.example.com/</code>. A common mistake is
a double hop: HTTP to HTTPS on the bare domain, then a second redirect to <code>www</code>. Redirect directly to the final
URL instead.</p>
<table class="data">
<thead><tr><th>Code</th><th>Type</th><th>Keeps method and body</th></tr></thead>
<tbody>
<tr><td><code>301</code></td><td>Permanent</td><td>No, clients may switch POST to GET</td></tr>
<tr><td><code>302</code></td><td>Temporary</td><td>No, clients may switch POST to GET</td></tr>
<tr><td><code>303</code></td><td>See Other</td><td>No, always GET</td></tr>
<tr><td><code>307</code></td><td>Temporary</td><td>Yes</td></tr>
<tr><td><code>308</code></td><td>Permanent</td><td>Yes</td></tr>
</tbody>
</table>
<p>Use <code>301</code> or <code>308</code> for permanent moves such as the HTTPS redirect; search engines treat them as a
signal to index the target URL. A chain that ends in an error or loops back on itself is shown with the failing hop.</p>

<h2>Other headers worth looking at</h2>
<p>The full header list shows more than security. <code>Cache-Control</code> and <code>Age</code> tell you whether a CDN served
a cached copy; <code>Set-Cookie</code> should carry <code>Secure</code>, <code>HttpOnly</code> and a <code>SameSite</code>
attribute for session cookies; <code>Location</code> shows the target of each redirect; and <code>Content-Encoding</code>
reveals whether compression such as <code>gzip</code> or <code>br</code> is active.</p>

<h2>Troubleshooting checklist</h2>
<ul>
<li>Header set in the web server but missing here: a CDN or reverse proxy in front may strip or override it. Compare the
<code>server</code> and <code>cf-ray</code> or <code>via</code> headers to see which layer answered.</li>
<li>Header present on the home page only: many configurations add headers per location. Check a deep URL too.</li>
<li>Nginx drops <code>add_header</code> directives from the parent block when a <code>location</code> block defines its own;
add <code>always</code> to send headers on error responses as well.</li>
<li>Status <code>403</code> or <code>429</code>: the site blocks automated requests. Use the
<a href="/is-it-down">website down checker</a> to confirm the server is online.</li>
<li>Redirect to an unexpected host: check the DNS records with the <a href="/dns-lookup">DNS lookup tool</a> and the TLS
port with the <a href="/port-checker">port checker</a>.</li>
</ul>
<p>Securing the web server is one half of a domain's setup. For mail, check SPF, DKIM and DMARC with the
<a href="/email-security">email security checker</a>.</p>`,

  faq: [
    { q: 'Which HSTS max-age should I use?', a: 'At least six months (15552000 seconds); one or two years (31536000 or 63072000) is common. For the browser preload list, one year plus includeSubDomains and preload is required. Add includeSubDomains only once every subdomain supports HTTPS.' },
    { q: 'Is a missing Permissions-Policy a problem?', a: 'Not really. It is an optional hardening header that disables browser features such as camera, microphone or geolocation for the page and any embedded frames.' },
    { q: 'Why do I see different headers in my browser?', a: 'Servers can answer differently depending on location, cookies, language or user agent, and CDNs may serve cached copies. This check sends a request without cookies from Cloudflare.' },
    { q: 'Do I need both X-Frame-Options and CSP frame-ancestors?', a: 'Modern browsers use frame-ancestors when both are present. Sending X-Frame-Options as well does no harm and covers very old browsers.' },
    { q: 'How do I add security headers?', a: 'In the web server configuration (add_header in nginx, Header set in Apache with mod_headers), in the application, or at the CDN. Set them once at the outermost layer so every response gets them.' },
    { q: 'How many redirects are too many?', a: 'One is normal, two is acceptable. More than that slows down the first page load. This check follows up to 5 hops and stops after that.' },
  ],
};

export default tool;
