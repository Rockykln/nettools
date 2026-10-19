import { cachedJson } from '../core/cache';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { fetchChain, normalizeUrl, USER_AGENT } from '../core/http-probe';
import { groupFor, isAllowed, parseRobots, type Robots, type Rule } from '../core/robots';
import type { Tool, ToolContext } from '../core/tool';

const MAX_ROBOTS = 500 * 1024;
const MAX_SITEMAP = 5 * 1024 * 1024;

const AGENTS = ['Googlebot', 'Bingbot', 'GPTBot', 'ClaudeBot', 'CCBot', 'Applebot', 'facebookexternalhit', 'Twitterbot'];

interface SitemapInfo {
  url: string;
  status: number | null;
  kind: 'urlset' | 'index' | 'unknown';
  entries: number;
  note: string | null;
}

interface Report {
  origin: string;
  status: number;
  text: string;
  robots: Robots;
  sitemap: SitemapInfo | null;
}

async function getText(url: string, env: Env, max: number): Promise<{ status: number; text: string; finalUrl: string; truncated: boolean } | { error: string }> {
  const chain = await fetchChain(url, env, { accept: '*/*', keepBody: true });
  const last = chain.hops[chain.hops.length - 1];
  const res = chain.final;
  if (chain.error || !last || !res) return { error: chain.error ?? 'No response' };
  if (res.status >= 300) {
    await res.body?.cancel().catch(() => {});
    return { status: last.status, text: '', finalUrl: last.url, truncated: false };
  }
  const reader = res.body?.getReader();
  let text = '';
  let size = 0;
  let truncated = false;
  if (reader) {
    const dec = new TextDecoder();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      // Only the first max bytes are used, as a crawler would (RFC 9309: at least 500 KiB).
      const part = size + value.byteLength > max ? value.subarray(0, max - size) : value;
      size += part.byteLength;
      text += dec.decode(part, { stream: true });
      if (part !== value) {
        truncated = true;
        await reader.cancel();
        break;
      }
    }
    text += dec.decode();
  }
  return { status: res.status, text, finalUrl: last.url, truncated };
}

async function sitemapInfo(url: string, env: Env): Promise<SitemapInfo> {
  if (/\.gz($|\?)/i.test(url)) return { url, status: null, kind: 'unknown', entries: 0, note: 'Compressed sitemaps (.gz) are not opened.' };
  const r = await getText(url, env, MAX_SITEMAP).catch(() => ({ error: 'Could not load the sitemap' }));
  if ('error' in r) return { url, status: null, kind: 'unknown', entries: 0, note: r.error };
  const index = /<sitemapindex[\s>]/i.test(r.text);
  const entries = (r.text.match(index ? /<sitemap[\s>]/gi : /<url[\s>]/gi) ?? []).length;
  return {
    url,
    status: r.status,
    kind: index ? 'index' : /<urlset[\s>]/i.test(r.text) ? 'urlset' : 'unknown',
    entries,
    note: r.truncated ? 'Only the first 5 MB were read.' : null,
  };
}

async function check(url: string, env: Env): Promise<Report | { error: string }> {
  const origin = new URL(url).origin;
  return cachedJson(`robots:${origin}`, (r) => ('error' in r ? 0 : 300), async () => {
    const r = await getText(`${origin}/robots.txt`, env, MAX_ROBOTS);
    if ('error' in r) return r;
    const robots = parseRobots(r.status < 400 ? r.text : '');
    const first = robots.sitemaps[0] ?? (r.status < 400 ? null : `${origin}/sitemap.xml`);
    // Report where the file actually came from, e.g. en.wikipedia.org after a redirect.
    return { origin: 'finalUrl' in r ? new URL(r.finalUrl).origin : origin, status: r.status, text: r.status < 400 ? r.text.slice(0, 20000) : '', robots, sitemap: first ? await sitemapInfo(first, env) : null };
  });
}

function form(value: string, path: string, agent: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/robots-txt">
<div class="field grow"><label for="url">Website</label>
<input id="url" name="url" type="text" value="${value}" placeholder="example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><label for="path">Test a path (optional)</label>
<input id="path" name="path" type="text" value="${path}" placeholder="/private/page" autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><label for="agent">Crawler</label>
<select id="agent" name="agent">${AGENTS.map((a) => html`<option${a === agent ? html` selected` : ''}>${a}</option>`)}</select></div>
<div class="field"><button type="submit">Check</button></div>
</form>`;
}

const INVALID = 'Enter a website such as example.com.';

/** Path plus query to test; a full URL is reduced to that part. */
function testPath(raw: string): string {
  if (/^https?:\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      return u.pathname + u.search;
    } catch {
      // Fall through and treat it as a path.
    }
  }
  return raw.startsWith('/') ? raw : `/${raw}`;
}

/** RFC 9309: 4xx means no rules, 5xx (server error) means everything is disallowed. */
function testRobots(r: Report, agent: string, path: string): { allowed: boolean; rule: Rule | null } {
  if (r.status >= 500) return { allowed: false, rule: null };
  return isAllowed(groupFor(r.robots, agent), path);
}

const tool: Tool = {
  slug: 'robots-txt',
  name: 'robots.txt checker',
  icon: 'robots',
  category: 'web',
  title: 'robots.txt Checker & Tester – Sitemaps and Crawler Rules',
  description: 'Fetch and test any site’s robots.txt: which paths Googlebot, Bingbot or AI crawlers may access, crawl delay, syntax problems and the sitemaps it lists.',
  h1: 'robots.txt checker',
  lead: 'Read a site’s robots.txt, test whether a crawler may fetch a path, and check the listed sitemap.',
  heavy: () => true,
  examples: [['github.com', 'url=github.com'], ['wikipedia.org /w/index.php', 'url=wikipedia.org&path=/w/index.php&agent=Googlebot']],
  related: ['social-preview', 'http-headers', 'subdomain-finder'],
  isQuery: (url) => url.searchParams.has('url'),

  async render(c: ToolContext) {
    const value = (c.url.searchParams.get('url') ?? '').trim();
    const rawPath = (c.url.searchParams.get('path') ?? '').trim();
    const agent = AGENTS.includes(c.url.searchParams.get('agent') ?? '') ? c.url.searchParams.get('agent')! : 'Googlebot';
    if (!c.url.searchParams.has('url')) return form('', '', agent);
    const url = normalizeUrl(value);
    if (!url) return html`${form(value, rawPath, agent)}<p class="error">${INVALID}</p>`;
    const r = await check(url, c.env);
    if ('error' in r) return html`${form(value, rawPath, agent)}<p class="error">${r.error}</p>`;
    const group = groupFor(r.robots, agent);
    const path = rawPath ? testPath(rawPath) : null;
    const test = path ? testRobots(r, agent, path) : null;
    return html`${form(value, rawPath, agent)}
${r.status >= 500
      ? html`<div class="verdict bad"><strong>robots.txt returned a server error (HTTP ${r.status}).</strong> Crawlers must then treat the whole site as disallowed${path ? html`, so ${agent} may not fetch <code>${path}</code>` : ''}. Google pauses crawling until the file is reachable again.</div>`
      : r.status >= 400
      ? html`<div class="verdict ok"><strong>No robots.txt (HTTP ${r.status}).</strong> Crawlers may fetch every page. That is fine if you do not need to block anything.</div>`
      : test
        ? html`<div class="verdict ${test.allowed ? 'ok' : 'bad'}"><strong>${agent} ${test.allowed ? 'may' : 'may not'} fetch <code>${path}</code>.</strong>
${test.rule ? html` Matching rule: <code>${test.rule.allow ? 'Allow' : 'Disallow'}: ${test.rule.path}</code> in the group for ${group?.agents.join(', ')}.` : ' No rule matches this path.'}</div>`
        : html`<p class="result-head"><code>${r.origin}/robots.txt</code> · ${r.robots.groups.length} groups · ${r.robots.sitemaps.length} sitemaps${r.robots.invalidLines ? html` · <span class="status warn">${r.robots.invalidLines} unknown lines</span>` : ''}</p>`}
${r.robots.groups.length ? html`<h2>Rules by crawler</h2>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>User agents</th><th>Disallow</th><th>Allow</th><th>Crawl delay</th></tr></thead>
<tbody>${r.robots.groups.map((g) => html`<tr><td class="wrap-any"><code>${g.agents.join(', ')}</code></td><td>${g.rules.filter((x) => !x.allow).length}</td><td>${g.rules.filter((x) => x.allow).length}</td><td>${g.crawlDelay ? `${g.crawlDelay} s` : '—'}</td></tr>`)}</tbody></table></div>` : ''}
${r.sitemap ? html`<h2>Sitemap</h2><table class="kv"><tbody>
<tr><th scope="row">URL</th><td class="wrap-any"><code>${r.sitemap.url}</code></td></tr>
<tr><th scope="row">Status</th><td>${r.sitemap.status === null ? '—' : r.sitemap.status < 400 ? html`<span class="status ok">HTTP ${r.sitemap.status}</span>` : html`<span class="status bad">HTTP ${r.sitemap.status}</span>`}</td></tr>
<tr><th scope="row">Content</th><td>${r.sitemap.kind === 'index' ? `Sitemap index with ${r.sitemap.entries} sitemaps` : r.sitemap.kind === 'urlset' ? `${r.sitemap.entries.toLocaleString('en-US')} URLs` : 'Not a valid sitemap'}${r.sitemap.note ? html` <span class="muted">(${r.sitemap.note})</span>` : ''}</td></tr>
</tbody></table>` : ''}
${r.robots.sitemaps.length > 1 ? html`<details class="raw-details"><summary>All ${r.robots.sitemaps.length} sitemap lines</summary><pre class="raw">${r.robots.sitemaps.join('\n')}</pre></details>` : ''}
${r.text ? html`<details class="raw-details"><summary>Show robots.txt</summary><pre class="raw">${r.text}</pre></details>` : ''}`;
  },

  apiDoc: 'GET /api/robots-txt?url=example.com&path=/private/&agent=Googlebot (path and agent optional)',

  async api(c) {
    const url = normalizeUrl(c.url.searchParams.get('url') ?? '');
    if (!url) return json({ error: INVALID }, { status: 400 });
    const r = await check(url, c.env);
    if ('error' in r) return json(r, { status: 400 });
    const agent = c.url.searchParams.get('agent') ?? 'Googlebot';
    const path = c.url.searchParams.get('path');
    return json({ ...r, test: path ? { agent, path, ...testRobots(r, agent, testPath(path)) } : null });
  },

  article: html`<h2>What robots.txt does and does not do</h2>
<p>A <code>robots.txt</code> file at the root of a site tells crawlers which paths they should not fetch. Well-behaved
crawlers such as Googlebot and Bingbot follow it; malicious ones ignore it. Since September 2022 the format is
standardized as RFC 9309, after decades as an informal convention.</p>
<p>robots.txt controls crawling, not indexing and not access:</p>
<ul>
<li><strong>It is not access control.</strong> Anyone can read the file and request the listed paths. Listing
<code>/backup/</code> or <code>/admin-old/</code> even points people to them. Protect private areas with
authentication.</li>
<li><strong>It does not remove pages from search results.</strong> A disallowed URL can still be indexed if other
pages link to it, shown with the URL and no snippet.</li>
<li><strong>It cannot carry noindex.</strong> Google stopped supporting <code>Noindex:</code> lines in robots.txt in
2019. Use <code>&lt;meta name="robots" content="noindex"&gt;</code> or the <code>X-Robots-Tag: noindex</code> HTTP
header, and keep the page crawlable so the crawler can see that instruction.</li>
</ul>

<h2>How this checker works</h2>
<p>The tool fetches <code>/robots.txt</code> from the origin you enter, following redirects, and parses it according
to RFC 9309. It lists each group with its number of Allow and Disallow rules and its crawl delay, counts lines it
does not recognize, and reads the first sitemap listed. If you enter a path and pick a crawler, it finds the group
that applies to that crawler and reports which rule decides. Results are cached for 5 minutes. You can verify the
raw file yourself with curl:</p>
<pre class="raw">curl -i https://example.com/robots.txt
curl -s -A "Googlebot" https://example.com/robots.txt</pre>
<p>The <code>-i</code> output shows the status code and the <code>Content-Type</code>, which should be
<code>text/plain</code>. If the response differs by user agent, a firewall or bot filter is treating crawlers
differently.</p>

<h2>Syntax</h2>
<p>The file is plain UTF-8 text made of groups. Each group starts with one or more <code>User-agent</code> lines,
followed by <code>Allow</code> and <code>Disallow</code> rules. <code>Sitemap</code> lines stand on their own and
apply to the whole file. Everything after <code>#</code> is a comment.</p>
<pre class="raw">User-agent: *
Disallow: /admin/
Allow: /admin/help.html
Disallow: /*?sessionid=
Disallow: /*.pdf$

User-agent: Googlebot
User-agent: Bingbot
Disallow: /search

User-agent: GPTBot
Disallow: /

Sitemap: https://example.com/sitemap.xml</pre>
<p>Rule paths start with <code>/</code> and match from the beginning of the URL path, including the query string.
<code>*</code> matches any sequence of characters, and <code>$</code> at the end anchors the rule to the end of the
URL. An empty <code>Disallow:</code> line allows everything for that group.</p>

<h2>How the rules are matched</h2>
<p>A crawler first picks one group. It uses the group whose <code>User-agent</code> matches its product token, such
as <code>Googlebot</code>, ignoring case. Only if no group names it does it use the <code>*</code> group. Groups are
not combined: in the example above, Googlebot obeys only <code>Disallow: /search</code> and may fetch
<code>/admin/</code>, because the <code>*</code> rules no longer apply to it.</p>
<p>Within the chosen group, the most specific rule wins, meaning the one with the longest matching path. If an
<code>Allow</code> and a <code>Disallow</code> rule match with the same length, <code>Allow</code> wins. If no rule
matches, the path is allowed.</p>
<table class="data">
<thead><tr><th>Path</th><th>Result for <code>*</code></th><th>Deciding rule</th></tr></thead>
<tbody>
<tr><td><code>/admin/settings</code></td><td>Blocked</td><td><code>Disallow: /admin/</code></td></tr>
<tr><td><code>/admin/help.html</code></td><td>Allowed</td><td><code>Allow: /admin/help.html</code> (longer match)</td></tr>
<tr><td><code>/files/report.pdf</code></td><td>Blocked</td><td><code>Disallow: /*.pdf$</code></td></tr>
<tr><td><code>/files/report.pdf?dl=1</code></td><td>Allowed</td><td>None; <code>$</code> requires the URL to end in .pdf</td></tr>
<tr><td><code>/Admin/settings</code></td><td>Allowed</td><td>None; paths are case-sensitive</td></tr>
</tbody>
</table>

<h2>Location, status codes and size</h2>
<p>The file must be at <code>/robots.txt</code> on each host. It applies only to that combination of protocol, host
and port: <code>https://www.example.com/robots.txt</code> does not cover <code>http://www.example.com</code>,
<code>example.com</code> or <code>shop.example.com</code>. A <a href="/subdomain-finder">subdomain finder</a> helps to
spot hosts that need their own file.</p>
<p>RFC 9309 also defines what the HTTP status means:</p>
<ul>
<li><strong>2xx:</strong> the rules are used.</li>
<li><strong>4xx (for example 404):</strong> the file is treated as missing, and crawlers may fetch everything.</li>
<li><strong>5xx or no response:</strong> crawlers must assume everything is disallowed. Google pauses crawling of the
site while the error lasts, so a broken robots.txt endpoint can stop indexing even if every page works.</li>
</ul>
<p>Crawlers must read at least the first 500 KiB of the file; Google ignores anything after that limit. Crawlers may
cache the file, usually for up to 24 hours, so changes do not take effect immediately.</p>

<h2>Common mistakes</h2>
<ul>
<li><code>Disallow: /</code> left over from a staging site blocks the whole site after launch.</li>
<li>Blocking CSS, JavaScript or image directories prevents search engines from rendering pages correctly.</li>
<li>Expecting rules for a specific crawler to add to the <code>*</code> group. They replace it, so repeat the general
rules in that group if they should still apply.</li>
<li>Wrong case in paths. <code>Disallow: /Private/</code> does not block <code>/private/</code>.</li>
<li>Relative sitemap URLs. <code>Sitemap:</code> needs a full URL such as
<code>https://example.com/sitemap.xml</code>.</li>
<li>Serving an HTML error page or a login redirect at <code>/robots.txt</code>. Check the status code with the
<a href="/http-headers">HTTP header checker</a>.</li>
<li>Relying on <code>Crawl-delay</code>. Google ignores it; Bing and some other crawlers respect it.</li>
</ul>

<h2>AI crawlers</h2>
<p>Many AI companies publish crawler names you can block, for example <code>GPTBot</code> (OpenAI),
<code>ClaudeBot</code> (Anthropic), <code>CCBot</code> (Common Crawl) and <code>Google-Extended</code> (Google AI training,
without affecting Google Search). Select a crawler above to test your rules for it. Social platforms fetch pages with
their own crawlers too, such as <code>facebookexternalhit</code> and <code>Twitterbot</code>; if you block them, link
previews break. The <a href="/social-preview">social preview checker</a> shows how your pages look when shared.</p>`,

  faq: [
    { q: 'Where must robots.txt be located?', a: 'At the root of each host, for example https://example.com/robots.txt. It applies only to that protocol, host and port, so a file on www.example.com does not apply to shop.example.com or to the http:// version.' },
    { q: 'What happens without a robots.txt?', a: 'Crawlers may fetch everything. A missing file (HTTP 404) is fine. A server error (5xx) is different: crawlers must then treat the whole site as disallowed, and Google pauses crawling until the file is reachable again.' },
    { q: 'Does Disallow remove a page from Google?', a: 'No. It only stops crawling, and the URL can still appear in results if other pages link to it. To remove a page, allow crawling and add a noindex meta tag or X-Robots-Tag header.' },
    { q: 'Which rule wins when Allow and Disallow both match?', a: 'The rule with the longest matching path. If both are equally long, Allow wins. This checker shows the deciding rule when you test a path.' },
    { q: 'Do rules for Googlebot add to the rules for all crawlers?', a: 'No. A crawler uses only the most specific group that names it. Once a Googlebot group exists, Googlebot ignores the User-agent: * group, so general rules must be repeated there.' },
    { q: 'Are robots.txt paths case-sensitive?', a: 'Yes. Disallow: /Private/ does not block /private/. The field names such as User-agent and Disallow, and the crawler names, are not case-sensitive.' },
  ],
};

export default tool;
