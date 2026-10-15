import { readCapped } from '../core/body';
import { cachedJson } from '../core/cache';
import { checkTarget } from '../core/guard';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { fetchChain, normalizeUrl, USER_AGENT } from '../core/http-probe';
import { imageSize, type ImageSize } from '../core/image-size';
import type { Tool, ToolContext } from '../core/tool';

const MAX_HTML = 512 * 1024;
const MAX_IMAGE = 5 * 1024 * 1024;
const PREVIEW_TAG = /^(og:|twitter:|description$|theme-color$)/;
const IMAGE_TYPES = /^image\/(png|jpeg|gif|webp|avif)\b/i;

interface Meta {
  url: string;
  title: string | null;
  tags: Record<string, string>;
  canonical: string | null;
}

interface ImageInfo {
  url: string;
  ok: boolean;
  status: number | null;
  type: string | null;
  bytes: number | null;
  size: ImageSize | null;
}

type Level = 'ok' | 'warn' | 'bad';

interface Report {
  meta: Meta;
  image: ImageInfo | null;
  findings: { level: Level; text: string }[];
}

// Follows redirects through the SSRF guard, then fetches the final URL once more for its body.
async function fetchFinal(url: string, env: Env, accept: string): Promise<Response | { error: string; status?: number }> {
  const chain = await fetchChain(url, env);
  const last = chain.hops[chain.hops.length - 1];
  if (chain.error || !last) return { error: chain.error ?? 'No response' };
  if (last.status >= 400) return { error: `The page answered with HTTP ${last.status}`, status: last.status };
  return fetch(last.url, { redirect: 'manual', headers: { 'user-agent': USER_AGENT, accept }, signal: AbortSignal.timeout(8000) });
}

const ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', ndash: '–', mdash: '—', hellip: '…', laquo: '«', raquo: '»',
  lsquo: '‘', rsquo: '’', sbquo: '‚', ldquo: '“', rdquo: '”', bdquo: '„', middot: '·', bull: '•', copy: '©', reg: '®', trade: '™',
  euro: '€', pound: '£', times: '×', auml: 'ä', ouml: 'ö', uuml: 'ü', Auml: 'Ä', Ouml: 'Ö', Uuml: 'Ü', szlig: 'ß',
  eacute: 'é', egrave: 'è', aacute: 'á', agrave: 'à', oacute: 'ó', iacute: 'í', uacute: 'ú', ccedil: 'ç', ntilde: 'ñ',
};

/** HTMLRewriter returns attribute values and <title> text with character references still encoded. */
export function decodeEntities(s: string): string {
  return s.replace(/&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([A-Za-z][A-Za-z0-9]{1,31}));?/g, (m, dec?: string, hex?: string, name?: string) => {
    if (name !== undefined) return ENTITIES[name] ?? m;
    const cp = dec !== undefined ? Number(dec) : parseInt(hex!, 16);
    return cp > 0 && cp <= 0x10ffff && (cp < 0xd800 || cp > 0xdfff) ? String.fromCodePoint(cp) : '\ufffd';
  });
}

async function extractMeta(res: Response, url: string): Promise<Meta> {
  const meta: Meta = { url, title: null, tags: {}, canonical: null };
  let titleText = '';
  let titleDone = false;
  let base: string | null = null;
  const body = await readCapped(res.body, MAX_HTML);
  const rewriter = () => new HTMLRewriter()
    // Only the first <title>; an SVG <title> later in the page is not the page title.
    .on('title', { text(t) { if (titleDone) return; titleText += t.text; if (t.lastInTextNode) titleDone = true; } })
    .on('base[href]', { element(e) { base ??= e.getAttribute('href'); } })
    .on('meta', {
      element(e) {
        const key = (e.getAttribute('property') ?? e.getAttribute('name') ?? '').trim().toLowerCase();
        const content = e.getAttribute('content');
        // Only tags that matter for previews; pages also carry nonces, request IDs and the like.
        if (key && content !== null && !(key in meta.tags) && PREVIEW_TAG.test(key)) meta.tags[key] = decodeEntities(content).trim();
      },
    })
    .on('link[rel~="canonical" i]', { element(e) { meta.canonical ??= e.getAttribute('href'); } });
  // The original content type carries the charset, so pages in e.g. windows-1252 are decoded correctly.
  const type = res.headers.get('content-type') ?? 'text/html';
  try {
    await rewriter().transform(new Response(body, { headers: { 'content-type': type } })).arrayBuffer();
  } catch {
    // Unsupported charset: read it as UTF-8 instead.
    meta.tags = {};
    titleText = '';
    titleDone = false;
    base = null;
    meta.canonical = null;
    await rewriter().transform(new Response(body, { headers: { 'content-type': 'text/html' } })).arrayBuffer();
  }
  meta.title = decodeEntities(titleText).replace(/\s+/g, ' ').trim() || null;
  if (base) meta.url = absolute(decodeEntities(base), url) ?? url;
  if (meta.canonical) meta.canonical = absolute(decodeEntities(meta.canonical), meta.url) ?? meta.canonical;
  return meta;
}

async function inspectImage(src: string, env: Env): Promise<ImageInfo> {
  const info: ImageInfo = { url: src, ok: false, status: null, type: null, bytes: null, size: null };
  const res = await fetchFinal(src, env, 'image/*').catch(() => null);
  if (!res || 'error' in res) {
    info.status = res?.status ?? null;
    return info;
  }
  info.status = res.status;
  info.type = res.headers.get('content-type');
  const body = await readCapped(res.body, MAX_IMAGE);
  info.bytes = Number(res.headers.get('content-length')) || body.byteLength;
  info.size = imageSize(body);
  info.ok = res.ok && IMAGE_TYPES.test(info.type ?? '');
  return info;
}

function absolute(value: string | undefined, base: string): string | null {
  if (!value) return null;
  try {
    const u = new URL(value, base);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : null;
  } catch {
    return null;
  }
}

function review(meta: Meta, image: ImageInfo | null, rawImage: string | undefined): Report['findings'] {
  const f: Report['findings'] = [];
  const t = meta.tags;
  const add = (level: Level, text: string) => f.push({ level, text });
  t['og:title'] ? add('ok', 'og:title is set.') : add('bad', 'og:title is missing; platforms fall back to the <title> tag.');
  t['og:description'] ? add('ok', 'og:description is set.') : add('warn', 'og:description is missing.');
  if (!rawImage) add('bad', 'og:image is missing, so shared links show no picture.');
  else if (!/^https?:\/\//i.test(rawImage)) add('warn', 'og:image is a relative URL; use an absolute https:// URL.');
  if (image) {
    if (!image.ok) add('bad', `The image could not be loaded as PNG, JPEG, GIF or WebP${image.status ? ` (HTTP ${image.status})` : ''}.`);
    else {
      if (image.size && (image.size.width < 1200 || image.size.height < 630)) add('warn', `The image is ${image.size.width}×${image.size.height}; 1200×630 or larger is recommended for large previews.`);
      else if (image.size) add('ok', `The image is ${image.size.width}×${image.size.height}.`);
      if (image.bytes && image.bytes > 5 * 1024 * 1024) add('warn', 'The image is larger than 5 MB; some platforms ignore it.');
      else if (image.bytes && image.bytes > 600 * 1024) add('warn', 'The image is larger than 600 KB; WhatsApp may not show it.');
    }
  }
  t['og:url'] ? add('ok', 'og:url is set.') : add('warn', 'og:url is missing; set it to the canonical URL.');
  t['twitter:card'] ? add('ok', `twitter:card is “${t['twitter:card']}”.`) : add('warn', 'twitter:card is missing; X shows a small card by default.');
  if ((t['og:title'] ?? meta.title ?? '').length > 70) add('warn', 'The title is longer than 70 characters and will be cut off.');
  if ((t['og:description'] ?? '').length > 200) add('warn', 'The description is longer than 200 characters and will be cut off.');
  return f;
}

async function analyze(url: string, env: Env): Promise<Report | { error: string }> {
  return cachedJson(`og:${url}`, (r) => ('error' in r ? 0 : 600), async () => {
    const res = await fetchFinal(url, env, 'text/html,application/xhtml+xml');
    if ('error' in res) return res;
    if (!/html/i.test(res.headers.get('content-type') ?? '')) return { error: 'The URL does not return an HTML page.' };
    const meta = await extractMeta(res, res.url || url);
    const rawImage = meta.tags['og:image'] || meta.tags['og:image:url'] || meta.tags['og:image:secure_url'] || meta.tags['twitter:image'] || meta.tags['twitter:image:src'] || undefined;
    const src = absolute(rawImage, meta.url);
    const image = src ? await inspectImage(src, env) : null;
    return { meta, image, findings: review(meta, image, rawImage) };
  });
}

/** MIME type from the file signature, for the formats the proxy serves. */
export function sniffImage(b: Uint8Array): string | null {
  const ascii = (o: number, n: number) => String.fromCharCode(...b.subarray(o, o + n));
  if (b.length < 12) return null;
  if (b[0] === 0x89 && ascii(1, 3) === 'PNG') return 'image/png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (ascii(0, 6) === 'GIF87a' || ascii(0, 6) === 'GIF89a') return 'image/gif';
  if (ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WEBP') return 'image/webp';
  if (ascii(4, 4) === 'ftyp' && /^avi[fs]$/.test(ascii(8, 4))) return 'image/avif';
  return null;
}

/** Image proxy for the preview cards, so visitors' browsers never contact the checked site. */
async function proxyImage(c: ToolContext): Promise<Response> {
  const src = normalizeUrl(c.url.searchParams.get('url') ?? '');
  if (!src) return json({ error: 'Invalid image URL' }, { status: 400 });
  const target = await checkTarget(new URL(src).hostname, c.env);
  if (!target.ok) return json({ error: target.reason }, { status: 400 });
  const res = await fetchFinal(src, c.env, 'image/*').catch(() => null);
  if (!res || 'error' in res || !res.ok) return json({ error: 'Image not available' }, { status: 502 });
  const type = res.headers.get('content-type') ?? '';
  // SVG is refused: served from this origin it could carry script.
  if (!IMAGE_TYPES.test(type)) return json({ error: 'Not a supported image type' }, { status: 415 });
  const body = await readCapped(res.body, MAX_IMAGE);
  if (body.byteLength >= MAX_IMAGE) return json({ error: 'Image too large' }, { status: 502 });
  // The bytes must really be one of the allowed formats; the declared type alone is not trusted.
  const detected = sniffImage(body);
  if (!detected) return json({ error: 'Not a supported image type' }, { status: 415 });
  return new Response(body, {
    headers: { 'content-type': detected, 'cache-control': 'public, max-age=3600', 'content-security-policy': "default-src 'none'", 'x-content-type-options': 'nosniff' },
  });
}

const host = (u: string) => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return u; } };

function cards(r: Report): SafeHtml {
  const t = r.meta.tags;
  const title = t['og:title'] ?? t['twitter:title'] ?? r.meta.title ?? r.meta.url;
  const desc = t['og:description'] ?? t['twitter:description'] ?? t['description'] ?? '';
  const img = r.image?.ok ? html`<img src="/api/social-preview/image?url=${encodeURIComponent(r.image.url)}" alt="" loading="lazy">` : html`<div class="og-noimg">No image</div>`;
  return html`<div class="og-cards">
<figure class="og-card"><figcaption class="muted">Facebook, LinkedIn, WhatsApp</figcaption>
<div class="og-frame">${img}<div class="og-text"><span class="og-host">${host(r.meta.url).toUpperCase()}</span><strong>${title}</strong><span class="og-desc">${desc}</span></div></div></figure>
<figure class="og-card"><figcaption class="muted">X (Twitter)${t['twitter:card'] === 'summary_large_image' ? '' : ' · small card'}</figcaption>
<div class="og-frame x ${t['twitter:card'] === 'summary_large_image' ? '' : 'small'}">${img}<div class="og-text"><strong>${t['twitter:title'] ?? title}</strong><span class="og-host">${host(r.meta.url)}</span></div></div></figure>
</div>`;
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/social-preview">
<div class="field grow"><label for="url">Page URL</label>
<input id="url" name="url" type="text" value="${value}" placeholder="https://example.com/article" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Check preview</button></div>
</form>`;
}

const LABEL: Record<Level, string> = { ok: 'good', warn: 'improve', bad: 'missing' };
const INVALID = 'Enter a page URL such as https://example.com/article.';

const tool: Tool = {
  slug: 'social-preview',
  name: 'Social preview checker',
  icon: 'og',
  category: 'web',
  title: 'Open Graph Checker – Preview Links on Facebook, LinkedIn & X',
  description: 'See how a link looks when shared on Facebook, LinkedIn, WhatsApp and X. Checks Open Graph and Twitter tags, image size and file size, with fixes.',
  h1: 'Social preview checker',
  lead: 'See how a link will look when shared, and which Open Graph and Twitter tags are missing.',
  // The image proxy is requested by every preview page and only gets the normal limit.
  heavy: (url) => !url.pathname.endsWith('/image'),
  examples: [['github.com', 'url=https://github.com'], ['wikipedia.org', 'url=https://www.wikipedia.org']],
  related: ['http-headers', 'robots-txt', 'is-it-down'],
  isQuery: (url) => url.searchParams.has('url'),

  async render(c) {
    const value = (c.url.searchParams.get('url') ?? '').trim();
    if (!c.url.searchParams.has('url')) return form('');
    const url = normalizeUrl(value);
    if (!url) return html`${form(value)}<p class="error">${INVALID}</p>`;
    const r = await analyze(url, c.env);
    if ('error' in r) return html`${form(value)}<p class="error">${r.error}</p>`;
    const tags = Object.entries(r.meta.tags);
    return html`${form(value)}
<h2>Preview</h2>${cards(r)}
<h2>Checks</h2>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>Result</th><th>Details</th></tr></thead>
<tbody>${r.findings.map((f) => html`<tr><td><span class="status ${f.level}">${LABEL[f.level]}</span></td><td class="wrap-any">${f.text}</td></tr>`)}</tbody></table></div>
<h2>Tags found</h2>
${tags.length ? html`<table class="data records pairs"><colgroup><col class="c-name"><col></colgroup><thead><tr><th>Tag</th><th>Content</th></tr></thead>
<tbody>${tags.map(([k, v]) => html`<tr><td data-label="Tag"><code>${k}</code></td><td data-label="Content" class="wrap-any">${v}</td></tr>`)}</tbody></table>` : html`<p class="muted">No Open Graph or Twitter tags found.</p>`}`;
  },

  apiDoc: 'GET /api/social-preview?url=https://example.com/',

  async api(c, sub) {
    if (sub === 'image') return proxyImage(c);
    const url = normalizeUrl(c.url.searchParams.get('url') ?? '');
    if (!url) return json({ error: INVALID }, { status: 400 });
    const r = await analyze(url, c.env);
    return 'error' in r ? json(r, { status: 400 }) : json(r);
  },

  article: html`<h2>How link previews work</h2>
<p>When you paste a link into Facebook, LinkedIn, WhatsApp, Slack, Discord, Telegram or X, the platform's server
fetches the page and reads a few meta tags from its <code>&lt;head&gt;</code> to build a preview card. It does not run
JavaScript and does not log in, so the tags must be in the HTML the server sends. Pages that set their meta tags only
on the client side, as some single-page apps do, show no preview or a generic one.</p>
<p>Most platforms use the Open Graph protocol, originally introduced by Facebook. X reads its own
<code>twitter:</code> tags first and falls back to Open Graph for anything that is missing. Slack, Discord, WhatsApp
and Telegram read Open Graph as well, so one clean set of tags covers almost every place a link gets shared.</p>

<h2>How this checker works</h2>
<ol>
<li>The page is fetched from Cloudflare's network, following redirects, and the first 512 KB of HTML are read.</li>
<li>All <code>og:</code> and <code>twitter:</code> tags are collected, together with the <code>&lt;title&gt;</code>,
the <code>description</code> meta tag and the canonical link, which serve as fallbacks.</li>
<li>The image from <code>og:image</code> (or <code>twitter:image</code>) is downloaded to check its HTTP status,
content type, file size and pixel dimensions.</li>
<li>The preview cards are drawn from these values. The image is passed through our own proxy, so your browser never
contacts the checked site.</li>
</ol>
<p>Results are cached for 10 minutes. The cards approximate each platform's layout; the real apps crop and truncate
slightly differently, and they change their designs from time to time.</p>

<h2>The tags that matter</h2>
<table class="data"><thead><tr><th>Tag</th><th>Purpose</th></tr></thead><tbody>
<tr><td><code>og:title</code></td><td>Headline of the card. Keep it under about 60–70 characters; longer titles are cut off.</td></tr>
<tr><td><code>og:description</code></td><td>One or two sentences, up to about 155–200 characters. Some layouts hide it entirely.</td></tr>
<tr><td><code>og:image</code></td><td>Absolute URL of the image, ideally 1200×630 pixels (1.91:1), PNG or JPEG.</td></tr>
<tr><td><code>og:url</code></td><td>Canonical URL of the page, so shares of URLs with tracking parameters count for the same page.</td></tr>
<tr><td><code>og:type</code></td><td><code>website</code> for home and landing pages, <code>article</code> for posts and news.</td></tr>
<tr><td><code>og:site_name</code></td><td>Name of the site, shown above or below the title on some platforms.</td></tr>
<tr><td><code>twitter:card</code></td><td>Layout on X: <code>summary_large_image</code> for a wide image above the title, <code>summary</code> for a small square thumbnail next to it.</td></tr>
</tbody></table>
<p>Open Graph tags use the <code>property</code> attribute, Twitter tags traditionally use <code>name</code>. Most
parsers accept either, but sticking to the documented form avoids surprises.</p>

<h2>A minimal, complete example</h2>
<pre class="raw">&lt;title&gt;Example article – Example Site&lt;/title&gt;
&lt;meta name="description" content="What the article is about in one sentence."&gt;
&lt;meta property="og:title" content="Example article"&gt;
&lt;meta property="og:description" content="What the article is about in one sentence."&gt;
&lt;meta property="og:image" content="https://example.com/images/article.png"&gt;
&lt;meta property="og:image:width" content="1200"&gt;
&lt;meta property="og:image:height" content="630"&gt;
&lt;meta property="og:image:alt" content="Diagram of the setup described in the article"&gt;
&lt;meta property="og:url" content="https://example.com/article"&gt;
&lt;meta property="og:type" content="article"&gt;
&lt;meta property="og:site_name" content="Example Site"&gt;
&lt;meta name="twitter:card" content="summary_large_image"&gt;</pre>
<p><code>og:image:width</code> and <code>og:image:height</code> are optional, but they let a platform lay out the
card before it has downloaded the image, which helps on the very first share of a new URL.</p>

<h2>Choosing the image</h2>
<p>A 1200×630 pixel image in a 1.91:1 aspect ratio works as a large card on Facebook, LinkedIn and X. Smaller images
are often shown as a small thumbnail instead, and very small ones may be dropped. Keep text and logos away from the
edges, because some apps crop the image to a different ratio, and make sure text is still readable at phone size.</p>
<p>Use PNG or JPEG for the widest support; WebP is accepted by many but not all platforms. SVG is not used for
previews. Keep the file small: JPEG at 1200×630 is usually well under 300 KB. WhatsApp is known to skip large images,
so this checker warns above 600 KB, and above 5 MB most platforms ignore the image.</p>

<h2>What happens when tags are missing</h2>
<ul>
<li>No <code>og:title</code>: the platform uses the <code>&lt;title&gt;</code> element, which often carries the
site name and separators you did not want in a share.</li>
<li>No <code>og:description</code>: the <code>description</code> meta tag is used, or the card shows no text.</li>
<li>No <code>og:image</code>: some platforms pick a random image from the page, others show a card without a picture.
Both look worse than a chosen image.</li>
<li>No <code>twitter:card</code>: X shows the small <code>summary</code> layout even when a large image is available.</li>
</ul>

<h2>Common mistakes</h2>
<ul>
<li><strong>Relative image URL.</strong> <code>/images/og.png</code> does not work everywhere; use the full
<code>https://</code> URL.</li>
<li><strong>Blocked crawlers.</strong> The page or image is behind a login, a bot challenge, a geo block or a
<code>Disallow</code> rule. X's <code>Twitterbot</code>, for example, follows
<a href="/robots-txt">robots.txt</a>, so a blocked image path means no picture on X.</li>
<li><strong>Wrong content type.</strong> The image URL returns an HTML error page or is served as
<code>application/octet-stream</code> instead of <code>image/png</code> or <code>image/jpeg</code>.</li>
<li><strong>Mixed or broken HTTPS.</strong> An <code>http://</code> image on an HTTPS page, or an expired certificate
on the image host. The <a href="/ssl-check">SSL checker</a> shows certificate problems.</li>
<li><strong>Slow responses.</strong> Platform crawlers wait only a few seconds. Check the server with the
<a href="/http-headers">HTTP header checker</a>.</li>
</ul>

<h2>The preview still shows the old image</h2>
<p>Platforms cache previews, often for days, and keep using the cached version until they fetch the page again. After
changing the tags, ask the platform to re-read the page: Facebook's Sharing Debugger has a "Scrape Again" button, and
LinkedIn's Post Inspector fetches the URL fresh. X no longer offers a preview in its Card Validator; it updates cards
on its own schedule. For any platform, changing the image file name or adding a version parameter such as
<code>?v=2</code> to the image URL forces a new download. Messengers cache per URL as well, so testing with a slightly
different URL, for example with an extra query string, shows the current state.</p>`,

  faq: [
    { q: 'What image size should I use for og:image?', a: '1200×630 pixels, an aspect ratio of about 1.91:1. Smaller images may be shown as a small thumbnail. Use PNG or JPEG and keep the file small; this checker warns above 600 KB because WhatsApp may skip larger images.' },
    { q: 'Why does WhatsApp show no image?', a: 'Usually the image is too large, uses an unsupported format such as SVG, or the URL is relative. Use an absolute https URL to a PNG or JPEG under about 600 KB, and make sure it loads without login.' },
    { q: 'Do I need both Open Graph and Twitter tags?', a: 'No. X falls back to Open Graph for title, description and image. You only need twitter:card set to summary_large_image to get the large image layout.' },
    { q: 'What is the difference between summary and summary_large_image?', a: 'summary shows a small square thumbnail next to the title. summary_large_image shows a wide image above the title, which is what most sites want for articles and landing pages.' },
    { q: 'I changed the tags, but Facebook or LinkedIn still show the old preview. Why?', a: 'Platforms cache previews. Use the Facebook Sharing Debugger or LinkedIn Post Inspector to fetch the page again, and rename the image or add a version parameter to its URL if the old picture persists.' },
    { q: 'Why does the preview work for one page but not for another?', a: 'Each page needs its own tags in the server-rendered HTML. Pages that add tags with JavaScript, require a login or are blocked by robots.txt show no preview, because platform crawlers do not run scripts or sign in.' },
  ],
};

export default tool;
