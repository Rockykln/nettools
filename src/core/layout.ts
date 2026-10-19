import { SITE } from '../config';
import { TOOLS } from '../tools/registry';
import { html, jsonForScript, raw, type SafeHtml } from './html';
import { THEME_BOOT } from './theme-boot';
import { icon } from './ui';
import { absolute } from './seo';
import { CATEGORIES } from './tool';

export interface PageOptions {
  title: string;
  description: string;
  /** Canonical path, e.g. "/dns-lookup". */
  path: string;
  /** Absolute URL of this exact page (query pages) for og:url; defaults to the canonical URL. */
  url?: string;
  body: SafeHtml;
  noindex?: boolean;
  jsonLd?: unknown[];
  scripts?: string[];
  status?: number;
  /** Contains per-visitor data; never cache. */
  personal?: boolean;
  /** Social preview image path (1200x630 PNG) and its alt text. */
  image?: string;
  imageAlt?: string;
}

export { icon } from './ui';


function footer(): SafeHtml {
  return html`<footer class="site-footer"><div class="wrap">
<div class="footer-top">
<div class="footer-brand"><a class="brand" href="/"><img src="/assets/brand/logo.svg?v=${SITE.assetVersion}" alt="" width="32" height="32">${SITE.name}</a>
<p>${SITE.tagline}. Open source, no cookies, no sign-up.</p></div>
<div class="footer-cols">${CATEGORIES.map((cat) => {
    const tools = TOOLS.filter((t) => t.category === cat.id);
    if (!tools.length) return '';
    return html`<div class="footer-col"><p class="footer-h">${cat.name}</p><ul>${tools.map((t) => html`<li><a href="/${t.slug}">${t.name}</a></li>`)}</ul></div>`;
  })}</div>
</div>
<div class="footer-meta"><span>© ${new Date().getUTCFullYear()} · Operated by <a href="${SITE.authorGithub}" rel="noopener author">${SITE.author}</a> · Made in Germany</span>
<span><a href="${SITE.license.url}" rel="noopener license">${SITE.license.name} License</a> · <a href="${SITE.github}" rel="noopener">GitHub</a> · <a href="/llms.txt">llms.txt</a> · <a href="/legal">Legal notice &amp; privacy</a></span></div>
</div></footer>`;
}

// Result pages link to further lookups (prefixes, AS numbers, hosts), an endless graph for crawlers.
const QUERY_LINK = /<a href="(\/[^"]*\?[^"]*)"(?![^>]*\brel=)/g;

export function page(env: Env, o: PageOptions): Response {
  const body = o.noindex ? raw(o.body.value.replace(QUERY_LINK, '<a href="$1" rel="nofollow"')) : o.body;
  const canonical = absolute(env, o.path);
  const v = SITE.assetVersion;
  const image = absolute(env, `${o.image ?? '/og/default.png'}?v=${v}`);
  const imageAlt = o.imageAlt ?? `${SITE.name}: ${SITE.tagline}`;
  const doc = html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${o.title}</title>
<meta name="description" content="${o.description}">
${o.noindex ? '' : html`<link rel="canonical" href="${canonical}">`}
<meta name="robots" content="${o.noindex ? 'noindex, nofollow' : 'index, follow, max-image-preview:large, max-snippet:-1'}">
<meta name="author" content="${SITE.author}">
<meta name="application-name" content="${SITE.name}">
<meta name="apple-mobile-web-app-title" content="${SITE.name}">
<meta name="theme-color" content="${SITE.themeColor}">
<meta name="msapplication-TileColor" content="${SITE.themeColor}">
<meta name="color-scheme" content="light dark">
<meta name="format-detection" content="telephone=no">
<meta property="og:type" content="website">
<meta property="og:site_name" content="${SITE.name}">
<meta property="og:locale" content="en_US">
<meta property="og:title" content="${o.title}">
<meta property="og:description" content="${o.description}">
<meta property="og:url" content="${o.url ?? canonical}">
<meta property="og:image" content="${image}">
<meta property="og:image:secure_url" content="${image}">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="${imageAlt}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${o.title}">
<meta name="twitter:description" content="${o.description}">
<meta name="twitter:image" content="${image}">
<meta name="twitter:image:alt" content="${imageAlt}">
<meta name="twitter:label1" content="Price">
<meta name="twitter:data1" content="Free, no sign-up">
<meta name="twitter:label2" content="Ads &amp; cookies">
<meta name="twitter:data2" content="None">
<link rel="icon" href="/favicon.ico" sizes="48x48">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="manifest" href="/manifest.webmanifest">
<meta name="mobile-web-app-capable" content="yes">
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
<link rel="search" type="application/opensearchdescription+xml" title="nettools DNS" href="/opensearch.xml">
<link rel="author" href="${SITE.authorUrl}">
<link rel="preload" href="/assets/fonts/inter-latin.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="/assets/style.css?v=${v}">
<script>${raw(THEME_BOOT)}</script>
<script src="/assets/js/theme.js?v=${v}" defer></script>
${(o.jsonLd ?? []).map((d) => html`<script type="application/ld+json">${jsonForScript(d)}</script>\n`)}</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="site-header"><div class="wrap">
<a class="brand" href="/"><img src="/assets/brand/logo.svg?v=${SITE.assetVersion}" alt="" width="32" height="32">${SITE.name}</a>
<nav aria-label="Main"><a href="/#tools" class="hide-sm">Tools</a><a href="/api" class="hide-sm">API</a>
<a href="${SITE.github}" class="gh" rel="noopener" aria-label="GitHub">${icon('github')}<span class="hide-sm">GitHub</span></a>
<button type="button" class="theme-toggle" data-theme-toggle aria-label="Dark mode" aria-pressed="false" title="Dark mode">${icon('sun', 'sun')}${icon('moon', 'moon')}</button></nav>
</div></header>
<main id="main">
${body}
</main>
${footer()}
<script src="/assets/js/site.js?v=${v}" defer></script>
${(o.scripts ?? []).map((s) => html`<script src="/assets/js/${s}?v=${v}" defer></script>\n`)}</body>
</html>
`;
  return new Response(doc.value, {
    status: o.status ?? 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': o.personal || o.noindex ? 'private, no-store' : 'public, max-age=600',
      ...(o.noindex ? { 'x-robots-tag': 'noindex, nofollow' } : {}),
      ...(o.path === '/go' ? { 'referrer-policy': 'no-referrer' } : {}),
    },
  });
}
