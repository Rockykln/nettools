import { allow, clientIp, json, rateKey, text, withSecurityHeaders } from './core/http';
import { llmsTxt, robotsTxt, sitemapXml } from './core/seo';
import { logError, recordRequest, type EventKind } from './core/telemetry';
import { badgeCached, badgeResponse } from './badges';
import { sampleRoots } from './jobs/root-monitor';
import { setDohByIp } from './core/transport';
import type { ToolContext } from './core/tool';
import { apiPage, goPage, homePage, legalPage, notFoundPage, rateLimitedPage, toolPage } from './pages';
import { LANDING_PAGES, TOOLS, TOOLS_BY_SLUG } from './tools/registry';

const ALIASES: Record<string, string> = {
  '/my-ip': '/what-is-my-ip', '/whats-my-ip': '/what-is-my-ip', '/ip-address': '/what-is-my-ip', '/myip': '/what-is-my-ip', '/whatsmyip': '/what-is-my-ip',
  '/cidr-calculator': '/subnet-calculator', '/ip-calculator': '/subnet-calculator',
  '/speedtest': '/speed-test', '/dns': '/dns-lookup', '/rdap': '/whois',
  '/open-port-checker': '/port-checker', '/ping': '/tcp-ping', '/mac-address-lookup': '/mac-lookup',
  '/spam-blacklist-check': '/blacklist-check', '/dnsbl': '/blacklist-check',
};

// Other sites must not make their visitors' browsers run lookups (e.g. port checks via <img> or fetch).
// Navigations (a shared result link) and non-browser clients (no Sec-Fetch headers) are allowed.
function crossSiteSubresource(req: Request): boolean {
  return req.headers.get('sec-fetch-site') === 'cross-site' && req.headers.get('sec-fetch-mode') !== 'navigate';
}

const STATIC_PAGES = new Set(['/', '/api', '/legal', '/ip', '/go']);

/** Alias target, or the lower-case form of a known page; otherwise the path unchanged. */
function canonicalPath(path: string): string {
  const lower = path.toLowerCase();
  return ALIASES[lower] ?? (TOOLS_BY_SLUG.has(lower.slice(1)) || STATIC_PAGES.has(lower) ? lower : path);
}

function methodNotAllowed(api: boolean, allowed: string): Response {
  const headers = { allow: allowed };
  return api ? json({ error: 'Method not allowed' }, { status: 405, headers }) : text('Method not allowed', { status: 405, headers });
}

async function route(c: ToolContext): Promise<Response> {
  const { url, env, req } = c;
  const path = url.pathname;
  const read = req.method === 'GET' || req.method === 'HEAD';

  // Latency probe of the speed test: answered before any other work (no rate limiter call), so the measured
  // time reflects the network rather than processing inside the Worker.
  if (path === '/api/speed-test/ping' && read) return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });

  // Canonical URLs have no trailing slash (except the root).
  if (path.length > 1 && path.endsWith('/')) {
    // Relative location built from the path only, so "//evil.com/" cannot redirect off-site.
    const clean = '/' + path.replace(/^[/\\]+/, '').replace(/\/+$/, '');
    return new Response(null, { status: 301, headers: { location: canonicalPath(clean) + url.search } });
  }

  if (path === '/api/tools') {
    if (!read) return methodNotAllowed(true, 'GET, HEAD');
    return json(
      [...TOOLS, ...LANDING_PAGES].map((t) => ({
        slug: t.slug, name: t.name, title: t.h1, description: t.lead, icon: t.icon,
        url: new URL(`/${t.slug}`, env.SITE_URL).toString(), api: t.apiDoc ?? null, landing: !!t.querySlug,
      })),
      { headers: { 'cache-control': 'public, max-age=3600' } },
    );
  }

  if (path.startsWith('/api/') && path !== '/api/') {
    const [, , slug = '', ...rest] = path.split('/');
    const tool = TOOLS_BY_SLUG.get(slug);
    if (!tool?.api) return json({ error: 'Not found' }, { status: 404 });
    // Only the speed test upload accepts POST.
    if (!read && !(req.method === 'POST' && slug === 'speed-test')) return methodNotAllowed(true, slug === 'speed-test' ? 'GET, HEAD, POST' : 'GET, HEAD');
    if (crossSiteSubresource(req)) return json({ error: 'Cross-site requests are not allowed' }, { status: 403 });
    const sub = rest.join('/');
    const key = rateKey(c.clientIp);
    // The speed test and per-root live tests make many small requests and have their own budgets.
    const limiter = slug === 'speed-test' ? env.RL_SPEED : slug === 'root-dns-servers' && rest[0] === 'test' ? env.RL_ROOT : env.RL_TOOLS;
    if (!(await allow(limiter, key))) return json({ error: 'Too many requests' }, { status: 429 });
    if (tool.heavy?.(url, c) && !(await allow(env.RL_HEAVY, key))) return json({ error: 'Too many requests' }, { status: 429 });
    return tool.api(c, sub);
  }

  if (!read) return methodNotAllowed(false, 'GET, HEAD');

  if (path.startsWith('/badge/')) {
    const [, , kind = '', file = ''] = path.split('/');
    const key = rateKey(c.clientIp);
    if (!(await allow(env.RL_TOOLS, key))) return text('Too many requests', { status: 429 });
    if (!(await badgeCached(kind, file)) && !(await allow(env.RL_HEAVY, key))) return text('Too many requests', { status: 429 });
    const badge = await badgeResponse(c, kind, file);
    if (!badge) return notFoundPage(c);
    // Badges are meant to be embedded on other sites, including ones that require CORP (COEP: require-corp).
    const out = new Response(badge.body, badge);
    out.headers.set('cross-origin-resource-policy', 'cross-origin');
    return out;
  }

  // Common alternative spellings and upper-case paths lead to the canonical tool URL.
  const canonical = canonicalPath(path);
  const alias = canonical !== path ? canonical : null;
  if (alias) return new Response(null, { status: 301, headers: { location: alias + url.search } });

  // iOS asks for size-specific names (e.g. apple-touch-icon-240x240-precomposed.png) when adding to the home screen.
  if (/^\/apple-touch-icon(-\d+x\d+)?(-precomposed)?\.png$/.test(path)) {
    const icon = await env.ASSETS.fetch(new URL('/apple-touch-icon.png', url));
    if (!icon.ok) return icon;
    return new Response(icon.body, { status: icon.status, headers: { 'content-type': 'image/png', 'cache-control': 'public, max-age=86400' } });
  }

  switch (path) {
    case '/':
      // Command-line clients get just the IP, like ifconfig.me.
      if (/^(curl|wget|httpie|xh)\//i.test(req.headers.get('user-agent') ?? '')) return text(`${c.clientIp}\n`);
      return homePage(c);
    case '/ip':
      return text(`${c.clientIp}\n`);
    case '/legal':
      return legalPage(c);
    case '/go':
      return goPage(c);
    case '/api':
      return apiPage(c);
    case '/robots.txt':
      return text(robotsTxt(env), { headers: { 'cache-control': 'public, max-age=3600' } });
    case '/llms.txt':
      return text(llmsTxt(env, TOOLS), { headers: { 'cache-control': 'public, max-age=3600' } });
    case '/sitemap.xml':
      return new Response(sitemapXml(env, [...TOOLS, ...LANDING_PAGES]), {
        headers: { 'content-type': 'application/xml; charset=utf-8', 'cache-control': 'public, max-age=3600' },
      });
  }

  const tool = TOOLS_BY_SLUG.get(path.slice(1));
  if (!tool) return notFoundPage(c);
  // Landing pages never run a lookup; links with input go to the tool that does, with the page's presets.
  // Only real input redirects; tracking parameters alone (utm_source etc.) keep the landing page.
  if (tool.querySlug && TOOLS_BY_SLUG.get(tool.querySlug)?.isQuery?.(url)) {
    const target = new URL(`/${tool.querySlug}`, url);
    for (const [k, v] of Object.entries(tool.queryDefaults ?? {})) target.searchParams.set(k, v);
    url.searchParams.forEach((v, k) => target.searchParams.set(k, v));
    return new Response(null, { status: 302, headers: { location: target.pathname + target.search } });
  }
  if (tool.isQuery?.(url)) {
    if (crossSiteSubresource(req)) return text('Cross-site requests are not allowed', { status: 403 });
    if (isCrawler(req.headers.get('user-agent'))) return text('Result pages are not for crawlers; see /robots.txt.', { status: 403 });
    const key = rateKey(c.clientIp);
    if (!(await allow(env.RL_TOOLS, key))) return rateLimitedPage(c);
    if (tool.heavy?.(url, c) && !(await allow(env.RL_HEAVY, key))) return rateLimitedPage(c);
  }
  return toolPage(c, tool);
}

// Classifies a request for metrics. Speed test transfers are excluded: one test makes ~60 requests.
function classify(c: ToolContext, status: number): { kind: EventKind; route: string } | null {
  const path = c.url.pathname;
  if (path.startsWith('/api/') && path !== '/api/') {
    const slug = path.split('/')[2] ?? '';
    if (slug === 'speed-test') return null;
    // Unknown slugs are free-form user input and must not end up in metrics.
    const route = slug === 'tools' || TOOLS_BY_SLUG.get(slug)?.api ? slug : 'not_found';
    return { kind: status === 429 ? 'rate_limited' : 'api', route };
  }
  if (path.startsWith('/badge/')) return { kind: status === 429 ? 'rate_limited' : 'api', route: 'badge' };
  if (path.startsWith('/assets/') || path === '/robots.txt' || path === '/sitemap.xml' || path === '/llms.txt' || path === '/favicon.svg') return null;
  if (status >= 300 && status < 400) return { kind: 'page', route: 'redirect' };
  const tool = TOOLS_BY_SLUG.get(path.slice(1));
  if (status === 429) return { kind: 'rate_limited', route: tool?.slug ?? 'other' };
  if (tool) return { kind: tool.isQuery?.(c.url) ? 'query' : 'page', route: tool.slug };
  const named: Record<string, string> = { '/': 'home', '/ip': 'ip', '/legal': 'legal', '/go': 'go', '/api': 'api-docs' };
  return { kind: 'page', route: named[path] ?? 'not_found' };
}

// Search and AI crawlers that ignore robots.txt would otherwise run lookups (outbound requests, CPU) on every
// result link they find. Link preview bots stay allowed, so shared result links still get a preview.
const CRAWLER_UA = /bot|crawl|spider|slurp|scrapy|python-requests|go-http-client|curl-impersonate/i;
const PREVIEW_UA = /discordbot|twitterbot|slackbot|telegrambot|whatsapp|facebookexternalhit|linkedinbot|mastodon|bluesky|skypeuripreview|redditbot|applebot/i;

export function isCrawler(ua: string | null): boolean {
  return !!ua && CRAWLER_UA.test(ua) && !PREVIEW_UA.test(ua);
}

// Paths only vulnerability scanners ask for (this site has no PHP, CMS or dotfiles). They get a bare 404 without
// rendering the not-found page or recording metrics.
const SCANNER_PATH = /\.(php\d?|aspx?|jsp|cgi|env\w*|envrc|ini|sql|bak|old|dist|git|ya?ml|json|md)(\/|$)|^\/(wp-|wordpress|xmlrpc|phpmyadmin|cgi-bin|actuator|credentials|\.git|\.env|\.aws|\.github|vendor\/|admin\/|api\/config)|\/\/wp/i;

export function isScannerPath(path: string): boolean {
  return SCANNER_PATH.test(path);
}

export default {
  async fetch(req, env, exec): Promise<Response> {
    if (isScannerPath(new URL(req.url).pathname)) return new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain', 'cache-control': 'public, max-age=86400' } });
    setDohByIp((env as { DOH_BY_IP?: string }).DOH_BY_IP === '1');
    const c: ToolContext = { req, env, exec, url: new URL(req.url), clientIp: clientIp(req) };
    const start = Date.now();
    let res: Response;
    try {
      res = await route(c);
    } catch (e) {
      logError(c, c.url.pathname, e);
      const msg = 'Internal error. Please try again later.';
      res = c.url.pathname.startsWith('/api/') ? json({ error: msg }, { status: 500 }) : text(msg, { status: 500 });
    }
    const cls = classify(c, res.status);
    if (res.status >= 500) recordRequest(c, { kind: 'error', route: cls?.route ?? 'unknown', status: res.status, ms: Date.now() - start });
    else if (cls) recordRequest(c, { ...cls, status: res.status, ms: Date.now() - start });
    return withSecurityHeaders(res);
  },

  async scheduled(_event, env, exec): Promise<void> {
    exec.waitUntil(
      sampleRoots(env).catch((e) => console.error({ event: 'exception', job: 'root-monitor', message: String(e) })),
    );
  },
} satisfies ExportedHandler<Env>;
