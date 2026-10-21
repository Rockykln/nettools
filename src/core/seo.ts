import { SITE } from '../config';
import type { Tool } from './tool';
import { LANDING_PAGES } from '../tools/landing';
import { COMPARE_RESOLVERS, RESOLVERS } from './transport';

export function absolute(env: Env, path: string): string {
  // Collapse leading slashes/backslashes so a request path like "//evil.com" stays on this host.
  return new URL('/' + path.replace(/^[/\\]+/, ''), env.SITE_URL).toString();
}

function publisher(env: Env): unknown {
  return {
    '@type': 'Person',
    name: SITE.author,
    url: SITE.authorUrl,
    sameAs: [SITE.github.replace(/\/[^/]+$/, '')],
  };
}

export function websiteJsonLd(env: Env): unknown {
  return {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    name: SITE.name,
    alternateName: `${SITE.name} – free network tools`,
    url: absolute(env, '/'),
    description: SITE.tagline,
    inLanguage: 'en',
    image: absolute(env, '/og/default.png'),
    publisher: publisher(env),
    license: SITE.license.url,
  };
}

/** Plain content pages (API docs, legal notice): WebPage plus a two-level breadcrumb. */
export function pageJsonLd(env: Env, path: string, name: string, description: string, type = 'WebPage'): unknown[] {
  const url = absolute(env, path);
  return [
    { '@context': 'https://schema.org', '@type': type, name, url, description, inLanguage: 'en', isPartOf: { '@type': 'WebSite', name: SITE.name, url: absolute(env, '/') }, publisher: publisher(env) },
    {
      '@context': 'https://schema.org',
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: SITE.name, item: absolute(env, '/') },
        { '@type': 'ListItem', position: 2, name, item: url },
      ],
    },
  ];
}

export function toolJsonLd(env: Env, tool: Tool): unknown[] {
  const url = absolute(env, `/${tool.slug}`);
  const data: unknown[] = [
    {
      '@context': 'https://schema.org',
      '@type': 'WebApplication',
      name: tool.h1,
      url,
      description: tool.description,
      applicationCategory: 'UtilitiesApplication',
      operatingSystem: 'Any',
      isAccessibleForFree: true,
      offers: { '@type': 'Offer', price: '0', priceCurrency: 'EUR' },
      image: absolute(env, `/og/${tool.slug}.png`),
      license: SITE.license.url,
      inLanguage: 'en',
      author: publisher(env),
    },
    {
      '@context': 'https://schema.org',
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: SITE.name, item: absolute(env, '/') },
        { '@type': 'ListItem', position: 2, name: tool.name, item: url },
      ],
    },
  ];
  if (tool.faq.length) {
    data.push({
      '@context': 'https://schema.org',
      '@type': 'FAQPage',
      mainEntity: tool.faq.map((f) => ({
        '@type': 'Question',
        name: f.q,
        acceptedAnswer: { '@type': 'Answer', text: f.a },
      })),
    });
  }
  return data;
}

const xmlEscape = (s: string): string => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export function sitemapXml(env: Env, tools: Tool[]): string {
  const urls = ['/', '/api', ...tools.map((t) => `/${t.slug}`)];
  const entries = urls
    .map((p) => `  <url><loc>${xmlEscape(absolute(env, p))}</loc><lastmod>${SITE.updated}</lastmod></url>`)
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries}\n</urlset>\n`;
}

export function robotsTxt(env: Env): string {
  // Query URLs are results (noindex) that link to endless further lookups; crawlers only need the tool pages.
  // Assets and preview images carry ?v= cache busters, so they are allowed explicitly (the longer rule wins).
  // The rules are repeated for the heaviest crawlers in case a parser reads only the first "*" group, which
  // Cloudflare's managed robots.txt puts in front of this one.
  const rules = 'Allow: /\nAllow: /assets/\nAllow: /og/\nDisallow: /api/\nDisallow: /badge/\nDisallow: /go\nDisallow: /*?\n';
  return `User-agent: *\n${rules}\nUser-agent: Claude-SearchBot\nUser-agent: MJ12bot\n${rules}\nSitemap: ${absolute(env, '/sitemap.xml')}\n`;
}

function apiLine(doc: string): string {
  // "GET /a (note); GET /b" -> "`GET /a` (note), `GET /b`"
  return doc
    .split('; ')
    .map((part) => {
      const m = part.match(/^(.*?)(?: \((.*)\))?$/)!;
      return `\`${m[1]}\`${m[2] ? ` (${m[2]})` : ''}`;
    })
    .join(', ');
}

// https://llmstxt.org: a plain overview for AI assistants and agents.
export function llmsTxt(env: Env, tools: Tool[]): string {
  const resolvers = RESOLVERS.map((r) => `  - ${r.name}: ${r.location.replace(/^Global/, 'global')}, ${r.transport === 'dot' ? 'DNS-over-TLS' : 'DNS-over-HTTPS'}`);
  const lines = [
    `# ${SITE.name}`,
    '',
    `> ${SITE.tagline}: ${tools.length} tools for IP addresses and networks, DNS (${RESOLVERS.length} public resolvers, ${COMPARE_RESOLVERS.length} in compare mode), domains and WHOIS/RDAP, websites (status, headers, certificates, social previews, robots.txt), email security and performance. Every lookup tool has a free JSON API. No sign-up, no ads, no cookies.`,
    '',
    '## Tools',
    '',
    ...tools.map((t) => `- [${t.name}](${absolute(env, `/${t.slug}`)}): ${t.lead}`),
    '',
    '## Popular checks',
    '',
    ...LANDING_PAGES.map((t) => `- [${t.name}](${absolute(env, `/${t.slug}`)}): ${t.lead}`),
    '',
    '## API',
    '',
    `All endpoints answer GET requests with JSON. No key or account is needed. Errors return {"error": "..."} with HTTP 400, 403, 404, 405, 429, 502 or 503. Documentation: ${absolute(env, '/api')}`,
    '',
    `- Tool index: \`GET /api/tools\``,
    ...tools.filter((t) => t.apiDoc).map((t) => `- ${t.name}: ${apiLine(t.apiDoc!)}`),
    '- Grade badges (SVG, A–F, cached 6 hours): `GET /badge/headers/example.com.svg`, `GET /badge/email/example.com.svg`',
    '- Plain-text IP: `curl ' + new URL(env.SITE_URL).host + '` or `GET /ip`',
    '- Speed test, IPv6 test and email header analyzer: run in the browser only; there is no API for them.',
    '',
    '## Terms of use',
    '',
    '- Free for personal and commercial use. Please keep automated use moderate.',
    '- Rate limits per IP address (IPv6 per /64): 30 lookups per minute; tools that make many outbound connections (port checks of other hosts, TCP ping, DNSSEC, certificates, social preview, robots.txt, response time, DNS benchmark, blocklists, IP lookups, subdomains, email, domain availability, compare-all DNS, the full root server test, range-to-CIDR with more than 20 entries, uncached badges) additionally 10 per minute; per-server root tests 30 and the speed test 600 requests per minute. Exceeding a limit returns HTTP 429.',
    '- Results come live from third-party services and are provided without warranty.',
    '- Registration data returned by RDAP/WHOIS is subject to the terms of the respective registry.',
    '- Only check ports and servers you are allowed to test.',
    '',
    '## How the tools get their data',
    '',
    `- DNS lookups, ${RESOLVERS.length} public resolvers:`,
    ...resolvers,
    '- Root DNS servers: TCP port 53 of all 13 root servers, live on request and every 30 minutes by a scheduled job (24-hour history).',
    '- WHOIS: RDAP servers found through the IANA bootstrap registry (https://data.iana.org/rdap/), classic WHOIS on port 43 where no RDAP exists. Results are cached for up to one hour.',
    '- Port checker, website status and HTTP headers: TCP connections and HTTP requests made from Cloudflare\'s network, not from the visitor\'s device.',
    '- Email security: SPF, DKIM, DMARC, MTA-STS, TLS-RPT and BIMI records via Cloudflare DNS; the MTA-STS policy file over HTTPS.',
    '- What is my IP: Cloudflare connection metadata, including Cloudflare\'s approximate location.',
    '- IP lookup: country from the DB-IP IP to Country Lite database (CC BY 4.0), owner and abuse contact via RDAP, routing from RIPEstat, reverse DNS and blocklists via Cloudflare DNS.',
    '- IPv6 test: runs in the browser against ipify (api4.ipify.org, api6.ipify.org), started by the visitor.',
    '- ASN and BGP: RIPEstat (RIPE NCC). MAC vendors: a copy of the IEEE Registration Authority listings. Subdomains: crt.sh; certificates: Cert Spotter (SSLMate) and crt.sh (Certificate Transparency). Blocklists: 10 public DNSBLs. DNSSEC: Cloudflare\'s validating resolver with and without the CD bit. Domain availability: RDAP/WHOIS of the registries.',
    '- Website, certificate, robots.txt, social preview and response time checks: requests from Cloudflare\'s network to the given site.',
    '',
    '## License',
    '',
    `- Source code: ${SITE.license.name} License, ${SITE.license.url}`,
    '- IP to country data: IP Geolocation by DB-IP, https://db-ip.com, CC BY 4.0',
    `- Font: Inter by The Inter Project Authors, SIL Open Font License 1.1, ${absolute(env, '/assets/fonts/LICENSE-Inter.txt')}`,
    `- Icons: Phosphor Icons, MIT License, ${absolute(env, '/assets/LICENSE-Phosphor.txt')}`,
    '',
    '## Contact',
    '',
    `- Source and issues: ${SITE.github}`,
    `- Email: ${SITE.operator.email}`,
    `- Legal notice and privacy: ${absolute(env, '/legal')}`,
    '',
  ];
  return lines.join('\n');
}
