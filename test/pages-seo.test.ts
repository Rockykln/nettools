import { describe, expect, it } from 'vitest';
import { page } from '../src/core/layout';
import { html } from '../src/core/html';
import { absolute, llmsTxt, robotsTxt, sitemapXml } from '../src/core/seo';
import { LANDING_PAGES, TOOLS, TOOLS_BY_SLUG } from '../src/tools/registry';

const env = { SITE_URL: 'https://net.example.com' } as unknown as Env;

describe('absolute', () => {
  it('stays on the site host', () => {
    expect(absolute(env, '//evil.com/x')).toBe('https://net.example.com/evil.com/x');
    expect(absolute(env, '/\\evil.com')).toBe('https://net.example.com/evil.com');
    expect(absolute(env, '/dns-lookup?name=a&type=MX')).toBe('https://net.example.com/dns-lookup?name=a&type=MX');
  });
});

describe('sitemap.xml', () => {
  const xml = sitemapXml(env, [...TOOLS, ...LANDING_PAGES]);
  const locs = [...xml.matchAll(/<loc>([^<]*)<\/loc>/g)].map((m) => m[1]);

  it('lists home, API, every tool and every landing page exactly once', () => {
    expect(locs).toContain('https://net.example.com/');
    expect(locs).toContain('https://net.example.com/api');
    for (const t of [...TOOLS, ...LANDING_PAGES]) expect(locs).toContain(`https://net.example.com/${t.slug}`);
    expect(new Set(locs).size).toBe(locs.length);
  });

  it('is well-formed XML without noindex pages', () => {
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>\n<urlset')).toBe(true);
    expect(xml).not.toMatch(/&(?!#\d+;|amp;|lt;|gt;|quot;|apos;)/);
    expect(locs.some((l) => /\/(legal|go)$/.test(l!))).toBe(false);
  });
});

describe('robots.txt and llms.txt', () => {
  it('robots.txt points to the absolute sitemap', () => {
    expect(robotsTxt(env)).toContain('Sitemap: https://net.example.com/sitemap.xml');
    expect(robotsTxt(env)).toContain('Disallow: /*?');
  });

  it('llms.txt links every tool and landing page', () => {
    const txt = llmsTxt(env, TOOLS);
    for (const t of [...TOOLS, ...LANDING_PAGES]) expect(txt).toContain(`(https://net.example.com/${t.slug})`);
    expect(txt).toContain(`${TOOLS.length} tools`);
  });
});

describe('page()', () => {
  async function render(o: Partial<Parameters<typeof page>[1]>): Promise<string> {
    return page(env, { title: 'T <x>', description: 'D "q"', path: '/dns-lookup', body: html`<p>b</p>`, ...o }).text();
  }

  it('sets canonical and og:url for indexable pages', async () => {
    const doc = await render({});
    expect(doc).toContain('<link rel="canonical" href="https://net.example.com/dns-lookup">');
    expect(doc).toContain('<meta property="og:url" content="https://net.example.com/dns-lookup">');
    expect(doc).toContain('<title>T &#60;x&#62;</title>');
    expect(doc).toContain('content="D &#34;q&#34;"');
  });

  it('uses the exact URL for og:url on noindex query pages and drops the canonical', async () => {
    const doc = await render({ noindex: true, url: absolute(env, '/dns-lookup?name=a&type=MX') });
    expect(doc).not.toContain('rel="canonical"');
    expect(doc).toContain('<meta name="robots" content="noindex, nofollow">');
    expect(doc).toContain('<meta property="og:url" content="https://net.example.com/dns-lookup?name=a&#38;type=MX">');
  });

  it('escapes JSON-LD so it cannot close its script element', async () => {
    const doc = await render({ jsonLd: [{ name: '</script><b>' }] });
    expect(doc).not.toContain('</script><b>');
    expect(doc).toContain('\\u003c/script>\\u003cb>');
  });
});

describe('landing pages', () => {
  it('examples go to the base tool and keep its presets', () => {
    const problems: string[] = [];
    for (const l of LANDING_PAGES) {
      const base = TOOLS_BY_SLUG.get(l.querySlug!);
      if (!base || base.querySlug) problems.push(`${l.slug}: bad querySlug`);
      for (const [label, q] of l.examples ?? []) {
        const params = new URLSearchParams(q);
        for (const [k, v] of Object.entries(l.queryDefaults ?? {})) {
          // An IP address as name is looked up as PTR automatically.
          if (k === 'type' && v === 'PTR' && /^[\d.:a-f]+$/i.test(params.get('name') ?? '')) continue;
          // The propagation checker compares any type; its type preset is only the initial selection.
          if (k === 'type' && l.slug === 'dns-propagation-checker' && params.has('type')) continue;
          if (params.get(k) !== v) problems.push(`${l.slug} "${label}": ${k} should be ${v}`);
        }
      }
    }
    expect(problems).toEqual([]);
  });
});
