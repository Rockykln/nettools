import { describe, expect, it } from 'vitest';
import type { Tool } from '../src/core/tool';
import { LANDING_PAGES, TOOLS, TOOLS_BY_SLUG } from '../src/tools/registry';

// Tests run in Node, but the project only has Workers types; load fs without pulling in @types/node.
const { readFileSync } = (globalThis as unknown as {
  process: { getBuiltinModule(id: 'node:fs'): { readFileSync(path: string, enc: 'utf8'): string } };
}).process.getBuiltinModule('node:fs');

const ICONS = new Set(
  [...readFileSync('public/assets/icons.svg', 'utf8').matchAll(/<symbol\s+id="i-([^"]+)"/g)].map((m) => m[1]!),
);

function words(markup: string): number {
  const text = markup.replace(/<[^>]*>/g, ' ').replace(/&[#\w]+;/g, ' ');
  return text.split(/\s+/).filter((w) => /[\p{L}\p{N}]/u.test(w)).length;
}

/** Collects every violation of one rule so a failure lists all offending pages at once. */
function violations(pages: Tool[], check: (t: Tool) => string | null): string[] {
  return pages.flatMap((t) => {
    const problem = check(t);
    return problem ? [`${t.slug}: ${problem}`] : [];
  });
}

const ALL = [...TOOLS, ...LANDING_PAGES];

describe('registry', () => {
  it('has unique slugs across tools and landing pages', () => {
    const slugs = ALL.map((t) => t.slug);
    expect(slugs.filter((s, i) => slugs.indexOf(s) !== i)).toEqual([]);
    expect(TOOLS_BY_SLUG.size).toBe(ALL.length);
  });

  it('uses URL-safe slugs', () => {
    expect(violations(ALL, (t) => (/^[a-z0-9]+(-[a-z0-9]+)*$/.test(t.slug) ? null : 'not lower-case kebab-case'))).toEqual([]);
  });
});

for (const [group, pages] of [['tools', TOOLS], ['landing pages', LANDING_PAGES]] as const) {
  describe(`SEO fields of ${group}`, () => {
    it('title is at most 60 characters', () => {
      expect(violations(pages, (t) => (t.title.length <= 60 ? null : `title has ${t.title.length} characters`))).toEqual([]);
    });

    it('description is 120-160 characters', () => {
      expect(
        violations(pages, (t) => (t.description.length >= 120 && t.description.length <= 160 ? null : `description has ${t.description.length} characters`)),
      ).toEqual([]);
    });

    it('has an h1 and a lead', () => {
      expect(violations(pages, (t) => (t.h1.trim() && t.lead.trim() ? null : 'h1 or lead is empty'))).toEqual([]);
    });

    it('article has at least 500 words', () => {
      expect(violations(pages, (t) => {
        const n = words(t.article.value);
        return n >= 500 ? null : `article has ${n} words`;
      })).toEqual([]);
    });

    it('has at least 3 FAQ entries with question and answer', () => {
      expect(violations(pages, (t) => {
        if (t.faq.length < 3) return `${t.faq.length} FAQ entries`;
        return t.faq.every((f) => f.q.trim() && f.a.trim()) ? null : 'empty FAQ question or answer';
      })).toEqual([]);
    });

    it('related slugs exist and do not point to the page itself', () => {
      expect(violations(pages, (t) => {
        const bad = t.related.filter((s) => s === t.slug || !TOOLS_BY_SLUG.has(s));
        return bad.length ? `unknown or self related slugs: ${bad.join(', ')}` : null;
      })).toEqual([]);
    });

    it('icon exists in public/assets/icons.svg', () => {
      expect(violations(pages, (t) => (ICONS.has(t.icon) ? null : `icon "i-${t.icon}" missing`))).toEqual([]);
    });
  });
}

describe('landing pages', () => {
  it('point to an existing tool via querySlug', () => {
    const toolSlugs = new Set(TOOLS.map((t) => t.slug));
    expect(violations(LANDING_PAGES, (t) => (t.querySlug && toolSlugs.has(t.querySlug) ? null : `querySlug "${t.querySlug}" is not a tool`))).toEqual([]);
  });

  it('are not listed as tools', () => {
    expect(violations(TOOLS, (t) => (t.querySlug ? 'tool has a querySlug' : null))).toEqual([]);
  });
});
