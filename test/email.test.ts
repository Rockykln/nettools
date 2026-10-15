import { describe, expect, it } from 'vitest';
import { analyzeDmarc, analyzeSpf, txtValue, type TxtLookup } from '../src/core/email';

const zone = (records: Record<string, string[]>): TxtLookup => async (name) => records[name] ?? [];

describe('txtValue', () => {
  it('joins character-strings and unescapes quotes', () => {
    expect(txtValue('"v=spf1 include:a.example" " -all"')).toBe('v=spf1 include:a.example -all');
    expect(txtValue('"say \\"hi\\""')).toBe('say "hi"');
  });
});

describe('analyzeSpf', () => {
  it('counts nested lookups and reads the all qualifier', async () => {
    const r = await analyzeSpf('example.com', zone({
      'example.com': ['v=spf1 mx include:_spf.mail.example -all', 'google-site-verification=x'],
      '_spf.mail.example': ['v=spf1 ip4:192.0.2.0/24 include:_n1.mail.example ~all'],
      '_n1.mail.example': ['v=spf1 a ip6:2001:db8::/32 ~all'],
    }));
    expect(r.totalLookups).toBe(4); // mx, include, include, a
    expect(r.allQualifier).toBe('-');
    expect(r.problems).toEqual([]);
  });

  it('flags too many lookups, multiple records and +all', async () => {
    const includes = Array.from({ length: 11 }, (_, i) => `include:s${i}.example`).join(' ');
    const records: Record<string, string[]> = { 'example.com': [`v=spf1 ${includes} +all`] };
    for (let i = 0; i < 11; i++) records[`s${i}.example`] = ['v=spf1 -all'];
    const r = await analyzeSpf('example.com', zone(records));
    expect(r.totalLookups).toBeGreaterThan(10);
    expect(r.problems.join(' ')).toMatch(/limit is 10/);
    expect(r.problems.join(' ')).toMatch(/\+all/);

    const dup = await analyzeSpf('d.example', zone({ 'd.example': ['v=spf1 -all', 'v=spf1 ~all'] }));
    expect(dup.problems[0]).toMatch(/More than one SPF record/);
  });

  it('reports a missing record', async () => {
    const r = await analyzeSpf('none.example', zone({}));
    expect(r.record).toBeNull();
    expect(r.problems).toHaveLength(1);
  });
});

describe('analyzeDmarc', () => {
  it('parses tags and warns about weak policies', () => {
    const r = analyzeDmarc(['v=DMARC1; p=none; pct=50']);
    expect(r.tags.p).toBe('none');
    expect(r.problems).toHaveLength(3);
    const strict = analyzeDmarc(['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']);
    expect(strict.problems).toEqual([]);
    expect(analyzeDmarc(['v=spf1 -all']).record).toBeNull();
  });
});
