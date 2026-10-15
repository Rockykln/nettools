import { describe, expect, it } from 'vitest';
import { imageSize } from '../src/core/image-size';
import { groupFor, isAllowed, normalizePath, parseRobots } from '../src/core/robots';

describe('robots.txt parsing (RFC 9309)', () => {
  it('ignores a BOM and accepts CR-only line endings', () => {
    const r = parseRobots('﻿User-agent: *\rDisallow: /x\r');
    expect(r.invalidLines).toBe(0);
    expect(isAllowed(groupFor(r, 'AnyBot'), '/x/y').allowed).toBe(false);
  });

  it('matches user-agent lines by product token, not substring', () => {
    const r = parseRobots('User-agent: bot\nDisallow: /\n\nUser-agent: Googlebot/2.1\nDisallow: /g\n\nUser-agent: *\nDisallow: /star');
    expect(groupFor(r, 'Googlebot')!.rules[0]!.path).toBe('/g');
    expect(groupFor(r, 'Bingbot')!.agents).toEqual(['*']);
    expect(groupFor(r, 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')!.rules[0]!.path).toBe('/g');
  });

  it('combines all groups for the same crawler', () => {
    const r = parseRobots('User-agent: googlebot\nDisallow: /a\n\nUser-agent: other\nDisallow: /o\n\nUser-agent: Googlebot\nDisallow: /b');
    const g = groupFor(r, 'Googlebot');
    expect(isAllowed(g, '/a').allowed).toBe(false);
    expect(isAllowed(g, '/b').allowed).toBe(false);
    expect(isAllowed(g, '/o').allowed).toBe(true);
  });

  it('does not end a user-agent run at a sitemap line', () => {
    const r = parseRobots('User-agent: a\nSitemap: https://e.com/s.xml\nUser-agent: b\nDisallow: /x');
    expect(r.groups).toHaveLength(1);
    expect(r.groups[0]!.agents).toEqual(['a', 'b']);
  });

  it('counts rules outside any group as invalid and rejects bad crawl delays', () => {
    const r = parseRobots('Disallow: /early\nUser-agent: *\nCrawl-delay: -3');
    expect(r.invalidLines).toBe(1);
    expect(r.groups[0]!.crawlDelay).toBeNull();
  });
});

describe('robots.txt matching', () => {
  const g = (txt: string) => groupFor(parseRobots(`User-agent: *\n${txt}`), 'x');
  it('prefers allow on equal length and the longest match otherwise', () => {
    expect(isAllowed(g('Disallow: /page\nAllow: /page'), '/page').allowed).toBe(true);
    expect(isAllowed(g('Allow: /p\nDisallow: /page'), '/page').allowed).toBe(false);
  });
  it('handles * and $', () => {
    const grp = g('Disallow: /*.php$\nDisallow: /a*b*c\nDisallow: /lit$eral');
    expect(isAllowed(grp, '/x/index.php').allowed).toBe(false);
    expect(isAllowed(grp, '/x/index.php?q').allowed).toBe(true);
    expect(isAllowed(grp, '/a-1-b-2-c-3').allowed).toBe(false);
    expect(isAllowed(grp, '/a-1-c-2-b').allowed).toBe(true);
    expect(isAllowed(grp, '/lit$eral').allowed).toBe(false);
  });
  it('does not backtrack exponentially on many wildcards', () => {
    const grp = g(`Disallow: /${'a*'.repeat(40)}b`);
    const t0 = Date.now();
    expect(isAllowed(grp, `/${'a'.repeat(2000)}`).allowed).toBe(true);
    expect(Date.now() - t0).toBeLessThan(1000);
  });
  it('compares percent-encoded and raw paths equally', () => {
    expect(normalizePath('/%7euser/%c3%a4')).toBe('/~user/%C3%A4');
    expect(normalizePath('/ä b')).toBe('/%C3%A4%20b');
    expect(isAllowed(g('Disallow: /%E4%BD%A0'), '/你好').allowed).toBe(false);
    expect(isAllowed(g('Disallow: /ä'), '/%c3%a4x').allowed).toBe(false);
    expect(isAllowed(g('Disallow: /a%2Fb'), '/a/b').allowed).toBe(true);
  });
});

describe('imageSize extras', () => {
  it('skips JPEG fill bytes and standalone markers, reads progressive SOF2', () => {
    const jpg = Uint8Array.from([0xff, 0xd8, 0xff, 0xff, 0xe1, 0x00, 0x04, 0x00, 0x00, 0xff, 0xd0, 0xff, 0xc2, 0x00, 0x11, 0x08, 0x00, 0x10, 0x00, 0x20, 0x03, 0, 0, 0]);
    expect(imageSize(jpg)).toEqual({ type: 'jpeg', width: 32, height: 16 });
  });
  it('reads AVIF ispe boxes and picks the largest', () => {
    const b = new Uint8Array(80);
    const v = new DataView(b.buffer);
    const put = (o: number, s: string) => b.set([...s].map((c) => c.charCodeAt(0)), o);
    v.setUint32(0, 20); put(4, 'ftyp'); put(8, 'avif'); put(16, 'mif1');
    v.setUint32(24, 20); put(28, 'ispe'); v.setUint32(36, 64); v.setUint32(40, 64);
    v.setUint32(44, 20); put(48, 'ispe'); v.setUint32(56, 1200); v.setUint32(60, 630);
    expect(imageSize(b)).toEqual({ type: 'avif', width: 1200, height: 630 });
  });
  it('rejects a VP8 chunk without start code', () => {
    const b = new Uint8Array(30);
    b.set([...'RIFF\0\0\0\0WEBPVP8 '].map((c) => c.charCodeAt(0)));
    expect(imageSize(b)).toBeNull();
  });
});
