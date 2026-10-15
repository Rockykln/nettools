import { describe, expect, it } from 'vitest';
import { imageSize } from '../src/core/image-size';
import { groupFor, isAllowed, parseRobots } from '../src/core/robots';

describe('imageSize', () => {
  it('reads PNG and GIF headers', () => {
    const png = new Uint8Array(24);
    png.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    new DataView(png.buffer).setUint32(16, 1200);
    new DataView(png.buffer).setUint32(20, 630);
    expect(imageSize(png)).toEqual({ type: 'png', width: 1200, height: 630 });
    const gif = Uint8Array.from([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x10, 0x00, 0x20, 0x00]);
    expect(imageSize(gif)).toEqual({ type: 'gif', width: 16, height: 32 });
  });
  it('reads a JPEG start-of-frame segment', () => {
    const jpg = Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x02, 0x76, 0x04, 0xb0, 0x03]);
    expect(imageSize(jpg)).toEqual({ type: 'jpeg', width: 1200, height: 630 });
  });
  it('returns null for unknown data', () => {
    expect(imageSize(new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"/>'))).toBeNull();
  });
});

describe('robots.txt', () => {
  const robots = parseRobots(`# comment
User-agent: *
Disallow: /private/
Allow: /private/public.html
Disallow: /*.pdf$

User-agent: Googlebot
User-agent: Bingbot
Disallow: /no-google/
Crawl-delay: 5

Sitemap: https://example.com/sitemap.xml
nonsense line`);

  it('parses groups, sitemaps and invalid lines', () => {
    expect(robots.groups).toHaveLength(2);
    expect(robots.groups[1]!.agents).toEqual(['googlebot', 'bingbot']);
    expect(robots.groups[1]!.crawlDelay).toBe(5);
    expect(robots.sitemaps).toEqual(['https://example.com/sitemap.xml']);
    expect(robots.invalidLines).toBe(1);
  });

  it('picks the most specific group and the longest rule', () => {
    const star = groupFor(robots, 'SomeBot/1.0');
    expect(isAllowed(star, '/private/secret').allowed).toBe(false);
    expect(isAllowed(star, '/private/public.html').allowed).toBe(true);
    expect(isAllowed(star, '/files/doc.pdf').allowed).toBe(false);
    expect(isAllowed(star, '/files/doc.pdf?x=1').allowed).toBe(true);
    const google = groupFor(robots, 'Mozilla/5.0 (compatible; Googlebot/2.1)');
    expect(isAllowed(google, '/private/secret').allowed).toBe(true);
    expect(isAllowed(google, '/no-google/x').allowed).toBe(false);
  });
});
