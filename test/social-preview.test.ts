import { describe, expect, it } from 'vitest';
import { decodeEntities, sniffImage } from '../src/tools/social-preview';

describe('social preview helpers', () => {
  it('decodes character references left in by HTMLRewriter', () => {
    expect(decodeEntities('A &amp; B &#8211; C &#x27;x&#X27; &quot;q&quot;')).toBe("A & B – C 'x' \"q\"");
    expect(decodeEntities('https://e.com/i.png?a=1&amp;b=2')).toBe('https://e.com/i.png?a=1&b=2');
    expect(decodeEntities('&unknown; &#0; &#xD800;')).toBe('&unknown; � �');
  });
  it('sniffs image formats by signature and refuses SVG/HTML', () => {
    const enc = (s: string) => new TextEncoder().encode(s.padEnd(16, '\0'));
    expect(sniffImage(Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]))).toBe('image/png');
    expect(sniffImage(Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0]))).toBe('image/jpeg');
    expect(sniffImage(enc('GIF89a'))).toBe('image/gif');
    expect(sniffImage(enc('RIFF\0\0\0\0WEBPVP8L'))).toBe('image/webp');
    expect(sniffImage(enc('\0\0\0\x1cftypavif'))).toBe('image/avif');
    expect(sniffImage(enc('<svg xmlns="http://www.w3.org/2000/svg">'))).toBeNull();
    expect(sniffImage(enc('<!doctype html><html>'))).toBeNull();
  });
});
