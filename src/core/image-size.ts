// Reads width and height from the first bytes of PNG, GIF, JPEG, WebP and AVIF files.

export interface ImageSize {
  type: 'png' | 'gif' | 'jpeg' | 'webp' | 'avif';
  width: number;
  height: number;
}

export function imageSize(b: Uint8Array): ImageSize | null {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const ascii = (o: number, n: number) => String.fromCharCode(...b.subarray(o, o + n));
  if (b.length >= 24 && b[0] === 0x89 && ascii(1, 3) === 'PNG') {
    return { type: 'png', width: v.getUint32(16), height: v.getUint32(20) };
  }
  if (b.length >= 10 && (ascii(0, 6) === 'GIF87a' || ascii(0, 6) === 'GIF89a')) {
    return { type: 'gif', width: v.getUint16(6, true), height: v.getUint16(8, true) };
  }
  if (b.length >= 30 && ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WEBP') {
    const chunk = ascii(12, 4);
    if (chunk === 'VP8X') return { type: 'webp', width: 1 + (b[24]! | (b[25]! << 8) | (b[26]! << 16)), height: 1 + (b[27]! | (b[28]! << 8) | (b[29]! << 16)) };
    if (chunk === 'VP8 ' && b[23] === 0x9d && b[24] === 0x01 && b[25] === 0x2a) {
      return { type: 'webp', width: v.getUint16(26, true) & 0x3fff, height: v.getUint16(28, true) & 0x3fff };
    }
    if (chunk === 'VP8L' && b[20] === 0x2f) {
      const bits = v.getUint32(21, true);
      return { type: 'webp', width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
    }
    return null;
  }
  if (b.length >= 16 && ascii(4, 4) === 'ftyp') return avifSize(b, v, ascii);
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8) {
    // Walk JPEG segments until a start-of-frame marker (SOF0–SOF15 except DHT/JPG/DAC).
    let i = 2;
    while (i + 9 < b.length) {
      if (b[i] !== 0xff) return null;
      const marker = b[i + 1]!;
      // 0xFF may be repeated as fill before a marker.
      if (marker === 0xff) {
        i++;
        continue;
      }
      // Standalone markers (TEM, RSTn, SOI) carry no length field.
      if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) {
        i += 2;
        continue;
      }
      if (marker === 0xd9 || marker === 0xda) return null;
      const len = v.getUint16(i + 2);
      if (len < 2) return null;
      if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) {
        return { type: 'jpeg', height: v.getUint16(i + 5), width: v.getUint16(i + 7) };
      }
      i += 2 + len;
    }
  }
  return null;
}

// AVIF (ISO BMFF): the size is in an "ispe" property box. Grid images also have smaller tile and
// thumbnail entries, so the largest one is taken as the image size.
function avifSize(b: Uint8Array, v: DataView, ascii: (o: number, n: number) => string): ImageSize | null {
  const ftypLen = v.getUint32(0);
  if (ftypLen < 16 || ftypLen > b.length) return null;
  const brands: string[] = [ascii(8, 4)];
  for (let o = 16; o + 4 <= ftypLen; o += 4) brands.push(ascii(o, 4));
  if (!brands.includes('avif') && !brands.includes('avis')) return null;
  let best: ImageSize | null = null;
  const end = Math.min(b.length, 64 * 1024) - 16;
  for (let i = ftypLen; i <= end; i++) {
    if (b[i] !== 0x69 || ascii(i, 4) !== 'ispe') continue;
    const width = v.getUint32(i + 8), height = v.getUint32(i + 12);
    if (width && height && (!best || width * height > best.width * best.height)) best = { type: 'avif', width, height };
  }
  return best;
}
