// Downloads the DB-IP "IP to Country Lite" database (CC BY 4.0, https://db-ip.com) and writes
// public/data/geo/: index.json plus fixed-size binary chunks that src/core/geo.ts searches.
// Usage: npm run geo:update (DB-IP publishes a new file at the start of each month).
//
// Chunk rows, sorted by start address; each range ends where the next one starts:
//   v4-N.bin: 4-byte start (big endian) + 1-byte country index
//   v6-N.bin: 16-byte start + 1-byte country index
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { isIPv6 } from 'node:net';

const OUT = 'public/data/geo';
const ROWS_PER_CHUNK = 4096;

async function download() {
  const now = new Date();
  // The new month's file can appear a day late; fall back to the previous month.
  for (const back of [0, 1]) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - back, 1));
    const month = d.toISOString().slice(0, 7);
    const res = await fetch(`https://download.db-ip.com/free/dbip-country-lite-${month}.csv.gz`, {
      headers: { 'user-agent': 'nettools geo updater' },
    });
    if (res.ok) return { month, text: gunzipSync(Buffer.from(await res.arrayBuffer())).toString('utf8') };
    await res.body?.cancel();
  }
  throw new Error('DB-IP download failed for this and the previous month');
}

const v4 = (s) => s.split('.').reduce((n, o) => n * 256 + Number(o), 0);

function v6(s) {
  const [head, tail = ''] = s.includes('::') ? s.split('::') : [s, null];
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = tail === null ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2));
  return out;
}

const { month, text } = await download();
const countries = [];
const countryIndex = new Map();
const rows = { v4: [], v6: [] };
for (const line of text.split('\n')) {
  const [start, , cc] = line.trim().split(',');
  if (!start || !cc) continue;
  // ZZ marks unassigned space; it stays in the table so that the previous range ends there.
  const code = cc === 'ZZ' ? '' : cc;
  if (!countryIndex.has(code)) { countryIndex.set(code, countries.length); countries.push(code); }
  rows[isIPv6(start) ? 'v6' : 'v4'].push([start, countryIndex.get(code)]);
}
if (rows.v4.length < 100000 || rows.v6.length < 100000 || countries.length > 255) {
  throw new Error(`Unexpected data: ${rows.v4.length} IPv4 rows, ${rows.v6.length} IPv6 rows, ${countries.length} countries`);
}

await rm(OUT, { recursive: true, force: true });
await mkdir(OUT, { recursive: true });
const index = { source: 'DB-IP IP to Country Lite', license: 'CC BY 4.0', url: 'https://db-ip.com', month, countries, v4: [], v6: [] };

for (const fam of ['v4', 'v6']) {
  const width = fam === 'v4' ? 4 : 16;
  const list = rows[fam].map(([s, c]) => [fam === 'v4' ? v4(s) : v6(s), c]);
  for (let i = 0; i * ROWS_PER_CHUNK < list.length; i++) {
    const part = list.slice(i * ROWS_PER_CHUNK, (i + 1) * ROWS_PER_CHUNK);
    const buf = Buffer.alloc(part.length * (width + 1));
    part.forEach(([s, c], k) => {
      if (fam === 'v4') buf.writeUInt32BE(s, k * 5);
      else s.copy(buf, k * 17);
      buf[k * (width + 1) + width] = c;
    });
    await writeFile(`${OUT}/${fam}-${i}.bin`, buf);
    // First start of each chunk, as a number (IPv4) or 32 hex digits (IPv6).
    index[fam].push(fam === 'v4' ? part[0][0] : part[0][0].toString('hex'));
  }
}
await writeFile(`${OUT}/index.json`, JSON.stringify(index));
console.log(`DB-IP ${month}: ${rows.v4.length} IPv4 and ${rows.v6.length} IPv6 ranges, ${index.v4.length + index.v6.length} chunks in ${OUT}`);
