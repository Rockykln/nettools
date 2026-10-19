// Downloads the IEEE MAC address registries and writes public/data/mac/XX.json, one file per first byte:
// { "PREFIX": [bits, vendor, country] }. Usage: npm run mac:update (run monthly by .github/workflows/update-data.yml).
import { mkdir, rm, writeFile } from 'node:fs/promises';

const SOURCES = [
  ['https://standards-oui.ieee.org/oui/oui.csv', 24],
  ['https://standards-oui.ieee.org/oui28/mam.csv', 28],
  ['https://standards-oui.ieee.org/oui36/oui36.csv', 36],
];

function parseCsv(text) {
  const rows = [];
  let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { row.push(field); field = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += ch;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

const regions = new Intl.DisplayNames(['en'], { type: 'region' });
const isCountry = (code) => { try { return regions.of(code) !== code; } catch { return false; } };

// IEEE addresses end with "<country> <postal code>" (e.g. "NL 5633 AD", "GB N3 1 RL", "CA M1R 3E4") or just the
// country; US addresses also contain the state ("CA US 95014"). Take the first valid ISO code that is followed
// only by something shaped like a postal code, so neither the state nor a part of the postal code wins.
function countryOf(address) {
  const a = address.trim();
  for (const m of a.matchAll(/\b([A-Z]{2})\b/g)) {
    const rest = a.slice(m.index + 2).trim();
    if (isCountry(m[1]) && rest.length <= 10 && /^[A-Z0-9 -]*$/.test(rest) && !/^[A-Z]{2}\b/.test(rest)) return m[1];
  }
  return null;
}

const records = new Map();

for (const [url, bits] of SOURCES) {
  const res = await fetch(url, { headers: { 'user-agent': 'nettools mac-vendor updater' } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const all = parseCsv(await res.text());
  // The IEEE site sometimes answers bot checks or errors with an HTML page and status 200;
  // writing that out would empty the table on the next seed.
  if (!/assignment/i.test((all[0] ?? []).join(',')) || all.length < (bits === 24 ? 10000 : 1000)) {
    throw new Error(`${url}: unexpected content (${all.length} rows), not a registry CSV`);
  }
  const rows = all.slice(1);
  for (const [, assignment, org, address] of rows) {
    if (!assignment || !org || !/^[0-9A-Fa-f]{6,9}$/.test(assignment.trim())) continue;
    const country = countryOf(address ?? '');
    records.set(assignment.trim().toUpperCase(), { bits, vendor: org.trim().replace(/\s+/g, ' '), country });
  }
  console.log(`${url}: ${rows.length} rows`);
}

const OUT = 'public/data/mac';
const files = new Map(Array.from({ length: 256 }, (_, i) => [i.toString(16).toUpperCase().padStart(2, '0'), {}]));
for (const [prefix, r] of [...records.entries()].sort(([a], [b]) => a.localeCompare(b))) {
  files.get(prefix.slice(0, 2))[prefix] = [r.bits, r.vendor, r.country];
}
await rm(OUT, { recursive: true, force: true });
await mkdir(OUT, { recursive: true });
// Every file exists, even if empty, so a missing file means missing data rather than an unknown vendor.
for (const [name, data] of files) await writeFile(`${OUT}/${name}.json`, JSON.stringify(data));
console.log(`wrote ${files.size} files to ${OUT} with ${records.size} prefixes`);
