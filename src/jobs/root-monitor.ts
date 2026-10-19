import { cachedJson } from '../core/cache';
import { html, type SafeHtml } from '../core/html';
import { ROOT_SERVERS, runAll } from '../tools/root-dns-servers';

const RETENTION_S = 7 * 86400;
const WINDOW_S = 86400;
const BUCKET_S = 1800;

async function currentColo(): Promise<string> {
  try {
    const res = await fetch('https://www.cloudflare.com/cdn-cgi/trace');
    return (await res.text()).match(/^colo=(\w+)/m)?.[1] ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

// Cron trigger: measure all root servers and keep a rolling 7-day history in D1.
export async function sampleRoots(env: Env): Promise<void> {
  const [colo, results] = await Promise.all([currentColo(), runAll()]);
  const ts = Math.floor(Date.now() / 1000);
  const insert = env.DB.prepare(
    'INSERT INTO root_samples (ts, colo, root, connect_ms, query_ms, serial, ok, instance) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  );
  await env.DB.batch([
    // Roots that Workers cannot reach from this location would only record false failures.
    ...results.filter((r) => !r.untestable).map((r) => insert.bind(ts, colo, r.server.letter, r.connectMs, r.queryMs, r.serial, r.error ? 0 : 1, r.instance)),
    env.DB.prepare('DELETE FROM root_samples WHERE ts < ?').bind(ts - RETENTION_S),
  ]);
  console.log({ event: 'cron', job: 'root-monitor', colo, ok: results.filter((r) => !r.error).length });
}

export interface LatestSample {
  ts: number;
  colo: string;
  ok: boolean;
  queryMs: number | null;
  serial: number | null;
  instance: string | null;
}

export interface RootHistory {
  samples: number;
  colos: string[];
  latestSerial: number | null;
  /** Most recent cron run per root letter. */
  latest: Record<string, LatestSample>;
  roots: {
    letter: string;
    availability: number | null;
    avgMs: number | null;
    /** Average query time per 30-minute bucket, oldest first; null = no data, -1 = all failed. */
    series: (number | null)[];
  }[];
}

async function loadHistory(env: Env): Promise<RootHistory> {
  const since = Math.floor(Date.now() / 1000) - WINDOW_S;
  const { results } = await env.DB.prepare(
    `SELECT root, CAST((ts - ?1) / ${BUCKET_S} AS INTEGER) AS bucket, colo, COUNT(*) AS n, SUM(ok) AS ok,
            AVG(CASE WHEN ok = 1 THEN query_ms END) AS avg_ms, MAX(serial) AS serial
       FROM root_samples WHERE ts >= ?1 GROUP BY root, bucket, colo`,
  )
    .bind(since)
    .all<{ root: string; bucket: number; colo: string; n: number; ok: number; avg_ms: number | null; serial: number | null }>();
  const latestRows = await env.DB.prepare(
    `SELECT root, ts, colo, ok, query_ms, serial, instance FROM root_samples WHERE ts = (SELECT MAX(ts) FROM root_samples)`,
  ).all<{ root: string; ts: number; colo: string; ok: number; query_ms: number | null; serial: number | null; instance: string | null }>();
  const latest: Record<string, LatestSample> = {};
  for (const r of latestRows.results) {
    latest[r.root] = { ts: r.ts, colo: r.colo, ok: r.ok === 1, queryMs: r.query_ms, serial: r.serial, instance: r.instance };
  }
  const buckets = WINDOW_S / BUCKET_S;
  const colos = new Set<string>();
  let samples = 0;
  let latestSerial: number | null = null;
  const roots = ROOT_SERVERS.map((s) => {
    const rows = results.filter((r) => r.root === s.letter);
    const n = rows.reduce((a, r) => a + r.n, 0);
    const ok = rows.reduce((a, r) => a + r.ok, 0);
    const timed = rows.filter((r) => r.avg_ms !== null);
    // Rows are per colo, so a bucket can have several; combine them weighted by successful samples.
    const okMs: number[] = Array(buckets).fill(0);
    const okN: number[] = Array(buckets).fill(0);
    const seen: boolean[] = Array(buckets).fill(false);
    for (const raw of rows) {
      // D1 binds JS numbers as REAL, so the bucket can arrive as 23.4; array slots need an integer.
      const r = { ...raw, bucket: Math.floor(raw.bucket) };
      if (r.bucket < 0 || r.bucket >= buckets) continue;
      seen[r.bucket] = true;
      if (r.avg_ms !== null && r.ok > 0) {
        okMs[r.bucket]! += r.avg_ms * r.ok;
        okN[r.bucket]! += r.ok;
      }
      colos.add(r.colo);
      if (r.serial && (latestSerial === null || r.serial > latestSerial)) latestSerial = r.serial;
    }
    const series: (number | null)[] = seen.map((s, i) => (!s ? null : okN[i] ? Math.round(okMs[i]! / okN[i]!) : -1));
    samples = Math.max(samples, n);
    return {
      letter: s.letter,
      availability: n ? ok / n : null,
      avgMs: timed.length ? Math.round(timed.reduce((a, r) => a + r.avg_ms! * r.ok, 0) / Math.max(1, ok)) : null,
      series,
    };
  });
  return { samples, colos: [...colos].sort(), latestSerial, latest, roots };
}

export function rootHistory(env: Env): Promise<RootHistory> {
  return cachedJson('root-history', () => 120, () => loadHistory(env));
}

export function sparkline(series: (number | null)[], max: number): SafeHtml {
  const w = 144, h = 28, step = w / series.length;
  const points: string[] = [];
  const fails: SafeHtml[] = [];
  series.forEach((v, i) => {
    const x = (i + 0.5) * step;
    if (v === -1) fails.push(html`<rect x="${(i * step).toFixed(1)}" y="${h - 4}" width="${step.toFixed(1)}" height="4" class="spark-fail"/>`);
    else if (v !== null) points.push(`${x.toFixed(1)},${(h - 6 - (Math.min(v, max) / max) * (h - 10)).toFixed(1)}`);
  });
  const dots = points.length <= 3 ? points.map((p) => { const [x, y] = p.split(','); return html`<circle cx="${x}" cy="${y}" r="2" class="spark-dot"/>`; }) : [];
  return html`<svg class="spark" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="Query time over the last 24 hours">
<polyline points="${points.join(' ')}" class="spark-line"/>${dots}${fails}</svg>`;
}
