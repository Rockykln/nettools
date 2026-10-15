// Embeddable SVG grade badges: /badge/headers/<domain>.svg and /badge/email/<domain>.svg
import { cachedJson } from './core/cache';
import { esc } from './core/html';
import { fetchChain, normalizeUrl } from './core/http-probe';
import { normalizeDomain } from './core/net';
import type { ToolContext } from './core/tool';
import { analyze } from './tools/email-security';
import { securityFindings } from './tools/http-headers';

export type BadgeKind = 'headers' | 'email';
type Grade = 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | '?';

const LABELS: Record<BadgeKind, string> = { headers: 'security headers', email: 'email security' };
const COLORS: Record<Grade, string> = { A: '#2E7D32', B: '#558B2F', C: '#9E9D24', D: '#EF6C00', E: '#D84315', F: '#C62828', '?': '#6B7280' };

/** 0–5 points from the five main security headers; plain HTTP is an F. */
export function headersGrade(levels: Record<string, string>, https: boolean): Grade {
  if (!https) return 'F';
  const keys = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'Clickjacking protection', 'Referrer-Policy'];
  const points = keys.reduce((p, k) => p + (levels[k] === 'ok' ? 1 : levels[k] === 'warn' && k === 'Strict-Transport-Security' ? 0.5 : 0), 0);
  return (['F', 'E', 'D', 'C', 'B', 'A'] as const)[Math.floor(points)]!;
}

/** SPF, DKIM and DMARC: 1 point each, half a point for a monitoring-only DMARC policy. */
export function emailGrade(levels: Record<string, string>, dmarcPolicy: string | null, sendsNoMail: boolean): Grade {
  if (sendsNoMail && dmarcPolicy === 'reject') return 'A';
  let points = 0;
  if (levels.SPF === 'ok') points += 1;
  else if (levels.SPF === 'warn') points += 0.5;
  if (levels.DKIM === 'ok') points += 1;
  if (dmarcPolicy === 'reject' || dmarcPolicy === 'quarantine') points += 1;
  else if (dmarcPolicy === 'none') points += 0.5;
  return points >= 3 ? 'A' : points >= 2.5 ? 'B' : points >= 2 ? 'C' : points >= 1.5 ? 'D' : points >= 1 ? 'E' : 'F';
}

/**
 * The DMARC policy receivers actually apply. With more than one DMARC record they ignore DMARC
 * entirely (RFC 7489 6.6.3), so there is no policy. analyzeDmarc() only reports that as a problem text.
 */
export function effectiveDmarcPolicy(dmarc: { record: string | null; tags: Record<string, string>; problems: string[] }): string | null {
  if (!dmarc.record || dmarc.problems.some((p) => /more than one dmarc record/i.test(p))) return null;
  return dmarc.tags.p?.toLowerCase() ?? null;
}

async function grade(kind: BadgeKind, domain: string, env: Env): Promise<Grade> {
  // '?' means the check failed; it is not cached so the badge recovers on the next request.
  return cachedJson(`badge:${kind}:${domain}`, (g) => (g === '?' ? 0 : 6 * 3600), async () => {
    try {
      if (kind === 'headers') {
        const chain = await fetchChain(normalizeUrl(domain)!, env);
        const last = chain.hops[chain.hops.length - 1];
        // An error page (e.g. a CDN 520) says nothing about the site's own headers.
        if (!last || chain.error || last.status >= 400) return '?';
        const levels = Object.fromEntries(securityFindings(last).map((f) => [f.header, f.level]));
        return headersGrade(levels, last.url.startsWith('https:'));
      }
      const r = await analyze(domain, null, env);
      const levels = Object.fromEntries(r.rows.map((row) => [row.check, row.level]));
      return emailGrade(levels, effectiveDmarcPolicy(r.dmarc), /^v=spf1\s+-all\s*$/i.test(r.spf.record ?? ''));
    } catch {
      return '?';
    }
  });
}

// Approximate Verdana 11px widths, good enough for short labels (same approach as shields.io).
const textWidth = (s: string) => Math.round(s.length * 6.6 + 10);

export function badgeSvg(label: string, value: string, color: string): string {
  const lw = textWidth(label), vw = textWidth(value), w = lw + vw;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(label)}: ${esc(value)}">
<title>${esc(label)}: ${esc(value)}</title>
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)"><rect width="${lw}" height="20" fill="#555"/><rect x="${lw}" width="${vw}" height="20" fill="${color}"/><rect width="${w}" height="20" fill="url(#s)"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="${lw / 2}" y="15" fill="#010101" fill-opacity=".3">${esc(label)}</text><text x="${lw / 2}" y="14">${esc(label)}</text>
<text x="${lw + vw / 2}" y="15" fill="#010101" fill-opacity=".3">${esc(value)}</text><text x="${lw + vw / 2}" y="14">${esc(value)}</text></g></svg>`;
}

/** True if the grade is already cached here, so serving it costs no outbound requests. */
export async function badgeCached(kind: string, file: string): Promise<boolean> {
  const domain = normalizeDomain(file.replace(/\.svg$/i, ''));
  if (!domain) return false;
  return !!(await caches.default.match(new Request(`https://cache.nettools.invalid/${encodeURIComponent(`badge:${kind}:${domain}`)}`)).catch(() => null));
}

export async function badgeResponse(c: ToolContext, kind: string, file: string): Promise<Response | null> {
  if (kind !== 'headers' && kind !== 'email') return null;
  const domain = normalizeDomain(file.replace(/\.svg$/i, ''));
  if (!domain?.includes('.')) {
    return new Response(badgeSvg(LABELS[kind], 'invalid domain', COLORS['?']), { status: 400, headers: { 'content-type': 'image/svg+xml; charset=utf-8', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'" } });
  }
  const g = await grade(kind, domain, c.env);
  return new Response(badgeSvg(LABELS[kind], g === '?' ? 'unknown' : g, COLORS[g]), {
    headers: {
      'content-type': 'image/svg+xml; charset=utf-8',
      'cache-control': 'public, max-age=21600',
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'",
    },
  });
}
