// robots.txt parsing and matching as specified in RFC 9309.

export interface Rule {
  allow: boolean;
  path: string;
}

export interface Group {
  agents: string[];
  rules: Rule[];
  crawlDelay: number | null;
}

export interface Robots {
  groups: Group[];
  sitemaps: string[];
  invalidLines: number;
}

export function parseRobots(text: string): Robots {
  const groups: Group[] = [];
  const sitemaps: string[] = [];
  let invalidLines = 0;
  let current: Group | null = null;
  let lastWasAgent = false;
  for (const rawLine of text.replace(/^﻿/, '').split(/\r\n|\r|\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const m = line.match(/^([A-Za-z_-]+)\s*:\s*(.*)$/);
    if (!m) {
      invalidLines++;
      continue;
    }
    const key = m[1]!.toLowerCase();
    const value = m[2]!.trim();
    if (key === 'user-agent') {
      // Consecutive user-agent lines share one group; only rule lines end a run of them.
      if (!current || !lastWasAgent) {
        current = { agents: [], rules: [], crawlDelay: null };
        groups.push(current);
      }
      current.agents.push(value.toLowerCase());
      lastWasAgent = true;
      continue;
    }
    if (key === 'sitemap') {
      if (value) sitemaps.push(value);
      continue;
    }
    if ((key === 'allow' || key === 'disallow' || key === 'crawl-delay') && current) {
      lastWasAgent = false;
      if (key === 'crawl-delay') {
        const n = Number(value);
        current.crawlDelay = Number.isFinite(n) && n > 0 ? n : null;
      } else if (value) current.rules.push({ allow: key === 'allow', path: value });
    } else if (!['host', 'clean-param', 'request-rate', 'visit-time', 'noindex'].includes(key)) invalidLines++;
  }
  return { groups, sitemaps, invalidLines };
}

/** Product token of a user-agent line (RFC 9309: letters, "-" and "_"), or "*". */
function agentToken(value: string): string {
  if (value.startsWith('*')) return '*';
  return value.match(/^[a-z_-]+/i)?.[0]?.toLowerCase() ?? '';
}

function mergeGroups(list: Group[], agents: string[]): Group {
  if (list.length === 1) return list[0]!;
  return { agents, rules: list.flatMap((g) => g.rules), crawlDelay: list.find((g) => g.crawlDelay !== null)?.crawlDelay ?? null };
}

/**
 * The group that applies to a crawler, given its product token ("Googlebot") or a full user-agent string.
 * Agent lines are compared by whole product token, so "bot" does not match "Googlebot". All groups naming
 * the chosen token are combined (RFC 9309, 2.2.1); without one, the "*" groups are combined.
 */
export function groupFor(robots: Robots, userAgent: string): Group | null {
  const tokens = new Set((userAgent.replace(/\+?https?:\/\/\S*/gi, ' ').toLowerCase().match(/[a-z_-]+/g) ?? []));
  let best = '';
  for (const g of robots.groups) {
    for (const a of g.agents) {
      const t = agentToken(a);
      if (t && t !== '*' && tokens.has(t) && t.length > best.length) best = t;
    }
  }
  if (best) {
    const list = robots.groups.filter((g) => g.agents.some((a) => agentToken(a) === best));
    return mergeGroups(list, [...new Set(list.flatMap((g) => g.agents.filter((a) => agentToken(a) === best)))]);
  }
  const star = robots.groups.filter((g) => g.agents.some((a) => agentToken(a) === '*'));
  return star.length ? mergeGroups(star, ['*']) : null;
}

const UNRESERVED = /[A-Za-z0-9\-._~]/;

/** Normalizes percent-encoding so that "/a%7Eb", "/a~b" and "/ä" vs "/%C3%A4" compare equal. */
export function normalizePath(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === '%' && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3))) {
      const ch = String.fromCharCode(parseInt(s.slice(i + 1, i + 3), 16));
      out += UNRESERVED.test(ch) ? ch : `%${s.slice(i + 1, i + 3).toUpperCase()}`;
      i += 2;
    } else {
      const code = c.charCodeAt(0);
      if (code > 0x20 && code < 0x7f) out += c;
      else {
        // Non-ASCII and control characters are compared as UTF-8 percent-encoded octets.
        const cp = s.codePointAt(i)!;
        const ch = String.fromCodePoint(cp);
        if (ch.length === 2) i++;
        out += cp >= 0xd800 && cp <= 0xdfff ? '%EF%BF%BD' : encodeURIComponent(ch);
      }
    }
  }
  return out;
}

/** Matches a rule pattern against a normalized path: "*" is any sequence, a trailing "$" anchors the end. */
function matches(pattern: string, path: string): boolean {
  // Set of path positions reachable so far; linear per pattern character, no regex backtracking.
  let pos: number[] = [0];
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === '$' && i === pattern.length - 1) return pos.includes(path.length);
    if (c === '*') {
      const from = pos[0]!;
      pos = [];
      for (let p = from; p <= path.length; p++) pos.push(p);
      continue;
    }
    const next: number[] = [];
    for (const p of pos) if (path[p] === c) next.push(p + 1);
    if (!next.length) return false;
    pos = next;
  }
  return true;
}

/** Longest matching rule wins; on a tie, allow wins. No matching rule means allowed. */
export function isAllowed(group: Group | null, path: string): { allowed: boolean; rule: Rule | null } {
  if (!group) return { allowed: true, rule: null };
  const target = normalizePath(path);
  let best: Rule | null = null;
  let bestLen = -1;
  for (const r of group.rules) {
    const p = normalizePath(r.path);
    if (!matches(p, target)) continue;
    if (p.length > bestLen || (p.length === bestLen && r.allow && !best!.allow)) {
      best = r;
      bestLen = p.length;
    }
  }
  return { allowed: best ? best.allow : true, rule: best };
}
