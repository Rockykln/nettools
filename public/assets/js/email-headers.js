// Email header analysis, entirely client-side.
(() => {
  const form = document.getElementById('mh-form');
  const input = document.getElementById('mh-input');
  const out = document.getElementById('mh-result');
  if (!form || !input || !out) return;

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

  // Unfold continuation lines and split into [name, value] pairs, in original order.
  // The header block ends at the first empty line; leading blank lines from copying are ignored.
  function parse(text) {
    const lines = text.replace(/\r\n?/g, '\n').replace(/^\s*\n/, '').split('\n');
    const end = lines.findIndex((l) => !l.trim());
    const unfolded = (end < 0 ? lines : lines.slice(0, end)).join('\n').replace(/\n[ \t]+/g, ' ');
    return unfolded.split('\n').map((l) => l.match(/^([!-9;-~]+)[ \t]*:\s*(.*)$/)).filter(Boolean).map((m) => [m[1].toLowerCase(), m[2]]);
  }

  // RFC 2047 encoded words, e.g. =?utf-8?B?...?= or =?iso-8859-1?Q?...?=.
  function decodeWords(s) {
    return String(s).replace(/(=\?[^?\s]+\?[bq]\?[^?\s]*\?=)(\s+(?==\?[^?\s]+\?[bq]\?[^?\s]*\?=))/gi, '$1')
      .replace(/=\?([^?\s*]+)(?:\*[^?\s]*)?\?([bq])\?([^?\s]*)\?=/gi, (all, charset, enc, text) => {
        try {
          let bytes;
          if (enc.toLowerCase() === 'b') {
            bytes = Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
          } else {
            const raw = text.replace(/_/g, ' ').replace(/=([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
            bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
          }
          return new TextDecoder(charset).decode(bytes);
        } catch {
          return all;
        }
      });
  }

  // Replace (nested) comments with spaces, keeping offsets; returns the stripped text and the comments.
  function comments(s) {
    let depth = 0, start = 0, out = '';
    const found = [];
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '\\' && depth) { out += '  '; i++; continue; }
      if (c === '(') { if (!depth++) start = i; out += ' '; continue; }
      if (c === ')' && depth) { if (!--depth) found.push({ at: start, text: s.slice(start, i + 1) }); out += ' '; continue; }
      out += depth ? ' ' : c;
    }
    return { text: out, comments: found };
  }

  const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
  const ZONES = { ut: 0, utc: 0, gmt: 0, z: 0, edt: -4, est: -5, cdt: -5, cst: -6, mdt: -6, mst: -7, pdt: -7, pst: -8 };

  // RFC 5322 date-time ("Tue, 13 Oct 2026 09:14:07 +0200"); falls back to the browser parser.
  function parseDate(s) {
    const m = s.match(/(\d{1,2})\s+([a-z]{3})[a-z]*\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?\s*([+-]\d{4}|[a-z]{1,5})?/i);
    if (m && m[2].toLowerCase() in MONTHS) {
      let year = +m[3];
      if (m[3].length === 2) year += year < 50 ? 2000 : 1900;
      let offset = 0;
      const z = m[7] || '';
      if (/^[+-]\d{4}$/.test(z)) offset = (z[0] === '-' ? -1 : 1) * (+z.slice(1, 3) * 60 + +z.slice(3));
      else if (z.toLowerCase() in ZONES) offset = ZONES[z.toLowerCase()] * 60;
      const t = Date.UTC(year, MONTHS[m[2].toLowerCase()], +m[1], +m[4], +m[5], +(m[6] || 0)) - offset * 60000;
      return new Date(t);
    }
    const d = new Date(s);
    return isNaN(d) ? null : d;
  }

  function hop(value) {
    const { text, comments: notes } = comments(value);
    const semi = text.lastIndexOf(';');
    const date = semi >= 0 ? parseDate(text.slice(semi + 1).trim()) : null;
    const clauses = semi >= 0 ? text.slice(0, semi) : text;
    const at = (re) => { const m = re.exec(clauses); return m ? { word: m[1], end: m.index + m[0].length } : null; };
    const from = at(/\bfrom\s+(\S+)/i);
    const by = at(/\bby\s+(\S+)/i);
    // The comment right after the "from" name holds the reverse DNS name and IP the receiver saw.
    const seen = from && notes.find((n) => n.at >= from.end && (!by || n.at < by.end) && /\[(?:ipv6:)?[0-9a-f.:]+\]|\d+\.\d+\.\d+\.\d+|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b/i.test(n.text));
    return {
      from: from ? `${from.word}${seen ? ` ${seen.text}` : ''}` : '',
      by: by ? by.word : '',
      with: (at(/\bwith\s+(Microsoft SMTP Server|\S+)/i) || {}).word || '',
      time: date,
    };
  }

  // Results of the topmost Authentication-Results header (added by the receiving server); Received-SPF as fallback.
  function auth(headers) {
    const results = headers.filter(([n]) => n === 'authentication-results').map(([, v]) => comments(v).text);
    const first = results[0] || '';
    const get = (k) => {
      const all = [...first.matchAll(new RegExp(`(?:^|[;\\s])${k}\\s*=\\s*([a-z]+)`, 'gi'))].map((m) => m[1].toLowerCase());
      return all.length ? [...new Set(all)] : [];
    };
    let spf = get('spf');
    if (!spf.length) {
      const rs = (headers.find(([n]) => n === 'received-spf') || [])[1];
      const m = rs && rs.match(/^\s*([a-z]+)/i);
      if (m) spf = [m[1].toLowerCase()];
    }
    // compauth is Microsoft's composite verdict, set when DMARC alone does not decide.
    return { spf, dkim: get('dkim'), dmarc: get('dmarc'), compauth: get('compauth') };
  }

  const fmtDelay = (s) => {
    if (s === null) return '—';
    const a = Math.abs(s), sign = s < 0 ? '−' : '';
    return sign + (a < 60 ? `${a} s` : a < 3600 ? `${Math.floor(a / 60)} min${a % 60 ? ` ${a % 60} s` : ''}` : `${(a / 3600).toFixed(1)} h`);
  };
  const badge1 = (v) => `<span class="status ${v === 'pass' ? 'ok' : /fail|permerror/.test(v) ? 'bad' : 'warn'}">${esc(v)}</span>`;
  const badge = (vs) => (vs.length ? vs.map(badge1).join(' ') : '<span class="status info">none</span>');

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const headers = parse(input.value);
    if (!headers.length) {
      out.innerHTML = '<p class="error">No headers found. Paste the full header block, starting with lines like "Received:".</p>';
      return;
    }
    const get = (n) => decodeWords((headers.find(([k]) => k === n) || [])[1] || '');
    const hops = headers.filter(([n]) => n === 'received').map(([, v]) => hop(v)).reverse();
    // Delays are measured from the previous hop that has a usable date. Negative values come from
    // clocks that are off; they are shown but do not count towards the total.
    let total = null, prev = null;
    const rows = hops.map((h) => {
      const delay = h.time && prev ? Math.round((h.time - prev) / 1000) : null;
      if (delay !== null) total = (total || 0) + Math.max(0, delay);
      if (h.time) prev = h.time;
      return { ...h, delay };
    });
    const max = Math.max(1, ...rows.map((r) => Math.max(0, r.delay || 0)));
    const a = auth(headers);
    // The bare domain of an address header, for comparing From with Return-Path and Reply-To.
    const domainOf = (v) => ((v.match(/@([^\s>]+)/) || [])[1] || '').toLowerCase().replace(/\.$/, '');
    const fromDomain = domainOf(get('from'));
    const differs = (v) => (v && fromDomain && domainOf(v) && domainOf(v) !== fromDomain
      ? ' <span class="status warn">differs from From</span>' : '');
    out.innerHTML = `
<h2>Summary</h2>
<table class="kv"><tbody>
${[['From', get('from')], ['To', get('to')], ['Subject', get('subject')], ['Date', get('date')], ['Return-Path', get('return-path'), true], ['Reply-To', get('reply-to'), true], ['Message-ID', get('message-id')]]
  .filter(([k, v]) => k !== 'Reply-To' || v)
  .map(([k, v, cmp]) => `<tr><th scope="row">${k}</th><td class="wrap-any">${esc(v) || '—'}${cmp ? differs(v) : ''}</td></tr>`).join('')}
</tbody></table>
<h2>Authentication</h2>
<table class="kv"><tbody>
<tr><th scope="row">SPF</th><td>${badge(a.spf)}</td></tr>
<tr><th scope="row">DKIM</th><td>${badge(a.dkim)}</td></tr>
<tr><th scope="row">DMARC</th><td>${badge(a.dmarc)}</td></tr>
${a.compauth.length ? `<tr><th scope="row">compauth</th><td>${badge(a.compauth)}</td></tr>` : ''}
</tbody></table>
<h2>Route (${rows.length} hops${total !== null ? `, ${fmtDelay(total)} in total` : ''})</h2>
<div class="table-scroll" tabindex="0" role="region" aria-label="Route"><table class="data"><thead><tr><th>#</th><th>From</th><th>By</th><th>With</th><th>Time (UTC)</th><th>Delay</th><th></th></tr></thead><tbody>
${rows.map((r, i) => `<tr><td>${i + 1}</td><td class="wrap-any"><code>${esc(r.from) || '—'}</code></td><td class="wrap-any"><code>${esc(r.by) || '—'}</code></td><td>${esc(r.with) || '—'}</td>
<td>${r.time ? esc(r.time.toISOString().replace('T', ' ').slice(0, 19)) : '—'}</td><td>${fmtDelay(r.delay)}</td>
<td class="bar-cell"><svg class="hbar" width="100%" height="10" aria-hidden="true"><rect class="hbar-track" width="100%" height="10" rx="2"/><rect class="hbar-fill${(r.delay || 0) > 60 ? ' slow' : ''}" width="${((Math.max(0, r.delay || 0) / max) * 100).toFixed(1)}%" height="10" rx="2"/></svg></td></tr>`).join('')}
</tbody></table></div>`;
    out.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
})();
