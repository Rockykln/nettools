// Runs the live root server test row by row, so results appear as each server answers.
(() => {
  const form = document.querySelector('form[data-root-test]');
  const table = document.querySelector('table.roots');
  if (!form || !table) return;
  const summary = document.querySelector('[data-summary]');
  const button = form.querySelector('button');
  const rows = [...table.querySelectorAll('tr[data-root]')];

  const cell = (row, name) => row.querySelector(`[data-cell="${name}"]`);
  const set = (el, html) => { el.innerHTML = html; el.classList.remove('pending'); el.classList.add('updated'); };
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

  async function testRow(row) {
    const letter = row.dataset.root.toLowerCase();
    for (const n of ['status', 'query', 'instance']) {
      const el = cell(row, n);
      el.classList.remove('updated', 'best');
      el.classList.add('pending');
      el.textContent = '…';
    }
    try {
      const res = await fetch(`/api/root-dns-servers/test/${letter}`, { cache: 'no-store' });
      // Rate limit and error pages are not JSON.
      const r = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(r.error || (res.status === 429 ? 'Too many requests, try again later' : `HTTP ${res.status}`));
      set(cell(row, 'status'), r.untestable ? `<span class="status info" title="${esc(r.error)}">Not testable</span>`
        : r.error ? `<span class="status bad" title="${esc(r.error)}">Failed</span>` : '<span class="status ok">OK</span>');
      set(cell(row, 'query'), r.queryMs != null ? (r.queryMs < 1 ? '&lt;1 ms' : `${esc(r.queryMs)} ms`) : '—');
      set(cell(row, 'instance'), `<code>${esc(r.instance ?? r.error ?? '—')}</code>`);
      return r;
    } catch (e) {
      set(cell(row, 'status'), '<span class="status bad">Failed</span>');
      set(cell(row, 'query'), '—');
      set(cell(row, 'instance'), `<code>${esc(e.message)}</code>`);
      return null;
    }
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    button.disabled = true;
    button.textContent = 'Testing…';
    summary.textContent = 'Testing all 13 root servers…';
    const queue = [...rows];
    const results = [];
    const worker = async () => {
      while (queue.length) {
        const row = queue.shift();
        results.push([row, await testRow(row)]);
      }
    };
    await Promise.all(Array.from({ length: 6 }, worker));

    const ok = results.filter(([, r]) => r && !r.error);
    const fastest = ok.reduce((best, cur) => (best === null || cur[1].queryMs < best[1].queryMs ? cur : best), null);
    if (fastest) cell(fastest[0], 'query').classList.add('best');
    const serials = [...new Set(ok.map(([, r]) => r.serial).filter(Boolean))];
    const from = ok[0]?.[1].from ?? '';
    const tested = results.filter(([, r]) => !r?.untestable).length;
    summary.innerHTML = `Tested just now from Cloudflare <strong>${esc(from)}</strong>: ${ok.length} of ${tested} testable roots answered` +
      (serials.length === 1 ? `, root zone serial <code>${esc(serials[0])}</code>.` : serials.length > 1 ? `. Different zone serials (${esc(serials.join(', '))}): an update is propagating.` : '.');
    button.disabled = false;
    button.textContent = 'Run again';
  });
})();
