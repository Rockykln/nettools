// Progressive enhancement shared by all pages. Every tool also works without JavaScript.
(() => {
  const live = document.createElement('div');
  live.setAttribute('aria-live', 'polite');
  live.className = 'visually-hidden';
  document.addEventListener('DOMContentLoaded', () => document.body.append(live));
  const announce = (msg) => { live.textContent = ''; setTimeout(() => { live.textContent = msg; }, 50); };

  // Touch devices have no hover: a tap toggles blurred values. Keyboard: Enter or Space keeps the value revealed.
  document.addEventListener('click', (e) => {
    const secret = e.target instanceof Element ? e.target.closest('.secret') : null;
    if (secret) secret.classList.toggle('revealed');
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const secret = e.target instanceof Element && e.target.matches('.secret') ? e.target : null;
    if (!secret) return;
    e.preventDefault();
    secret.classList.toggle('revealed');
  });

  // The Clipboard API needs a secure context (HTTPS or localhost); plain HTTP falls back to execCommand.
  const writeClipboard = async (text) => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch { /* denied: try the fallback */ }
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;top:0;left:0;width:1px;height:1px;opacity:0;';
    const focused = document.activeElement;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    if (focused instanceof HTMLElement) focused.focus({ preventScroll: true });
    return ok;
  };
  const timers = new WeakMap();
  const flash = (btn, text) => {
    btn.dataset.label ??= btn.textContent;
    const label = btn.dataset.label;
    btn.textContent = text;
    clearTimeout(timers.get(btn));
    timers.set(btn, setTimeout(() => { btn.textContent = label; }, 1500));
  };

  document.addEventListener('click', async (e) => {
    const btn = e.target instanceof Element ? e.target.closest('[data-copy]') : null;
    if (!btn) return;
    const text = btn.getAttribute('data-copy') ?? '';
    if (await writeClipboard(text)) {
      flash(btn, 'Copied');
      announce('Copied to clipboard');
    } else {
      window.prompt('Copy this text:', text);
    }
  });

  // Native share sheet where the browser has one (mostly mobile). Otherwise, or if sharing fails, the link is copied.
  const copyLink = async (btn, url) => {
    if (await writeClipboard(url)) {
      flash(btn, 'Link copied');
      announce('Link copied to clipboard');
    } else {
      window.prompt('Copy this link:', url);
    }
  };
  if (typeof navigator.share === 'function') document.querySelectorAll('[data-share]').forEach((b) => { b.hidden = false; });
  document.addEventListener('click', async (e) => {
    const btn = e.target instanceof Element ? e.target.closest('[data-share]') : null;
    if (!btn) return;
    const url = btn.getAttribute('data-share');
    if (!url) return;
    const data = { title: btn.getAttribute('data-share-title') || document.title, url };
    if (typeof navigator.share !== 'function' || (navigator.canShare && !navigator.canShare(data))) {
      await copyLink(btn, url);
      return;
    }
    try {
      await navigator.share(data);
    } catch (err) {
      // AbortError means the user closed the share sheet on purpose.
      if (!(err instanceof DOMException && err.name === 'AbortError')) await copyLink(btn, url);
    }
  });

  document.addEventListener('click', (e) => {
    if (!(e.target instanceof Element) || !e.target.closest('[data-back]')) return;
    // Opened in a new tab from a tool: close it; otherwise go back.
    if (history.length <= 1) window.close();
    else history.back();
  });

  // Listens on the document so it runs after page scripts: forms they handle themselves (preventDefault) are left alone.
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (e.defaultPrevented || !(form instanceof HTMLFormElement) || !form.matches('form.tool-form')) return;
    const btn = form.querySelector('button[type="submit"]');
    if (!btn) return;
    btn.dataset.label = btn.textContent;
    btn.textContent = 'Working…';
    btn.disabled = true;
  });

  // "Copy as Markdown" under every result table, for tickets, chats and docs.
  // Cells hold third-party data (TXT records, headers); escape Markdown syntax so it cannot become links or images.
  const cellText = (cell) => cell.textContent.replace(/\s+/g, ' ').trim().replace(/[\\|`*_[\]()!<>#~]/g, '\\$&');
  const toMarkdown = (table) => {
    const rows = [...table.querySelectorAll('tr')].map((tr) => [...tr.children].map(cellText));
    if (!rows.length) return '';
    const head = table.tHead ? rows.shift() : rows[0].map(() => '');
    return [head, head.map(() => '---'), ...rows].map((r) => `| ${r.join(' | ')} |`).join('\n');
  };
  document.querySelectorAll('section.tool table.data').forEach((table) => {
    if (table.closest('.legal-card') || table.rows.length < 2) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn-small copy-md';
    btn.textContent = 'Copy as Markdown';
    btn.setAttribute('data-copy', '');
    btn.addEventListener('click', () => btn.setAttribute('data-copy', toMarkdown(table)), true);
    (table.closest('.table-scroll') ?? table).after(btn);
  });

  // Restore buttons when the page comes back from the back/forward cache.
  window.addEventListener('pageshow', () => {
    document.querySelectorAll('form.tool-form button[type="submit"][data-label]').forEach((btn) => {
      btn.textContent = btn.dataset.label;
      btn.disabled = false;
    });
  });

  // Narrow screens: tables that would scroll sideways are shown as one block per row,
  // each value labelled with its column header (labels come from the table head).
  const narrow = matchMedia('(max-width: 900px)');
  const labelCells = (table) => {
    const heads = [...table.querySelectorAll('thead th')].map((th) => th.textContent.trim());
    if (!heads.length) return false;
    // Name/value tables read better as a bold name with the value below it.
    table.classList.toggle('pairs', heads.length === 2);
    table.querySelectorAll('tbody tr').forEach((tr) => {
      let col = 0;
      for (const td of tr.children) {
        if (!td.hasAttribute('data-label')) td.setAttribute('data-label', heads[col] ?? '');
        col += td.colSpan || 1;
      }
    });
    return true;
  };
  const fitTables = () => {
    // DNS record tables (.records) have their own phone layout in the stylesheet.
    document.querySelectorAll('table.data:not(.records)').forEach((table) => {
      if (!labelCells(table)) return;
      table.classList.remove('stack');
      const box = table.parentElement;
      if (narrow.matches && box && table.scrollWidth > box.clientWidth + 1) table.classList.add('stack');
    });
  };
  let pending = 0;
  const schedule = () => { cancelAnimationFrame(pending); pending = requestAnimationFrame(fitTables); };
  // Some tools fill their tables later from script. Text-only updates (live values) are ignored.
  const addsRows = (n) => n instanceof Element && (n.matches('table, thead, tbody, tr') || n.querySelector('table, tr') !== null);
  document.addEventListener('DOMContentLoaded', () => {
    fitTables();
    new MutationObserver((list) => { if (list.some((m) => [...m.addedNodes].some(addsRows))) schedule(); })
      .observe(document.body, { childList: true, subtree: true });
  });
  // Mobile browsers fire resize when the address bar slides in or out; only width changes matter here.
  let lastWidth = innerWidth;
  addEventListener('resize', () => { if (innerWidth !== lastWidth) { lastWidth = innerWidth; schedule(); } });
})();
