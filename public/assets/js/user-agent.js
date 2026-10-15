// Fills the "what scripts can read" table on /user-agent. Values stay in the browser.
(() => {
  const table = document.querySelector('[data-browser-info]');
  if (!table) return;
  const set = (k, v) => { const td = table.querySelector(`[data-k="${k}"]`); if (td) td.textContent = v || '—'; };

  set('js', 'enabled');
  set('cookies', navigator.cookieEnabled ? 'enabled' : 'disabled');
  set('screen', `${screen.width} × ${screen.height} (${screen.colorDepth}-bit color)`);
  const viewport = () => set('viewport', `${innerWidth} × ${innerHeight}`);
  viewport();
  addEventListener('resize', viewport);
  set('dpr', String(Math.round(devicePixelRatio * 100) / 100));
  try { set('tz', Intl.DateTimeFormat().resolvedOptions().timeZone); } catch { /* old browsers */ }
  set('langs', (navigator.languages || [navigator.language]).join(', '));
  set('scheme', matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  // iPadOS Safari in desktop mode sends a Mac user agent; Macs have no touch screen.
  const ipadAsMac = /Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1;
  set('touch', navigator.maxTouchPoints > 0
    ? `yes (${navigator.maxTouchPoints} points)${ipadAsMac ? ', so the "macOS" above is most likely an iPad in desktop mode' : ''}`
    : 'no');

  // User-Agent Client Hints exist in Chromium-based browsers only.
  const uad = navigator.userAgentData;
  if (!uad) { set('platform', 'not supported by this browser'); return; }
  set('platform', uad.platform);
  if (typeof uad.getHighEntropyValues !== 'function') return;
  uad.getHighEntropyValues(['platformVersion', 'model', 'architecture'])
    .then((v) => {
      const parts = [uad.platform, v.platformVersion, v.architecture, v.model].filter(Boolean);
      set('platform', parts.join(' · '));
    })
    .catch(() => {});
})();
