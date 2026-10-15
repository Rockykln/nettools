// Deferred. The saved theme is already applied by the inline script in <head> (src/core/theme-boot.ts);
// this adds the toggle and keeps the browser chrome colors in sync. Without a saved choice the CSS follows the device.
(() => {
  const KEY = 'theme';
  const root = document.documentElement;
  const read = () => { try { return localStorage.getItem(KEY); } catch { return null; } };
  // Browser chrome (iOS overscroll area, status bar) follows these tags, not the CSS.
  const COLORS = { light: '#FFFFFF', dark: '#0B1220' };
  const apply = (theme) => {
    root.dataset.theme = theme;
    document.querySelector('meta[name="color-scheme"]')?.setAttribute('content', theme);
    document.querySelectorAll('meta[name="theme-color"]').forEach((m) => m.setAttribute('content', COLORS[theme]));
  };
  const saved = read();
  if (saved === 'light' || saved === 'dark') apply(saved);

  const current = () => root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  // The HTML carries the brand color for link previews (Discord, Slack); browsers get the page background.
  const syncChrome = () => document.querySelectorAll('meta[name="theme-color"]').forEach((m) => m.setAttribute('content', COLORS[current()]));
  // Reflect the current state for screen readers.
  const syncToggle = () => document.querySelectorAll('[data-theme-toggle]').forEach((b) => b.setAttribute('aria-pressed', String(current() === 'dark')));
  syncChrome();
  syncToggle();
  // Without a saved choice the page follows the device, so the toggle state has to follow it too.
  const media = matchMedia('(prefers-color-scheme: dark)');
  const onSystemChange = () => { syncChrome(); syncToggle(); };
  if (media.addEventListener) media.addEventListener('change', onSystemChange);
  else media.addListener?.(onSystemChange);
  document.addEventListener('DOMContentLoaded', syncToggle);

  document.addEventListener('click', (e) => {
    const btn = e.target instanceof Element ? e.target.closest('[data-theme-toggle]') : null;
    if (!btn) return;
    const next = current() === 'dark' ? 'light' : 'dark';
    apply(next);
    try { localStorage.setItem(KEY, next); } catch { /* private mode: choice lasts for this page only */ }
    syncToggle();
  });
  // Another tab changed the theme.
  addEventListener('storage', (e) => {
    if (e.key === KEY && (e.newValue === 'light' || e.newValue === 'dark')) { apply(e.newValue); syncToggle(); }
  });
})();
