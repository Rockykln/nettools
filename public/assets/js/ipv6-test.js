// IPv6 test: one request to an IPv4-only and one to an IPv6-only endpoint, started by the visitor.
(() => {
  const box = document.querySelector('[data-ipv6-test]');
  if (!box) return;
  const out = (k) => box.querySelector(`[data-k="${k}"]`);
  const btn = box.querySelector('[data-run]');

  // family: '.' for IPv4, ':' for IPv6; an answer of the wrong family means the test did not run over that protocol.
  const probe = async (url, family) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const start = performance.now();
    try {
      const res = await fetch(url, { cache: 'no-store', signal: ctrl.signal, referrerPolicy: 'no-referrer' });
      if (!res.ok) return { ip: null, ms: null };
      const data = await res.json();
      const ip = data && typeof data.ip === 'string' && data.ip.includes(family) ? data.ip : null;
      return { ip, ms: ip ? Math.round(performance.now() - start) : null };
    } catch {
      return { ip: null, ms: null };
    } finally {
      clearTimeout(timer);
    }
  };

  const cell = (td, r) => {
    td.textContent = '';
    const status = document.createElement('span');
    status.className = `status ${r.ip ? 'ok' : 'bad'}`;
    status.textContent = r.ip ? 'works' : 'no connection';
    td.append(status);
    if (r.ip) {
      const code = document.createElement('code');
      code.textContent = r.ip;
      td.append(' ', code, ` · ${r.ms} ms`);
    }
  };

  btn?.addEventListener('click', async () => {
    if (btn.disabled) return;
    btn.disabled = true;
    out('v4').textContent = 'testing…';
    out('v6').textContent = 'testing…';
    const [v4, v6] = await Promise.all([probe(box.dataset.v4, '.'), probe(box.dataset.v6, ':')]);
    cell(out('v4'), v4);
    cell(out('v6'), v6);
    const verdict = out('verdict');
    verdict.hidden = false;
    verdict.className = `verdict ${v6.ip ? 'ok' : v4.ip ? 'warn' : 'bad'}`;
    verdict.textContent = v6.ip && v4.ip ? 'Your connection supports IPv6 and IPv4 (dual stack).'
      : v6.ip ? 'Your connection works over IPv6 only. Sites that have only IPv4 addresses will not load.'
      : v4.ip ? 'No IPv6: your connection reaches the internet over IPv4 only.'
      : 'Neither test answered. A firewall, content blocker or the network may block the test service.';
    btn.disabled = false;
    btn.textContent = 'Start again';
  });
})();
