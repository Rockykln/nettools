(() => {
  const root = document.getElementById('speed');
  if (!root) return;

  const API = '/api/speed-test';
  const PHASE_MS = 8000;
  const WARMUP_MS = 1000;
  // A stalled request is aborted this long after the phase should have ended.
  const GRACE_MS = 4000;
  const MAX_DOWN = 50e6;
  const MAX_UP = 16e6;

  const $ = (sel) => root.querySelector(sel);
  const startBtn = $('[data-start]');
  const statusEl = $('[data-status]');
  const bar = $('[data-progress]');

  const setMetric = (key, value) => { $(`[data-metric="${key}"]`).textContent = value; };
  const setStatus = (msg) => { statusEl.textContent = msg; };
  const setProgress = (fraction) => { bar.style.width = `${Math.min(100, fraction * 100).toFixed(1)}%`; };
  const fmtMbps = (v) => (v >= 100 ? v.toFixed(0) : v.toFixed(1));
  const volumeEl = $('[data-volume]');
  const fmtBytes = (b) => (b >= 1e9 ? `${(b / 1e9).toFixed(2)} GB` : `${(b / 1e6).toFixed(b >= 1e8 ? 0 : 1)} MB`);
  const volume = { down: 0, up: 0 };
  const showVolume = () => {
    volumeEl.hidden = false;
    volumeEl.textContent = `Data transferred: ${fmtBytes(volume.down)} download · ${fmtBytes(volume.up)} upload · ${fmtBytes(volume.down + volume.up)} total`;
  };
  const nonce = () => Math.random().toString(36).slice(2);

  const median = (xs) => {
    const s = [...xs].sort((a, b) => a - b);
    const m = s.length >> 1;
    return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
  };

  async function measurePing(count, onStep) {
    performance.clearResourceTimings();
    const samples = [];
    for (let i = 0; i <= count; i++) {
      const url = new URL(`${API}/ping?r=${nonce()}`, location.href).href;
      const t0 = performance.now();
      const signal = typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(5000) : undefined;
      const res = await fetch(url, { cache: 'no-store', signal });
      if (!res.ok) throw new Error(`Latency test failed (HTTP ${res.status})`);
      let t = performance.now() - t0;
      // Resource timing excludes JS overhead. Firefox records the entry only after the body has been consumed
      // and the current task has ended, so read the (empty) body and yield once before looking it up.
      await res.arrayBuffer().catch(() => {});
      await new Promise((r) => setTimeout(r, 0));
      const entry = performance.getEntriesByName(url).pop();
      if (entry && entry.requestStart > 0 && entry.responseStart > entry.requestStart) {
        t = entry.responseStart - entry.requestStart;
      }
      if (i > 0) samples.push(t); // first request includes connection setup
      onStep(i / count);
    }
    // Jitter: mean difference between consecutive samples. The largest 10 % are dropped so that a single
    // hiccup (which counts twice in consecutive differences) does not dominate the result.
    const diffs = [];
    for (let i = 1; i < samples.length; i++) diffs.push(Math.abs(samples[i] - samples[i - 1]));
    diffs.sort((a, b) => a - b);
    const kept = diffs.slice(0, Math.max(1, Math.ceil(diffs.length * 0.9)));
    const jitter = kept.reduce((a, b) => a + b, 0) / kept.length;
    return { ping: median(samples), jitter };
  }

  // Runs `streams` parallel loops of `task` for PHASE_MS and reports throughput after the warm-up.
  async function measureThroughput(streams, task, onUpdate, onBytes) {
    const start = performance.now();
    const base = start + WARMUP_MS;
    const ctrl = new AbortController();
    const state = {
      stop: start + PHASE_MS,
      signal: ctrl.signal,
      total: 0,
      counted: 0,
      lastTime: start,
      // Bytes moved between t0 and t1 are spread evenly over that span; only the part after the warm-up counts.
      // Uploads report a whole request at once, so crediting it all at completion would overstate the rate.
      add(bytes, t0, t1) {
        this.total += bytes;
        if (t1 > base) this.counted += t1 > t0 ? (bytes * (t1 - Math.max(t0, base))) / (t1 - t0) : bytes;
        if (t1 > this.lastTime) this.lastTime = t1;
      },
    };
    const rate = () => (state.lastTime > base && state.counted > 0 ? (state.counted * 8) / ((state.lastTime - base) * 1000) : null);
    const timer = setInterval(() => {
      onBytes(state.total);
      onUpdate(rate(), (performance.now() - start) / PHASE_MS);
    }, 200);
    const deadline = setTimeout(() => ctrl.abort(), PHASE_MS + GRACE_MS);
    try {
      await Promise.all(Array.from({ length: streams }, () => task(state).catch((e) => {
        // Requests cut off by the deadline (or by another stream's failure) just end that stream.
        if (ctrl.signal.aborted) return;
        ctrl.abort();
        throw e;
      })));
    } finally {
      clearInterval(timer);
      clearTimeout(deadline);
      onBytes(state.total);
    }
    const r = rate();
    if (r !== null) return r;
    if (state.total === 0 || state.lastTime <= start) throw new Error('no data could be transferred');
    // Very slow connection: nothing finished after the warm-up, so use the whole phase.
    return (state.total * 8) / ((state.lastTime - start) * 1000);
  }

  async function downloadTask(state) {
    let size = 1e6;
    while (performance.now() < state.stop) {
      const t0 = performance.now();
      const res = await fetch(`${API}/down?bytes=${size}&r=${nonce()}`, { cache: 'no-store', signal: state.signal });
      if (!res.ok || !res.body) throw new Error(`Download failed (HTTP ${res.status})`);
      const reader = res.body.getReader();
      let last = t0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        const now = performance.now();
        state.add(value.byteLength, last, now);
        last = now;
        if (now > state.stop) {
          await reader.cancel().catch(() => {});
          break;
        }
      }
      if (performance.now() - t0 < 1500) size = Math.min(size * 2, MAX_DOWN);
    }
  }

  let uploadBuffer = null;
  function getUploadBuffer() {
    if (!uploadBuffer) {
      uploadBuffer = new Uint8Array(MAX_UP);
      for (let i = 0; i < MAX_UP; i += 65536) crypto.getRandomValues(uploadBuffer.subarray(i, i + 65536));
    }
    return uploadBuffer;
  }

  async function uploadTask(state) {
    const buf = getUploadBuffer();
    let size = 1e6;
    while (performance.now() < state.stop) {
      const t0 = performance.now();
      const res = await fetch(`${API}/up?r=${nonce()}`, { method: 'POST', body: buf.subarray(0, size), cache: 'no-store', signal: state.signal });
      if (!res.ok) throw new Error(`Upload failed (HTTP ${res.status})`);
      const t1 = performance.now();
      state.add(size, t0, t1);
      if (t1 - t0 < 1500) size = Math.min(size * 2, MAX_UP);
    }
  }

  // Plain-language meaning of the numbers for non-technical visitors.
  function verdict(down, up, ping) {
    const use = down >= 100 ? 'several 4K streams and large downloads at once'
      : down >= 25 ? '4K streaming and video calls'
      : down >= 10 ? 'HD streaming and video calls'
      : down >= 3 ? 'browsing and SD video'
      : 'basic browsing; video may stall';
    const calls = up >= 5 && ping < 80 ? 'Upload and latency are fine for HD video calls.'
      : up >= 1 ? 'Upload is enough for normal video calls.'
      : 'Upload is low; video calls may freeze.';
    return `Done. Good for ${use}. ${calls}`;
  }

  async function run() {
    startBtn.disabled = true;
    startBtn.textContent = 'Testing…';
    ['down', 'up', 'ping', 'jitter'].forEach((k) => setMetric(k, '—'));
    volume.down = 0;
    volume.up = 0;
    volumeEl.hidden = true;
    setProgress(0);
    try {
      setStatus('Measuring latency…');
      const { ping, jitter } = await measurePing(20, (f) => setProgress(f * 0.1));
      setMetric('ping', ping.toFixed(0));
      setMetric('jitter', jitter.toFixed(1));

      setStatus('Measuring download…');
      const down = await measureThroughput(4, downloadTask, (mbps, f) => {
        if (mbps !== null) setMetric('down', fmtMbps(mbps));
        setProgress(0.1 + f * 0.45);
      }, (b) => { volume.down = b; showVolume(); });
      setMetric('down', fmtMbps(down));

      setStatus('Measuring upload…');
      const up = await measureThroughput(3, uploadTask, (mbps, f) => {
        if (mbps !== null) setMetric('up', fmtMbps(mbps));
        setProgress(0.55 + f * 0.45);
      }, (b) => { volume.up = b; showVolume(); });
      setMetric('up', fmtMbps(up));

      setProgress(1);
      setStatus(verdict(down, up, ping));
      showShare(down, up, ping, jitter);
    } catch (e) {
      setStatus(`Test failed: ${e instanceof Error ? e.message : e}. Please try again.`);
    } finally {
      startBtn.disabled = false;
      startBtn.textContent = 'Run again';
    }
  }

  // Results are shared as /speed-test#r=down,up,ping,jitter,colo,unixtime. Nothing is stored on the server.
  const shareBox = $('[data-speed-share]');
  function showShare(down, up, ping, jitter) {
    const colo = root.dataset.colo || '';
    const hash = `#r=${[down, up, ping, jitter].map((v) => v.toFixed(1)).join(',')},${colo},${Math.floor(Date.now() / 1000)}`;
    const url = `${location.origin}${location.pathname}${hash}`;
    history.replaceState(null, '', hash);
    shareBox.querySelector('[data-share-url]').textContent = url;
    shareBox.querySelector('[data-copy]').setAttribute('data-copy', url);
    const native = shareBox.querySelector('[data-share]');
    native.setAttribute('data-share', url);
    native.hidden = typeof navigator.share !== 'function';
    shareBox.hidden = false;
  }

  function showShared() {
    const m = location.hash.match(/^#r=([\d.]+),([\d.]+),([\d.]+),([\d.]+),([A-Z]{0,4}),(\d+)$/);
    if (!m) return;
    const [, down, up, ping, jitter, colo, ts] = m;
    // Shared links are user input: ignore values no real connection or test date can have.
    const time = Number(ts) * 1000;
    if ([down, up].some((v) => Number(v) > 100000) || Number(ping) > 60000 || Number(jitter) > 60000) return;
    if (time < Date.UTC(2026, 0, 1) || time > Date.now() + 86400000) return;
    setMetric('down', fmtMbps(Number(down)));
    setMetric('up', fmtMbps(Number(up)));
    setMetric('ping', Number(ping).toFixed(0));
    setMetric('jitter', Number(jitter).toFixed(1));
    setProgress(1);
    const when = new Date(time).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    setStatus(`Shared result from ${when}${colo ? `, measured via Cloudflare ${colo}` : ''}. Start the test to measure your own connection.`);
  }

  showShared();
  addEventListener('hashchange', showShared);
  startBtn.addEventListener('click', run);
})();
