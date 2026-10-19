import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import type { Tool, ToolContext } from '../core/tool';

export interface ParsedUa {
  browser: string | null;
  browserVersion: string | null;
  engine: string | null;
  os: string | null;
  osVersion: string | null;
  device: 'desktop' | 'mobile' | 'tablet' | 'bot' | 'unknown';
}

const BOTS: [RegExp, string][] = [
  [/Googlebot(?:-[A-Za-z]+)?\/([\d.]+)/, 'Googlebot'],
  [/bingbot\/([\d.]+)/i, 'Bingbot'],
  [/Applebot\/([\d.]+)/, 'Applebot'],
  [/DuckDuckBot\/([\d.]+)/, 'DuckDuckBot'],
  [/YandexBot\/([\d.]+)/, 'YandexBot'],
  [/facebookexternalhit\/([\d.]+)/, 'Facebook crawler'],
  [/Twitterbot\/([\d.]+)/, 'Twitterbot'],
  [/^curl\/([\d.]+)/, 'curl'],
  [/^Wget\/([\d.]+)/, 'Wget'],
  [/python-requests\/([\d.]+)/, 'Python requests'],
  [/^Go-http-client\/([\d.]+)/, 'Go HTTP client'],
];

// Order matters: Chromium-based browsers also send "Chrome/" and "Safari/".
const BROWSERS: [RegExp, string][] = [
  [/EdgiOS\/([\d.]+)/, 'Microsoft Edge'],
  [/Edge?A?\/([\d.]+)/, 'Microsoft Edge'],
  [/OPR\/([\d.]+)/, 'Opera'],
  [/(?:OPiOS|OPT)\/([\d.]+)/, 'Opera'],
  [/Opera\/.*Version\/([\d.]+)/, 'Opera'],
  [/SamsungBrowser\/([\d.]+)/, 'Samsung Internet'],
  [/YaBrowser\/([\d.]+)/, 'Yandex Browser'],
  [/FxiOS\/([\d.]+)/, 'Firefox'],
  [/Firefox\/([\d.]+)/, 'Firefox'],
  [/CriOS\/([\d.]+)/, 'Chrome'],
  [/Chrome\/([\d.]+)/, 'Chrome'],
  [/Version\/([\d.]+).*Safari\//, 'Safari'],
  [/Trident\/.*rv:([\d.]+)/, 'Internet Explorer'],
  [/MSIE ([\d.]+)/, 'Internet Explorer'],
];

/** Heuristic parser; user agent strings are reduced and partly frozen, so versions can be approximate. */
export function parseUa(ua: string): ParsedUa {
  const r: ParsedUa = { browser: null, browserVersion: null, engine: null, os: null, osVersion: null, device: 'unknown' };
  for (const [re, name] of BOTS) {
    const m = ua.match(re);
    if (m) return { ...r, browser: name, browserVersion: m[1] ?? null, device: 'bot' };
  }
  if (/\b(bot|crawler|spider)\b|bot\//i.test(ua)) return { ...r, device: 'bot' };

  for (const [re, name] of BROWSERS) {
    const m = ua.match(re);
    if (m) {
      r.browser = name;
      r.browserVersion = m[1] ?? null;
      break;
    }
  }

  let m: RegExpMatchArray | null;
  if ((m = ua.match(/(?:iPhone|CPU) OS (\d+(?:_\d+)*)/))) {
    r.os = /iPad/.test(ua) ? 'iPadOS' : 'iOS';
    r.osVersion = m[1]!.replace(/_/g, '.');
    // Since iOS 26 the OS token is frozen at 18_6; Safari's Version/ token still carries the real release.
    const safari = ua.match(/Version\/(\d+(?:\.\d+)*)/);
    if (r.osVersion.startsWith('18.6') && safari && Number(safari[1]!.split('.')[0]) >= 26) r.osVersion = safari[1]!;
  } else if ((m = ua.match(/Android (\d+(?:\.\d+)*)/))) {
    r.os = 'Android';
    r.osVersion = m[1]!;
  } else if ((m = ua.match(/Windows NT (\d+\.\d+)/))) {
    r.os = 'Windows';
    r.osVersion = ({ '10.0': '10 or 11', '6.3': '8.1', '6.2': '8', '6.1': '7' } as Record<string, string>)[m[1]!] ?? `NT ${m[1]}`;
  } else if (/Android/.test(ua)) {
    r.os = 'Android';
  } else if ((m = ua.match(/Mac OS X (\d+(?:[_.]\d+)*)/))) {
    r.os = 'macOS';
    // Safari, Chrome and Firefox freeze the version at 10.15(.7) on every newer macOS.
    // iPadOS Safari in desktop mode sends the same string; only scripts can tell them apart.
    r.osVersion = m[1]!.replace(/_/g, '.');
    if (/^10\.15(\.7)?$/.test(r.osVersion)) r.osVersion = '10.15 or later';
  } else if (/CrOS/.test(ua)) {
    r.os = 'ChromeOS';
  } else if (/Linux/.test(ua)) {
    r.os = 'Linux';
  }

  // On iOS and iPadOS every browser uses WebKit.
  r.engine = r.os === 'iOS' || r.os === 'iPadOS' ? 'WebKit'
    : /Gecko\/\d/.test(ua) && /Firefox\//.test(ua) ? 'Gecko'
    : /Edge\/\d/.test(ua) ? 'EdgeHTML'
    : /Presto\//.test(ua) ? 'Presto'
    : /Trident\//.test(ua) ? 'Trident'
    : /Chrome\//.test(ua) ? 'Blink'
    : /AppleWebKit\//.test(ua) ? 'WebKit'
    : null;

  r.device = /iPad|Tablet(?! PC)/.test(ua) || (/Android/.test(ua) && !/Mobile/.test(ua)) ? 'tablet'
    : /Mobi|iPhone|iPod/.test(ua) ? 'mobile'
    : r.os ? 'desktop'
    : 'unknown';
  return r;
}

const HINTS = ['sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform'];
const MAX_UA = 1024;

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/user-agent">
<div class="field grow"><label for="ua">User agent string</label>
<input id="ua" name="ua" type="text" value="${value}" placeholder="Mozilla/5.0 (...)" autocapitalize="off" autocomplete="off" spellcheck="false" maxlength="${MAX_UA}"></div>
<div class="field"><button type="submit">Parse</button></div>
</form>`;
}

const dash = (v: string | null | undefined) => v || '—';

function parsedRows(p: ParsedUa): SafeHtml {
  return html`<tr><th scope="row">Browser</th><td>${p.browser ? `${p.browser}${p.browserVersion ? ` ${p.browserVersion}` : ''}` : '—'}</td></tr>
<tr><th scope="row">Rendering engine</th><td>${dash(p.engine)}</td></tr>
<tr><th scope="row">Operating system</th><td>${p.os ? `${p.os}${p.osVersion ? ` ${p.osVersion}` : ''}` : '—'}</td></tr>
<tr><th scope="row">Device type</th><td>${p.device}</td></tr>`;
}

function own(c: ToolContext): SafeHtml {
  const ua = c.req.headers.get('user-agent') ?? '';
  const p = parseUa(ua);
  const h = (name: string) => c.req.headers.get(name);
  const cf = c.req.cf as IncomingRequestCfProperties | undefined;
  const hints = HINTS.filter((k) => h(k));
  return html`<div class="ip-hero">
<span class="label">Your user agent</span>
<div class="ip-line"><code class="ua-string">${ua || '(none sent)'}</code>
${ua ? html`<button type="button" class="btn-small" data-copy="${ua}">Copy</button>` : ''}</div>
</div>
<table class="kv compact"><tbody>
${parsedRows(p)}
<tr><th scope="row">Languages</th><td>${dash(h('accept-language'))}</td></tr>
<tr><th scope="row">Compression</th><td>${dash(h('accept-encoding'))}</td></tr>
<tr><th scope="row">Do Not Track / GPC</th><td>${h('dnt') === '1' ? 'DNT on' : 'DNT off'} · ${h('sec-gpc') === '1' ? 'GPC on' : 'GPC off'}</td></tr>
<tr><th scope="row">Connection</th><td>${dash(typeof cf?.httpProtocol === 'string' ? cf.httpProtocol : null)}${typeof cf?.tlsVersion === 'string' ? ` · ${cf.tlsVersion}` : ''}</td></tr>
${hints.map((k) => html`<tr><th scope="row"><code>${k}</code></th><td class="wrap-any"><code>${h(k)}</code></td></tr>`)}
</tbody></table>
<h2>What your browser reports to scripts</h2>
<table class="kv compact" data-browser-info><tbody>
<tr><th scope="row">JavaScript</th><td data-k="js">disabled</td></tr>
<tr><th scope="row">Cookies</th><td data-k="cookies">—</td></tr>
<tr><th scope="row">Screen</th><td data-k="screen">—</td></tr>
<tr><th scope="row">Window</th><td data-k="viewport">—</td></tr>
<tr><th scope="row">Pixel ratio</th><td data-k="dpr">—</td></tr>
<tr><th scope="row">Time zone</th><td data-k="tz">—</td></tr>
<tr><th scope="row">Languages</th><td data-k="langs">—</td></tr>
<tr><th scope="row">Color scheme</th><td data-k="scheme">—</td></tr>
<tr><th scope="row">Touch</th><td data-k="touch">—</td></tr>
<tr><th scope="row">Platform (client hints)</th><td data-k="platform">—</td></tr>
</tbody></table>
<p class="hint">Read in your browser and shown only to you. Not stored by us (apart from Cloudflare’s technical logs, see the privacy notice).</p>`;
}

const tool: Tool = {
  slug: 'user-agent',
  name: 'What is my user agent',
  icon: 'browser',
  category: 'ip',
  title: 'What Is My User Agent? – Browser, OS & Client Hints',
  description: 'See the user agent string your browser sends, which browser, engine and operating system it reveals, client hints, screen size and time zone.',
  h1: 'What is my user agent?',
  lead: 'The user agent string your browser sends, what it reveals, and what scripts can read on top of it.',
  personal: true,
  script: 'user-agent.js',
  examples: [
    ['iPhone Safari', `ua=${encodeURIComponent('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1')}`],
    ['Googlebot', `ua=${encodeURIComponent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')}`],
  ],
  related: ['what-is-my-ip', 'http-headers', 'robots-txt'],
  isQuery: (url) => url.searchParams.has('ua'),

  render(c) {
    if (!c.url.searchParams.has('ua')) return html`${own(c)}<h2>Parse a user agent string</h2>${form('')}`;
    const value = (c.url.searchParams.get('ua') ?? '').trim().slice(0, MAX_UA);
    if (!value) return html`${form('')}<p class="error">Paste a user agent string.</p>`;
    return html`${form(value)}
<p class="result-head">Parsed user agent</p>
<pre class="raw">${value}</pre>
<table class="kv compact"><tbody>${parsedRows(parseUa(value))}</tbody></table>
<p class="hint">User agent strings are reduced and partly frozen by modern browsers, so versions and operating systems can be approximate.</p>`;
  },

  apiDoc: 'GET /api/user-agent (your own); GET /api/user-agent?ua=Mozilla/5.0... (parse any string)',

  async api(c) {
    const given = c.url.searchParams.get('ua');
    const ua = (given ?? c.req.headers.get('user-agent') ?? '').slice(0, MAX_UA);
    if (given !== null && !given.trim()) return json({ error: 'Paste a user agent string.' }, { status: 400 });
    return json({ userAgent: ua, ...parseUa(ua) }, { headers: { 'cache-control': 'private, no-store' } });
  },

  article: html`<h2>What a user agent string is</h2>
<p>Every HTTP request from a browser carries a <code>User-Agent</code> header. It names the client software so that
servers can adapt their response or log who visited. Browsers, crawlers, command-line tools and libraries all send
one, and most of them let you change it.</p>
<p>Almost every browser string starts with <code>Mozilla/5.0</code>. That is history, not information: in the 1990s
some sites sent frames and other features only to Netscape Navigator (code name Mozilla), so Internet Explorer
began calling itself "Mozilla compatible" to get the same pages. Later browsers copied the tokens of whatever came
before them, which is why Chrome claims to be Safari and every WebKit or Blink browser says "like Gecko".</p>

<h2>Anatomy of a user agent</h2>
<p>Chrome on Windows sends a string like this (the version number changes every four weeks):</p>
<pre class="raw">Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36</pre>
<table class="data">
<thead><tr><th>Token</th><th>Meaning</th></tr></thead>
<tbody>
<tr><td><code>Mozilla/5.0</code></td><td>Compatibility token, sent by nearly all browsers.</td></tr>
<tr><td><code>Windows NT 10.0; Win64; x64</code></td><td>Platform: Windows, 64-bit. The same value is sent on Windows 10 and Windows 11.</td></tr>
<tr><td><code>AppleWebKit/537.36</code></td><td>Engine token. Blink forked from WebKit and kept this value frozen.</td></tr>
<tr><td><code>(KHTML, like Gecko)</code></td><td>WebKit started as a fork of KDE's KHTML; "like Gecko" claims Firefox compatibility.</td></tr>
<tr><td><code>Chrome/141.0.0.0</code></td><td>The actual browser and its major version. Minor, build and patch are zeros.</td></tr>
<tr><td><code>Safari/537.36</code></td><td>Compatibility token for sites that only checked for Safari.</td></tr>
</tbody>
</table>
<p>Edge, Opera and other Chromium browsers append their own token, such as <code>Edg/130.0.0.0</code> or
<code>OPR/</code>. A parser therefore has to check for those before it checks for <code>Chrome/</code>, and for
<code>Chrome/</code> before <code>Safari/</code>.</p>

<h2>Reduced and frozen values</h2>
<p>To limit the information sent to every server, Chromium-based browsers send a reduced user agent. Several parts
no longer change:</p>
<ul>
<li><strong>Windows:</strong> always <code>Windows NT 10.0</code>. This is why the tool shows "10 or 11"; the string
cannot tell them apart. Firefox does the same.</li>
<li><strong>macOS:</strong> Chrome and Safari report <code>Intel Mac OS X 10_15_7</code> on every newer macOS release,
including Macs with Apple silicon. Firefox reports <code>10.15</code>.</li>
<li><strong>Android:</strong> the reduced string contains <code>Android 10; K</code> regardless of the real Android
version, and the device model is replaced by the letter K.</li>
<li><strong>Browser version:</strong> only the major version is real, the rest is <code>.0.0.0</code>.</li>
</ul>
<p>On iPadOS, Safari requests desktop sites by default and sends a macOS user agent, so an iPad often appears as a Mac.</p>

<h2>User-Agent Client Hints</h2>
<p>Chromium browsers moved the detailed information into User-Agent Client Hints. Over HTTPS, they send three
low-entropy hints with every request:</p>
<ul>
<li><code>Sec-CH-UA</code>: brand list with major versions, including a deliberately fake brand such as
<code>"Not A(Brand"</code> so that servers do not depend on an exact list.</li>
<li><code>Sec-CH-UA-Mobile</code>: <code>?1</code> on mobile devices, <code>?0</code> otherwise.</li>
<li><code>Sec-CH-UA-Platform</code>: the operating system name, for example <code>"Windows"</code>.</li>
</ul>
<p>Detailed values such as the platform version, device model, CPU architecture and full browser version are
high-entropy hints. A server has to ask for them with the <code>Accept-CH</code> response header, and scripts can
read them with <code>navigator.userAgentData.getHighEntropyValues()</code>. This page does the latter, which is how
it can show the real platform version. On Windows, a platform version of 13 or higher means Windows 11. Firefox and
Safari do not support client hints.</p>

<h2>Engines on iOS</h2>
<p>Outside the EU and Japan, Apple requires browsers on iOS and iPadOS to use WebKit, and most still do so everywhere. Chrome (<code>CriOS</code>), Firefox
(<code>FxiOS</code>) and Edge (<code>EdgiOS</code>) on an iPhone are WebKit browsers with their own interface, so
the tool reports WebKit for all of them.</p>

<h2>Do not rely on user agent sniffing</h2>
<p>Because the string is freely editable, partly frozen and full of compatibility tokens, it is a poor basis for
decisions. Check for the feature you need instead (<code>'serviceWorker' in navigator</code>, CSS
<code>@supports</code>), and use the user agent only for statistics and debugging. For bots the same applies: anyone
can send <code>Googlebot</code> in the header. Verify a crawler by looking up the
<a href="/reverse-dns-lookup">reverse DNS</a> of its IP address, checking that the name belongs to the search
engine (for example <code>googlebot.com</code>), and confirming that the forward lookup of that name returns the same
address. Rules for well-behaved crawlers belong in <a href="/robots-txt">robots.txt</a>.</p>

<h2>Fingerprinting and privacy</h2>
<p>The user agent alone rarely identifies a person. Combined with screen size, pixel ratio, time zone, languages,
installed fonts and similar values, it can make a browser stand out among many others. That is why browsers reduce
the string and why the second table on this page exists: it shows what any script can read without asking.</p>
<p>The <code>DNT</code> (Do Not Track) header never gained real support from websites, and the W3C stopped work on
it. Global Privacy Control (<code>Sec-GPC: 1</code>) is the newer signal. It is supported by Firefox, Brave and
DuckDuckGo, among others, and California treats it as a valid request to opt out of the sale of personal data.</p>

<h2>Changing your user agent</h2>
<ul>
<li><strong>Chrome and Edge:</strong> DevTools, More tools, Network conditions, then uncheck "Use browser default".
Device emulation (<kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>M</kbd>) also switches to a mobile string.</li>
<li><strong>Firefox:</strong> Responsive Design Mode lets you set a custom user agent.</li>
<li><strong>Command line:</strong> <code>curl -A "Mozilla/5.0 ..." https://example.com</code> or
<code>wget --user-agent="..."</code>.</li>
</ul>
<p>To see the full set of headers a server sends back for a given request, use the
<a href="/http-headers">HTTP headers check</a>.</p>`,

  faq: [
    {
      q: 'Why does it say Windows 10 or 11?',
      a: 'Browsers send "Windows NT 10.0" on both Windows 10 and Windows 11, so the user agent string cannot tell them apart. Chromium browsers expose the real platform version through client hints, where a version of 13 or higher means Windows 11.',
    },
    {
      q: 'Why does every browser claim to be Mozilla?',
      a: 'In the 1990s some sites served advanced features only to Netscape, whose code name was Mozilla. Other browsers copied the token to get the same pages, and it has stayed for compatibility.',
    },
    {
      q: 'Why does my iPad show up as a Mac?',
      a: 'Safari on iPadOS requests desktop websites by default and sends a macOS user agent. You can switch to the mobile version per site in Safari’s settings.',
    },
    {
      q: 'Is my browser version shown correctly?',
      a: 'The major version is correct. Chromium-based browsers replace minor, build and patch numbers with zeros in the user agent string, and the full version is only available through client hints.',
    },
    {
      q: 'Can a website identify me by my user agent?',
      a: 'Not by the user agent alone, since millions of people send the same string. Combined with screen size, time zone, languages and other values it can contribute to a browser fingerprint.',
    },
    {
      q: 'How do I check a user agent from my server logs?',
      a: 'Paste it into the field on this page, or call /api/user-agent?ua= with the URL-encoded string. The tool shows browser, engine, operating system and device type.',
    },
  ],
};

export default tool;
