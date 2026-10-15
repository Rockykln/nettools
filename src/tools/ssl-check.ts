import { connect } from 'cloudflare:sockets';
import { readJsonCapped } from '../core/body';
import { cachedJson } from '../core/cache';
import { checkTarget, isCloudflareAddress } from '../core/guard';
import { html, type SafeHtml } from '../core/html';
import { json } from '../core/http';
import { fetchChain } from '../core/http-probe';
import { normalizeDomain, socketHost } from '../core/net';
import type { Tool, ToolContext } from '../core/tool';
import { withTimeout } from '../core/transport';

interface Cert {
  issuer: string;
  notBefore: string;
  notAfter: string;
  names: string[];
}

interface Report {
  host: string;
  /** Behind Cloudflare: Workers cannot open sockets there, so reachability comes from an HTTPS request and validity from CT logs. */
  cloudflare: boolean;
  tcp: boolean;
  tls: boolean;
  tlsMs: number | null;
  redirectsToHttps: boolean | null;
  certs: Cert[] | null;
}

async function opens(host: string, tls: boolean): Promise<number | null> {
  const start = Date.now();
  const s = connect({ hostname: socketHost(host), port: 443 }, { secureTransport: tls ? 'on' : 'off', allowHalfOpen: false });
  try {
    await withTimeout(s.opened, 8000);
    return Date.now() - start;
  } catch {
    return null;
  } finally {
    s.close().catch(() => {});
  }
}

// Current certificates for exactly this host name from Certificate Transparency:
// Cert Spotter (SSLMate) first, crt.sh as fallback, which is often slow for large domains.
async function ctCerts(host: string): Promise<Cert[] | null> {
  // A failed lookup (null) is not cached, so a short outage does not stick for an hour.
  return cachedJson(`ctssl:${host}`, (v) => (v ? 3600 : 0), async () => (await certSpotter(host)) ?? (await crtSh(host)));
}

async function certSpotter(host: string): Promise<Cert[] | null> {
  try {
    const res = await fetch(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(host)}&expand=dns_names&expand=issuer`, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return null;
    const rows = await readJsonCapped<{ dns_names: string[]; issuer: { friendly_name?: string; name: string }; not_before: string; not_after: string; revoked?: boolean }[]>(res, 2 * 1024 * 1024);
    if (!Array.isArray(rows)) return null;
    const now = Date.now();
    return rows
      .filter((r) => !r.revoked && Date.parse(r.not_after) > now)
      .map((r) => ({
        issuer: r.issuer.friendly_name ?? r.issuer.name.match(/O=([^,]+)/)?.[1] ?? r.issuer.name,
        notBefore: r.not_before.replace(/Z$/, ''),
        notAfter: r.not_after.replace(/Z$/, ''),
        names: r.dns_names.map((n) => n.toLowerCase()),
      }))
      .sort((a, b) => b.notBefore.localeCompare(a.notBefore))
      .slice(0, 8);
  } catch {
    return null;
  }
}

async function crtSh(host: string): Promise<Cert[] | null> {
  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(host)}&output=json&exclude=expired&deduplicate=Y`, { signal: AbortSignal.timeout(12000) });
    if (!res.ok) return null;
    const rows = await readJsonCapped<{ issuer_name: string; not_before: string; not_after: string; name_value: string }[]>(res, 2 * 1024 * 1024);
    return rows
      .map((r) => ({
        issuer: r.issuer_name.match(/O=("([^"]+)"|[^,]+)/)?.[2] ?? r.issuer_name.match(/O=([^,]+)/)?.[1] ?? r.issuer_name,
        notBefore: r.not_before,
        notAfter: r.not_after,
        names: r.name_value.split('\n').map((n) => n.trim().toLowerCase()),
      }))
      .sort((a, b) => b.notBefore.localeCompare(a.notBefore))
      .slice(0, 8);
  } catch {
    return null;
  }
}

// Any HTTP answer over HTTPS means the connection and certificate were accepted.
async function httpsResponds(host: string): Promise<number | null> {
  const start = Date.now();
  try {
    const res = await fetch(`https://${host}/`, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(10000) });
    await res.body?.cancel();
    return Date.now() - start;
  } catch {
    return null;
  }
}

async function check(host: string, env: Env, cloudflare: boolean): Promise<Report> {
  const https = cloudflare ? httpsResponds(host) : null;
  const [tcpMs, tlsMs, chain, certs] = await Promise.all([
    https ?? opens(host, false),
    https ?? opens(host, true),
    fetchChain(`http://${host}/`, env).catch(() => null),
    ctCerts(host),
  ]);
  // A redirect to https counts even if the https hop itself then fails, e.g. with an expired certificate.
  const toHttps = chain?.hops.some((h) => h.status >= 300 && h.status < 400 && !!h.location && /^https:/i.test(new URL(h.location, h.url).href)) ?? false;
  return {
    host,
    cloudflare,
    tcp: tcpMs !== null,
    tls: tlsMs !== null,
    tlsMs,
    redirectsToHttps: toHttps ? true : chain && !chain.error ? false : null,
    certs,
  };
}

const days = (iso: string) => Math.floor((Date.parse(`${iso}Z`) - Date.now()) / 86400000);

const covers = (c: Cert, host: string) => c.names.some((n) => n === host || (n.startsWith('*.') && host.endsWith(n.slice(1)) && !host.slice(0, -n.length + 1).includes('.')));

function verdict(r: Report): SafeHtml {
  if (r.cloudflare) {
    if (!r.tls) return html`<div class="verdict bad"><strong>HTTPS does not answer.</strong> The site is served by Cloudflare, but no HTTPS response came back.</div>`;
    const valid = (r.certs ?? []).filter((c) => covers(c, r.host) && days(c.notAfter) >= 0);
    const left = valid.length ? Math.max(...valid.map((c) => days(c.notAfter))) : null;
    return html`<div class="verdict ${left !== null ? 'ok' : 'warn'}"><strong>${left !== null ? 'HTTPS works and a valid certificate exists.' : 'HTTPS works.'}</strong>
The site is served by Cloudflare, which cannot be reached with a raw TLS handshake from here. The result is based on an HTTPS request
and the certificates logged in Certificate Transparency${left !== null ? html`; the newest one for this name is valid for another <strong>${left} days</strong>` : ', where no current certificate for exactly this name was found'}.</div>`;
  }
  if (!r.tcp) return html`<div class="verdict bad"><strong>Port 443 is not reachable.</strong> The server does not accept HTTPS connections, or a firewall blocks them.</div>`;
  if (!r.tls) {
    return html`<div class="verdict bad"><strong>The TLS handshake failed.</strong> The server answers on port 443, but its certificate was rejected:
it is expired, self-signed, issued for another name, or the chain is incomplete. Browsers will show a security warning.</div>`;
  }
  const newest = r.certs?.length ? Math.max(...r.certs.filter((c) => covers(c, r.host)).map((c) => days(c.notAfter)), -Infinity) : null;
  return html`<div class="verdict ok"><strong>The certificate is valid and trusted.</strong> The TLS handshake succeeded with full chain and host name verification
in ${r.tlsMs} ms.${newest !== null && Number.isFinite(newest) ? html` The newest certificate for this name is valid for another <strong>${newest} days</strong>.` : ''}</div>`;
}

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/ssl-check">
<div class="field grow"><label for="host">Host name</label>
<input id="host" name="host" type="text" value="${value}" placeholder="example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Check certificate</button></div>
</form>`;
}

const INVALID = 'Enter a host name such as example.com.';

function parseHost(raw: string): string | null {
  const h = normalizeDomain(raw);
  return h?.includes('.') ? h : null;
}

const tool: Tool = {
  slug: 'ssl-check',
  name: 'SSL certificate check',
  icon: 'tls',
  category: 'web',
  title: 'SSL Certificate Checker – Validity, Expiry & Issuer',
  description: 'Check whether a site’s SSL/TLS certificate is valid and trusted, when it expires, who issued it and whether HTTP redirects to HTTPS.',
  h1: 'SSL certificate checker',
  lead: 'Check whether a website’s certificate is trusted, when it expires and whether HTTP redirects to HTTPS.',
  heavy: () => true,
  examples: [['github.com', 'host=github.com'], ['expired.badssl.com (broken)', 'host=expired.badssl.com']],
  related: ['caa-lookup', 'http-headers', 'subdomain-finder', 'is-it-down'],
  isQuery: (url) => url.searchParams.has('host'),

  async render(c: ToolContext) {
    const value = (c.url.searchParams.get('host') ?? '').trim();
    if (!c.url.searchParams.has('host')) return form('');
    const host = parseHost(value);
    if (!host) return html`${form(value)}<p class="error">${INVALID}</p>`;
    const target = await checkTarget(host, c.env);
    if (!target.ok) return html`${form(value)}<p class="error">${target.reason}</p>`;
    const r = await check(host, c.env, target.addresses.some(isCloudflareAddress));
    return html`${form(value)}${verdict(r)}
<table class="kv compact"><tbody>
${r.cloudflare ? html`<tr><th scope="row">Hosting</th><td>Cloudflare (handshake checked via HTTPS request)</td></tr>` : ''}
<tr><th scope="row">HTTPS (port 443)</th><td>${r.tcp ? html`<span class="status ok">reachable</span>` : html`<span class="status bad">not reachable</span>`}</td></tr>
<tr><th scope="row">Certificate</th><td>${!r.tcp ? '—' : r.tls ? html`<span class="status ok">${r.cloudflare ? 'accepted' : 'valid'}</span>` : html`<span class="status bad">rejected</span>`}</td></tr>
<tr><th scope="row">HTTP → HTTPS redirect</th><td>${r.redirectsToHttps === null ? '—' : r.redirectsToHttps ? html`<span class="status ok">yes</span>` : html`<span class="status warn">no</span>`}</td></tr>
</tbody></table>
<h2>Certificates issued for ${host}</h2>
${r.certs === null ? html`<p class="muted">Certificate Transparency data is not available right now.</p>`
      : r.certs.length ? html`<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>Issuer</th><th>Valid from</th><th>Valid until</th><th>Days left</th><th>Names</th></tr></thead>
<tbody>${r.certs.map((x) => html`<tr><td>${x.issuer}</td><td>${x.notBefore.slice(0, 10)}</td><td>${x.notAfter.slice(0, 10)}</td><td>${days(x.notAfter) < 14 ? html`<span class="status warn">${days(x.notAfter)}</span>` : days(x.notAfter)}</td><td class="wrap-any">${x.names.slice(0, 4).join(', ')}${x.names.length > 4 ? ` +${x.names.length - 4}` : ''}</td></tr>`)}</tbody></table></div>
<p class="hint">From public Certificate Transparency logs. The server may use any of these; wildcard certificates issued for a parent name may not appear here.</p>`
      : html`<p class="muted">No current certificate was found for exactly this name; it may use a wildcard certificate.</p>`}`;
  },

  apiDoc: 'GET /api/ssl-check?host=github.com',

  async api(c) {
    const host = parseHost(c.url.searchParams.get('host') ?? '');
    if (!host) return json({ error: INVALID }, { status: 400 });
    const target = await checkTarget(host, c.env);
    if (!target.ok) return json({ error: target.reason }, { status: 400 });
    return json(await check(host, c.env, target.addresses.some(isCloudflareAddress)));
  },

  article: html`<h2>What this check does</h2>
<p>A certificate check answers one practical question: will a browser or an API client accept the HTTPS connection to
this host without a warning? Enter a host name such as <code>github.com</code> or <code>your-domain.tld</code>; the tool
runs three tests in parallel.</p>
<ol>
<li>It opens a TCP connection to port 443 and performs a TLS handshake with full verification: the certificate chain
must lead to a trusted root certificate, the certificate must be within its validity dates, and it must cover the host
name you entered (sent as SNI). These are the same checks a browser makes. If the handshake succeeds, the time it took
is shown.</li>
<li>It requests <code>http://</code> for the host, follows the redirects and reports whether the final address uses
HTTPS.</li>
<li>It looks up the current certificates for exactly this host name in public Certificate Transparency logs, using
Cert Spotter by SSLMate first and crt.sh as a fallback. Expired and (where the log source reports it) revoked
certificates are left out. The table shows issuer, validity dates, days left and the names each certificate covers.</li>
</ol>
<p>For sites served by Cloudflare, a raw TLS handshake from this tool is not possible, because it runs on Cloudflare
Workers, which cannot open sockets to Cloudflare's own network. In that case the tool sends an HTTPS request instead
(any answer means the certificate was accepted) and takes the expiry from the Certificate Transparency data. The result
says when this fallback was used.</p>

<h2>What gets verified during the handshake</h2>
<table class="data"><thead><tr><th>Check</th><th>What it means</th></tr></thead><tbody>
<tr><td>Chain of trust</td><td>The server certificate is signed by an intermediate, which is signed by a root certificate in the client's trust store. The server has to send the intermediate itself.</td></tr>
<tr><td>Host name</td><td>The host name must appear in the Subject Alternative Name (SAN) list, either exactly or matched by a wildcard. The Common Name field is ignored by modern clients.</td></tr>
<tr><td>Validity period</td><td>The current time must be between Not Before and Not After.</td></tr>
<tr><td>Key and signature</td><td>The server proves it holds the private key that belongs to the certificate.</td></tr>
</tbody></table>
<p>The check does not report the TLS version or the cipher suite. If the handshake works, a current client can connect
securely, which is what visitors care about.</p>

<h2>Why a certificate is rejected</h2>
<table class="data"><thead><tr><th>Cause</th><th>Typical error</th><th>Fix</th></tr></thead><tbody>
<tr><td>Expired</td><td><code>NET::ERR_CERT_DATE_INVALID</code>, OpenSSL: <code>certificate has expired</code></td><td>Renew it and reload the web server. With ACME clients, find out why automatic renewal did not run (cron or systemd timer, DNS challenge credentials, firewall blocking port 80 for HTTP-01).</td></tr>
<tr><td>Wrong host name</td><td><code>NET::ERR_CERT_COMMON_NAME_INVALID</code></td><td>The certificate must list the exact name or a matching wildcard, for example both <code>example.com</code> and <code>www.example.com</code>. Also check that the server picks the right virtual host for the SNI name.</td></tr>
<tr><td>Incomplete chain</td><td>OpenSSL: <code>unable to verify the first certificate</code></td><td>Configure the full chain (often the <code>fullchain.pem</code> file), not only the site certificate. Browsers sometimes hide this problem because they cache or fetch intermediates; curl, Java, Python and mobile apps do not.</td></tr>
<tr><td>Self-signed or private CA</td><td><code>NET::ERR_CERT_AUTHORITY_INVALID</code>, OpenSSL: <code>self-signed certificate</code></td><td>Use a certificate from a public certificate authority. Self-signed and internal CA certificates only work on clients that trust them explicitly.</td></tr>
</tbody></table>

<h2>Check a certificate from the command line</h2>
<p>OpenSSL shows the same information on any Linux or macOS machine. The <code>-servername</code> option sets SNI; without
it, a server that hosts several sites may return its default certificate instead.</p>
<pre class="raw">$ openssl s_client -connect github.com:443 -servername github.com &lt;/dev/null 2&gt;/dev/null | openssl x509 -noout -subject -issuer -dates
subject=CN=github.com
issuer=C=..., O=(issuing CA), CN=(intermediate name)
notBefore=(issue date) GMT
notAfter=(expiry date) GMT</pre>
<ul>
<li><code>openssl s_client -connect host:443 -servername host -showcerts</code> prints every certificate the server sends,
which shows a missing intermediate immediately. The line <code>Verify return code: 0 (ok)</code> means the chain is fine.</li>
<li><code>openssl x509 -noout -ext subjectAltName</code> (OpenSSL 1.1.1 or later) lists the names a certificate covers.</li>
<li><code>openssl x509 -noout -checkend 1209600</code> returns a non-zero exit code if the certificate expires within
14 days, which is handy for a simple monitoring script.</li>
<li><code>curl -vI https://host/</code> shows the handshake and fails with a clear message if verification does not pass.</li>
</ul>

<h2>Certificate lifetimes are getting shorter</h2>
<p>The CA/Browser Forum adopted ballot SC-081, which lowers the maximum lifetime of public TLS certificates in steps:
200 days from 15 March 2026, 100 days from March 2027 and 47 days from March 2029. Before that, the limit was 398 days.
Manual renewal once a year is therefore no longer an option; certificates have to be renewed automatically.</p>
<p>The standard way to do this is ACME (RFC 8555), the protocol behind Let's Encrypt and supported by several other CAs.
Clients such as certbot, acme.sh, lego or the built-in support in Caddy and Traefik prove control of the domain with an
HTTP-01 challenge (a file under <code>/.well-known/acme-challenge/</code> on port 80) or a DNS-01 challenge (a TXT
record), then renew well before expiry. Let's Encrypt certificates are valid for 90 days, and Let's Encrypt no longer
sends expiry reminder emails, so external monitoring of the expiry date is worth having. To limit which CAs may issue
for your domain at all, publish a CAA record and check it with the <a href="/dns-lookup">DNS lookup</a>.</p>

<h2>Certificate Transparency</h2>
<p>Chrome and Safari only accept publicly trusted certificates that are recorded in public, append-only Certificate
Transparency logs, so in practice CAs log every certificate they issue. That makes the logs a useful data source: you can see every
certificate issued for your names, including ones you did not request. Unexpected issuers in the list can point to a
forgotten service, a second hosting provider or a misissued certificate. New certificates usually appear in the search
services within minutes to hours. To find all host names of a domain that ever had a certificate, use the
<a href="/subdomain-finder">subdomain finder</a>.</p>

<h2>Wildcard certificates</h2>
<p>A wildcard certificate for <code>*.example.com</code> covers exactly one label: it is valid for
<code>www.example.com</code> and <code>api.example.com</code>, but not for <code>example.com</code> itself and not for
<code>a.b.example.com</code>. That is why wildcard certificates usually list the bare domain as a second name. Let's
Encrypt issues wildcards only with the DNS-01 challenge. Because this tool searches the logs for the exact host name, a
host that is served with a parent wildcard certificate may show no entries in the table even though the handshake
succeeds.</p>

<h2>After the certificate</h2>
<p>A valid certificate is only part of a correct HTTPS setup. Plain HTTP should redirect to HTTPS, and the HTTPS
response should send a <code>Strict-Transport-Security</code> header so browsers stop trying HTTP at all. Check that and
the other security headers with the <a href="/http-headers">HTTP header checker</a>. If port 443 does not answer, test
it with the <a href="/port-checker">port checker</a>.</p>`,

  faq: [
    { q: 'Can I see the TLS version and cipher?', a: 'Not with this check. It confirms that a current client can complete a verified handshake and that the certificate is trusted. For protocol details, run openssl s_client -connect host:443 -servername host and read the Protocol and Cipher lines.' },
    { q: 'When should I renew a certificate?', a: 'ACME clients usually renew when about a third of the lifetime is left, which is 30 days for a 90-day certificate. If fewer than 14 days are left and nothing has happened, check your renewal job and its logs.' },
    { q: 'Why is my new certificate not listed yet?', a: 'Certificate Transparency search services need minutes to a few hours to index new certificates, and the results are cached here for up to an hour. The handshake test always reflects the certificate the server presents right now.' },
    { q: 'The site works in my browser, but curl or my app reports a certificate error. Why?', a: 'Most often the server does not send the intermediate certificate. Browsers can sometimes fill the gap from their cache or by downloading the intermediate, while curl, Java, Python and many apps cannot. Configure the full chain file on the server.' },
    { q: 'Does a wildcard certificate cover the bare domain?', a: 'No. *.example.com matches one label, such as www.example.com, but neither example.com nor a.b.example.com. Add the bare domain as an additional name on the certificate.' },
    { q: 'Why does the result say the site is served by Cloudflare?', a: 'This tool runs on Cloudflare’s network, which cannot open raw TLS connections to sites behind Cloudflare. For those hosts it checks HTTPS with a normal request and reads the expiry date from Certificate Transparency logs instead.' },
  ],
};

export default tool;
