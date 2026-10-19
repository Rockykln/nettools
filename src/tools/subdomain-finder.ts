import { readJsonCapped } from '../core/body';
import { cachedJson } from '../core/cache';
import { html, type SafeHtml } from '../core/html';
import { openLink } from '../core/ui';
import { json } from '../core/http';
import { normalizeDomain } from '../core/net';
import type { Tool } from '../core/tool';

const MAX_BYTES = 5 * 1024 * 1024;
// Error message thrown by readJsonCapped for oversized bodies.
const TOO_LARGE = 'Response too large';

export interface CtEntry {
  issuer_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
}

export interface Host {
  name: string;
  wildcard: boolean;
  certificates: number;
  firstSeen: string;
  validUntil: string;
  issuer: string;
}

interface Report {
  domain: string;
  includeExpired: boolean;
  hosts: Host[];
}

const issuerOrg = (dn: string) => dn.match(/O=("([^"]+)"|[^,]+)/)?.[2] ?? dn.match(/O=([^,]+)/)?.[1] ?? dn;

// Host names and wildcards only; crt.sh also lists email addresses and other identities.
const HOST_NAME = /^(\*\.)?[a-z0-9_-]+(\.[a-z0-9_-]+)*$/;

/** Groups crt.sh entries by host name, keeping only names under `domain`. */
export function collectHosts(domain: string, entries: CtEntry[]): Host[] {
  const hosts = new Map<string, Host>();
  for (const e of entries) {
    // A name can appear twice in one certificate (subject CN and SAN); count it once.
    const names = new Set(String(e.name_value ?? '').split('\n').map((raw) => raw.trim().toLowerCase().replace(/\.$/, '')));
    for (const name of names) {
      if (!name || !HOST_NAME.test(name) || !(name === domain || name.endsWith(`.${domain}`))) continue;
      const h = hosts.get(name);
      if (!h) {
        hosts.set(name, { name, wildcard: name.startsWith('*.'), certificates: 1, firstSeen: e.not_before, validUntil: e.not_after, issuer: issuerOrg(String(e.issuer_name ?? '')) });
        continue;
      }
      h.certificates++;
      if (e.not_before < h.firstSeen) h.firstSeen = e.not_before;
      if (e.not_after > h.validUntil) { h.validUntil = e.not_after; h.issuer = issuerOrg(String(e.issuer_name ?? '')); }
    }
  }
  return [...hosts.values()].sort((a, b) => Number(a.wildcard) - Number(b.wildcard) || a.name.localeCompare(b.name));
}

async function search(domain: string, includeExpired: boolean): Promise<Report> {
  // An empty answer is cached briefly: crt.sh sometimes returns [] while its database is overloaded.
  return cachedJson(`ct2:${domain}:${includeExpired ? 1 : 0}`, (r) => (r.hosts.length ? 6 * 3600 : 600), async () => {
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json&deduplicate=Y${includeExpired ? '' : '&exclude=expired'}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(25000), headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error(`crt.sh returned HTTP ${res.status}`);
    const entries = await readJsonCapped<unknown>(res, MAX_BYTES);
    if (!Array.isArray(entries)) throw new Error('crt.sh returned an unexpected answer');
    return { domain, includeExpired, hosts: collectHosts(domain, entries as CtEntry[]) };
  });
}

function form(value: string, expired: boolean): SafeHtml {
  return html`<form class="tool-form" method="get" action="/subdomain-finder">
<div class="field grow"><label for="domain">Domain</label>
<input id="domain" name="domain" type="text" value="${value}" placeholder="example.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field checkbox"><label><input type="checkbox" name="expired" value="1"${expired ? html` checked` : ''}> Include expired certificates</label></div>
<div class="field"><button type="submit">Find subdomains</button></div>
</form>`;
}

const day = (s: string) => s.slice(0, 10);
const INVALID = 'Enter a domain such as example.com.';

const tool: Tool = {
  slug: 'subdomain-finder',
  name: 'Subdomain finder',
  icon: 'cert',
  category: 'domain',
  title: 'Subdomain Finder – Certificate Transparency Search',
  description:
    'Find subdomains of any domain from public Certificate Transparency logs: every host name that ever got a TLS certificate, with issuer and validity dates.',
  h1: 'Subdomain finder',
  lead: 'List the host names of a domain that appear in public TLS certificates, from Certificate Transparency logs.',
  examples: [['github.com', 'domain=github.com']],
  related: ['dns-lookup', 'whois', 'http-headers'],
  heavy: () => true,
  isQuery: (url) => url.searchParams.has('domain'),

  async render(c) {
    const value = (c.url.searchParams.get('domain') ?? '').trim();
    const expired = c.url.searchParams.get('expired') === '1';
    if (!c.url.searchParams.has('domain')) return form('', false);
    const domain = normalizeDomain(value)?.replace(/^www\./, '');
    if (!domain?.includes('.')) return html`${form(value, expired)}<p class="error">${INVALID}</p>`;
    let r: Report;
    try {
      r = await search(domain, expired);
    } catch (e) {
      const msg = e instanceof Error && e.message === TOO_LARGE
        ? 'This domain has too many certificates to list here. Try a more specific subdomain.'
        : 'The Certificate Transparency search (crt.sh) is slow or unavailable right now. Please try again in a minute.';
      return html`${form(value, expired)}<p class="error">${msg}</p>`;
    }
    const plain = r.hosts.filter((h) => !h.wildcard);
    const list = plain.map((h) => h.name).join('\n');
    return html`${form(value, expired)}
<p class="result-head"><strong>${plain.length}</strong> host name${plain.length === 1 ? '' : 's'} and ${r.hosts.length - plain.length} wildcard${r.hosts.length - plain.length === 1 ? '' : 's'} found for <code>${domain}</code>${expired ? '' : ' (current certificates only)'}
${plain.length ? html`<button type="button" class="btn-small" data-copy="${list}">Copy list</button>` : ''}</p>
${r.hosts.length ? html`<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>Host name</th><th>Certificates</th><th>First seen</th><th>Valid until</th><th>Issuer</th></tr></thead>
<tbody>${r.hosts.map((h) => html`<tr><td class="wrap-any">${h.wildcard ? html`<code>${h.name}</code>` : html`<a href="/dns-lookup?name=${encodeURIComponent(h.name)}" title="DNS lookup"><code>${h.name}</code></a>${openLink(`https://${h.name}/`)}`}</td><td>${h.certificates}</td><td>${day(h.firstSeen)}</td><td>${day(h.validUntil)}</td><td>${h.issuer}</td></tr>`)}</tbody></table></div>`
      : html`<p class="muted">No certificates found.${expired ? '' : ' Try including expired certificates.'}</p>`}`;
  },

  apiDoc: 'GET /api/subdomain-finder?domain=example.com&expired=1 (expired is optional)',

  async api(c) {
    const domain = normalizeDomain(c.url.searchParams.get('domain') ?? '')?.replace(/^www\./, '');
    if (!domain?.includes('.')) return json({ error: INVALID }, { status: 400 });
    try {
      return json(await search(domain, c.url.searchParams.get('expired') === '1'));
    } catch (e) {
      if (e instanceof Error && e.message === TOO_LARGE) {
        return json({ error: 'This domain has too many certificates to list. Try a more specific subdomain.' }, { status: 502 });
      }
      return json({ error: 'Certificate Transparency search is unavailable right now.' }, { status: 502 });
    }
  },

  article: html`<h2>How it works</h2>
<p>Every publicly trusted TLS certificate is recorded in Certificate Transparency (CT) logs. CT is defined in RFC 6962 (version 1, the one in use; RFC 9162 defines version 2):
certificate authorities submit each certificate, or a precertificate before issuance, to public append-only logs and
receive signed certificate timestamps (SCTs) in return. Chrome has required SCTs for all newly issued publicly
trusted certificates since April 2018; Safari and, since version 135, desktop Firefox enforce CT as well, so a
certificate that was not logged is rejected by most browsers.</p>
<p>Because the logs are public, the host names in every certificate ever issued for a domain can be searched. This
tool queries <a href="https://crt.sh/" rel="noopener">crt.sh</a>, a search service that indexes the major logs, for
all names ending in your domain, then removes duplicates and groups the results by host name. Wildcard entries such
as <code>*.example.com</code> are counted separately.</p>

<h2>How to use it</h2>
<ol>
<li>Enter the registered domain, for example <code>example.com</code>, without <code>https://</code> or a path.</li>
<li>By default, only certificates that are still valid are included. This shows names that are most likely in use
today.</li>
<li>Tick <em>Include expired certificates</em> to search the full history. This finds old staging systems,
retired products and names that were used years ago.</li>
<li>Check the interesting names in DNS. A <a href="/dns-lookup">DNS lookup</a> shows whether a name still resolves
and where it points.</li>
</ol>
<p>Results are cached for six hours. A certificate issued a few minutes ago may also take some time to appear in
crt.sh, because logs have a maximum merge delay and crt.sh needs to import new entries.</p>

<h2>What it finds and what it does not</h2>
<table class="data">
<thead><tr><th>Found</th><th>Not found</th></tr></thead>
<tbody>
<tr><td>Every name that appeared in a publicly trusted certificate, including the subject alternative names</td><td>Names that never had a certificate, for example internal hosts reached over plain HTTP</td></tr>
<tr><td>Staging, test and internal systems that use public certificates</td><td>Names covered only by a wildcard certificate</td></tr>
<tr><td>Names from certificates that have since expired (with the option enabled)</td><td>Names that use certificates from a private certificate authority</td></tr>
<tr><td>Names in certificates issued by any public CA, not only by your usual one</td><td>DNS records without TLS, such as most <code>MX</code> or <code>TXT</code>-only names</td></tr>
</tbody>
</table>
<p>A listed name does not have to exist today, and a missing name may still exist. CT search shows what was
certified, not what is in your DNS zone.</p>

<h2>Searching CT logs on the command line</h2>
<p>crt.sh offers a JSON output that you can process with <code>jq</code>. The <code>%</code> wildcard is written as
<code>%25</code> in the URL:</p>
<pre class="raw">curl -s "https://crt.sh/?q=%25.example.com&amp;output=json" | jq -r '.[].name_value' | sort -u</pre>
<p>Large domains can return tens of thousands of entries and the request may time out. Adding
<code>&amp;exclude=expired</code> limits the search to valid certificates, which is what this tool does by default.</p>

<h2>Reading the results</h2>
<p>Names are listed in lower case, one per row. A name such as <code>www.example.com</code> often appears in dozens
of certificates because it is renewed every few months; the tool shows it once. Typical patterns tell you a lot
about an organization: <code>mail</code>, <code>autodiscover</code> and <code>webmail</code> point to email
services, <code>vpn</code> or <code>remote</code> to remote access, and names with <code>dev</code>,
<code>test</code> or <code>staging</code> to development systems.</p>

<h2>Other ways subdomains become known</h2>
<ul>
<li><strong>DNS brute force:</strong> tools try common names such as <code>www</code>, <code>mail</code>,
<code>vpn</code> or <code>dev</code> and see which ones resolve. Anything with a guessable name should be expected
to be found.</li>
<li><strong>Zone transfers:</strong> a name server that allows <code>AXFR</code> to anyone hands out the whole zone.
Test your own servers with <code>dig @ns1.example.com example.com AXFR</code>; the answer should be refused.</li>
<li><strong>NSEC zone walking:</strong> zones signed with DNSSEC using NSEC records can be enumerated by following the
chain of NSEC records. NSEC3 makes this much harder. To see which method a zone uses, query a name that does not exist, for example
<code>dig +dnssec doesnotexist.example.com</code>, and look for NSEC or NSEC3 records in the authority section.</li>
<li><strong>Passive DNS and web crawlers:</strong> commercial databases record names seen in DNS traffic and links.</li>
</ul>

<h2>Using the results for security</h2>
<p>For administrators, a CT search is a quick inventory of what your organization has exposed. Work through the
list:</p>
<ol>
<li><strong>Unknown names:</strong> find out who requested the certificate. Unexpected names can point to shadow IT
or to a certificate issued by mistake.</li>
<li><strong>Dangling DNS records:</strong> if a name still has a <code>CNAME</code> to a cloud service, storage
bucket or hosting platform that was deleted, someone else may be able to claim that resource and serve content
under your domain. This is called subdomain takeover. Remove DNS records for services you no longer use.</li>
<li><strong>Exposed admin and test systems:</strong> check which names answer and what they show. The
<a href="/port-checker">open port checker</a> tests individual ports, and the <a href="/http-headers">HTTP headers
check</a> shows what a web server reveals about itself.</li>
<li><strong>Unexpected certificate authorities:</strong> publish a <code>CAA</code> record to limit which CAs may
issue certificates for your domain, for example <code>example.com. CAA 0 issue "letsencrypt.org"</code>.</li>
</ol>

<h2>Keeping names private</h2>
<p>If host names should not become public, use a wildcard certificate for them or a certificate from a private
certificate authority that is trusted only inside your organization. Once a certificate is logged, its names stay in
the logs permanently; revoking the certificate does not remove the entry. Do not put confidential information such
as customer or project names into host names that need public certificates.</p>

<h2>Troubleshooting</h2>
<ul>
<li><strong>No results:</strong> enable expired certificates. Small domains may have only one certificate for
<code>www</code> and the bare domain.</li>
<li><strong>Error or timeout:</strong> crt.sh is a free service and is sometimes slow or overloaded. Wait a minute
and try again.</li>
<li><strong>Only wildcards:</strong> the domain uses a wildcard certificate, so individual names are not logged.</li>
<li><strong>A new certificate is missing:</strong> it can take a while to be imported, and cached results can be up
to six hours old.</li>
</ul>`,

  faq: [
    { q: 'Is it legal to search for subdomains?', a: 'Yes. Certificate Transparency logs are public by design, so that anyone can monitor which certificates exist for a domain. Probing or attacking the systems you find is a different matter and needs the owner\'s permission.' },
    { q: 'Why does the search take several seconds?', a: 'crt.sh searches billions of log entries. Results are cached here for six hours, so repeated searches for the same domain are fast.' },
    { q: 'Why are some subdomains I know missing?', a: 'Only names that appeared in a publicly trusted certificate are found. Names covered by a wildcard certificate, names using a private CA and names without TLS do not appear in CT logs.' },
    { q: 'Can I remove a subdomain from Certificate Transparency logs?', a: 'No. CT logs are append-only, and entries stay even after the certificate expires or is revoked. To keep future names private, use a wildcard certificate or a private certificate authority.' },
    { q: 'What is the difference between current and expired results?', a: 'By default only certificates that are still valid are searched, which reflects names likely in use today. Including expired certificates shows the full history, including systems that may have been shut down.' },
    { q: 'How can I be notified about new certificates for my domain?', a: 'Set a CAA record to limit which certificate authorities may issue for your domain, and use a CT monitoring service to get alerts when a new certificate appears.' },
  ],
};

export default tool;
