import { mapLimit } from '../core/async';
import { cachedJson } from '../core/cache';
import { html, type SafeHtml } from '../core/html';
import { openLink } from '../core/ui';
import { json } from '../core/http';
import { normalizeDomain } from '../core/net';
import type { Tool } from '../core/tool';
import { lookup, whoisNotFound, type Lookup } from './whois';

const POPULAR_TLDS = ['com', 'net', 'org', 'io', 'dev', 'app', 'co', 'ai', 'de', 'eu', 'xyz', 'me'];

type Status = 'available' | 'taken' | 'unknown';

interface Check {
  domain: string;
  status: Status;
  registrar: string | null;
  expires: string | null;
  note: string | null;
}

function vcardName(entity: Record<string, any> | undefined): string | null {
  const props: unknown[] = entity?.vcardArray?.[1] ?? [];
  const fn = props.find((p) => Array.isArray(p) && p[0] === 'fn') as unknown[] | undefined;
  return typeof fn?.[3] === 'string' && fn[3].trim() ? fn[3].trim() : null;
}

function findEntity(entities: Record<string, any>[] | undefined, role: string): Record<string, any> | undefined {
  for (const e of entities ?? []) {
    if (e.roles?.includes(role)) return e;
    const nested = findEntity(e.entities, role);
    if (nested) return nested;
  }
  return undefined;
}

// Field names differ between registries; .de and .eu publish neither.
const REGISTRAR = /^\s*(?:registrar|sponsoring registrar|registrar name)\s*:[ \t]*(\S[^\r\n]*)$/im;
const EXPIRY = /^\s*(?:registry expiry date|registrar registration expiration date|expiry date|expiration date|expires(?: on)?|paid-till)\s*:[ \t]*(\S[^\r\n]*)$/im;

function whoisField(text: string, re: RegExp): string | null {
  return text.match(re)?.[1]?.trim() || null;
}

function whoisDate(text: string): string | null {
  const t = Date.parse(whoisField(text, EXPIRY) ?? '');
  return Number.isFinite(t) && t > 0 ? new Date(t).toISOString().slice(0, 10) : null;
}

export function interpret(domain: string, l: Lookup): Check {
  if (l.notFound) return { domain, status: 'available', registrar: null, expires: null, note: null };
  if (l.whoisText !== null) {
    // Plain WHOIS servers use different wording for unregistered names.
    if (whoisNotFound(l.whoisText)) {
      return { domain, status: 'available', registrar: null, expires: null, note: null };
    }
    return { domain, status: 'taken', registrar: whoisField(l.whoisText, REGISTRAR), expires: whoisDate(l.whoisText), note: null };
  }
  const d = l.rdap!;
  const registrar = vcardName(findEntity(d.entities, 'registrar'));
  const exp = Date.parse(String((d.events ?? []).find((e: Record<string, any>) => e.eventAction === 'expiration')?.eventDate ?? ''));
  // Some registries use the Unix epoch as "unknown".
  const expires = Number.isFinite(exp) && exp > 0 ? new Date(exp).toISOString().slice(0, 10) : null;
  return { domain, status: 'taken', registrar, expires, note: null };
}

async function check(domain: string): Promise<Check> {
  try {
    return interpret(domain, await lookup({ input: domain, kind: 'domain', value: domain }));
  } catch {
    return { domain, status: 'unknown', registrar: null, expires: null, note: 'The registry did not answer.' };
  }
}

// Second-level labels under country code TLDs, e.g. example.co.uk.
const GENERIC_SLDS = new Set(['co', 'com', 'net', 'org', 'ac', 'edu', 'gov', 'ltd', 'plc', 'ne', 'or', 'go', 'gv', 'nom']);

// "example" checks popular TLDs; "www.example.co.uk" checks that domain first, then the same name on other TLDs.
export function candidates(input: string): { name: string; domains: string[] } | null {
  const domain = normalizeDomain(input.trim());
  if (!domain) return null;
  // Underscores are allowed in DNS names but not in registrable domains.
  if (domain.includes('_')) return null;
  const labels = domain.replace(/^www\./, '').split('.');
  if (labels.length === 1) {
    const name = labels[0]!;
    if (name.startsWith('-') || name.endsWith('-')) return null;
    return { name, domains: POPULAR_TLDS.map((t) => `${name}.${t}`) };
  }
  const tld = labels[labels.length - 1]!;
  if (/^\d+$/.test(tld)) return null;
  const sldIsGeneric = tld.length === 2 && labels.length >= 3 && GENERIC_SLDS.has(labels[labels.length - 2]!);
  const registered = labels.slice(sldIsGeneric ? -3 : -2).join('.');
  const name = registered.split('.')[0]!;
  const others = POPULAR_TLDS.map((t) => `${name}.${t}`).filter((d) => d !== registered);
  return { name, domains: [registered, ...others].slice(0, POPULAR_TLDS.length) };
}

const LABEL: Record<Status, SafeHtml> = {
  available: html`<span class="status ok">available</span>`,
  taken: html`<span class="status bad">taken</span>`,
  unknown: html`<span class="status info">unknown</span>`,
};

function form(value: string): SafeHtml {
  return html`<form class="tool-form" method="get" action="/domain-availability">
<div class="field grow"><label for="name">Domain or name</label>
<input id="name" name="name" type="text" value="${value}" placeholder="myproject or myproject.com" required autocapitalize="off" autocomplete="off" spellcheck="false"></div>
<div class="field"><button type="submit">Check availability</button></div>
</form>`;
}

const INVALID = 'Enter a name such as myproject, or a domain such as myproject.com.';

// Twelve registry lookups per request; a short cache covers reloads, shared links and HTML/API switches.
// Results with an unanswered registry are not cached, so a retry asks again.
// A Worker keeps at most six connections open; four lookups at a time leave room for bootstrap fetches.
// Registries that did not answer get one more try once the others are done.
async function checkWithRetry(domains: string[]): Promise<Check[]> {
  const out = await mapLimit(domains, 4, check);
  const retry = out.flatMap((c, i) => (c.status === 'unknown' ? [i] : []));
  const again = await mapLimit(retry, 4, (i) => check(domains[i]!));
  retry.forEach((i, k) => { out[i] = again[k]!; });
  return out;
}

const checkAll = (domains: string[]) =>
  cachedJson(`avail:${domains.join(',')}`, (r) => (r.some((c) => c.status === 'unknown') ? 0 : 300), () => checkWithRetry(domains));

const tool: Tool = {
  slug: 'domain-availability',
  name: 'Domain availability',
  icon: 'domain',
  category: 'domain',
  title: 'Domain Name Availability Check – .com, .io, .dev & More',
  description:
    'Check if a domain name is available on .com, .net, .org, .io, .dev, .app, .de and more at once, straight from the registries via RDAP. No sign-up.',
  h1: 'Domain availability check',
  lead: 'Find out whether a domain name is still free, across the most popular endings at once.',
  examples: [['myproject', 'name=myproject']],
  related: ['whois', 'dns-lookup', 'subdomain-finder'],
  heavy: () => true,
  isQuery: (url) => url.searchParams.has('name'),

  async render(c) {
    const value = (c.url.searchParams.get('name') ?? '').trim();
    if (!c.url.searchParams.has('name')) return form('');
    const cand = candidates(value);
    if (!cand) return html`${form(value)}<p class="error">${INVALID}</p>`;
    const results = await checkAll(cand.domains);
    const free = results.filter((r) => r.status === 'available').length;
    return html`${form(value)}
<p class="result-head"><strong>${free}</strong> of ${results.length} checked domains look available for <code>${cand.name}</code></p>
<div class="table-scroll" tabindex="0" role="region" aria-label="Results table"><table class="data"><thead><tr><th>Domain</th><th>Status</th><th>Registrar</th><th>Expires</th><th></th></tr></thead>
<tbody>${results.map((r) => html`<tr><td><code>${r.domain}</code>${r.status === 'taken' ? openLink(`https://${r.domain}/`) : ''}</td><td>${LABEL[r.status]}</td><td>${r.registrar ?? '—'}</td><td>${r.expires ?? '—'}</td>
<td>${r.status === 'taken' ? html`<a href="/whois?q=${encodeURIComponent(r.domain)}">WHOIS</a>` : r.note ?? ''}</td></tr>`)}</tbody></table></div>
<p class="hint">"Available" means the registry has no record of the name. Premium or reserved names can still be unavailable or cost more; your registrar has the final word.</p>`;
  },

  apiDoc: 'GET /api/domain-availability?name=myproject (or name=myproject.com)',

  async api(c) {
    const cand = candidates(c.url.searchParams.get('name') ?? '');
    if (!cand) return json({ error: INVALID }, { status: 400 });
    return json({ name: cand.name, results: await checkAll(cand.domains) });
  },

  article: html`<h2>How the check works</h2>
<p>For every domain, the tool asks the registry responsible for its ending, using RDAP, the modern successor of
WHOIS. The registry is the organization that runs a top-level domain, for example Verisign for <code>.com</code> and
<code>.net</code>. If the registry has no record of the name, it is not registered. For endings whose registry does
not offer RDAP, such as <code>.de</code>, the registry's classic WHOIS service on port 43 is used instead.</p>
<p>Nothing is reserved, stored or passed on to registrars, so checking a name here cannot lead to someone
registering it before you. Some registrar search boxes have been accused of exactly that practice, known as domain
front-running; querying the registry directly avoids the question.</p>

<h2>How to use it</h2>
<ol>
<li>Enter a name without an ending, such as <code>myproject</code>. The tool checks it on 12 popular endings at
once.</li>
<li>Or enter a full domain such as <code>myproject.com</code>. That domain is checked first, followed by the same
name on the other endings.</li>
<li>Read the status column. For taken names, the registrar and expiry date are shown when the registry publishes
them, with a link to the full <a href="/whois">WHOIS and RDAP record</a>.</li>
<li>Register an available name at a registrar of your choice. The check here is not a reservation, so do not wait
long with short or common names.</li>
</ol>

<h2>Endings checked</h2>
<table class="data">
<thead><tr><th>Ending</th><th>Type</th><th>Notes</th></tr></thead>
<tbody>
<tr><td><code>.com</code>, <code>.net</code>, <code>.org</code></td><td>Generic</td><td>The classic endings, open to anyone. <code>.com</code> has by far the most registrations.</td></tr>
<tr><td><code>.dev</code>, <code>.app</code></td><td>Generic</td><td>HSTS preloaded: browsers only connect over HTTPS, so a valid certificate is required from day one.</td></tr>
<tr><td><code>.xyz</code></td><td>Generic</td><td>Low first-year prices, open to anyone.</td></tr>
<tr><td><code>.io</code></td><td>Country code (British Indian Ocean Territory)</td><td>Popular with technology companies.</td></tr>
<tr><td><code>.ai</code></td><td>Country code (Anguilla)</td><td>Popular for AI products; prices are higher than for most endings.</td></tr>
<tr><td><code>.co</code></td><td>Country code (Colombia)</td><td>Marketed internationally as an alternative to <code>.com</code>.</td></tr>
<tr><td><code>.me</code></td><td>Country code (Montenegro)</td><td>Common for personal sites.</td></tr>
<tr><td><code>.de</code></td><td>Country code (Germany)</td><td>Checked through DENIC's WHOIS service.</td></tr>
<tr><td><code>.eu</code></td><td>European Union</td><td>Requires EU or EEA citizenship, residence or an organization established there.</td></tr>
</tbody>
</table>

<h2>What "available" and "taken" mean</h2>
<ul>
<li><strong>Available:</strong> the registry has no record of the name. In most cases you can register it right
away.</li>
<li><strong>Taken:</strong> the name is registered. That includes domains in a grace or redemption period after
expiry, which are still held for the previous owner.</li>
<li><strong>Unknown:</strong> the registry did not answer in time or rate-limited the request. Try again a little
later.</li>
</ul>
<p>"Available" is a strong signal but not a guarantee. Registries reserve some names, for example very short names or
terms they keep for their own use, and these can return "not found" while still being blocked at checkout. Premium
names are registrable but at a much higher price, set by the registry. Your registrar has the final word.</p>

<h2>Checking availability on the command line</h2>
<p>An RDAP server answers with HTTP status 404 for names it has no record of and with 200 for registered names:</p>
<pre class="raw">curl -s -o /dev/null -w "%{http_code}\\n" https://rdap.verisign.com/com/v1/domain/example.com
whois example.com
whois -h whois.denic.de -- "-T dn example.de"</pre>
<p>The first command prints <code>200</code>, because <code>example.com</code> is registered. For a <code>.de</code>
name, DENIC replies with <code>Status: connect</code> for registered names and <code>Status: free</code> for names
that can be registered.</p>

<h2>When a name you want is taken</h2>
<ol>
<li>Look at the <a href="/whois">WHOIS record</a>. A recent registration date and a parking page usually mean a
reseller; an old registration with a working site means an active owner.</li>
<li>Check whether the domain is in use. The <a href="/is-it-down">website status check</a> shows if the site
responds, and an <a href="/mx-lookup">MX lookup</a> shows whether it receives email. A domain that is used only for
email is not abandoned.</li>
<li>Note the expiry date, but do not count on it. Most domains are renewed automatically. If a gTLD domain is not
renewed, it usually passes through an auto-renew grace period of up to 45 days, a 30-day redemption period and
five days of pending delete before it becomes available again.</li>
<li>Try variations: add a verb (<em>get</em>, <em>try</em>, <em>use</em>), a category word or a location, or use a
different ending.</li>
</ol>

<h2>Generic and country code endings</h2>
<p>Generic endings such as <code>.com</code>, <code>.app</code> or <code>.xyz</code> are governed by ICANN contracts,
which set common rules for transfers, expiry and registration data. Country code endings are run by national
registries with their own policies. Some are open to anyone worldwide, such as <code>.io</code> or <code>.co</code>,
others have residency or presence requirements, such as <code>.eu</code>. Prices, renewal costs and transfer rules
differ, so compare the renewal price, not only the first-year offer, before you register.</p>

<h2>Rules for valid domain names</h2>
<ul>
<li>Letters <code>a</code> to <code>z</code>, digits and hyphens. Upper and lower case are the same.</li>
<li>1 to 63 characters per label, and no hyphen at the start or end.</li>
<li>Hyphens in the third and fourth position are reserved for internationalized names, which are stored in the
<code>xn--</code> form.</li>
</ul>

<h2>Tips for finding a free name</h2>
<ul>
<li>Short, pronounceable names on <code>.com</code> are rare. Shorter is not always better: a clear two-word name is
easier to spell over the phone than an invented one.</li>
<li>Avoid names that differ from an existing brand only by a typo or a hyphen. Besides confusing users, they can lead
to a trademark dispute.</li>
<li>Register the same name on the endings you care about, and consider common misspellings if you expect a lot of
traffic.</li>
</ul>

<h2>After registering</h2>
<p>Once you have registered a domain, point it to your name servers and verify the
<a href="/dns-lookup">DNS records</a>. If you plan to send email from it, publish SPF, DKIM and DMARC records and
check them with the <a href="/email-security">email security check</a>. A domain that will never send email should
still publish an SPF record of <code>v=spf1 -all</code> and a DMARC policy of <code>p=reject</code> to make spoofing
harder.</p>`,

  faq: [
    { q: 'Is the result always correct?', a: 'It reflects what the registry reports at the time of the check. Names that were just deleted, premium names and names reserved by the registry can still behave differently at checkout. Your registrar has the final word.' },
    { q: 'Do you store or sell the names I check?', a: 'No. Lookups are not stored and nothing is sent to registrars. Registry answers are cached for up to about an hour for registered names and 15 minutes for unregistered names to reduce load on the registries.' },
    { q: 'Which domain endings are checked?', a: 'Twelve popular endings: .com, .net, .org, .io, .dev, .app, .co, .ai, .de, .eu, .xyz and .me. If you enter a full domain with another ending, that domain is checked first.' },
    { q: 'Why is a domain taken but no website works?', a: 'Many domains are registered without a website, for example to protect a brand, for email only, or to resell them. Use the WHOIS lookup to see the registrar and expiry date.' },
    { q: 'When does an expired domain become available again?', a: 'For most generic endings, an expired domain passes through a grace period of up to 45 days, a 30-day redemption period and about five days of pending delete. Country code endings have their own rules.' },
    { q: 'Why does a domain show as unknown?', a: 'The registry did not answer in time or limited the number of requests. Wait a minute and check again.' },
  ],
};

export default tool;
