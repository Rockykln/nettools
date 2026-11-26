// Pages for the nettools iPhone app: overview with the TestFlight beta, privacy policy and support.
import { SITE } from './config';
import { html, type SafeHtml } from './core/html';
import { icon, page } from './core/layout';
import { pageJsonLd } from './core/seo';
import type { ToolContext } from './core/tool';

const TESTFLIGHT_APP = 'https://apps.apple.com/app/testflight/id899247664';
const UPDATED = '26 November 2026';

/** Sub navigation of the three app pages. */
function appNav(current: string): SafeHtml {
  const links: [string, string][] = [['/app', 'Overview'], ['/app/privacy', 'Privacy'], ['/app/support', 'Support']];
  return html`<nav class="app-nav" aria-label="iPhone app">${links.map(([href, name]) => html`<a href="${href}"${href === current ? html` aria-current="page"` : ''}>${name}</a>`)}</nav>`;
}

/** The app icon in its light and dark variant; CSS shows the one matching the theme. */
function appIcon(size: number, alt = `${SITE.name} app icon`): SafeHtml {
  const v = SITE.assetVersion;
  return html`<img class="app-icon light" src="/assets/brand/app-icon-light.svg?v=${v}" alt="${alt}" width="${size}" height="${size}"><img class="app-icon dark" src="/assets/brand/app-icon-dark.svg?v=${v}" alt="" width="${size}" height="${size}">`;
}

/** Header logo of the app pages: the app icon instead of the site logo. */
const brandIcon = (): SafeHtml => appIcon(32, '');

/** Page heading of the privacy and support pages: app icon next to the title. */
function appTitle(title: string): SafeHtml {
  return html`<div class="app-title">${appIcon(64)}<h1>${title}</h1></div>`;
}

/** Card with a small icon next to its title. */
function feature(ico: string, title: string, text: SafeHtml | string): SafeHtml {
  return html`<div class="feature compact"><h3><span class="tile">${icon(ico, '')}</span>${title}</h3><p>${text}</p></div>`;
}

function betaCard(): SafeHtml {
  const link = SITE.app.testflight;
  const facts = html`<table class="kv compact"><tbody>
<tr><th scope="row">Requires</th><td>iPhone with iOS ${SITE.app.minIOS} or later</td></tr>
<tr><th scope="row">Status</th><td>Public beta on TestFlight</td></tr>
</tbody></table>`;
  if (!link) {
    return html`<section class="tool" aria-label="Public beta">
<h2>Public beta</h2>
<p>The public beta on TestFlight opens soon. The link to join will be on this page.</p>
${facts}
</section>`;
  }
  return html`<section class="tool" aria-label="Public beta">
<h2>Join the public beta</h2>
<ol class="steps">
<li>Install <a href="${TESTFLIGHT_APP}" rel="noopener">TestFlight</a> from the App Store.</li>
<li>Open the beta link on your iPhone.</li>
<li>Tap <strong>Accept</strong>, then <strong>Install</strong>.</li>
</ol>
<div class="hero-actions"><a class="btn" href="${link}" rel="noopener">Join the beta on TestFlight</a></div>
${facts}
</section>`;
}

export function appPage(c: ToolContext): Response {
  const body = html`<section class="hero"><div class="wrap hero-grid">
<div>
<span class="eyebrow">iPhone app</span>
<h1>Network tools <em>for your iPhone.</em></h1>
<p class="lead">The tools of this site as a native iPhone app, plus what only works on the device itself: ping,
traceroute, LAN scan, Bonjour and the details of your Wi-Fi.</p>
<div class="hero-actions"><a class="btn secondary" href="/app/support">${icon('support')}Support</a>
<a class="btn secondary" href="/app/privacy">${icon('privacy')}Privacy</a></div>
<ul class="trust">${['Free', 'No ads', 'No tracking', 'No account'].map((t) => html`<li>${icon('check')}${t}</li>`)}</ul>
</div>
${betaCard()}
</div></section>

<section class="section"><div class="wrap">
<h2 class="section-title">What it does</h2>
<p class="section-intro">Most tools measure in two places: from your iPhone inside your network and from a server on
the internet. That shows what others see.</p>
<div class="features">
${feature('ip', 'Your network', 'The path from your iPhone to the internet: local address, router, public IPv4 and IPv6, provider and AS, connection type, VPN and cellular technology.')}
${feature('ping', 'From this iPhone', 'Ping, traceroute, TCP ping, port checks and DNS over HTTPS, measured from inside your network.')}
${feature('dns', 'From outside', 'The lookups of this site: DNS, WHOIS and RDAP, SSL, HTTP headers, email security, blocklists, is it down and more.')}
${feature('port', 'LAN scan and Bonjour', 'The devices on your Wi-Fi with open ports and names, and the services they announce: printers, AirPlay, Home Assistant.')}
${feature('subnet', 'Offline', 'Subnet calculator, MAC vendor lookup (also by scanning a device label), IP to country and the email header analyzer.')}
${feature('root', 'Widgets', 'Your public IP address and the status of the DNS root servers on the Home Screen and Lock Screen.')}
${feature('bolt', 'Shortcuts and Siri', 'Public IP, DNS record, ping, port check and “is it down?” as Shortcuts actions.')}
${feature('open', 'Links open the app', 'Tool links to this site open the matching tool in the app, with the query filled in.')}
</div>
</div></section>

<section class="section"><div class="wrap">
<div class="features">
${feature('shield', 'Private by design', html`No ads, no tracking, no account. The <a href="/app/privacy">app privacy policy</a> explains which data leaves your iPhone and where it goes.`)}
${feature('mail', 'Help and feedback', html`Answers to common questions and how to reach us are on the <a href="/app/support">support page</a>.`)}
${feature('code', 'Also in the browser', html`Every lookup of the app’s server side works on <a href="/">this website</a> as well, with a free JSON API.`)}
</div>
</div></section>`;
  return page(c.env, {
    title: `${SITE.name} for iPhone – Network Tools App (Beta)`,
    description: 'Network tools as a native iPhone app: ping, traceroute, DNS, LAN scan, port checks, WHOIS and more. Free, no ads, no tracking. Join the public beta on TestFlight.',
    path: '/app',
    body,
    brandIcon: brandIcon(),
    jsonLd: pageJsonLd(c.env, '/app', `${SITE.name} for iPhone`, 'The nettools iPhone app and its public beta.'),
  });
}

export function appPrivacyPage(c: ToolContext): Response {
  const o = SITE.operator;
  const summary: [string, string, string][] = [
    ['shield', 'No account, no ads, no tracking', 'The app contains no third-party code for analytics, crash reports or advertising.'],
    ['subnet', 'Only on your iPhone', 'History, pinned tools and settings. The header analyzer, subnet calculator, MAC vendor lookup and IP to country work offline.'],
    ['ping', 'Directly from your iPhone', 'Checks set to “This iPhone” connect to the target or DNS resolver you choose. We receive nothing.'],
    ['dns', 'Through this website', 'Checks set to “Server” send your input to this site’s API: technical logs up to 7 days, statistics without IP addresses or inputs.'],
    ['root', 'Widgets', 'Ask this site’s API for your public IP address and the root server status.'],
  ];
  const body = html`<div class="wrap">
${appTitle(`${SITE.name} for iPhone: privacy`)}
${appNav('/app/privacy')}
<p class="lead">What the iPhone app does with your data, in plain words. Last updated ${UPDATED}.</p>
<div class="legal-grid">
<aside class="tool legal-card" aria-label="In short">
<h2>In short</h2>
<ul class="facts">${summary.map(([ico, t, d]) => html`<li><span class="tile">${icon(ico, '')}</span><span><strong>${t}</strong>${d}</span></li>`)}</ul>
</aside>
<div class="legal-body">
<h2>Controller</h2>
<p>${o.name}, contact details in the <a href="/legal">legal notice</a>. Email about the app: <a href="mailto:${SITE.app.email}">${SITE.app.email}</a>.</p>

<h2>Checks that run on the server</h2>
<p>Many tools can measure from outside your network. For these, and for lookups that only exist on the server (for
example WHOIS, email security or the SSL check), the app sends your input to the API of ${SITE.name}
(net.rockykln.com) together with the app version. The API runs on Cloudflare and is the same one the website uses, so
the <a href="/legal#privacy">website’s privacy policy</a> applies: Cloudflare’s technical logs contain the request
including your input, your IP address and approximate location and are deleted after 7 days; the usage statistics
record the tool, whether it succeeded, its duration and your country, without IP address or input; results may be
cached for up to 6 hours; to answer, the server passes your input to the services named there (DNS resolvers,
registries, certificate logs). Legal basis: Art. 6 (1) (b) and (f) GDPR.</p>

<h2>Checks that run on your iPhone</h2>
<p>Ping, traceroute, TCP ping, port, TLS and website checks, DNS over HTTPS, the LAN scan and the Bonjour browser
connect directly from your iPhone to the target, the devices in your network or the DNS resolver you choose (for
example Cloudflare, Google or Quad9). These hosts see your IP address as with any connection. Nothing about it is
sent to us.</p>

<h2>Widgets and background refresh</h2>
<p>The public IP widget asks this site’s API for your public IPv4 and IPv6 address, your provider and approximate
location, up to every 5 minutes and when your connection changes; iOS decides how often it actually runs. The Root DNS
widget loads the status of the root servers. If Background App Refresh is on for ${SITE.name}, the app also checks your
public IP address in the background so the widget notices a new network. These requests are handled like the
server checks above.</p>

<h2>Data updates</h2>
<p>About once a month the app downloads the current IP to country and MAC vendor data from this website. The
request contains nothing but the file names.</p>

<h2>Permissions</h2>
<div class="features">
${feature('subnet', 'Local network', 'To reach devices in your network: LAN scan, Bonjour, and ping or port checks of local addresses. Asked for when you first use one of them.')}
${feature('ip', 'Location', 'iOS shows the name of your Wi-Fi only to apps with location access. The app reads the Wi-Fi name, never your location, and stores neither.')}
${feature('mac', 'Camera', 'Optional, to scan a MAC address from a device label. Images are processed on the iPhone and not saved.')}
</div>
<p>You can change these at any time in the Settings app under ${SITE.name}.</p>

<h2>Data on your iPhone</h2>
<p>History, pinned tools and settings are stored only in the app on your iPhone. You can clear the history in the app;
everything is removed when you delete the app.</p>

<h2>App Store and TestFlight</h2>
<p>Apple distributes the app and processes data for this under its own privacy policy. If you test the beta, TestFlight
shares with us what Apple describes in its TestFlight privacy notice, such as crash reports, usage data like the
number of sessions, and the feedback and screenshots you choose to send.</p>

<h2>Your rights</h2>
<p>You have the rights described in the <a href="/legal">website’s privacy policy</a>: access, rectification, erasure,
restriction, data portability, objection and complaint to a supervisory authority. As the app has no account and we
keep no data that identifies you, there is usually nothing to disclose. Contact:
<a href="mailto:${SITE.app.email}">${SITE.app.email}</a>.</p>
</div>
</div>
</div>`;
  return page(c.env, {
    title: `iPhone app privacy – ${SITE.name}`,
    description: `Privacy policy of the ${SITE.name} iPhone app: which data leaves your iPhone and where it goes.`,
    path: '/app/privacy',
    body,
    brandIcon: brandIcon(),
    noindex: true,
    jsonLd: pageJsonLd(c.env, '/app/privacy', 'iPhone app privacy', 'Privacy policy of the nettools iPhone app.'),
  });
}

export function appSupportPage(c: ToolContext): Response {
  const mail = `mailto:${SITE.app.email}?subject=${encodeURIComponent(`${SITE.name} iPhone app`)}`;
  const faq: [string, string, SafeHtml][] = [
    ['subnet', 'Why does the app ask for local network access?', html`Ping, port checks, the LAN scan and Bonjour reach devices in your own network, which iOS only allows with this permission. If you declined, turn it on in Settings › ${SITE.name} › Local Network.`],
    ['ip', 'Why does it ask for my location?', html`Only to show the name of your Wi-Fi, which iOS hides from apps without location access. The app never reads your location.`],
    ['ping', 'The LAN scan or a local ping finds nothing', html`Check the local network permission. A VPN or iCloud Private Relay may send traffic past your local network, and some routers isolate Wi-Fi clients from each other (guest networks).`],
    ['iplookup', 'The widget shows an old address', html`iOS decides how often widgets refresh. Opening the app refreshes them right away; with Background App Refresh on (Settings › General › Background App Refresh) the app also checks for a new address in the background.`],
    ['dns', 'Why do “This iPhone” and “Server” differ?', html`That is the point of the comparison: “This iPhone” measures from your network, “Server” from Cloudflare’s network on the internet. A port that is open inside your network can be closed from outside, and DNS answers can differ by resolver and location.`],
    ['bolt', '“Too many requests”', html`Server checks are limited to about 30 requests per minute per IP address, heavier lookups to 10. Wait a minute and try again.`],
  ];
  const body = html`<div class="wrap">
${appTitle(`${SITE.name} for iPhone: support`)}
${appNav('/app/support')}
<p class="lead">Answers to common questions and how to reach us.</p>
<div class="legal-grid">
<aside class="tool legal-card" aria-label="Contact">
<h2>Contact</h2>
<p>Write with your iPhone model, iOS version and app version (shown under About in the app). The app needs iOS ${SITE.app.minIOS} or later.</p>
<div class="hero-actions"><a class="btn" href="${mail}">${icon('mail')}${SITE.app.email}</a></div>
<p>In the beta, you can also send feedback in TestFlight: take a screenshot and tap <strong>Share Beta Feedback</strong>.</p>
<p class="hint">A problem with a lookup on the website as well? Issues are welcome on <a href="${SITE.github}/issues" rel="noopener">GitHub</a>.</p>
</aside>
<div>
<h2 class="section-title">Questions</h2>
<div class="features">
${faq.map(([ico, q, a]) => feature(ico, q, a))}
</div>
</div>
</div>
</div>`;
  return page(c.env, {
    title: `iPhone app support – ${SITE.name}`,
    description: `Help with the ${SITE.name} iPhone app: permissions, widgets, local network checks and contact.`,
    path: '/app/support',
    body,
    brandIcon: brandIcon(),
    jsonLd: pageJsonLd(c.env, '/app/support', 'iPhone app support', 'Help and contact for the nettools iPhone app.'),
  });
}
