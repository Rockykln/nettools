// Pages for the nettools iPhone app: overview with the TestFlight beta, privacy policy and support.
import { SITE } from './config';
import { html, type SafeHtml } from './core/html';
import { page } from './core/layout';
import { pageJsonLd } from './core/seo';
import type { ToolContext } from './core/tool';

const TESTFLIGHT_APP = 'https://apps.apple.com/app/testflight/id899247664';
const UPDATED = '26 November 2026';

function appNav(current: string): SafeHtml {
  const links: [string, string][] = [['/app', 'Overview'], ['/app/privacy', 'Privacy'], ['/app/support', 'Support']];
  return html`<p class="app-nav">${links.map(([href, name], i) => html`${i ? ' · ' : ''}${href === current ? html`<strong>${name}</strong>` : html`<a href="${href}">${name}</a>`}`)}</p>`;
}

function betaBox(): SafeHtml {
  const link = SITE.app.testflight;
  if (!link) {
    return html`<section class="tool" aria-label="Beta">
<h2>Public beta</h2>
<p>The public beta on TestFlight opens soon. The link to join will be on this page.</p>
<p class="hint">For iPhone with iOS ${SITE.app.minIOS} or later. Free, no account.</p>
</section>`;
  }
  return html`<section class="tool" aria-label="Beta">
<h2>Public beta</h2>
<p>The app is in a public beta on TestFlight, Apple’s app for testing apps before their release. Anyone can join.</p>
<ol>
<li>Install <a href="${TESTFLIGHT_APP}" rel="noopener">TestFlight</a> from the App Store.</li>
<li>Open the beta link on your iPhone, tap <strong>Accept</strong>, then <strong>Install</strong>.</li>
</ol>
<div class="hero-actions"><a class="btn" href="${link}" rel="noopener">Join the beta on TestFlight</a></div>
<p class="hint">For iPhone with iOS ${SITE.app.minIOS} or later. Free, no account. Each beta build runs for 90 days; TestFlight offers new builds as they come.</p>
</section>`;
}

export function appPage(c: ToolContext): Response {
  const body = html`<div class="wrap narrow">
<h1>${SITE.name} for iPhone</h1>
${appNav('/app')}
<p class="lead">The tools of this site as a native iPhone app, plus what only works on the device itself: ping,
traceroute, LAN scan, Bonjour and the details of your Wi-Fi.</p>
${betaBox()}

<h2>What it does</h2>
<table class="kv"><tbody>
<tr><th scope="row">Your network</th><td>The path from your iPhone to the internet: local address, router, public IPv4 and IPv6, provider and AS, connection type, VPN and cellular technology</td></tr>
<tr><th scope="row">From this iPhone</th><td>Ping, traceroute, TCP ping, port checks, DNS over HTTPS, LAN scan and Bonjour, measured from inside your network</td></tr>
<tr><th scope="row">From outside</th><td>The lookups of this site: DNS, WHOIS and RDAP, SSL, HTTP headers, email security, blocklists, is it down and more</td></tr>
<tr><th scope="row">Offline</th><td>Subnet calculator, MAC vendor lookup (also by scanning a device label), IP to country, email header analyzer</td></tr>
<tr><th scope="row">Widgets and Siri</th><td>Your public IP and the DNS root servers on the Home and Lock Screen; Shortcuts for public IP, DNS, ping, port check and “is it down?”</td></tr>
<tr><th scope="row">Links</th><td>Tool links to this site open the matching tool in the app</td></tr>
</tbody></table>

<h2>Free and private</h2>
<p>No ads, no tracking, no account. The <a href="/app/privacy">app privacy policy</a> explains which data leaves your
iPhone and where it goes. Questions or found a bug? See <a href="/app/support">support</a>.</p>
</div>`;
  return page(c.env, {
    title: `${SITE.name} for iPhone – Network Tools App (Beta)`,
    description: 'Network tools as a native iPhone app: ping, traceroute, DNS, LAN scan, port checks, WHOIS and more. Free, no ads, no tracking. Join the public beta on TestFlight.',
    path: '/app',
    body,
    jsonLd: pageJsonLd(c.env, '/app', `${SITE.name} for iPhone`, 'The nettools iPhone app and its public beta.'),
  });
}

export function appPrivacyPage(c: ToolContext): Response {
  const o = SITE.operator;
  const summary: [string, string][] = [
    ['Account', 'None.'],
    ['Advertising and tracking', 'None. The app contains no third-party code for analytics, crash reports or advertising.'],
    ['Only on your iPhone', 'History, pinned tools and settings. The email header analyzer, subnet calculator, MAC vendor lookup and IP to country work offline.'],
    ['Directly from your iPhone', 'Checks set to “This iPhone” connect to the target or DNS resolver you choose. That host sees your IP address; we receive nothing.'],
    ['Through this website', 'Checks set to “Server” and lookups that only run there send your input to this site’s API. Technical logs up to 7 days, statistics without IP addresses or inputs.'],
    ['Widgets', 'Ask this site’s API for your public IP address and the root server status.'],
  ];
  const body = html`<div class="wrap narrow">
<h1>${SITE.name} for iPhone: privacy</h1>
${appNav('/app/privacy')}
<p class="lead">What the iPhone app does with your data, in plain words. Last updated ${UPDATED}.</p>
<table class="kv"><tbody>${summary.map(([t, d]) => html`<tr><th scope="row">${t}</th><td>${d}</td></tr>`)}</tbody></table>

<h2>Controller</h2>
<p>${o.name}, contact details in the <a href="/legal">legal notice</a>. Email: <a href="mailto:${o.email}">${o.email}</a>.</p>

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
<table class="kv"><tbody>
<tr><th scope="row">Local network</th><td>To reach devices in your network: LAN scan, Bonjour, and ping or port checks of local addresses. Asked for when you first use one of them.</td></tr>
<tr><th scope="row">Location</th><td>iOS shows the name of your Wi-Fi only to apps with location access. The app reads the Wi-Fi name, never your location, and stores neither.</td></tr>
<tr><th scope="row">Camera</th><td>Optional, to scan a MAC address from a device label. Images are processed on the iPhone and not saved.</td></tr>
</tbody></table>
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
<a href="mailto:${o.email}">${o.email}</a>.</p>
</div>`;
  return page(c.env, {
    title: `iPhone app privacy – ${SITE.name}`,
    description: `Privacy policy of the ${SITE.name} iPhone app: which data leaves your iPhone and where it goes.`,
    path: '/app/privacy',
    body,
    noindex: true,
    jsonLd: pageJsonLd(c.env, '/app/privacy', 'iPhone app privacy', 'Privacy policy of the nettools iPhone app.'),
  });
}

export function appSupportPage(c: ToolContext): Response {
  const o = SITE.operator;
  const faq: [string, SafeHtml][] = [
    ['Which iPhones are supported?', html`Every iPhone with iOS ${SITE.app.minIOS} or later.`],
    ['Why does the app ask for local network access?', html`Ping, port checks, the LAN scan and Bonjour reach devices in your own network, which iOS only allows with this permission. If you declined, turn it on in Settings › ${SITE.name} › Local Network.`],
    ['Why does it ask for my location?', html`Only to show the name of your Wi-Fi, which iOS hides from apps without location access. The app never reads your location.`],
    ['The LAN scan or ping to a local address finds nothing', html`Check the local network permission above. A VPN or iCloud Private Relay may send traffic past your local network, and some routers isolate Wi-Fi clients from each other (guest networks).`],
    ['The widget shows an old address', html`iOS decides how often widgets refresh. Opening the app refreshes them right away; with Background App Refresh on (Settings › General › Background App Refresh) the app also checks for a new address in the background.`],
    ['Why do “This iPhone” and “Server” show different results?', html`That is the point of the comparison: “This iPhone” measures from your network, “Server” from Cloudflare’s network on the internet. A port that is open inside your network can be closed from outside, and DNS answers can differ by resolver and location.`],
    ['“Too many requests”', html`Server checks are limited to about 30 requests per minute per IP address, heavier lookups to 10. Wait a minute and try again.`],
  ];
  const body = html`<div class="wrap narrow">
<h1>${SITE.name} for iPhone: support</h1>
${appNav('/app/support')}
<p class="lead">Answers to common questions and how to reach us.</p>
<section class="tool" aria-label="Contact">
<h2>Contact</h2>
<p>Email <a href="mailto:${o.email}?subject=${encodeURIComponent(`${SITE.name} iPhone app`)}">${o.email}</a> with your iPhone model, iOS version and app version
(shown under About in the app). In the beta, you can also send feedback in TestFlight: take a screenshot and tap
<strong>Share Beta Feedback</strong>.</p>
<p class="hint">Found a problem with a lookup on the website as well? Issues are welcome on <a href="${SITE.github}/issues" rel="noopener">GitHub</a>.</p>
</section>

<h2>Questions</h2>
${faq.map(([q, a]) => html`<h3>${q}</h3>
<p>${a}</p>`)}

<h2>Privacy</h2>
<p>No ads, no tracking, no account. Details in the <a href="/app/privacy">app privacy policy</a>.</p>
</div>`;
  return page(c.env, {
    title: `iPhone app support – ${SITE.name}`,
    description: `Help with the ${SITE.name} iPhone app: permissions, widgets, local network checks and contact.`,
    path: '/app/support',
    body,
    jsonLd: pageJsonLd(c.env, '/app/support', 'iPhone app support', 'Help and contact for the nettools iPhone app.'),
  });
}
