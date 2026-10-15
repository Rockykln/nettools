import { html } from '../core/html';
import type { Tool } from '../core/tool';

// Parsing happens entirely in the browser (public/assets/js/email-headers.js): headers contain
// addresses and IPs of real people and are never sent to the server.
const tool: Tool = {
  slug: 'email-headers',
  name: 'Email header analyzer',
  icon: 'mailheader',
  category: 'email',
  title: 'Email Header Analyzer – Trace Delays, SPF, DKIM & DMARC',
  description: 'Paste email headers to see every server the message passed, where it was delayed, and the SPF, DKIM and DMARC results. Runs in your browser only.',
  h1: 'Email header analyzer',
  lead: 'See the route of an email, where it was delayed and whether it passed SPF, DKIM and DMARC.',
  script: 'email-headers.js',
  related: ['email-security', 'blacklist-check', 'reverse-dns-lookup'],

  render() {
    return html`<form class="tool-form" id="mh-form" action="#">
<div class="field grow"><label for="mh-input">Full email headers</label>
<textarea id="mh-input" rows="10" required autocapitalize="off" autocomplete="off" spellcheck="false" placeholder="Received: from mail.example.com (mail.example.com [192.0.2.10]) by mx.example.net …"></textarea></div>
<div class="field"><button type="submit">Analyze</button></div>
</form>
<p class="hint">Processed only in your browser. Nothing you paste is sent to our server.</p>
<noscript><p class="error">This tool needs JavaScript, because the headers are analyzed on your device only.</p></noscript>
<div id="mh-result" aria-live="polite"></div>`;
  },

  article: html`<h2>What the analyzer shows</h2>
<p>Paste the complete header block of a message and the analyzer lists the key fields (From, To, Subject, Date,
Return-Path and Message-ID), the SPF, DKIM and DMARC results recorded by the receiving server, and every
<code>Received</code> hop in the order the message travelled, with the delay between hops and the total transit time.
Hops that took longer than a minute are highlighted.</p>
<p>The parsing runs in your browser. Nothing you paste is sent to our server, which matters because headers contain
real addresses, host names and IP addresses.</p>

<h2>How to get the full headers</h2>
<p>The analyzer needs the raw header lines, not the short From/To/Subject view that every mail program shows. Copy
everything from the first line down to the first empty line; if you copy the whole message source, the body is
ignored.</p>
<table class="data"><thead><tr><th>Mail program</th><th>Where to find them</th></tr></thead><tbody>
<tr><td>Gmail</td><td>Open the message, three-dot menu, <em>Show original</em>.</td></tr>
<tr><td>Outlook on the web, new Outlook</td><td>Three-dot menu, <em>View</em>, <em>View message source</em>.</td></tr>
<tr><td>Outlook (classic desktop)</td><td>Open the message, <em>File</em>, <em>Properties</em>, field <em>Internet headers</em>.</td></tr>
<tr><td>Apple Mail</td><td><em>View</em>, <em>Message</em>, <em>All Headers</em> or <em>Raw Source</em>.</td></tr>
<tr><td>Thunderbird</td><td><em>View</em>, <em>Message Source</em> (Ctrl+U).</td></tr>
</tbody></table>
<p>Forwarding a message does not work: the forward is a new message with new headers. If someone needs to analyze a
message for you, send it as an attachment (<code>.eml</code>) or paste the source.</p>

<h2>Reading the route</h2>
<p>Every mail server that handles a message adds a <code>Received</code> header at the top, so the headers read from
bottom to top: the lowest one is usually the sender's submission server, the highest one your provider's last internal
hop. A typical entry looks like this:</p>
<pre class="raw">Received: from mail.example.com (mail.example.com [192.0.2.10])
        by mx.example.net with ESMTPS id 4Xk2pQ0f7Hz9
        for user@example.net; Tue, 13 Oct 2026 09:14:07 +0200</pre>
<p><code>from</code> is the server that handed the message over: first the name it announced in its HELO, then in
parentheses the reverse DNS name and IP address the receiving server saw. <code>by</code> is the server that accepted
it, and the date after the semicolon is when it did. A HELO name that does not match the reverse DNS name is common and
not suspicious by itself; the IP address in brackets is what the receiver actually observed. You can check it with the
<a href="/reverse-dns-lookup">reverse DNS lookup</a> or the <a href="/blacklist-check">blacklist check</a>.</p>
<p>The <code>with</code> keyword names the protocol (RFC 3848):</p>
<table class="data"><thead><tr><th>Value</th><th>Meaning</th></tr></thead><tbody>
<tr><td><code>SMTP</code>, <code>ESMTP</code></td><td>Unencrypted transfer between servers.</td></tr>
<tr><td><code>ESMTPS</code></td><td>Transfer over TLS (STARTTLS or implicit TLS).</td></tr>
<tr><td><code>ESMTPA</code>, <code>ESMTPSA</code></td><td>The client logged in, usually a user submitting mail; the S means TLS.</td></tr>
<tr><td><code>LMTP</code></td><td>Local delivery from the mail server to the mailbox store.</td></tr>
</tbody></table>
<p>Large providers add several internal hops, often with private addresses or IPv6 addresses inside their own
network. Those are normal; the interesting hop is the one where the message crossed from the sender's infrastructure
to your provider's.</p>

<h2>Finding delays</h2>
<p>The analyzer converts every timestamp to UTC before comparing, so different time zones do not appear as delays.
Small negative values come from clocks that are not perfectly in sync. Common reasons for a large gap:</p>
<ul>
<li><strong>Greylisting:</strong> the receiver temporarily rejects the first attempt and the sender retries after a
few minutes. The delay appears on the hop into the receiving server.</li>
<li><strong>Queues at the sender:</strong> newsletter platforms and overloaded servers send in batches or retry slowly.
A long gap on the first external hop points there.</li>
<li><strong>Filtering:</strong> spam and malware scanning, sometimes with an external gateway in between, adds
seconds to minutes.</li>
<li><strong>Time before the first hop:</strong> the Date header is set by the sender's mail program. A message that sat
in an outbox or was sent from a device that was offline shows a gap between Date and the first Received header.</li>
</ul>

<h2>Authentication results</h2>
<p>The receiving server records its checks in the <code>Authentication-Results</code> header (RFC 8601):</p>
<pre class="raw">Authentication-Results: mx.example.net;
       spf=pass smtp.mailfrom=example.com;
       dkim=pass header.d=example.com header.s=sel1;
       dmarc=pass header.from=example.com</pre>
<p><code>spf=pass</code> means the sending IP is allowed by the SPF record of the envelope sender domain
(<code>smtp.mailfrom</code>, the same as Return-Path). <code>dkim=pass</code> means the signature of the domain in
<code>header.d</code> is valid and the signed parts were not changed. <code>dmarc=pass</code> means at least one of
the two passed for a domain that matches the visible From domain. Microsoft adds its own <code>compauth</code> result
with a combined verdict.</p>
<p>The analyzer reads the topmost Authentication-Results header, which is normally the one your own provider added.
Only trust results whose first token, the authserv-id, names your provider; anything further down could have been
added by the sender. To check the published SPF, DKIM and DMARC records of a domain, use the
<a href="/email-security">email security check</a>.</p>

<h3>ARC headers</h3>
<p>Forwarders and mailing lists often break SPF, and sometimes DKIM, because they change the sending IP or the
message. ARC (Authenticated Received Chain, RFC 8617) lets them record the results they saw before forwarding. Each
intermediary adds an <code>ARC-Authentication-Results</code>, <code>ARC-Message-Signature</code> and
<code>ARC-Seal</code> set numbered with <code>i=1</code>, <code>i=2</code> and so on. A receiver that trusts the
forwarder can use the earlier results instead of rejecting the message. The analyzer does not evaluate ARC; read those
headers in the raw source if a forwarded message failed DMARC.</p>

<h2>Signs of spoofing and phishing</h2>
<ul>
<li><strong>DMARC fail</strong> for a message that claims to come from a bank, a shop or your own company is the
clearest sign. If the domain has no DMARC record, the check shows <code>none</code> and proves nothing.</li>
<li><strong>From and Return-Path differ:</strong> normal for newsletters and ticket systems that use a bounce domain
of their provider. Suspicious when the Return-Path domain has nothing to do with the sender and DMARC did not pass.</li>
<li><strong>Reply-To differs from From:</strong> replies go to the Reply-To address. A free-mail address there on a
message from a company is a typical sign of invoice fraud. The analyzer does not list Reply-To; search the pasted text
for it.</li>
<li><strong>Look-alike domains:</strong> all checks can pass for a domain registered by the attacker, such as one
letter changed or a different ending. Authentication proves who sent the mail, not that the sender is who you think.</li>
</ul>

<h2>Privacy when sharing headers</h2>
<p>Headers often reveal more than expected: your address and those of other recipients, internal host names and
private IP addresses of the sender's network, and with some services the IP address of the device that sent the
message. Before you post headers in a forum or ticket, replace addresses and names consistently but keep the structure
and timestamps, so others can still follow the route.</p>`,

  faq: [
    { q: 'Is it safe to paste my email headers here?', a: 'Yes. The analysis runs in your browser and nothing is uploaded. Headers still contain addresses, host names and IP addresses, so be careful where else you paste them.' },
    { q: 'Can headers be forged?', a: 'Everything below the first server you trust can be faked by the sender, including Received and Authentication-Results lines. The headers added by your own provider at the top are reliable.' },
    { q: 'Why does my email take minutes to arrive?', a: 'Look for the hop with the largest delay. Common causes are greylisting, where the sender retries after a few minutes, spam scanning, or a queue at the sender.' },
    { q: 'Does the Received header show the sender’s real IP address?', a: 'The lowest external hop shows the server that submitted the message, usually the sender’s mail provider. Whether the IP address of the sender’s own device appears depends on the provider; many large providers leave it out.' },
    { q: 'SPF passes but DMARC fails. Why?', a: 'DMARC also requires alignment. SPF checks the Return-Path domain, and if that domain differs from the From domain and DKIM is missing or signed by another domain, DMARC fails although SPF passed.' },
    { q: 'Why does the analyzer show fewer hops than I expected?', a: 'Only Received headers are counted, and some servers do not add one or add it in an unusual format. Make sure you pasted the full header block and not the forwarded copy of a message.' },
  ],
};

export default tool;
