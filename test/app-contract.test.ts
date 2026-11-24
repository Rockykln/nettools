// Contract tests for the JSON API used by the nettools iPhone app. Installed app versions decode these responses
// with fixed models: a field the app relies on must not disappear, change its name or change its JSON type.
// Every request runs offline against the small fake network below (DNS, sockets, HTTP and registry APIs).
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { RR_TYPES, dnskeyTag, frameTcp, parseMessage, unframeTcp, type RrTypeName } from '../src/core/dns';
import { addressBytes } from '../src/core/geo';

vi.mock('cloudflare:sockets', () => ({ connect: (address: SocketAddress) => fakeConnect(address) }));

const { default: worker } = await import('../src/index');

// --- Schema of what the app decodes ------------------------------------------------------------------------

type Leaf = 'string' | 'int' | 'uint' | 'number' | 'bool' | 'url' | 'json';
type Schema = Leaf | Opt | List | Dict | Tuple | OneOf | Lazy | { [key: string]: Schema };

/** May be missing or null. Optional fields still must have the right type when present. */
class Opt { constructor(readonly of: Schema) {} }
class List { constructor(readonly of: Schema) {} }
class Dict { constructor(readonly of: Schema) {} }
class Tuple { constructor(readonly items: Schema[]) {} }
/** A string the app maps to a known case. */
class OneOf { constructor(readonly values: string[]) {} }
class Lazy { constructor(readonly get: () => Schema) {} }

const opt = (s: Schema) => new Opt(s);
const list = (s: Schema) => new List(s);
const dict = (s: Schema) => new Dict(s);
const tuple = (...items: Schema[]) => new Tuple(items);
const oneOf = (...values: string[]) => new OneOf(values);
const lazy = (get: () => Schema) => new Lazy(get);

const LEAF: Record<Leaf, (v: unknown) => boolean> = {
  string: (v) => typeof v === 'string',
  // Swift's Int and UInt refuse fractions such as 12.5.
  int: (v) => Number.isInteger(v),
  uint: (v) => Number.isInteger(v) && (v as number) >= 0,
  number: (v) => typeof v === 'number' && Number.isFinite(v),
  bool: (v) => typeof v === 'boolean',
  url: (v) => typeof v === 'string' && URL.canParse(v),
  json: () => true,
};

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function walk(v: unknown, s: Schema, path: string, out: string[]): void {
  const at = path || '(root)';
  if (s instanceof Lazy) return walk(v, s.get(), path, out);
  if (s instanceof Opt) {
    if (v !== undefined && v !== null) walk(v, s.of, path, out);
    return;
  }
  if (v === undefined || v === null) {
    out.push(`${at}: missing`);
    return;
  }
  if (typeof s === 'string') {
    if (!LEAF[s](v)) out.push(`${at}: expected ${s}, got ${JSON.stringify(v)}`);
  } else if (s instanceof OneOf) {
    if (typeof v !== 'string' || !s.values.includes(v)) out.push(`${at}: expected one of ${s.values.join('|')}, got ${JSON.stringify(v)}`);
  } else if (s instanceof List || s instanceof Tuple) {
    if (!Array.isArray(v)) out.push(`${at}: expected array`);
    else if (s instanceof List) v.forEach((x, i) => walk(x, s.of, `${path}[${i}]`, out));
    else s.items.forEach((item, i) => walk(v[i], item, `${path}[${i}]`, out));
  } else if (s instanceof Dict) {
    if (!isObject(v)) out.push(`${at}: expected object`);
    else for (const [k, x] of Object.entries(v)) walk(x, s.of, `${path}.${k}`, out);
  } else if (!isObject(v)) {
    out.push(`${at}: expected object`);
  } else {
    for (const [k, field] of Object.entries(s)) walk(v[k], field, path ? `${path}.${k}` : k, out);
  }
}

function violations(value: unknown, schema: Schema): string[] {
  const out: string[] = [];
  walk(value, schema, '', out);
  return out;
}

// --- Fields the app relies on, per endpoint ------------------------------------------------------------------

const MY_IP: Schema = {
  ip: 'string', version: opt('int'), hostname: opt('string'), asn: opt('int'), isp: opt('string'), city: opt('string'),
  region: opt('string'), country: opt('string'), countryCode: opt('string'), timezone: opt('string'), colo: opt('string'),
  httpProtocol: opt('string'), tlsVersion: opt('string'), tcpRttMs: opt('int'),
};

const WEB_TOOL: Schema = { slug: 'string', name: 'string', description: opt('string'), url: opt('url'), landing: opt('bool') };

const DNS_RECORD: Schema = { name: 'string', type: 'uint', typeName: 'string', cls: 'uint', ttl: 'uint', data: 'string' };

const DNS_LOOKUP: Schema = {
  name: opt('string'),
  resolver: opt('string'),
  results: list({
    type: 'string', ms: opt('int'), error: opt('string'), rcode: opt('int'), rcodeName: opt('string'), ad: opt('bool'),
    answers: opt(list(DNS_RECORD)), authority: opt(list(DNS_RECORD)),
  }),
};

const PORT_CHECK: Schema = {
  host: 'string',
  results: list({ port: 'int', state: oneOf('open', 'closed', 'filtered', 'not testable', 'error'), ms: opt('int'), detail: opt('string') }),
};

const TCP_PING: Schema = { host: 'string', port: 'int', from: opt('string'), probes: list({ seq: 'int', ms: opt('number'), error: opt('string') }) };

const ORIGIN_AS: Schema = { asn: 'int', holder: opt('string') };

const IP_LOOKUP: Schema = {
  ip: 'string', version: opt('int'), host: opt('string'), hostname: opt('string'), country: opt('string'), countryName: opt('string'),
  owner: opt({ network: opt('string'), range: opt('string'), organization: opt('string'), country: opt('string'), abuse: opt('string') }),
  prefix: opt('string'),
  origins: opt(list(ORIGIN_AS)),
  blocklists: opt({ listed: opt(list('string')), answered: opt('int'), total: opt('int') }),
  sources: opt({ country: opt('string'), owner: opt('string'), routing: opt('string') }),
};

const NEIGHBOUR: Schema = { asn: 'int', power: opt('int') };

const ASN_REPORT: Schema = {
  asn: 'int', holder: opt('string'), announced: opt('bool'), v4: opt(list('string')), v6: opt(list('string')),
  upstreams: opt(list(NEIGHBOUR)), downstreams: opt(list(NEIGHBOUR)), counts: opt({ left: opt('int'), right: opt('int') }), special: opt('string'),
};

// The app tells both answers apart by the "query" key.
const ROUTED_PREFIX: Schema = { query: 'string', prefix: opt('string'), origins: opt(list(ORIGIN_AS)), announced: opt('bool'), as: opt(ASN_REPORT) };

const BLACKLIST: Schema = {
  ip: opt('string'),
  source: opt('string'),
  results: opt(list({ list: opt('string'), name: opt('string'), state: opt(oneOf('listed', 'clean', 'unavailable')), code: opt('string'), reason: opt('string') })),
};

const DNS_BENCHMARK: Schema = {
  name: opt('string'),
  from: opt('string'),
  results: list({ resolver: 'string', firstMs: opt('int'), cachedMs: opt('int'), failures: opt('int') }),
};

const SSL_CHECK: Schema = {
  host: 'string', cloudflare: opt('bool'), tcp: opt('bool'), tls: opt('bool'), tlsMs: opt('int'), redirectsToHttps: opt('bool'),
  certs: opt(list({ issuer: opt('string'), notBefore: opt('string'), notAfter: opt('string'), names: opt(list('string')) })),
};

const SPF_NODE: Schema = {
  domain: opt('string'), record: opt('string'), lookups: opt('int'), includes: opt(list(lazy(() => SPF_NODE))), error: opt('string'), via: opt('string'),
};

const EMAIL_SECURITY: Schema = {
  domain: opt('string'),
  mx: opt(list({ pref: opt('int'), host: opt('string') })),
  spf: opt({ record: opt('string'), records: opt('int'), allQualifier: opt('string'), totalLookups: opt('int'), tree: opt(SPF_NODE), problems: opt(list('string')) }),
  dmarc: opt({ record: opt('string'), tags: opt(dict('string')), problems: opt(list('string')) }),
  dkim: opt(list({ selector: opt('string'), record: opt('string'), valid: opt('bool'), keyType: opt('string'), bits: opt('int') })),
  mtaSts: opt({
    record: opt('string'),
    mode: opt('string'),
    policy: opt({ mode: opt('string'), maxAge: opt('int'), mx: opt(list('string')), problems: opt(list('string')) }),
  }),
  tlsRpt: opt('string'),
  bimi: opt('string'),
  rows: opt(list({ check: opt('string'), level: opt(oneOf('ok', 'warn', 'bad', 'info')), summary: opt('string') })),
};

const WHOIS: Schema = {
  query: opt('string'), kind: opt(oneOf('domain', 'ip', 'asn')), source: opt('string'), notFound: opt('bool'), rdap: opt('json'), whois: opt('string'),
};

const HTTP_HEADERS: Schema = {
  hops: opt(list({
    url: 'string', status: 'int', statusText: opt('string'), ms: opt('int'), location: opt('string'),
    headers: opt(list(tuple('string', 'string'))),
  })),
  error: opt('string'),
  errorKind: opt('string'),
  security: opt(list({ header: 'string', level: oneOf('ok', 'warn', 'bad', 'info'), note: opt('string') })),
};

// The app only accepts an answer with a verdict; a site that is down is still HTTP 200.
const IS_IT_DOWN: Schema = {
  url: opt('string'),
  verdict: oneOf('up', 'blocked', 'error', 'down'),
  addresses: opt(list('string')),
  hops: opt(list({ url: 'string', status: 'int', statusText: opt('string'), ms: opt('number'), location: opt('string') })),
  error: opt('string'),
};

// The app only accepts a report with a verdict.
const DNSSEC: Schema = {
  name: opt('string'),
  verdict: oneOf('secure', 'insecure', 'bogus', 'broken', 'missing', 'unknown'),
  zones: opt(list({
    zone: 'string',
    ds: opt(list({ tag: 'int', algorithm: 'int', digestType: 'int' })),
    keys: opt(list({ tag: opt('int'), flags: 'int', algorithm: 'int' })),
    linked: opt('bool'),
  })),
  notes: opt(list('string')),
};

const DOMAIN_AVAILABILITY: Schema = {
  name: opt('string'),
  results: opt(list({ domain: 'string', status: opt(oneOf('available', 'taken', 'unknown')), registrar: opt('string'), expires: opt('string'), note: opt('string') })),
};

const SUBDOMAINS: Schema = {
  domain: opt('string'), includeExpired: opt('bool'), source: opt('string'),
  hosts: opt(list({ name: 'string', wildcard: opt('bool'), certificates: opt('int'), firstSeen: opt('string'), validUntil: opt('string'), issuer: opt('string') })),
};

const RESPONSE_TIME: Schema = {
  url: opt('string'), host: opt('string'), https: opt('bool'), dnsMs: opt('number'), addresses: opt(list('string')), cloudflare: opt('bool'),
  runs: opt(list({ tcpMs: opt('number'), ttfbMs: opt('number'), totalMs: opt('number'), bytes: opt('int'), status: opt('string'), error: opt('string') })),
  from: opt('string'),
};

const ROBOTS_RULE: Schema = { allow: 'bool', path: 'string' };

// The app always sends a path and reads the verdict from "test"; without it the result would show as allowed.
const ROBOTS: Schema = {
  origin: opt('string'),
  status: opt('int'),
  text: opt('string'),
  robots: opt({
    groups: opt(list({ agents: list('string'), rules: list(ROBOTS_RULE), crawlDelay: opt('number') })),
    sitemaps: opt(list('string')),
    invalidLines: opt('int'),
  }),
  sitemap: opt({ url: 'string', status: opt('int'), kind: opt('string'), entries: opt('int'), note: opt('string') }),
  test: { agent: 'string', path: 'string', allowed: 'bool', rule: opt(ROBOTS_RULE) },
};

const SOCIAL_PREVIEW: Schema = {
  meta: { url: opt('string'), title: opt('string'), tags: opt(dict('string')), canonical: opt('string') },
  image: opt({
    url: 'string', ok: 'bool', status: opt('int'), type: opt('string'), bytes: opt('int'),
    size: opt({ type: opt('string'), width: 'int', height: 'int' }),
  }),
  findings: opt(list({ level: opt(oneOf('ok', 'warn', 'bad')), text: opt('string') })),
};

const ROOT_LIVE: Schema = {
  from: opt('string'),
  results: list({
    root: 'string', ipv4: opt('string'), connectMs: opt('int'), queryMs: opt('int'), serial: opt('int'),
    instance: opt('string'), error: opt('string'), untestable: opt('bool'),
  }),
};

const ROOT_HISTORY: Schema = {
  samples: opt('int'),
  colos: opt(list('string')),
  latestSerial: opt('int'),
  latest: opt(dict({ ts: opt('number'), colo: opt('string'), ok: opt('bool'), queryMs: opt('int'), serial: opt('int'), instance: opt('string') })),
  roots: opt(list({ letter: 'string', availability: opt('number'), avgMs: opt('number'), series: opt(list(opt('number'))) })),
};

// Resolver ids, record types and port groups the app offers.
const APP_RESOLVERS = ['cloudflare', 'google', 'quad9', 'opendns', 'adguard', 'controld', 'nextdns', 'dnssb', 'wikimedia', 'iij', 'alidns'];
const APP_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'PTR', 'SRV', 'HTTPS', 'DS', 'DNSKEY'];
const APP_PORT_GROUPS = ['web', 'remote', 'email', 'files', 'databases', 'gaming', 'selfhosting', 'vpn'];

// --- Fake DNS ----------------------------------------------------------------------------------------------

const enc = new TextEncoder();
const u16 = (n: number) => [n >> 8, n & 0xff];
const u32 = (n: number) => [n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
const b64 = (bytes: number[]) => btoa(String.fromCharCode(...bytes));
const wireName = (name: string) => [...name.split('.').filter(Boolean).flatMap((l) => [l.length, ...enc.encode(l)]), 0];

const KEY_COM = `257 3 13 ${b64(Array(64).fill(1))}`;
const KEY_EXAMPLE = `257 3 13 ${b64(Array(64).fill(2))}`;
const ds = (key: string) => `${dnskeyTag(key)} 13 2 ${'AB'.repeat(32)}`;

const ZONE: Record<string, [RrTypeName, string][]> = {
  '': [['SOA', 'a.root-servers.net nstld.verisign-grs.com 2026112400 1800 900 604800 86400']],
  'id.server': [['TXT', 'fra1a']],
  com: [['SOA', 'a.gtld-servers.net nstld.verisign-grs.com 1764000000 1800 900 604800 900'], ['DS', ds(KEY_COM)], ['DNSKEY', KEY_COM]],
  'example.com': [
    ['A', '93.184.215.14'], ['AAAA', '2606:2800:21f:cb07:6820:80da:af6b:8b2c'], ['MX', '10 mail.example.com'], ['NS', 'a.iana-servers.net'],
    ['TXT', 'v=spf1 include:_spf.example.net -all'], ['SOA', 'ns.icann.org noc.dns.icann.org 2026112401 7200 3600 1209600 3600'],
    ['CAA', '0 issue letsencrypt.org'], ['DS', ds(KEY_EXAMPLE)], ['DNSKEY', KEY_EXAMPLE],
  ],
  'mail.example.com': [['A', '93.184.215.20']],
  'mta-sts.example.com': [['A', '93.184.215.30']],
  '_spf.example.net': [['TXT', 'v=spf1 ip4:93.184.215.0/24 ~all']],
  '_dmarc.example.com': [['TXT', 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com']],
  'sel1._domainkey.example.com': [['TXT', `v=DKIM1; k=ed25519; p=${b64(Array(32).fill(3))}`]],
  '_mta-sts.example.com': [['TXT', 'v=STSv1; id=20261124']],
  '_smtp._tls.example.com': [['TXT', 'v=TLSRPTv1; rua=mailto:tls@example.com']],
  'default._bimi.example.com': [['TXT', 'v=BIMI1; l=https://example.com/logo.svg']],
  'dns.google': [['A', '8.8.8.8'], ['AAAA', '2001:4860:4860::8888']],
  '8.8.8.8.in-addr.arpa': [['PTR', 'dns.google']],
  '4.4.8.8.in-addr.arpa': [['PTR', 'dns.google']],
};

function rdata(type: number, value: string): number[] {
  const [a = '', b = '', c = '', d = ''] = value.split(' ');
  switch (type) {
    case RR_TYPES.A: return value.split('.').map(Number);
    case RR_TYPES.AAAA: return [...addressBytes(value)!];
    case RR_TYPES.NS: case RR_TYPES.CNAME: case RR_TYPES.PTR: return wireName(value);
    case RR_TYPES.MX: return [...u16(Number(a)), ...wireName(b)];
    case RR_TYPES.TXT: return [enc.encode(value).length, ...enc.encode(value)];
    case RR_TYPES.SOA: return [...wireName(a), ...wireName(b), ...value.split(' ').slice(2).flatMap((n) => u32(Number(n)))];
    case RR_TYPES.CAA: return [Number(a), b.length, ...enc.encode(b), ...enc.encode(c)];
    case RR_TYPES.DS: return [...u16(Number(a)), Number(b), Number(c), ...d.match(/../g)!.map((h) => parseInt(h, 16))];
    case RR_TYPES.DNSKEY: return [...u16(Number(a)), Number(b), Number(c), ...[...atob(d)].map((ch) => ch.charCodeAt(0))];
  }
  throw new Error(`No fake encoding for record type ${type}`);
}

function records(name: string, type: number): { rcode: number; answers: [number, string][] } {
  // One blocklist lists every address, so the "listed" path is covered too.
  const entries: [RrTypeName, string][] | undefined = name.endsWith('.bl.spamcop.net')
    ? [['A', '127.0.0.2'], ['TXT', 'Listed, see https://www.spamcop.net/bl.shtml']]
    : ZONE[name];
  if (!entries) return { rcode: 3, answers: [] };
  return { rcode: 0, answers: entries.filter(([t]) => RR_TYPES[t] === type).map(([t, v]) => [RR_TYPES[t], v]) };
}

/** Wire-format answer to a query; AD is set for the signed zones. */
function dnsAnswer(query: Uint8Array): Uint8Array {
  const q = parseMessage(query).questions[0]!;
  const name = q.name.toLowerCase().replace(/\.$/, '');
  const { rcode, answers } = records(name, q.type);
  const ad = rcode === 0 && (name === 'com' || name === 'example.com' || name.endsWith('.example.com'));
  const out = [...query.subarray(0, 2), 0x80 | (query[2]! & 0x01), 0x80 | (ad ? 0x20 : 0) | rcode, ...u16(1), ...u16(answers.length), 0, 0, 0, 0, ...query.subarray(12)];
  for (const [type, value] of answers) {
    const data = rdata(type, value);
    out.push(...wireName(name), ...u16(type), ...u16(q.cls), ...u32(300), ...u16(data.length), ...data);
  }
  return Uint8Array.from(out);
}

// --- Fake sockets: DNS over TCP/TLS, WHOIS on port 43, a minimal HTTP server otherwise -------------------------

// b.root-servers.net behaves like an instance inside Cloudflare's network, which Workers cannot reach.
const UNREACHABLE = new Set(['170.247.170.2']);
const HTTP_RESPONSE = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok';

function whoisText(server: string, query: string): string {
  if (server === 'whois.iana.org') return `domain:       ${query.toUpperCase()}\nwhois:        whois.denic.de\n`;
  if (server === 'whois.denic.de') return `Domain: ${query.split(' ').pop()}\nStatus: free\n`;
  return '';
}

function fakeConnect({ hostname, port }: SocketAddress): Socket {
  let out!: ReadableStreamDefaultController<Uint8Array>;
  let open = true;
  const end = () => {
    if (!open) return;
    open = false;
    try {
      out.close();
    } catch {
      // The reader already cancelled the stream.
    }
  };
  const readable = new ReadableStream<Uint8Array>({ start(c) { out = c; } });
  let pending: Uint8Array = new Uint8Array(0);
  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      if (port === 53 || port === 853) {
        const { messages, rest } = unframeTcp(Uint8Array.from([...pending, ...chunk]));
        pending = rest;
        for (const m of messages) out.enqueue(frameTcp(dnsAnswer(m)));
        return;
      }
      out.enqueue(enc.encode(port === 43 ? whoisText(hostname, new TextDecoder().decode(chunk).trim()) : HTTP_RESPONSE));
      end();
    },
  });
  const opened = UNREACHABLE.has(hostname)
    ? Promise.reject(new Error('proxy request failed, cannot connect to the specified address'))
    : Promise.resolve({ remoteAddress: hostname, localAddress: '192.0.2.1' });
  opened.catch(() => {});
  return {
    readable, writable, opened, closed: Promise.resolve(), upgraded: false, secureTransport: 'off',
    close: async () => end(),
    startTls: () => { throw new Error('startTls is not faked'); },
  } as unknown as Socket;
}

// --- Fake web, registries and data services ----------------------------------------------------------------

const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, ...u32(1200), ...u32(630), 8, 6, 0, 0, 0]);

const PAGE = `<!doctype html><html><head><title>Example Domain</title>
<meta property="og:title" content="Example Domain">
<meta property="og:description" content="This domain is for use in documentation examples.">
<meta property="og:image" content="https://example.com/og.png">
<meta property="og:url" content="https://example.com/">
<meta name="twitter:card" content="summary_large_image">
<link rel="canonical" href="https://example.com/">
</head><body><p>Example</p></body></html>`;

const WEB: Record<string, () => Response> = {
  'http://example.com/': () => new Response(null, { status: 301, statusText: 'Moved Permanently', headers: { location: 'https://example.com/' } }),
  'https://example.com/': () => new Response(PAGE, {
    statusText: 'OK',
    headers: { 'content-type': 'text/html; charset=utf-8', 'strict-transport-security': 'max-age=31536000', 'x-content-type-options': 'nosniff' },
  }),
  'https://example.com/robots.txt': () => new Response('User-agent: *\nDisallow: /private/\nCrawl-delay: 2\n\nUser-agent: GPTBot\nDisallow: /\n\nSitemap: https://example.com/sitemap.xml\n'),
  'https://example.com/sitemap.xml': () => new Response('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/</loc></url></urlset>'),
  'https://example.com/og.png': () => new Response(PNG, { headers: { 'content-type': 'image/png' } }),
  'https://mta-sts.example.com/.well-known/mta-sts.txt': () => new Response('version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n'),
};

const REGISTRY = 'https://rdap.registry.example/';
const ARIN = 'https://rdap.arin.net/registry/';

const BOOTSTRAP: Record<string, unknown> = {
  // No .de: the availability check answers it over WHOIS.
  'dns.json': { services: [[['com', 'net', 'org', 'io', 'dev', 'app', 'co', 'ai', 'eu', 'xyz', 'me'], [REGISTRY]]] },
  'ipv4.json': { services: [[['8.0.0.0/8', '93.0.0.0/8'], [ARIN]]] },
  'ipv6.json': { services: [[['2001:4800::/23', '2600::/12'], [ARIN]]] },
  'asn.json': { services: [[['1-399260'], [ARIN]]] },
};

const vcard = (...props: [string, string][]) => ['vcard', [['version', {}, 'text', '4.0'], ...props.map(([k, v]) => [k, {}, 'text', v])]];

const domainRdap = (name: string) => ({
  objectClassName: 'domain',
  ldhName: name.toUpperCase(),
  status: ['client transfer prohibited'],
  events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }, { eventAction: 'expiration', eventDate: '2027-08-13T04:00:00Z' }],
  entities: [{ objectClassName: 'entity', roles: ['registrar'], vcardArray: vcard(['fn', 'Example Registrar, Inc.']) }],
  nameservers: [{ objectClassName: 'nameserver', ldhName: 'A.IANA-SERVERS.NET' }],
  secureDNS: { delegationSigned: true },
});

const IP_RDAP = {
  objectClassName: 'ip network', handle: 'NET-8-8-8-0-2', startAddress: '8.8.8.0', endAddress: '8.8.8.255', name: 'GOGL', country: 'US',
  entities: [
    { roles: ['registrant'], vcardArray: vcard(['fn', 'Google LLC'], ['kind', 'org']) },
    { roles: ['abuse'], vcardArray: vcard(['email', 'network-abuse@google.com']) },
  ],
};

const AUTNUM_RDAP = { objectClassName: 'autnum', startAutnum: 15169, endAutnum: 15169, name: 'GOOGLE', entities: [] };

function registry(name: string): Response {
  if (name === 'example.com' || name === 'myproject.com') return Response.json(domainRdap(name));
  // One registry fails, so the "unknown" result of the availability check is covered.
  if (name === 'myproject.io') return new Response('', { status: 503 });
  return Response.json({ errorCode: 404, title: 'Not Found' }, { status: 404 });
}

const RIPESTAT: Record<string, unknown> = {
  'prefix-overview': { resource: '8.8.8.0/24', announced: true, asns: [{ asn: 15169, holder: 'GOOGLE - Google LLC' }] },
  'as-overview': { holder: 'GOOGLE - Google LLC', announced: true },
  'announced-prefixes': { prefixes: [{ prefix: '8.8.8.0/24' }, { prefix: '2001:4860::/32' }] },
  'asn-neighbours': { neighbours: [{ asn: 3356, type: 'left', power: 40 }, { asn: 36040, type: 'right', power: 3 }], neighbour_counts: { left: 1, right: 1 } },
};

const CRT_SH = [
  { issuer_name: "C=US, O=Let's Encrypt, CN=R11", name_value: 'example.com\nwww.example.com', not_before: '2026-10-01T00:00:00', not_after: '2099-01-01T00:00:00' },
  { issuer_name: 'C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1', name_value: '*.example.com', not_before: '2026-01-15T00:00:00', not_after: '2027-01-15T23:59:59' },
];

const CERT_SPOTTER = [{
  dns_names: ['example.com', 'www.example.com'],
  issuer: { friendly_name: "Let's Encrypt", name: "C=US, O=Let's Encrypt, CN=R11" },
  not_before: '2026-10-01T00:00:00Z',
  not_after: '2099-01-01T00:00:00Z',
}];

/** Requests the fake network does not know; each test must end with none. */
const unexpected: string[] = [];

async function fakeFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
  if (init?.method === 'POST' && new Headers(init.headers).get('content-type') === 'application/dns-message') {
    return new Response(dnsAnswer(new Uint8Array(init.body as Uint8Array)), { headers: { 'content-type': 'application/dns-message' } });
  }
  const page = WEB[url.origin + url.pathname];
  if (page) return page();
  const last = url.pathname.split('/').pop()!;
  switch (url.hostname) {
    case 'data.iana.org': return Response.json(BOOTSTRAP[last]);
    case 'rdap.registry.example': return registry(last);
    case 'rdap.arin.net': return Response.json(url.pathname.includes('/autnum/') ? AUTNUM_RDAP : IP_RDAP);
    case 'stat.ripe.net': return Response.json({ status: 'ok', data: RIPESTAT[url.pathname.split('/')[2]!] });
    case 'crt.sh': return Response.json(CRT_SH);
    case 'api.certspotter.com': return Response.json(CERT_SPOTTER);
  }
  unexpected.push(url.href);
  throw new TypeError('fetch failed');
}

interface RewriterHandlers {
  element?(e: { getAttribute(name: string): string | null }): void;
  text?(t: { text: string; lastInTextNode: boolean }): void;
}

/** Just enough of HTMLRewriter (a Workers runtime API) for the social preview: tags, attributes and title text. */
class FakeRewriter {
  private rules: [string, RewriterHandlers][] = [];

  on(selector: string, handlers: RewriterHandlers): this {
    this.rules.push([selector, handlers]);
    return this;
  }

  transform(res: Response): { arrayBuffer(): Promise<ArrayBuffer> } {
    return { arrayBuffer: async () => (this.run(await res.text()), new ArrayBuffer(0)) };
  }

  private run(page: string): void {
    for (const m of page.matchAll(/<([a-z]+)\b([^>]*)>/gi)) {
      const attrs = new Map([...m[2]!.matchAll(/([\w:-]+)="([^"]*)"/g)].map((a) => [a[1]!.toLowerCase(), a[2]!] as const));
      for (const [selector, h] of this.rules) {
        const [, tag, attr, word] = selector.match(/^(\w+)(?:\[(\w+)(?:~="(\w+)" i)?\])?$/) ?? [];
        if (tag !== m[1]!.toLowerCase() || (attr && !attrs.has(attr))) continue;
        if (attr && word && !attrs.get(attr)!.toLowerCase().split(/\s+/).includes(word)) continue;
        h.element?.({ getAttribute: (name) => attrs.get(name) ?? null });
        h.text?.({ text: page.slice(m.index! + m[0].length).split('<')[0]!, lastInTextNode: true });
      }
    }
  }
}

// --- Worker environment ------------------------------------------------------------------------------------

// The Workers types have no Node declarations; fetch the one function needed.
const { readFileSync } = (globalThis as unknown as {
  process: { getBuiltinModule(id: 'node:fs'): { readFileSync(path: string): Uint8Array } };
}).process.getBuiltinModule('node:fs');

const now = Math.floor(Date.now() / 1000);
const HISTORY_ROWS = [
  { root: 'A', bucket: 47, colo: 'FRA', n: 2, ok: 2, avg_ms: 11.5, serial: 2026112400 },
  // D1 returns buckets as REAL.
  { root: 'B', bucket: 46.6, colo: 'FRA', n: 2, ok: 0, avg_ms: null, serial: null },
];
const LATEST_ROWS = [
  { root: 'A', ts: now - 60, colo: 'FRA', ok: 1, query_ms: 11, serial: 2026112400, instance: 'fra1a' },
  { root: 'B', ts: now - 60, colo: 'FRA', ok: 0, query_ms: null, serial: null, instance: null },
];

const env = {
  SITE_URL: 'https://tools.example.org',
  // Serves public/data from disk like the ASSETS binding (geo data for the IP lookup).
  ASSETS: {
    async fetch(req: Request) {
      try {
        return new Response(readFileSync(`public${new URL(req.url).pathname}`));
      } catch {
        return new Response('not found', { status: 404 });
      }
    },
  },
  EVENTS: { writeDataPoint() {} },
  DB: {
    prepare(sql: string) {
      const stmt = { bind: () => stmt, all: async () => ({ results: sql.includes('GROUP BY') ? HISTORY_ROWS : LATEST_ROWS }) };
      return stmt;
    },
  },
} as unknown as Env;

const exec = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

const CF = {
  colo: 'FRA', country: 'DE', city: 'Frankfurt am Main', region: 'Hesse', timezone: 'Europe/Berlin', asn: 3320, asOrganization: 'Deutsche Telekom AG',
  httpProtocol: 'HTTP/2', tlsVersion: 'TLSv1.3', tlsCipher: 'AEAD-AES128-GCM-SHA256', clientTcpRtt: 14,
};

/** A request as the app sends it. */
function call(path: string, init: RequestInit = {}, opts: { ip?: string; env?: Env } = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set('accept', 'application/json');
  headers.set('x-client', 'nettools-ios/test');
  headers.set('user-agent', 'nettools-ios/test');
  headers.set('cf-connecting-ip', opts.ip ?? '8.8.4.4');
  const req = new Request(`https://tools.example.org${path}`, { ...init, headers });
  Object.defineProperty(req, 'cf', { value: CF });
  return worker.fetch(req as never, opts.env ?? env, exec);
}

beforeAll(() => {
  vi.spyOn(console, 'log').mockImplementation(() => {});
});

beforeEach(() => {
  unexpected.length = 0;
  vi.stubGlobal('fetch', fakeFetch);
  vi.stubGlobal('HTMLRewriter', FakeRewriter);
});

afterEach(() => {
  vi.unstubAllGlobals();
  expect(unexpected, 'requests the fake network does not answer').toEqual([]);
});

afterAll(() => {
  vi.restoreAllMocks();
});

// --- Tests -------------------------------------------------------------------------------------------------

interface Case {
  name: string;
  /** Path and query as the app sends them. */
  path: string;
  schema: Schema;
  status?: number;
  ip?: string;
  check?: (body: any) => void;
}

const CASES: Case[] = [
  { name: 'what-is-my-ip', path: '/api/what-is-my-ip', schema: MY_IP, check: (b) => expect(b.hostname).toBe('dns.google') },
  { name: 'what-is-my-ip over IPv6', path: '/api/what-is-my-ip', ip: '2001:4860:4860::8844', schema: MY_IP, check: (b) => expect(b.version).toBe(6) },
  {
    name: 'tools', path: '/api/tools', schema: list(WEB_TOOL),
    check: (b) => expect(b).toContainEqual(expect.objectContaining({ slug: 'whois', landing: false })),
  },
  {
    name: 'dns-lookup', path: '/api/dns-lookup?name=example.com&resolver=cloudflare&type=A', schema: DNS_LOOKUP,
    check: (b) => expect(b.results[0]).toMatchObject({ type: 'A', rcodeName: 'NOERROR', answers: [{ data: '93.184.215.14' }] }),
  },
  {
    name: 'dns-lookup over DNS-over-TLS', path: '/api/dns-lookup?name=example.com&resolver=quad9&type=MX', schema: DNS_LOOKUP,
    check: (b) => expect(b.results[0]).toMatchObject({ type: 'MX', answers: [{ data: '10 mail.example.com.' }] }),
  },
  {
    name: 'dns-lookup reverse', path: '/api/dns-lookup?name=8.8.8.8&resolver=google&type=PTR', schema: DNS_LOOKUP,
    check: (b) => expect(b.results[0]).toMatchObject({ type: 'PTR', answers: [{ data: 'dns.google.' }] }),
  },
  {
    name: 'port-checker', path: '/api/port-checker?host=dns.google&ports=443', schema: PORT_CHECK,
    check: (b) => expect(b.results[0]).toMatchObject({ port: 443, state: 'open' }),
  },
  { name: 'port-checker on the own IP with a group', path: '/api/port-checker?preset=web', schema: PORT_CHECK, check: (b) => expect(b.host).toBe('8.8.4.4') },
  { name: 'tcp-ping', path: '/api/tcp-ping?host=example.com&port=443', schema: TCP_PING, check: (b) => expect(b.probes).toHaveLength(8) },
  {
    name: 'ip-lookup', path: '/api/ip-lookup?q=8.8.8.8', schema: IP_LOOKUP,
    check: (b) => {
      expect(b).toMatchObject({ country: 'US', prefix: '8.8.8.0/24', owner: { organization: 'Google LLC' }, origins: [{ asn: 15169 }] });
      expect(b.blocklists.listed).toEqual(['SpamCop']);
    },
  },
  { name: 'ip-lookup by host name', path: '/api/ip-lookup?q=example.com', schema: IP_LOOKUP, check: (b) => expect(b).toMatchObject({ ip: '93.184.215.14', host: 'example.com' }) },
  {
    name: 'asn-lookup for an AS', path: '/api/asn-lookup?q=AS15169', schema: ASN_REPORT,
    check: (b) => {
      expect(b).not.toHaveProperty('query');
      expect(b.upstreams).toEqual([{ asn: 3356, power: 40 }]);
    },
  },
  {
    name: 'asn-lookup for an address', path: '/api/asn-lookup?q=8.8.8.8', schema: ROUTED_PREFIX,
    check: (b) => expect(b.as).toMatchObject({ asn: 15169, v4: ['8.8.8.0/24'] }),
  },
  {
    name: 'blacklist-check', path: '/api/blacklist-check?q=example.com', schema: BLACKLIST,
    check: (b) => expect(b.results.map((r: { state: string }) => r.state)).toContain('listed'),
  },
  {
    name: 'dns-benchmark', path: '/api/dns-benchmark?name=example.com', schema: DNS_BENCHMARK,
    check: (b) => expect(b.results.every((r: { failures: number }) => r.failures === 0)).toBe(true),
  },
  {
    name: 'ssl-check', path: '/api/ssl-check?host=example.com', schema: SSL_CHECK,
    check: (b) => expect(b).toMatchObject({ tcp: true, tls: true, redirectsToHttps: true, certs: [{ issuer: "Let's Encrypt" }] }),
  },
  {
    name: 'email-security', path: '/api/email-security?domain=example.com&selector=sel1', schema: EMAIL_SECURITY,
    check: (b) => {
      // The grade is computed from these three rows.
      expect(b.rows.map((r: { check: string }) => r.check)).toEqual(expect.arrayContaining(['SPF', 'DKIM', 'DMARC']));
      expect(b.spf.tree.includes[0].domain).toBe('_spf.example.net');
      expect(b.mtaSts.policy.maxAge).toBe(604800);
    },
  },
  {
    name: 'whois for a domain', path: '/api/whois?q=example.com', schema: WHOIS,
    check: (b) => expect(b).toMatchObject({ kind: 'domain', notFound: false, rdap: { ldhName: 'EXAMPLE.COM' } }),
  },
  { name: 'whois for an address', path: '/api/whois?q=8.8.8.8', schema: WHOIS, check: (b) => expect(b.rdap.name).toBe('GOGL') },
  { name: 'whois for an AS', path: '/api/whois?q=AS15169', schema: WHOIS, check: (b) => expect(b.rdap.startAutnum).toBe(15169) },
  // The app accepts HTTP 404 as a result only together with notFound: true.
  { name: 'whois for an unregistered name', path: '/api/whois?q=unregistered-name.com', schema: WHOIS, status: 404, check: (b) => expect(b.notFound).toBe(true) },
  {
    name: 'http-headers', path: '/api/http-headers?url=http://example.com', schema: HTTP_HEADERS,
    check: (b) => expect(b.hops.map((h: { status: number }) => h.status)).toEqual([301, 200]),
  },
  { name: 'is-it-down', path: '/api/is-it-down?url=example.com', schema: IS_IT_DOWN, check: (b) => expect(b.verdict).toBe('up') },
  { name: 'is-it-down for a site that is down', path: '/api/is-it-down?url=down.example.com', schema: IS_IT_DOWN, check: (b) => expect(b.verdict).toBe('down') },
  { name: 'dnssec-check', path: '/api/dnssec-check?name=example.com', schema: DNSSEC, check: (b) => expect(b).toMatchObject({ verdict: 'secure', zones: [{ linked: true }, { linked: true }] }) },
  {
    name: 'domain-availability', path: '/api/domain-availability?name=myproject', schema: DOMAIN_AVAILABILITY,
    check: (b) => {
      const status = Object.fromEntries(b.results.map((r: { domain: string; status: string }) => [r.domain, r.status]));
      expect(status).toMatchObject({ 'myproject.com': 'taken', 'myproject.de': 'available', 'myproject.io': 'unknown' });
    },
  },
  { name: 'subdomain-finder', path: '/api/subdomain-finder?domain=example.com', schema: SUBDOMAINS, check: (b) => expect(b.hosts).toHaveLength(3) },
  { name: 'subdomain-finder with expired certificates', path: '/api/subdomain-finder?domain=example.com&expired=1', schema: SUBDOMAINS, check: (b) => expect(b.includeExpired).toBe(true) },
  {
    name: 'response-time', path: '/api/response-time?url=https://example.com', schema: RESPONSE_TIME,
    check: (b) => expect(b.runs.map((r: { status: string }) => r.status)).toEqual(Array(3).fill('HTTP/1.1 200 OK')),
  },
  {
    name: 'robots-txt', path: '/api/robots-txt?agent=Googlebot&path=/private/&url=example.com', schema: ROBOTS,
    check: (b) => expect(b).toMatchObject({ status: 200, test: { allowed: false }, sitemap: { kind: 'urlset', entries: 1 } }),
  },
  {
    name: 'social-preview', path: '/api/social-preview?url=https://example.com', schema: SOCIAL_PREVIEW,
    check: (b) => expect(b).toMatchObject({ meta: { tags: { 'og:title': 'Example Domain' } }, image: { ok: true, size: { width: 1200, height: 630 } } }),
  },
  {
    name: 'root-dns-servers', path: '/api/root-dns-servers', schema: ROOT_LIVE,
    check: (b) => {
      expect(b.results).toHaveLength(13);
      // The app takes the root letter from the first character.
      expect(b.results.map((r: { root: string }) => r.root[0]).join('')).toBe('abcdefghijklm');
      expect(b.results[1]).toMatchObject({ untestable: true });
      expect(b.results[0]).toMatchObject({ serial: 2026112400, instance: 'fra1a' });
    },
  },
  { name: 'root-dns-servers history', path: '/api/root-dns-servers/history', schema: ROOT_HISTORY, check: (b) => expect(b.latest.A).toMatchObject({ ok: true, queryMs: 11 }) },
];

describe('app contract: response fields', () => {
  for (const c of CASES) {
    it(c.name, async () => {
      const res = await call(c.path, {}, { ip: c.ip });
      expect(res.status).toBe(c.status ?? 200);
      expect(res.headers.get('content-type')).toContain('application/json');
      const body = await res.json();
      expect(violations(body, c.schema)).toEqual([]);
      c.check?.(body);
    });
  }

  it('detects removed, renamed and retyped fields', () => {
    const result = { port: 443, state: 'open', ms: 12, detail: null };
    expect(violations({ host: 'example.com', results: [result] }, PORT_CHECK)).toEqual([]);
    expect(violations({ hostname: 'example.com', results: [result] }, PORT_CHECK)).toEqual(['host: missing']);
    expect(violations({ host: 'example.com', results: [{ ...result, port: '443' }] }, PORT_CHECK)).toEqual(['results[0].port: expected int, got "443"']);
    expect(violations({ host: 'example.com', results: [{ ...result, ms: 12.5 }] }, PORT_CHECK)).toEqual(['results[0].ms: expected int, got 12.5']);
    expect(violations({ host: 'example.com', results: [{ ...result, state: 'reachable' }] }, PORT_CHECK)).toHaveLength(1);
  });
});

describe('app contract: inputs', () => {
  it('accepts every resolver and record type the app offers', async () => {
    for (const id of APP_RESOLVERS) {
      const res = await call(`/api/dns-lookup?name=example.com&resolver=${id}&type=A`);
      expect(res.status, id).toBe(200);
    }
    for (const type of APP_RECORD_TYPES) {
      const res = await call(`/api/dns-lookup?name=example.com&resolver=cloudflare&type=${type}`);
      expect(res.status, type).toBe(200);
      expect(((await res.json()) as { results: { type: string }[] }).results[0]!.type).toBe(type);
    }
  });

  it('accepts every port group the app offers', async () => {
    for (const preset of APP_PORT_GROUPS) {
      const res = await call(`/api/port-checker?host=example.com&preset=${preset}`);
      expect(res.status, preset).toBe(200);
      expect(((await res.json()) as { results: unknown[] }).results.length, preset).toBeGreaterThan(0);
    }
  });

  it('serves the social preview image proxy', async () => {
    const res = await call('/api/social-preview/image?url=https://example.com/og.png');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('image/png');
  });
});

describe('app contract: speed test', () => {
  it('answers the latency probe with a 2xx status', async () => {
    expect((await call('/api/speed-test/ping?r=abc')).ok).toBe(true);
  });

  it('serves downloads up to the largest size the app requests', async () => {
    const small = await call('/api/speed-test/down?bytes=1000000&r=abc');
    expect(small.status).toBe(200);
    expect((await small.arrayBuffer()).byteLength).toBe(1_000_000);
    const largest = await call('/api/speed-test/down?bytes=50000000&r=abc');
    expect(largest.headers.get('content-length')).toBe('50000000');
    await largest.body?.cancel();
  });

  it('accepts uploads up to the largest size the app sends', async () => {
    const res = await call('/api/speed-test/up?r=abc', {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: new Uint8Array(16_000_000),
    });
    expect(res.status).toBe(200);
  });
});

describe('app contract: errors', () => {
  const BAD_INPUT = [
    '/api/dns-lookup?name=exa%20mple&resolver=cloudflare&type=A',
    '/api/dns-lookup?name=example.com&resolver=cloudflare&type=BOGUS',
    '/api/port-checker?host=example.com&ports=70000',
    '/api/tcp-ping?host=example.com&port=0',
    '/api/ip-lookup?q=192.168.1.1',
    '/api/asn-lookup?q=not-an-asn',
    '/api/blacklist-check?q=2001:db8::1',
    '/api/dns-benchmark?name=localhost',
    '/api/ssl-check?host=',
    '/api/email-security?domain=localhost',
    '/api/whois?q=',
    '/api/http-headers?url=ftp://example.com',
    '/api/is-it-down?url=http://192.168.1.1',
    '/api/dnssec-check?name=localhost',
    '/api/domain-availability?name=-bad-',
    '/api/subdomain-finder?domain=localhost',
    '/api/response-time?url=localhost',
    '/api/robots-txt?url=localhost',
    '/api/social-preview?url=localhost',
  ];

  // The app shows the "error" string of any answer that has one.
  it('answers invalid input with HTTP 400 and an error message', async () => {
    for (const path of BAD_INPUT) {
      const res = await call(path);
      expect(res.status, path).toBe(400);
      expect(res.headers.get('content-type'), path).toContain('application/json');
      expect(violations(await res.json(), { error: 'string' }), path).toEqual([]);
    }
  });

  it('answers rate limits with HTTP 429, a numeric Retry-After and an error message', async () => {
    const deny = { limit: async () => ({ success: false }) };
    const pass = { limit: async () => ({ success: true }) };
    const limited: [string, Partial<Env>][] = [
      ['/api/whois?q=example.com', { RL_TOOLS: deny as unknown as RateLimit }],
      ['/api/subdomain-finder?domain=example.com', { RL_TOOLS: pass as unknown as RateLimit, RL_HEAVY: deny as unknown as RateLimit }],
      ['/api/speed-test/down?bytes=10&r=abc', { RL_SPEED: deny as unknown as RateLimit }],
    ];
    for (const [path, limits] of limited) {
      const res = await call(path, {}, { env: { ...env, ...limits } });
      expect(res.status, path).toBe(429);
      expect(res.headers.get('retry-after'), path).toMatch(/^\d+$/);
      expect(violations(await res.json(), { error: 'string' }), path).toEqual([]);
    }
  });
});
