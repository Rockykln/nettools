// Decides whether a user-supplied host may be contacted by the server (HTTP checks, port checks, TCP ping).
// Private, loopback, link-local and other special-purpose ranges are refused, and so is this site itself.
import { RR_TYPES } from './dns';
import { cidrContains, isIP } from './net';
import { RESOLVERS, resolve } from './transport';

const BLOCKED_RANGES = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
  '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
  '192.88.99.0/24', '224.0.0.0/4', '240.0.0.0/4',
  // ::/96 also covers ::/128, ::1/128 and the deprecated IPv4-compatible form (::127.0.0.1).
  '::/96', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64', '2001::/32', '2001:2::/48', '2001:10::/28', '2001:20::/28',
  '2001:db8::/32', '2002::/16', '3fff::/20', '5f00::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
];

// https://www.cloudflare.com/ips/ plus the 1.1.1.1 resolver. Workers cannot open TCP sockets to these.
const CLOUDFLARE_RANGES = [
  '1.1.1.0/24', '1.0.0.0/24', '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
  '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15',
  '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/29',
];

export function isCloudflareAddress(ip: string): boolean {
  return isIP(ip) && CLOUDFLARE_RANGES.some((cidr) => cidrContains(cidr, ip));
}

export const CLOUDFLARE_SOCKET_NOTE = 'Cloudflare Workers cannot open TCP connections to Cloudflare addresses, so this check cannot run from here.';

export function isPublicAddress(ip: string): boolean {
  return isIP(ip) && !BLOCKED_RANGES.some((cidr) => cidrContains(cidr, ip));
}

/** `policy`: the target is not allowed (private, own site); `dns`: its addresses could not be determined. */
export type TargetCheck = { ok: true; addresses: string[] } | { ok: false; reason: string; kind: 'policy' | 'dns' };

// Host names are parsed like a URL host, so numeric IPv4 forms (2130706433, 0x7f.1, 127.1) become dotted quads
// and IDNs become punycode before any check. Returns null for unparsable input.
export function canonicalHost(host: string): string | null {
  const h = host.trim().replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (!h) return null;
  if (h.includes(':')) return isIP(h) ? h : null;
  try {
    const parsed = new URL(`http://${h}/`).hostname;
    return parsed.startsWith('[') ? null : parsed.replace(/\.$/, '');
  } catch {
    return null;
  }
}

/** Resolves `host` (if it is a name) and accepts it only if every address is public and it is not this site. */
export async function checkTarget(host: string, env: Env, opts: { sockets?: boolean } = {}): Promise<TargetCheck> {
  const r = await resolveTarget(host, env);
  // Tools that open raw TCP sockets cannot reach Cloudflare's network; say so instead of reporting a failure.
  if (r.ok && opts.sockets && r.addresses.some(isCloudflareAddress)) {
    return { ok: false, kind: 'policy', reason: `${host} ${isIP(host) ? 'belongs to Cloudflare' : 'is served by Cloudflare'}. ${CLOUDFLARE_SOCKET_NOTE}` };
  }
  return r;
}

// The whole zone of this site (e.g. rockykln.com) is excluded, not only its own host name.
// An IP-address SITE_URL (local development) only excludes that exact address.
export function isOwnHost(h: string, env: { SITE_URL: string }): boolean {
  const site = new URL(env.SITE_URL).hostname.replace(/^\[|\]$/g, '');
  if (isIP(site)) return h === site;
  const own = site.split('.').slice(-2).join('.');
  return h === own || h.endsWith(`.${own}`);
}

async function resolveTarget(host: string, env: Env): Promise<TargetCheck> {
  const h = canonicalHost(host);
  if (!h) return { ok: false, kind: 'policy', reason: 'This is not a valid host name.' };
  if (isOwnHost(h, env)) return { ok: false, kind: 'policy', reason: 'This site cannot check itself.' };
  if (isIP(h)) {
    return isPublicAddress(h) ? { ok: true, addresses: [h] } : { ok: false, kind: 'policy', reason: 'Private, local and reserved addresses cannot be checked.' };
  }
  const answers = await Promise.all(
    [RR_TYPES.A, RR_TYPES.AAAA].map((t) => resolve(RESOLVERS[0]!, h, t).then((r) => r.message.answers.filter((a) => a.type === t).map((a) => a.data)).catch(() => null)),
  );
  // If either lookup failed, the unchecked family could still be used for the connection, so refuse.
  if (answers.some((a) => a === null)) return { ok: false, kind: 'dns', reason: `The address of ${h} could not be checked right now. Please try again.` };
  const addresses = answers.flat() as string[];
  if (!addresses.length) return { ok: false, kind: 'dns', reason: `${h} does not resolve to an IP address.` };
  if (!addresses.every(isPublicAddress)) return { ok: false, kind: 'policy', reason: `${h} points to a private or reserved address, which cannot be checked.` };
  return { ok: true, addresses };
}
