import { socketHost } from './net';
import { connect } from 'cloudflare:sockets';
import { buildQuery, frameTcp, parseMessage, unframeTcp, type DnsMessage } from './dns';

export class TimeoutError extends Error {}

export function withTimeout<T>(p: Promise<T>, ms: number, onTimeout?: () => void): Promise<T> {
  let timer: number | null = null;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      onTimeout?.();
      reject(new TimeoutError(`No response within ${ms} ms`));
    }, ms);
  });
  return Promise.race([p, expired]).finally(() => clearTimeout(timer));
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

export interface TcpDnsResult {
  connectMs: number;
  totalMs: number;
  /** Responses in the same order as the queries. */
  messages: DnsMessage[];
}

// Sends one or more queries over a single DNS-over-TCP connection (RFC 7766 pipelining).
export interface TcpOptions {
  port?: number;
  /** DNS over TLS (RFC 7858), normally on port 853. */
  tls?: boolean;
}

export async function dnsOverTcp(host: string, queries: Uint8Array[], timeoutMs = 4000, opts: TcpOptions = {}): Promise<TcpDnsResult> {
  const start = Date.now();
  const socket = connect({ hostname: socketHost(host), port: opts.port ?? (opts.tls ? 853 : 53) }, { secureTransport: opts.tls ? 'on' : 'off', allowHalfOpen: false });
  const exchange = async (): Promise<TcpDnsResult> => {
    await socket.opened;
    const connectMs = Date.now() - start;
    const writer = socket.writable.getWriter();
    for (const q of queries) await writer.write(frameTcp(q));
    const reader = socket.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
    let buf: Uint8Array = new Uint8Array(0);
    const byId = new Map<number, DnsMessage>();
    while (byId.size < queries.length) {
      const { value, done } = await reader.read();
      if (done) break;
      const { messages, rest } = unframeTcp(concat(buf, value));
      buf = rest;
      for (const m of messages) {
        const parsed = parseMessage(m);
        byId.set(parsed.id, parsed);
      }
    }
    const ordered = queries.map((q) => byId.get((q[0]! << 8) | q[1]!));
    if (ordered.some((m) => !m)) throw new Error('Connection closed before all answers arrived');
    return { connectMs, totalMs: Date.now() - start, messages: ordered as DnsMessage[] };
  };
  try {
    return await withTimeout(exchange(), timeoutMs, () => void socket.close().catch(() => {}));
  } finally {
    socket.close().catch(() => {});
  }
}

/** True if the resolver answered the question (NOERROR or NXDOMAIN), not an error such as SERVFAIL. */
export const isAnswer = (m: DnsMessage): boolean => m.rcode === 0 || m.rcode === 3;

/**
 * Sends queries one after another over a single DNS-over-TLS connection and times each answer.
 * The first time includes the TCP and TLS handshake; the others show the resolver on a warm connection.
 */
export async function dotSequential(host: string, queries: Uint8Array[], timeoutMs = 3000): Promise<(number | null)[]> {
  const start = Date.now();
  const socket = connect({ hostname: socketHost(host), port: 853 }, { secureTransport: 'on', allowHalfOpen: false });
  const times: (number | null)[] = queries.map(() => null);
  try {
    await withTimeout(socket.opened, timeoutMs);
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
    let buf: Uint8Array = new Uint8Array(0);
    const readOne = async (): Promise<Uint8Array | null> => {
      for (;;) {
        const { messages, rest } = unframeTcp(buf);
        if (messages.length) {
          buf = rest;
          return messages[0]!;
        }
        const { value, done } = await reader.read();
        if (done) return null;
        buf = concat(buf, value);
      }
    };
    for (let i = 0; i < queries.length; i++) {
      const t0 = i === 0 ? start : Date.now();
      await writer.write(frameTcp(queries[i]!));
      // Each query gets its own timeout, like a single DoH request.
      const answer = await withTimeout(readOne(), timeoutMs);
      if (!answer) break;
      // An error answer (e.g. SERVFAIL) is not a successful lookup; NXDOMAIN is a valid answer.
      if (isAnswer(parseMessage(answer))) times[i] = Date.now() - t0;
    }
  } catch {
    // Unanswered queries stay null and count as failures.
  } finally {
    socket.close().catch(() => {});
  }
  return times;
}

interface ResolverBase {
  id: string;
  name: string;
  location: string;
  /** Only queried when chosen explicitly, never in "compare all" (e.g. no EU adequacy decision for its country). */
  explicitOnly?: boolean;
}

interface DohResolver extends ResolverBase {
  transport: 'doh';
  url: string;
  /** Same endpoint by IP address, for local development on networks that block DoH host names. */
  ipUrl?: string;
}

// Quad9 serves DoH only over HTTP/2, which Worker subrequests cannot rely on, so it is queried over TLS.
interface DotResolver extends ResolverBase {
  transport: 'dot';
  host: string;
  ip: string;
}

export type Resolver = DohResolver | DotResolver;

// Unfiltered public resolvers that answer DoH over HTTP/1.1. Order is the order shown in the UI.
export const RESOLVERS: Resolver[] = [
  { id: 'cloudflare', name: 'Cloudflare', location: 'Global anycast', transport: 'doh', url: 'https://cloudflare-dns.com/dns-query', ipUrl: 'https://1.1.1.1/dns-query' },
  { id: 'google', name: 'Google', location: 'Global anycast', transport: 'doh', url: 'https://dns.google/dns-query', ipUrl: 'https://8.8.8.8/dns-query' },
  { id: 'quad9', name: 'Quad9', location: 'Global anycast', transport: 'dot', host: 'dns.quad9.net', ip: '9.9.9.9' },
  { id: 'opendns', name: 'OpenDNS (Cisco)', location: 'Global anycast', transport: 'doh', url: 'https://doh.opendns.com/dns-query' },
  { id: 'adguard', name: 'AdGuard (unfiltered)', location: 'Global anycast', transport: 'doh', url: 'https://unfiltered.adguard-dns.com/dns-query' },
  { id: 'controld', name: 'Control D', location: 'Global anycast', transport: 'doh', url: 'https://freedns.controld.com/p0' },
  { id: 'nextdns', name: 'NextDNS', location: 'Global anycast', transport: 'doh', url: 'https://dns.nextdns.io/dns-query' },
  { id: 'dnssb', name: 'DNS.SB', location: 'Global anycast', transport: 'doh', url: 'https://doh.dns.sb/dns-query' },
  { id: 'wikimedia', name: 'Wikimedia DNS', location: 'Global anycast', transport: 'doh', url: 'https://wikimedia-dns.org/dns-query' },
  { id: 'iij', name: 'IIJ', location: 'Japan', transport: 'doh', url: 'https://public.dns.iij.jp/dns-query' },
  { id: 'alidns', name: 'AliDNS', location: 'China', transport: 'doh', url: 'https://dns.alidns.com/dns-query', explicitOnly: true },
];

/** Resolvers used by "compare all". */
export const COMPARE_RESOLVERS = RESOLVERS.filter((r) => !r.explicitOnly);

let byIp = false;

// Set from the DOH_BY_IP variable in .dev.vars; never enabled in production.
export function setDohByIp(enabled: boolean): void {
  byIp = enabled;
}

export const dohByIp = (): boolean => byIp;

export interface ResolveResult {
  message: DnsMessage;
  ms: number;
}

export async function resolve(resolver: Resolver, name: string, type: number, timeoutMs = 4000, opts: { cd?: boolean } = {}): Promise<ResolveResult> {
  try {
    return await resolveRaw(resolver, name, type, timeoutMs, opts.cd ?? false);
  } catch (e) {
    if (e instanceof TimeoutError) throw new Error(`${resolver.name} did not answer within ${timeoutMs / 1000} s`);
    if (e instanceof Error && e.message.startsWith(resolver.name)) throw e;
    // Runtime network errors carry internal references that mean nothing to users.
    throw new Error(`${resolver.name} is not reachable right now`);
  }
}

async function resolveRaw(resolver: Resolver, name: string, type: number, timeoutMs: number, cd: boolean): Promise<ResolveResult> {
  if (resolver.transport === 'dot') {
    const query = buildQuery(name, type, { ad: true, cd });
    const res = await dnsOverTcp(byIp ? resolver.ip : resolver.host, [query], timeoutMs, { tls: true });
    return { message: res.messages[0]!, ms: res.totalMs };
  }
  // ID 0 keeps DoH responses cacheable (RFC 8484 section 4.1).
  const body = buildQuery(name, type, { id: 0, ad: true, cd });
  const start = Date.now();
  const res = await withTimeout(
    fetch(byIp && resolver.ipUrl ? resolver.ipUrl : resolver.url, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
      body,
    }),
    timeoutMs,
  );
  if (!res.ok) throw new Error(`${resolver.name} returned HTTP ${res.status}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  const ms = Date.now() - start;
  let message: DnsMessage;
  try {
    message = parseMessage(buf);
  } catch {
    throw new Error(`${resolver.name} returned an invalid DNS response`);
  }
  return { message, ms };
}

const WHOIS_MAX_BYTES = 256 * 1024;

// Plain WHOIS (RFC 3912) over TCP port 43.
export async function whoisQuery(server: string, query: string, timeoutMs = 6000): Promise<string> {
  const socket = connect({ hostname: socketHost(server), port: 43 });
  const exchange = async (): Promise<string> => {
    const writer = socket.writable.getWriter();
    await writer.write(new TextEncoder().encode(`${query}\r\n`));
    const reader = socket.readable.getReader() as ReadableStreamDefaultReader<Uint8Array>;
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (size < WHOIS_MAX_BYTES) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
      size += value.byteLength;
    }
    const buf = new Uint8Array(size);
    let off = 0;
    for (const ch of chunks) {
      buf.set(ch, off);
      off += ch.byteLength;
    }
    return new TextDecoder('utf-8').decode(buf);
  };
  try {
    return await withTimeout(exchange(), timeoutMs, () => void socket.close().catch(() => {}));
  } finally {
    socket.close().catch(() => {});
  }
}
