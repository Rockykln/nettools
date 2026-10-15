import { describe, expect, it } from 'vitest';
import { RR_TYPES, buildQuery, dnskeyTag, encodeName, formatIPv6, frameTcp, parseMessage, unframeTcp } from '../src/core/dns';

// Builds a response to `query` with the given answer records (already wire-encoded, name as pointer to the question).
function response(query: Uint8Array, answers: { type: number; ttl: number; rdata: number[] }[], flags = 0x8180): Uint8Array {
  const out = [...query];
  out[2] = flags >> 8;
  out[3] = flags & 0xff;
  out[6] = 0;
  out[7] = answers.length;
  for (const a of answers) {
    out.push(0xc0, 12, a.type >> 8, a.type & 0xff, 0, 1, (a.ttl >>> 24) & 0xff, (a.ttl >>> 16) & 0xff, (a.ttl >>> 8) & 0xff, a.ttl & 0xff);
    out.push(a.rdata.length >> 8, a.rdata.length & 0xff, ...a.rdata);
  }
  return Uint8Array.from(out);
}

const label = (s: string) => [s.length, ...new TextEncoder().encode(s)];

describe('encodeName', () => {
  it('encodes labels and the root', () => {
    expect([...encodeName('example.com')]).toEqual([...label('example'), ...label('com'), 0]);
    expect([...encodeName('example.com.')]).toEqual([...label('example'), ...label('com'), 0]);
    expect([...encodeName('.')]).toEqual([0]);
  });

  it('rejects empty and oversized labels', () => {
    expect(() => encodeName('a..b')).toThrow();
    expect(() => encodeName(`${'a'.repeat(64)}.com`)).toThrow();
  });
});

describe('buildQuery', () => {
  it('sets id, flags and question', () => {
    const q = buildQuery('example.com', RR_TYPES.MX, { id: 0x1234, ad: true });
    expect(q[0]).toBe(0x12);
    expect(q[1]).toBe(0x34);
    expect((q[2]! << 8) | q[3]!).toBe(0x0120);
    expect((q[q.length - 4]! << 8) | q[q.length - 3]!).toBe(RR_TYPES.MX);
  });

  it('clears RD for iterative queries', () => {
    const q = buildQuery('.', RR_TYPES.SOA, { rd: false });
    expect((q[2]! << 8) | q[3]!).toBe(0);
  });
});

describe('parseMessage', () => {
  it('parses A, MX, TXT and CAA answers with name compression', () => {
    const q = buildQuery('example.com', RR_TYPES.A, { id: 7 });
    const msg = parseMessage(
      response(q, [
        { type: RR_TYPES.A, ttl: 300, rdata: [93, 184, 215, 14] },
        { type: RR_TYPES.MX, ttl: 60, rdata: [0, 10, ...label('mail'), 0xc0, 12] },
        { type: RR_TYPES.TXT, ttl: 60, rdata: [...label('v=spf1 -all'), ...label('say "hi"')] },
        { type: RR_TYPES.CAA, ttl: 60, rdata: [0, 5, ...new TextEncoder().encode('issuepki.example')] },
      ]),
    );
    expect(msg.id).toBe(7);
    expect(msg.rcodeName).toBe('NOERROR');
    expect(msg.ra).toBe(true);
    expect(msg.answers.map((a) => [a.name, a.typeName, a.ttl, a.data])).toEqual([
      ['example.com.', 'A', 300, '93.184.215.14'],
      ['example.com.', 'MX', 60, '10 mail.example.com.'],
      ['example.com.', 'TXT', 60, '"v=spf1 -all" "say \\"hi\\""'],
      ['example.com.', 'CAA', 60, '0 issue "pki.example"'],
    ]);
  });

  it('reports NXDOMAIN', () => {
    const q = buildQuery('nope.example', RR_TYPES.A);
    expect(parseMessage(response(q, [], 0x8183)).rcodeName).toBe('NXDOMAIN');
  });

  it('parses SOA records', () => {
    const q = buildQuery('.', RR_TYPES.SOA, { rd: false });
    const rdata = [...label('a'), ...label('root-servers'), ...label('net'), 0, ...label('nstld'), ...label('verisign-grs'), ...label('com'), 0];
    for (const n of [2026101500, 1800, 900, 604800, 86400]) rdata.push((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
    const msg = parseMessage(response(q, [{ type: RR_TYPES.SOA, ttl: 86400, rdata }], 0x8400));
    expect(msg.aa).toBe(true);
    expect(msg.answers[0]!.name).toBe('.');
    expect(msg.answers[0]!.data).toBe('a.root-servers.net. nstld.verisign-grs.com. 2026101500 1800 900 604800 86400');
  });

  it('throws on truncated input and pointer loops', () => {
    expect(() => parseMessage(new Uint8Array([0, 1, 0]))).toThrow();
    const q = buildQuery('a', RR_TYPES.A);
    const loop = response(q, [{ type: RR_TYPES.CNAME, ttl: 1, rdata: [0xc0, 0] }]);
    const ptrOffset = loop.length - 2;
    loop[ptrOffset] = 0xc0;
    loop[ptrOffset + 1] = ptrOffset;
    expect(() => parseMessage(loop)).toThrow();
  });
});

describe('formatIPv6', () => {
  it('compresses the longest zero run', () => {
    const b = new Uint8Array(16);
    b[0] = 0x20; b[1] = 0x01; b[2] = 0x0d; b[3] = 0xb8; b[15] = 1;
    expect(formatIPv6(b)).toBe('2001:db8::1');
    expect(formatIPv6(new Uint8Array(16))).toBe('::');
  });
});

describe('TCP framing', () => {
  it('round-trips and keeps partial messages', () => {
    const a = buildQuery('a.example', RR_TYPES.A);
    const b = buildQuery('b.example', RR_TYPES.AAAA);
    const stream = new Uint8Array([...frameTcp(a), ...frameTcp(b)]);
    const partial = unframeTcp(stream.subarray(0, stream.length - 3));
    expect(partial.messages).toHaveLength(1);
    expect(partial.rest.length).toBe(frameTcp(b).length - 3);
    const full = unframeTcp(stream);
    expect(full.messages.map((m) => [...m])).toEqual([[...a], [...b]]);
  });
});

describe('dnskeyTag', () => {
  it('computes the RFC 4034 key tag', () => {
    // Root KSK-2017 (key tag 20326), as published by IANA.
    const ksk2017 = '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=';
    expect(dnskeyTag(ksk2017)).toBe(20326);
    expect(dnskeyTag('257 3 8 !!!')).toBeNull();
  });
});
