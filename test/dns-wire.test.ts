import { describe, expect, it } from 'vitest';
import { RR_TYPES, buildQuery, parseMessage } from '../src/core/dns';
import { isAnswer } from '../src/core/transport';

// Response to `query` with answers whose owner is a pointer to the question name.
function response(query: Uint8Array, answers: { type: number; rdata: number[] }[], rcode = 0): Uint8Array {
  const out = [...query];
  out[2] = 0x81;
  out[3] = 0x80 | rcode;
  out[7] = answers.length;
  for (const a of answers) {
    out.push(0xc0, 12, a.type >> 8, a.type & 0xff, 0, 1, 0, 0, 0, 60, a.rdata.length >> 8, a.rdata.length & 0xff, ...a.rdata);
  }
  return Uint8Array.from(out);
}

const enc = (s: string) => [...new TextEncoder().encode(s)];
const label = (s: string) => [s.length, ...enc(s)];
const u16 = (n: number) => [n >> 8, n & 0xff];
const param = (key: number, value: number[]) => [...u16(key), ...u16(value.length), ...value];

const one = (type: number, rdata: number[]) =>
  parseMessage(response(buildQuery('example.com', type, { id: 1 }), [{ type, rdata }])).answers[0]!.data;

describe('HTTPS / SVCB records', () => {
  it('formats SvcParams in presentation format', () => {
    const rdata = [
      ...u16(1), 0,
      ...param(1, [...label('h3'), ...label('h2')]),
      ...param(3, u16(8443)),
      ...param(4, [104, 16, 132, 229, 104, 16, 133, 229]),
      ...param(6, [0x26, 0x06, 0x47, 0, ...Array(11).fill(0), 1]),
    ];
    expect(one(RR_TYPES.HTTPS, rdata)).toBe('1 . alpn="h3,h2" port=8443 ipv4hint=104.16.132.229,104.16.133.229 ipv6hint=2606:4700::1');
  });

  it('handles alias mode, flag keys, ech and unknown keys', () => {
    expect(one(RR_TYPES.HTTPS, [...u16(0), ...label('cdn'), ...label('example'), 0])).toBe('0 cdn.example.');
    const rdata = [...u16(1), 0, ...param(0, u16(1)), ...param(2, []), ...param(5, [1, 2, 3]), ...param(7, enc('/q{?dns}')), ...param(999, enc('x'))];
    expect(one(RR_TYPES.HTTPS, rdata)).toBe('1 . mandatory=alpn no-default-alpn ech=AQID dohpath="/q{?dns}" key999="x"');
    const svcb = parseMessage(response(buildQuery('_dns.example.com', 64, { id: 1 }), [{ type: 64, rdata: [...u16(1), 0] }])).answers[0]!;
    expect([svcb.typeName, svcb.data]).toEqual(['SVCB', '1 .']);
  });

  it('rejects hint lists with a partial address', () => {
    expect(() => one(RR_TYPES.HTTPS, [...u16(1), 0, ...param(4, [1, 2, 3])])).toThrow();
  });
});

describe('record data edge cases', () => {
  it('escapes quotes and non-ASCII bytes in CAA values', () => {
    expect(one(RR_TYPES.CAA, [128, 5, ...enc('issue'), ...enc('ca"x'), 0xc3, 0xa4])).toBe('128 issue "ca\\"x\\195\\164"');
  });

  it('rejects records whose data runs past RDLENGTH', () => {
    // TXT string claims 5 bytes but RDLENGTH is 3; the next bytes belong to another record.
    const q = buildQuery('example.com', RR_TYPES.TXT, { id: 1 });
    const buf = response(q, [{ type: RR_TYPES.TXT, rdata: [5, 0x61, 0x62] }, { type: RR_TYPES.A, rdata: [1, 2, 3, 4] }]);
    expect(() => parseMessage(buf)).toThrow(/RDLENGTH/);
  });

  it('rejects extended label types and over-long names', () => {
    expect(() => one(RR_TYPES.CNAME, [0x41, 0])).toThrow(/label type/);
    const long: number[] = [];
    for (let i = 0; i < 5; i++) long.push(...label('a'.repeat(60)));
    expect(() => one(RR_TYPES.CNAME, [...long, 0])).toThrow(/too long/);
  });

  it('keeps the case of owner names and names extended RCODEs', () => {
    const q = buildQuery('ExAmple.COM.', RR_TYPES.A, { id: 1 });
    const m = parseMessage(response(q, [], 9));
    expect(m.questions[0]!.name).toBe('ExAmple.COM.');
    expect(m.rcodeName).toBe('NOTAUTH');
  });
});

describe('isAnswer', () => {
  it('accepts NOERROR and NXDOMAIN only', () => {
    const q = buildQuery('example.com', RR_TYPES.A, { id: 1 });
    expect([0, 2, 3, 5].map((rc) => isAnswer(parseMessage(response(q, [], rc))))).toEqual([true, false, true, false]);
  });
});
