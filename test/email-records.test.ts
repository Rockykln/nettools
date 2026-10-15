import { describe, expect, it } from 'vitest';
import { analyzeDmarc, analyzeSpf, dkimKey, mxMatches, parseMtaStsPolicy, txtValue, type TxtLookup } from '../src/core/email';
import { classify } from '../src/tools/blacklist-check';

const zone = (records: Record<string, string[]>): TxtLookup => async (name) => records[name] ?? [];

describe('analyzeSpf redirect and loops', () => {
  it('takes the all qualifier from the redirect target', async () => {
    const r = await analyzeSpf('example.com', zone({
      'example.com': ['v=spf1 redirect=_spf.example.net'],
      '_spf.example.net': ['v=spf1 ip4:192.0.2.0/24 -all'],
    }));
    expect(r.allQualifier).toBe('-');
    expect(r.totalLookups).toBe(1);
    expect(r.problems).toEqual([]);
  });

  it('ignores redirect when the record has an all mechanism', async () => {
    const r = await analyzeSpf('example.com', zone({ 'example.com': ['v=spf1 mx ~all redirect=other.example'] }));
    expect(r.totalLookups).toBe(1);
    expect(r.tree!.includes).toHaveLength(0);
    expect(r.allQualifier).toBe('~');
  });

  it('reports a missing redirect target', async () => {
    const r = await analyzeSpf('example.com', zone({ 'example.com': ['v=spf1 redirect=gone.example'] }));
    expect(r.problems.join(' ')).toMatch(/Redirect gone\.example: No SPF record/);
  });

  it('detects include loops', async () => {
    const r = await analyzeSpf('a.example', zone({
      'a.example': ['v=spf1 include:b.example -all'],
      'b.example': ['v=spf1 include:a.example -all'],
    }));
    expect(r.problems.join(' ')).toMatch(/Include a\.example: Include loop/);
  });

  it('does not count "all" or modifiers as lookups and flags qualified ptr', async () => {
    const r = await analyzeSpf('example.com', zone({ 'example.com': ['v=spf1 a mx/24 ~ptr exists:%{i}.x.example exp=e.example -all'] }));
    expect(r.totalLookups).toBe(4);
    expect(r.problems.join(' ')).toMatch(/ptr/);
  });

  it('turns a failed root lookup into a problem instead of throwing', async () => {
    const r = await analyzeSpf('example.com', async () => { throw new Error('SERVFAIL'); });
    expect(r.record).toBeNull();
    expect(r.problems[0]).toMatch(/lookup for the domain failed/);
  });
});

describe('analyzeDmarc validation', () => {
  it('rejects invalid tag values', () => {
    const r = analyzeDmarc(['v=DMARC1; p=rejected; pct=abc; adkim=x; rua=dmarc@example.com']);
    const all = r.problems.join(' ');
    expect(all).toMatch(/Invalid policy "p=rejected"/);
    expect(all).toMatch(/Invalid "pct=abc"/);
    expect(all).toMatch(/Invalid "adkim=x"/);
    expect(all).toMatch(/not a mailto: address/);
  });

  it('accepts size limits on report URIs and warns about sp=none', () => {
    const r = analyzeDmarc(['v=DMARC1; p=reject; sp=none; rua=mailto:a@example.com!10m,mailto:b@example.net']);
    expect(r.problems).toEqual(['Subdomain policy "sp=none": spoofed mail from subdomains is still delivered.']);
    expect(analyzeDmarc(['v=DMARC1; p=quarantine; pct=0; rua=mailto:a@example.com']).problems[0]).toMatch(/only 0%/);
  });
});

describe('dkimKey', () => {
  const b64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  it('reads the RSA modulus length from an SPKI key', async () => {
    for (const bits of [1024, 2048]) {
      const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
      const spki = b64(await crypto.subtle.exportKey('spki', pair.publicKey) as ArrayBuffer);
      expect(dkimKey(`v=DKIM1; k=rsa; p=${spki.slice(0, 40)} ${spki.slice(40)}`)).toEqual({ keyType: 'rsa', revoked: false, bits });
    }
  });
  it('handles revoked, ed25519 and garbage keys', () => {
    expect(dkimKey('v=DKIM1; p=').revoked).toBe(true);
    expect(dkimKey('v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=')).toEqual({ keyType: 'ed25519', revoked: false, bits: 256 });
    expect(dkimKey('v=DKIM1; p=!!notbase64').bits).toBeNull();
  });
});

describe('MTA-STS policy', () => {
  it('parses the policy and validates fields', () => {
    const p = parseMtaStsPolicy('version: STSv1\r\nmode: enforce\r\nmx: mx1.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n');
    expect(p).toEqual({ mode: 'enforce', maxAge: 604800, mx: ['mx1.example.com', '*.example.net'], problems: [] });
    expect(parseMtaStsPolicy('version: STSv1\nmode: enforced\n').problems).toHaveLength(3);
  });
  it('matches wildcard mx patterns against one label only', () => {
    expect(mxMatches('mx1.example.net', '*.example.net')).toBe(true);
    expect(mxMatches('a.mx1.example.net', '*.example.net')).toBe(false);
    expect(mxMatches('example.net', '*.example.net')).toBe(false);
    expect(mxMatches('MX1.Example.com.', 'mx1.example.com')).toBe(true);
  });
});

describe('DNSBL answers', () => {
  it('treats Spamhaus 127.255.255.x and non-loopback answers as errors', () => {
    expect(classify('NOERROR', ['127.255.255.254']).state).toBe('unavailable');
    expect(classify('NOERROR', ['127.0.0.2', '127.255.255.252']).state).toBe('unavailable');
    expect(classify('NOERROR', ['198.51.100.1']).state).toBe('unavailable');
    expect(classify('NOERROR', ['127.0.0.2', '127.0.0.4'])).toEqual({ state: 'listed', code: '127.0.0.2, 127.0.0.4', reason: null });
    expect(classify('NXDOMAIN', []).state).toBe('clean');
    expect(classify('SERVFAIL', []).state).toBe('unavailable');
  });
});

describe('txtValue presentation escapes', () => {
  it('decodes \\DDD bytes as UTF-8 and \\X as literal characters', () => {
    expect(txtValue('"v=DMARC1\; p=reject\; ruf=mailto:h\\195\\164@example.com"')).toBe('v=DMARC1; p=reject; ruf=mailto:hä@example.com');
    expect(txtValue('"a\\195" "\\164b"')).toBe('aäb');
    expect(txtValue('"say \\"hi\\" \\\\ ok"')).toBe('say "hi" \\ ok');
  });
});
