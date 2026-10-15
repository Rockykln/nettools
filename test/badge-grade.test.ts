import { describe, expect, it } from 'vitest';
import { badgeSvg, effectiveDmarcPolicy, emailGrade } from '../src/badges';
import { analyzeDmarc } from '../src/core/email';

describe('email badge DMARC policy', () => {
  it('uses the policy of a single record', () => {
    expect(effectiveDmarcPolicy(analyzeDmarc(['v=DMARC1; p=Reject; rua=mailto:d@example.com']))).toBe('reject');
  });
  it('treats several DMARC records as no policy', () => {
    const d = analyzeDmarc(['v=DMARC1; p=reject; rua=mailto:d@example.com', 'v=DMARC1; p=none']);
    expect(effectiveDmarcPolicy(d)).toBeNull();
    expect(emailGrade({ SPF: 'ok', DKIM: 'ok' }, effectiveDmarcPolicy(d), false)).toBe('C');
    expect(emailGrade({}, effectiveDmarcPolicy(d), true)).toBe('F');
  });
  it('has no policy without a record', () => {
    expect(effectiveDmarcPolicy(analyzeDmarc([]))).toBeNull();
  });
});

describe('badgeSvg', () => {
  it('escapes label and value', () => {
    const svg = badgeSvg('a<b', '"x"&', '#000');
    expect(svg).not.toMatch(/a<b|"x"&/);
    expect(svg).toContain('a&#60;b');
  });
});
