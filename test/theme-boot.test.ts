import { describe, expect, it } from 'vitest';
import { THEME_BOOT, THEME_BOOT_HASH } from '../src/core/theme-boot';

describe('inline theme script', () => {
  it('matches the hash allowed by the CSP', async () => {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(THEME_BOOT)));
    expect(THEME_BOOT_HASH).toBe(`'sha256-${btoa(String.fromCharCode(...digest))}'`);
  });
});
