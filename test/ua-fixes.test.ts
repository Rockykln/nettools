import { describe, expect, it } from 'vitest';
import { parseUa } from '../src/tools/user-agent';

describe('parseUa additional browsers', () => {
  it('reports the frozen macOS version as a lower bound', () => {
    const p = parseUa('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15');
    expect(p).toMatchObject({ browser: 'Safari', os: 'macOS', osVersion: '10.15 or later', device: 'desktop', engine: 'WebKit' });
    expect(parseUa('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Safari/605.1.15').osVersion).toBe('10.13.6');
  });
  it('uses the Safari version on iOS 26 and later', () => {
    const p = parseUa('Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1');
    expect(p).toMatchObject({ os: 'iOS', osVersion: '26.0' });
    expect(parseUa('Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1').osVersion).toBe('18.6');
  });
  it('detects iPad, Samsung Internet and Opera', () => {
    expect(parseUa('Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1'))
      .toMatchObject({ os: 'iPadOS', device: 'tablet', browser: 'Safari' });
    expect(parseUa('Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36'))
      .toMatchObject({ browser: 'Samsung Internet', browserVersion: '25.0', os: 'Android', device: 'mobile', engine: 'Blink' });
    expect(parseUa('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0').browser).toBe('Opera');
    expect(parseUa('Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18')).toMatchObject({ browser: 'Opera', browserVersion: '12.18', engine: 'Presto', osVersion: '7' });
  });
  it('detects legacy Edge and Internet Explorer engines', () => {
    expect(parseUa('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19582'))
      .toMatchObject({ browser: 'Microsoft Edge', browserVersion: '18.19582', engine: 'EdgeHTML' });
    expect(parseUa('Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko')).toMatchObject({ browser: 'Internet Explorer', browserVersion: '11.0', engine: 'Trident' });
  });
  it('handles Firefox on Android tablets and Android without version', () => {
    expect(parseUa('Mozilla/5.0 (Android 14; Tablet; rv:130.0) Gecko/130.0 Firefox/130.0')).toMatchObject({ os: 'Android', device: 'tablet', engine: 'Gecko' });
    expect(parseUa('Mozilla/5.0 (Linux; Android; Mobile) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36')).toMatchObject({ os: 'Android', device: 'mobile' });
  });
  it('handles empty and bot strings', () => {
    expect(parseUa('')).toMatchObject({ browser: null, os: null, device: 'unknown' });
    expect(parseUa('Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)').device).toBe('bot');
  });
});
