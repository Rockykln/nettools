import { describe, expect, it } from 'vitest';
import { parseUa } from '../src/tools/user-agent';

describe('parseUa', () => {
  it('detects Safari on iPhone', () => {
    const p = parseUa('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1');
    expect(p).toMatchObject({ browser: 'Safari', browserVersion: '18.0', os: 'iOS', osVersion: '18.0', engine: 'WebKit', device: 'mobile' });
  });
  it('detects Chrome on iOS as WebKit', () => {
    const p = parseUa('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1');
    expect(p).toMatchObject({ browser: 'Chrome', engine: 'WebKit', os: 'iOS' });
  });
  it('detects Edge on Windows before Chrome', () => {
    const p = parseUa('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0');
    expect(p).toMatchObject({ browser: 'Microsoft Edge', os: 'Windows', osVersion: '10 or 11', engine: 'Blink', device: 'desktop' });
  });
  it('detects Firefox on Linux', () => {
    const p = parseUa('Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0');
    expect(p).toMatchObject({ browser: 'Firefox', browserVersion: '130.0', os: 'Linux', engine: 'Gecko' });
  });
  it('detects Android tablets and phones', () => {
    expect(parseUa('Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36').device).toBe('mobile');
    expect(parseUa('Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36').device).toBe('tablet');
  });
  it('detects bots and command-line clients', () => {
    expect(parseUa('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')).toMatchObject({ browser: 'Googlebot', device: 'bot' });
    expect(parseUa('curl/8.5.0')).toMatchObject({ browser: 'curl', browserVersion: '8.5.0', device: 'bot' });
  });
});
