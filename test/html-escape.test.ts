import { describe, expect, it } from 'vitest';
import { esc, html, jsonForScript, raw, secret } from '../src/core/html';

describe('html templates', () => {
  it('escapes interpolated strings, including quotes', () => {
    expect(esc(`<a href="x" title='y'>&</a>`)).toBe('&#60;a href=&#34;x&#34; title=&#39;y&#39;&#62;&#38;&#60;/a&#62;');
    expect(html`<p title="${'"><script>'}">${'<b>'}</p>`.value).toBe('<p title="&#34;&#62;&#60;script&#62;">&#60;b&#62;</p>');
  });

  it('keeps nested templates and raw() as markup, renders falsy values except 0 as empty', () => {
    const inner = html`<b>${'x&y'}</b>`;
    expect(html`<p>${inner}${raw('<i>ok</i>')}${[html`<br>`, '<']}</p>`.value).toBe('<p><b>x&#38;y</b><i>ok</i><br>&#60;</p>');
    expect(html`${null}${undefined}${false}${0}`.value).toBe('0');
  });

  it('escapes values in secret()', () => {
    expect(secret('<img>').value).toContain('&#60;img&#62;');
    expect(secret('1.2.3.4').value).toMatch(/^<span class="secret" role="button" tabindex="0"/);
  });
});

describe('jsonForScript', () => {
  it('cannot close the script element or open a comment', () => {
    const out = jsonForScript({ a: '</script><script>alert(1)</script>', b: '<!-- x' }).value;
    expect(out).not.toMatch(/<\/script/i);
    expect(out).not.toContain('<!--');
    expect(JSON.parse(out)).toEqual({ a: '</script><script>alert(1)</script>', b: '<!-- x' });
  });

  it('keeps unicode intact', () => {
    const data = { name: 'Kantstraße – “quoted” \u2028 😀' };
    expect(JSON.parse(jsonForScript(data).value)).toEqual(data);
  });
});
