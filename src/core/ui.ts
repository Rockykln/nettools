// Small shared UI fragments used by the layout and by tools.
import { SITE } from '../config';
import { html, type SafeHtml } from './html';

export const icon = (name: string, cls = 'ico'): SafeHtml =>
  html`<svg class="${cls}" aria-hidden="true"><use href="/assets/icons.svg?v=${SITE.assetVersion}#i-${name}"/></svg>`;

/** Horizontal bar as SVG (the CSP forbids inline styles). `left` and `width` are percentages. */
export function bar(width: number, cls = '', left = 0): SafeHtml {
  const w = Math.max(0, Math.min(100 - left, width)).toFixed(1);
  return html`<svg class="hbar" width="100%" height="10" aria-hidden="true"><rect class="hbar-track" x="0" y="0" width="100%" height="10" rx="2"/><rect class="hbar-fill ${cls}" x="${left.toFixed(1)}%" y="0" width="${w}%" height="10" rx="2"/></svg>`;
}

/** Icon link that opens an external URL through the /go warning page in a new tab. */
export function openLink(url: string): SafeHtml {
  return html`<a class="open-link" href="/go?url=${encodeURIComponent(url)}" target="_blank" rel="noopener nofollow" title="Open ${url}" aria-label="Open ${url} in a new tab">${icon('open')}</a>`;
}
