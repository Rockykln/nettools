// Minimal auto-escaping HTML templating. Interpolated values are escaped unless wrapped in raw()/html``.

export class SafeHtml {
  constructor(readonly value: string) {}
  toString(): string {
    return this.value;
  }
}

export const raw = (value: string): SafeHtml => new SafeHtml(value);

export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function render(v: unknown): string {
  if (v === null || v === undefined || v === false) return '';
  if (v instanceof SafeHtml) return v.value;
  if (Array.isArray(v)) return v.map(render).join('');
  return esc(String(v));
}

export function html(strings: TemplateStringsArray, ...values: unknown[]): SafeHtml {
  let out = strings[0]!;
  for (let i = 0; i < values.length; i++) out += render(values[i]) + strings[i + 1]!;
  return new SafeHtml(out);
}

// JSON for <script type="application/ld+json">; "<" is escaped so the payload cannot close the tag.
export function jsonForScript(data: unknown): SafeHtml {
  return raw(JSON.stringify(data).replace(/</g, '\\u003c'));
}

/**
 * A visitor-identifying value (IP, location) that stays blurred until hovered, focused or tapped,
 * so it does not leak on screen shares or streams. `strong` blurs more, for large text such as the IP.
 */
export function secret(value: string, opts: { code?: boolean; cls?: string; strong?: boolean } = {}): SafeHtml {
  const cls = ['secret', opts.strong ? 'strong' : '', opts.cls ?? ''].filter(Boolean).join(' ');
  return opts.code
    ? html`<code class="${cls}" role="button" tabindex="0" title="Hover, focus or tap to reveal">${value}</code>`
    : html`<span class="${cls}" role="button" tabindex="0" title="Hover, focus or tap to reveal">${value}</span>`;
}
