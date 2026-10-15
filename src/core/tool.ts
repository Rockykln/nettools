import type { SafeHtml } from './html';

export type Category = 'ip' | 'dns' | 'domain' | 'web' | 'email' | 'performance';

export const CATEGORIES: { id: Category; name: string }[] = [
  { id: 'ip', name: 'IP & network' },
  { id: 'dns', name: 'DNS' },
  { id: 'domain', name: 'Domain & WHOIS' },
  { id: 'web', name: 'Website' },
  { id: 'email', name: 'Email' },
  { id: 'performance', name: 'Performance' },
];

export interface Faq {
  q: string;
  /** Plain text; shown on the page and in FAQPage structured data. */
  a: string;
}

export interface ToolContext {
  req: Request;
  env: Env;
  url: URL;
  exec: ExecutionContext;
  clientIp: string;
}

export interface Tool {
  /** URL path without slashes, e.g. "dns-lookup". Never change after launch (SEO). */
  slug: string;
  /** Short label for navigation and the tool index. */
  name: string;
  /** Symbol id in public/assets/icons.svg without the "i-" prefix. */
  icon: string;
  category: Category;
  /** <title>, aim for <= 60 characters. */
  title: string;
  /** Meta description, aim for 120-155 characters. */
  description: string;
  h1: string;
  /** One-sentence summary under the H1. */
  lead: string;
  /** Interactive part of the page. Results for query params are rendered server-side. */
  render(c: ToolContext): Promise<SafeHtml> | SafeHtml;
  /** Explanatory long-form content below the tool. */
  article: SafeHtml;
  faq: Faq[];
  /** For landing pages: the tool whose URL renders results and receives example queries. */
  querySlug?: string;
  /** Landing pages: parameters preset on the target tool. */
  queryDefaults?: Record<string, string>;
  /** Example queries shown under the empty form, as [label, query string]. */
  examples?: [string, string][];
  /** Slugs of related tools for internal linking. */
  related: string[];
  /** Expensive requests (many outbound connections) that get the stricter RL_HEAVY limit in addition to RL_TOOLS. */
  heavy?(url: URL, c: ToolContext): boolean;
  /** True when the URL carries tool input. Such pages are rate limited and not indexed. */
  isQuery?(url: URL): boolean;
  /** Page-specific script under /assets/js/. */
  script?: string;
  /** One-line API usage for llms.txt and docs, e.g. "GET /api/whois?q=example.com". */
  apiDoc?: string;
  /** Handles /api/<slug>/<subpath>. */
  api?(c: ToolContext, subpath: string): Promise<Response>;
  /** The page shows per-visitor data (e.g. the visitor's IP) and must not be cached. */
  personal?: boolean;
}
