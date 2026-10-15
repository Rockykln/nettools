# Contributing

Bug reports, tool ideas and pull requests are welcome. For a new tool, please open an issue first so we can
agree on scope.

## Setup

```sh
npm install
npm run db:migrate:local
npm run dev     # http://localhost:8787
npm run check   # typecheck + tests, run before every pull request
```

If DNS lookups fail locally because your network blocks DNS-over-HTTPS host names, put `DOH_BY_IP=1` into
`.dev.vars`.

## Adding a tool

1. Create `src/tools/<slug>.ts` and export a `Tool` (see `src/core/tool.ts`). Use an existing tool such as
   `whois.ts` as a template.
2. Import it in `src/tools/registry.ts` and add it to `TOOLS`. Navigation, footer, sitemap, `/api/tools` and
   structured data pick it up from there.
3. Pick an `icon` that exists as `<symbol id="i-...">` in `public/assets/icons.svg`, or add a
   [Phosphor](https://phosphoricons.com) icon there.
4. If the tool needs browser-side code, put it in `public/assets/js/<slug>.js` and set `script`.
5. Add the tool to the table in `README.md`, and run `npm run brand` to render its social preview image.
6. Add unit tests for any parsing or validation logic in `test/`.

A landing page for a search term (e.g. `mx-lookup`) is not a separate tool: add it to `LANDING_PAGES` in
`src/tools/landing.ts`, based on an existing tool with preset form values.

Guidelines:

- **Works without JavaScript.** Inputs are a `GET` form; the result is rendered on the server so every result
  has a shareable URL. JavaScript is only for things the server cannot do (like measuring the visitor's
  connection).
- **`isQuery`** must return true when the URL carries input. Those requests are rate limited and marked
  `noindex`, so only the empty tool page is indexed.
- **SEO fields:** `title` up to 60 characters, `description` 120–155 characters, an `h1`, a short `lead`, an
  `article` of at least 500 words that explains the topic and 3–5 FAQ entries that answer real questions.
  `related` lists slugs of existing tools. Never change a `slug` after release.
- **Escaping:** build markup with the `html` tagged template from `src/core/html.ts`; it escapes interpolated
  values. Never use `raw()` on user input.
- **Outbound connections:** Workers allow 6 simultaneous connections per request. Use timeouts
  (`withTimeout`) for every network call.
- **Privacy:** never log or store user input or client IPs, and do not add third-party scripts or fonts.

## Tests

`npm test` runs the unit tests with Vitest in Node; `cloudflare:sockets` is replaced by a stub
(`test/stubs/sockets.ts`), so tests must not open real connections. `test/smoke-registry.test.ts` checks every
tool and landing page: unique slugs, title and description length, h1, article length, FAQ count, related slugs,
icons and the `querySlug` of landing pages. CI runs the typecheck, the tests and a dry-run deploy on every push
and pull request.

## Style

TypeScript, strict mode, no runtime dependencies. Code, UI text and comments in English. Keep comments for
the non-obvious.
