export const SITE = {
  name: 'nettools',
  tagline: 'Fast, ad-free network tools',
  author: 'rockykln',
  authorGithub: 'https://github.com/Rockykln',
  authorUrl: 'https://github.com/Rockykln',
  /** Brand color from the logo; used for theme-color (browser UI, Discord embeds). */
  themeColor: '#1D9AF7',
  github: 'https://github.com/Rockykln/nettools',
  license: { name: 'MIT', url: 'https://github.com/Rockykln/nettools/blob/main/LICENSE' },
  /** Bump when public/assets change so browsers fetch the new files. */
  assetVersion: '40',
  /** Last content update, used as <lastmod> in the sitemap. */
  updated: '2026-10-15',
  operator: {
    name: 'Linus Klein',
    street: 'Kantstraße 5',
    postBox: 'P.O. Box 1513',
    city: '59425 Unna',
    country: 'Germany',
    email: 'contact@rockykln.com',
  },
} as const;
