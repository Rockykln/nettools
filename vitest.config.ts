import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      'cloudflare:sockets': fileURLToPath(new URL('./test/stubs/sockets.ts', import.meta.url)),
      'cloudflare:workers': fileURLToPath(new URL('./test/stubs/workers.ts', import.meta.url)),
    },
  },
});
