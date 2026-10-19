import { defineConfig } from 'vitest/config';

/**
 * Root Vitest config: lists every project that has tests so `bun run test`
 * at the root runs them all. Each project owns its environment and includes.
 */
export default defineConfig({
  test: {
    projects: ['packages/*/vitest.config.ts'],
  },
});
