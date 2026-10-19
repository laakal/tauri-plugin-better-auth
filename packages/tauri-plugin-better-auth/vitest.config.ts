import { defineConfig } from 'vitest/config';

/**
 * Two environments, chosen by file suffix:
 * - `*.test.ts`      node (server plugin, protocol helpers)
 * - `*.dom.test.ts`  happy-dom (web hand-off client, Tauri webview client)
 * Type-level tests live in `*.test-d.ts` and run with `--typecheck`.
 */
export default defineConfig({
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: 'server',
          environment: 'node',
          include: ['src/**/*.test.ts', 'test/**/*.test.ts'],
          exclude: ['**/*.dom.test.ts'],
          testTimeout: 30_000,
        },
      },
      {
        extends: true,
        test: {
          name: 'dom',
          environment: 'happy-dom',
          include: ['src/**/*.dom.test.ts', 'test/**/*.dom.test.ts'],
        },
      },
    ],
    typecheck: {
      include: ['src/**/*.test-d.ts', 'test/**/*.test-d.ts'],
    },
  },
});
