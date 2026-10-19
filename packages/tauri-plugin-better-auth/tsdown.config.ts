import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    proxy: 'src/proxy.ts',
    client: 'src/client/index.ts',
  },
  format: 'esm',
  platform: 'neutral',
  target: 'es2022',
  clean: true,
  dts: true,
  tsconfig: 'tsconfig.build.json',
  deps: {
    // Peers stay external so the host app owns a single Better Auth instance.
    neverBundle: [
      /^better-auth(\/|$)/,
      /^@better-auth\//,
      /^better-call(\/|$)/,
      /^@better-fetch\//,
      /^@tauri-apps\//,
      /^zod(\/|$)/,
    ],
  },
});
