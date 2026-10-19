# tauri-plugin-better-auth

[Better Auth](https://better-auth.com) for [Tauri 2](https://tauri.app). Users
sign in through the system browser with PKCE. The session lives in Rust, and
webview code never sees a token.

This npm package is one half of the plugin. The other half is the Rust crate
[`tauri-plugin-better-auth`](https://crates.io/crates/tauri-plugin-better-auth).
Full documentation:
[github.com/laakal/tauri-plugin-better-auth](https://github.com/laakal/tauri-plugin-better-auth#readme).

```sh
npm install tauri-plugin-better-auth
```

| Import                            | Where                   | What                                                                  |
| --------------------------------- | ----------------------- | --------------------------------------------------------------------- |
| `tauri-plugin-better-auth`        | Your Better Auth server | `tauri()` server plugin: `/tauri/authorize`, `/tauri/token`           |
| `tauri-plugin-better-auth/proxy`  | Your hand-off web page  | `tauriProxyClient()`: request capture, consent hand-off, cancel       |
| `tauri-plugin-better-auth/client` | The Tauri webview       | `withTauri()`, `tauriFetch`, `requestAuth()`, events, tokenless types |

```ts
// Server
import { bearer } from 'better-auth/plugins';
import { tauri } from 'tauri-plugin-better-auth';
betterAuth({
  plugins: [
    bearer(),
    tauri({
      clientID: 'com.example.app',
      authorizeOrigins: ['https://example.com'],
    }),
  ],
});

// Tauri webview
import { createAuthClient } from 'better-auth/react';
import {
  asTauriClient,
  requestAuth,
  withTauri,
} from 'tauri-plugin-better-auth/client';
const authClient = asTauriClient(
  createAuthClient(withTauri({ baseURL: 'https://api.example.com/api/auth' })),
);
await requestAuth();
```

Requires `better-auth` >= 1.7.4 and, for `/client`, `@tauri-apps/api` >= 2.11.
MIT licensed.
