# tauri-plugin-better-auth

[Better Auth](https://better-auth.com) for [Tauri 2](https://tauri.app). Users
sign in through the system browser with PKCE. The session lives in Rust, and
webview code never sees a token.

> **Tauri 2 line (`0.1.x`).** For Tauri 3 (alpha), install
> `tauri-plugin-better-auth@next` and use crate version `0.2.0-alpha.4`
> ([`v3` branch](https://github.com/laakal/tauri-plugin-better-auth/tree/v3)).
> Keep the npm package and the crate on the same line.

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

## Streaming

`tauriFetch` streams app API responses: AI SDK chats, Server-Sent Events and
long downloads arrive chunk by chunk, while the bearer token stays in Rust. It
resolves when the headers arrive, and `res.body` is a standard `ReadableStream`.
Better Auth responses are read whole, so Rust can scrub them.

```tsx
import { useChat } from '@ai-sdk/react';
import { DefaultChatTransport } from 'ai';
import { tauriFetch } from 'tauri-plugin-better-auth/client';

const { messages, sendMessage, stop } = useChat({
  transport: new DefaultChatTransport({
    api: 'https://api.example.com/api/chat',
    fetch: tauriFetch, // tokens render as they arrive; stop() ends it in Rust
  }),
});

// Or read any stream yourself (a reader loop works in every Tauri webview):
const res = await tauriFetch('https://api.example.com/api/events');
const reader = res.body!.pipeThrough(new TextDecoderStream()).getReader();
for (let r = await reader.read(); !r.done; r = await reader.read()) {
  console.log(r.value);
}
```

- `abort()` or `res.body.cancel()` closes the connection.
- A stream may run as long as data keeps coming; it fails after 60 s of
  silence (`stream_idle_timeout` in Rust).
- For buffered responses, use `createTauriFetch({ stream: false })`.
- Capabilities that list permissions one by one need
  `better-auth:allow-fetch-stream`.

More, including SSE parsing and timeouts:
[Streaming responses](https://github.com/laakal/tauri-plugin-better-auth#streaming-responses).

Requires `better-auth` >= 1.7.4 (1.8 betas included) and, for `/client`, `@tauri-apps/api` >= 2.11.
MIT licensed.
