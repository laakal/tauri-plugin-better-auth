# tauri-plugin-better-auth

[Better Auth](https://better-auth.com) for [Tauri 3](https://tauri.app) desktop
apps. Users sign in through the system browser with PKCE. The session lives in
Rust (in the OS keychain), and the webview never sees a token.

> **Tauri 3 line (`0.2.x` pre-releases).** For Tauri 2, install
> `tauri-plugin-better-auth@latest` and use crate version `0.1`
> ([`main` branch](https://github.com/laakal/tauri-plugin-better-auth)).
> Keep the npm package and the crate on the same line.

This crate is the Tauri plugin. Pair it with the npm package
[`tauri-plugin-better-auth`](https://www.npmjs.com/package/tauri-plugin-better-auth),
which provides the server plugin, the hand-off page client and the webview
client. Full setup:
[github.com/laakal/tauri-plugin-better-auth](https://github.com/laakal/tauri-plugin-better-auth#readme).

```rust
tauri::Builder::default()
    // Tauri 3: pick a runtime (`tauri_runtime_cef::Cef` works too).
    .runtime(tauri_runtime_wry::Wry::default())
    // Windows/Linux: register tauri-plugin-single-instance (with `deep-link`) first.
    .plugin(tauri_plugin_deep_link::init())
    .plugin(
        tauri_plugin_better_auth::Builder::new()
            .base_url("https://api.example.com/api/auth")
            .sign_in_url("https://example.com/desktop")
            .scheme("com.example.app")
            .client_id("com.example.app")
            .api_routes("https://api.example.com", ["/api/"])
            .build(),
    )
```

**Capabilities:** `"better-auth:default"`. No command returns the token.

**What the plugin handles:**

- **Transports:** custom-scheme deep links, a loopback redirect (works in
  `tauri dev`), or a pasted code.
- **Code exchange:** the session is verified, then stored in the OS keychain
  (`keyring` feature, on by default) or your own `SessionStore`.
- **Request bridge** (`tauriFetch` in JS): adds `Authorization: Bearer` in Rust,
  never follows redirects, and only reaches allowlisted auth operations and your
  API routes.
- **Rust API:** `app.better_auth()` gives `request_auth`, `authenticate`,
  `session`, `sign_out` and `bearer_token`.

**Requirements:** Tauri 3 (alpha.5+), wry or CEF runtime, Rust 1.95+. Desktop:
macOS, Windows, Linux. For Tauri 2, use `0.1.x`. MIT licensed.
