# Changelog

All notable changes to the npm package and the crate, which share a version.
Wire protocol versions are tracked in [PROTOCOL.md](PROTOCOL.md).

## 0.2.0-alpha.0 (2026-10-20, npm tag `next`)

The Tauri 3 line. Tauri 2 apps keep using `0.1.x`.

- Requires Tauri 3 (`3.0.0-alpha.5`+), `tauri-plugin` 3, Rust 1.95 and
  `@tauri-apps/api` 3. The crate moves to edition 2024.
- Works with both Tauri 3 runtimes: wry (system webview) and CEF (Chromium).
  The README's "Tauri 3 and CEF" section covers the CEF origin, deep-link
  delivery and single-instance.
- `Transport::Auto` on macOS no longer treats the CEF runtime's `tauri dev`
  bundle (an `.app` under `target/`) as installed, so dev sign-in uses the
  loopback redirect instead of a deep link that never arrives.
- Command permissions follow Tauri 3's compact ACL: the per-command permission
  files are gone, and `allow-*`/`deny-*` resolve as before. `better-auth:default`
  is unchanged.
- No protocol changes: the wire protocol is still v1, so `0.1.x` servers and
  hand-off pages work with `0.2.x` apps.

## 0.1.0 (unreleased)

First release. Protocol v1.

**Server** (`tauri()`):
- `POST /tauri/authorize`: a database-checked session, an origin allowlist,
  single-use codes bound to PKCE S256.
- `POST /tauri/token`: atomic consumption, constant-time checks, and session
  creation in the app's request, so host hooks can reject or tag the session.

**Hand-off page** (`tauriProxyClient()`):
- request capture with URL cleanup
- the `redirect_uri` loopback allowlist
- `handoff()` and `cancelLink()`

**Webview** (`/client`):
- `tauriFetch`, a request bridge that adds the token in Rust
- `withTauri()`, which disables JS redirects and refreshes the session
- `asTauriClient()` tokenless types
- typed commands and events

**Rust plugin:**
- deep link, loopback and paste transports, with `Auto` selection
- the `SessionController`: generations and serialized commits
- an OS keychain store with a revision-matched profile and tombstones
- the auth bridge allowlist with response projections
- rustls with the OS certificate verifier, no redirects

**Platforms:** macOS, Windows and Linux.
