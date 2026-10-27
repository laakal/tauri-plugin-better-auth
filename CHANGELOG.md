# Changelog

All notable changes to the npm package and the crate, which share a version.
Wire protocol versions are tracked in [PROTOCOL.md](PROTOCOL.md).

## 0.2.0-alpha.2 (unreleased, npm tag `next`)

- The npm package depends on `zod ^4.5.4` (Better Auth's own range) instead of
  exactly `4.6.7`, so apps share one zod copy with Better Auth.
- README: a Limitations section (platforms, streaming, sign-in methods in the
  webview, the route and origin allowlists, redirects). The old "mobile is
  planned for 0.2" note is corrected: mobile is not supported on either line.
- README: a Roadmap section (streaming next, then Tauri 3 stable, mobile
  later) and what is not planned by design.

## 0.2.0-alpha.1 (2026-10-27, npm tag `next`)

Brings the `0.1.1` fixes to the Tauri 3 line. Protocol v1, unchanged.

- Security: the crate now requires `rustls` 0.23.46+ and `rustls-webpki`
  0.103.16+, the patched releases for RUSTSEC-2026-0285, RUSTSEC-2026-0346 to
  0349, and RUSTSEC-2026-0382.
- Tested with Better Auth 1.7.14. Peer ranges are unchanged.
- The READMEs say which line to install: `0.2.x` for Tauri 3, `0.1.x` for
  Tauri 2. The npm release now names its `next` dist-tag explicitly, so a
  pre-release never becomes `latest`.
- Internal: the controller is split into flow and session modules, route
  matching uses `strip_prefix` instead of slicing, and the repo is checked
  with Rust Doctor. No behaviour change.

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

## 0.1.0 (2026-10-20)

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
