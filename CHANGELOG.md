# Changelog

All notable changes to the npm package and the crate, which share a version.
Wire protocol versions are tracked in [PROTOCOL.md](PROTOCOL.md).

## 0.2.0-alpha.6 (unreleased, npm tag `next`)

Protocol v1, unchanged.

- iOS (experimental): the sign-in page opens in an
  `ASWebAuthenticationSession`, which returns the callback to the plugin
  without `tauri-plugin-deep-link` or an `Info.plist` URL scheme. Closing the
  sheet ends the sign-in with `ACCESS_DENIED`; `cancelAuth()` closes the sheet.
  The session is stored in the iOS Keychain. The loopback transport is refused
  on iOS. See "Platform notes" in the README.
- Android (experimental): the sign-in page opens in a Custom Tab and returns
  through `tauri-plugin-deep-link` (list the scheme under
  `plugins.deep-link.mobile`). Closing the tab keeps the sign-in open for a
  pasted code; `cancelAuth()` closes the tab. The session is stored encrypted
  with an Android Keystore key. HTTPS uses the bundled Mozilla roots there.
  The loopback transport is refused.
- Mobile: the plugin installs `ring` as the default rustls provider when the
  app has not chosen one. Without it, Tauri's own dev-server client panicked
  at startup under `tauri ios dev` and `tauri android dev`.
- The crate no longer depends on `open` on mobile. For the `keyring` feature it
  uses `apple-native-keyring-store` on iOS and `android-native-keyring-store`
  on Android.

## 0.2.0-alpha.5 (2026-11-11, npm tag `next`)

Protocol v1, unchanged. No API changes.

- Dependencies: the crate moves to `base64` 0.23 and `getrandom` 0.4, as in
  `0.1.5`. Rust 1.95 stays the minimum.
- Docs: a "Streaming responses" section with examples (AI SDK chat, Server-Sent
  Events, cancelling, timeouts, buffered fetch), and streaming on the npm and
  crates.io pages.
  These README changes landed after the 0.2.0-alpha.4 tag, so the npm and
  crates.io pages show them from this release.
- Development: tested against Better Auth 1.7.20 (`better-call` 1.4.5), with
  tsdown 0.23.7, Vitest 5.1, oxlint 1.93 and oxfmt 0.78. Working on the repo
  now needs Node 26; the published package still supports Node 22.

## 0.2.0-alpha.4 (2026-11-11, npm tag `next`)

Brings the `0.1.4` fix to the Tauri 3 line. Protocol v1, unchanged.

- Security: the bridge refuses other spellings of the auth base path on the
  auth origin (`/api/%61uth/…`, `/api//auth/…`, `/API/AUTH/…`, `..%2f`,
  `;parameters`) with `403 FORBIDDEN_URL`. Before, an `api_routes` prefix such
  as `/api/` let them through as app API requests, with the bearer token added
  and the response unscrubbed, and a proxy or framework that normalizes paths
  could route them to Better Auth (e.g. `list-sessions`). Upgrade if your
  `api_routes` cover the auth path.
- Tested with Better Auth 1.7.4, 1.7.20 and 1.8.0-beta.7.

## 0.2.0-alpha.3 (2026-11-04, npm tag `next`)

Brings the `0.1.3` changes to the Tauri 3 line. Protocol v1, unchanged.

- Security: `/tauri/token` now refuses a code whose authorizing browser session
  has ended (signed out, revoked or expired) since `/tauri/authorize`, with
  `INVALID_OR_EXPIRED_CODE`. Better Auth 1.8 makes the same change for its
  Electron sign-in. Codes issued before the upgrade are refused once; the user
  signs in again.
- The peer ranges admit the Better Auth 1.8 prereleases
  (`>=1.7.4 <2 || >=1.8.0-0 <2`): npm refused to install the plugin next to
  `better-auth@1.8.0-beta.x`. Tested with 1.7.4, 1.7.16 and 1.8.0-beta.5.
- CI tests Better Auth's `beta` tag too, and checks that npm accepts the peer
  ranges for each tested version.

## 0.2.0-alpha.2 (2026-10-28, npm tag `next`)

**Streaming responses.** Protocol v1, unchanged.

- `tauriFetch` streams app API responses (`api_routes`): it resolves when the
  headers arrive and the body follows chunk by chunk over a Tauri channel. SSE
  and AI SDK streams work. Auth responses are still read whole and scrubbed.
- New command `fetch_stream`, included in `better-auth:default`. A capability
  that lists permissions one by one needs `better-auth:allow-fetch-stream`;
  without it `tauriFetch` falls back to buffered responses.
- `timeout` now covers a streamed response until its headers. New
  `Builder::stream_idle_timeout` (60 s by default) ends a stream that sends
  nothing for that long. Streamed bodies have no total size cap.
- `abort()` and cancelling the body stop the request in Rust and close the
  connection.
- `createTauriFetch({ stream: false })` creates a buffered `fetch` for clients
  that should read every response whole. `tauriFetch` is `createTauriFetch()`.
- Fix: in-flight requests are tracked per window, so an abort in one window
  can no longer cancel another window's request with the same id.
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
