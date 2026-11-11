# Changelog

All notable changes to the npm package and the crate, which share a version.
Wire protocol versions are tracked in [PROTOCOL.md](PROTOCOL.md).

## 0.1.5 (unreleased)

Protocol v1, unchanged. No API changes.

- Dependencies: the crate moves to `base64` 0.23 and `getrandom` 0.4. Rust 1.88
  and Tauri 2.11 stay supported.
- Docs: a "Streaming responses" section with examples (AI SDK chat, Server-Sent
  Events, cancelling, timeouts, buffered fetch), and streaming on the npm and
  crates.io pages.
  These README changes landed after the 0.1.4 tag, so the npm and crates.io
  pages show them from this release.
- Development: tested against Better Auth 1.7.20 (`better-call` 1.4.5), with
  tsdown 0.23.7, Vitest 5.1, oxlint 1.93 and oxfmt 0.78. Working on the repo
  now needs Node 26; the published package still supports Node 22.

## 0.1.4 (2026-11-11)

Protocol v1, unchanged.

- Security: the bridge refuses other spellings of the auth base path on the
  auth origin (`/api/%61uth/…`, `/api//auth/…`, `/API/AUTH/…`, `..%2f`,
  `;parameters`) with `403 FORBIDDEN_URL`. Before, an `api_routes` prefix such
  as `/api/` let them through as app API requests, with the bearer token added
  and the response unscrubbed, and a proxy or framework that normalizes paths
  could route them to Better Auth (e.g. `list-sessions`). Upgrade if your
  `api_routes` cover the auth path.
- Tested with Better Auth 1.7.4, 1.7.20 and 1.8.0-beta.7.

## 0.1.3 (2026-11-04)

Protocol v1, unchanged.

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

## 0.1.2 (2026-10-28)

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

## 0.1.1 (2026-10-27)

Maintenance release. Protocol v1, unchanged.

- Security: the crate now requires `rustls` 0.23.46+ and `rustls-webpki`
  0.103.16+, the patched releases for RUSTSEC-2026-0285, RUSTSEC-2026-0346 to
  0349, and RUSTSEC-2026-0382. Apps get them with
  `cargo update -p tauri-plugin-better-auth`.
- Tested with Better Auth 1.7.14. Peer ranges are unchanged.
- Linux build note (not this crate): `tauri-plugin-deep-link` 2.6.2 does not
  compile against `rust-ini` 0.21.2+. If your app fails there, run
  `cargo update -p rust-ini --precise 0.21.1`.
- The READMEs say which line to install: `0.1.x` for Tauri 2, `0.2.x` (npm
  tag `next`) for Tauri 3.
- Internal: the controller is split into flow and session modules, route
  matching uses `strip_prefix` instead of slicing, and the repo is checked
  with Rust Doctor. No behaviour change.

## 0.1.0 (2026-10-20)

First release. Protocol v1.

- `Transport::Auto` on macOS treats an `.app` under a cargo `target/` directory
  as a dev build and uses the loopback redirect (deep links only reach bundles
  macOS has registered).

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
