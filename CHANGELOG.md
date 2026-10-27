# Changelog

All notable changes to the npm package and the crate, which share a version.
Wire protocol versions are tracked in [PROTOCOL.md](PROTOCOL.md).

## 0.1.2 (unreleased)

- The npm package depends on `zod ^4.5.4` (Better Auth's own range) instead of
  exactly `4.6.7`, so apps share one zod copy with Better Auth.
- README: a Limitations section (platforms, streaming, sign-in methods in the
  webview, the route and origin allowlists, redirects). The old "mobile is
  planned for 0.2" note is corrected: mobile is not supported on either line.

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
