# Contributing

Thanks for helping! This repository holds two halves of one protocol, which
always move together:

| Path                                | What                                                             |
| ----------------------------------- | ---------------------------------------------------------------- |
| `packages/tauri-plugin-better-auth` | npm package: server plugin, hand-off page client, webview client |
| `crates/tauri-plugin-better-auth`   | Rust crate: the Tauri plugin                                     |
| `examples/basic`                    | A runnable server and Tauri app; also the end-to-end test target |

## Setup

- Bun 1.4+, Node.js 24, Rust 1.88+ (stable)
- On Linux, the Tauri system packages: `libwebkit2gtk-4.1-dev`,
  `libayatana-appindicator3-dev`, `librsvg2-dev`, `libdbus-1-dev`, `pkg-config`
- Docker, for the Postgres tests

```sh
bun install
bun run build          # the examples import the built package
```

## Checks (CI runs all of them)

```sh
bun run check          # oxlint + oxfmt
bun run typecheck      # tsc, including the *.typecheck.ts type guarantees
bun run test           # vitest: server (node), hand-off and webview clients (happy-dom)
bun run lint:package   # publint + attw on the built package

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

**Postgres tests.** Better Auth's test instance uses a fixed connection string:

```sh
docker run -d --rm --name tpba-pg -e POSTGRES_USER=user -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=better_auth -p 5432:5432 postgres:17-alpine
TEST_POSTGRES=1 bun run test
```

**Protocol end-to-end test.** This runs the Rust plugin against the real example
server:

```sh
EXAMPLE_TEST_MODE=1 EXAMPLE_DB=/tmp/e2e.db bun examples/basic/server/src/server.ts &
TPBA_E2E_URL=http://localhost:3000 cargo test --test protocol_e2e
```

**The OS keychain test** touches your real credential store, so it is opt-in:

```sh
cargo test -p tauri-plugin-better-auth --lib -- --ignored keyring_round_trip
```

## Rules

- **Protocol changes are additive within v1.** Update [PROTOCOL.md](PROTOCOL.md)
  in the same change, with tests on both sides. Anything breaking needs a new
  protocol version.
- **Security-relevant behaviour needs a test.** That covers the bridge
  allowlist, scrubbing, state matching, generations and storage ordering.
  [SECURITY.md](SECURITY.md) lists the invariants.
- **Never log or emit secrets:** tokens, codes, states, verifiers.
- **No panics in library code.** Clippy denies `unwrap`/`expect` outside tests.
- **Public items are documented** (rustdoc and TSDoc).

## Releasing

The npm package and the crate share one version.

1. Add a changeset: `bunx changeset`.
2. `bunx changeset version` bumps `package.json` and `CHANGELOG.md`.
3. Set the same version in `crates/tauri-plugin-better-auth/Cargo.toml` and
   `packages/tauri-plugin-better-auth/src/version.ts`.
   `node scripts/check-versions.mjs` (also run in CI) verifies all three.
4. Tag `vX.Y.Z` and push. `release.yml` publishes the crate to crates.io and
   **stages** the npm version (with provenance).
5. Approve the staged npm version with 2FA: npmjs.com → Staged Packages →
   Approve, or `npm stage list` then `npm stage approve <stage-id>`.
6. `release.yml` then creates the GitHub Release from the version's
   `CHANGELOG.md` section (a pre-release for `-alpha`/`-beta` tags), so date the
   changelog heading before tagging.

The Tauri 3 line lives on the `v3` branch (`0.2.x` pre-releases). Its
`publishConfig.tag` is `next`, so approving a `v3` release never moves npm's
`latest` (the Tauri 2 line).

**npm auth:** trusted publishing (GitHub OIDC) for `release.yml`, set on the
package's npmjs.com settings. No npm token is stored in the repository.
