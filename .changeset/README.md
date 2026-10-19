# Changesets

Run `bunx changeset` to describe a change. The npm package and the Rust crate
share one version: after `bunx changeset version`, copy the new version into
`crates/tauri-plugin-better-auth/Cargo.toml` and
`packages/tauri-plugin-better-auth/src/version.ts` (CI checks all three).
