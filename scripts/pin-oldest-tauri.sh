#!/usr/bin/env sh
# Pins the lockfile to the oldest Tauri the crate supports (2.11.5), for CI's
# compat and MSRV jobs. The example app tracks the latest Tauri 2, so it leaves
# the workspace first. Tauri's caret requirements would otherwise pull 2.12
# runtime and build crates, which do not compile with tauri 2.11.5.
set -eu
sed -i.bak '/examples\/basic\/tauri-app\/src-tauri/d' Cargo.toml && rm Cargo.toml.bak
cargo update -p tauri --precise 2.11.5
cargo update -p tauri-runtime --precise 2.11.3
cargo update -p tauri-macros --precise 2.6.3
cargo update -p tauri-codegen --precise 2.6.3
cargo update -p tauri-plugin --precise 2.5.2
cargo update -p tauri-build --precise 2.6.3
cargo update -p tauri-utils --precise 2.9.3
