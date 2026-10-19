// Fails when the npm package, the crate and the VERSION constant disagree.
// They are released together under one version (see CONTRIBUTING.md).
import { readFileSync } from 'node:fs';

const read = (path) =>
  readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

const npm = JSON.parse(
  read('packages/tauri-plugin-better-auth/package.json'),
).version;
const crate = /^version\s*=\s*"([^"]+)"/m.exec(
  read('crates/tauri-plugin-better-auth/Cargo.toml'),
)?.[1];
const constant = /VERSION = '([^']+)'/.exec(
  read('packages/tauri-plugin-better-auth/src/version.ts'),
)?.[1];

if (npm !== crate || crate !== constant) {
  console.error(
    `version mismatch: package.json ${npm}, Cargo.toml ${crate}, src/version.ts ${constant}`,
  );
  process.exit(1);
}
console.log(`versions in lockstep: ${npm}`);
