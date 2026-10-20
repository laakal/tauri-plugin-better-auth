#!/usr/bin/env node
// Prepares a release commit and tag: `bun run release [version] [--dry-run]`.
//
// 1. Refuses a dirty tree or a branch other than `main` / `v3`.
// 2. Applies pending changesets (`changeset version`) when there are any;
//    otherwise uses the version given on the command line.
// 3. Writes the version to package.json, the crate's Cargo.toml (and
//    Cargo.lock) and src/version.ts, and dates the CHANGELOG.md heading.
// 4. Runs check-versions and `bun run check`, then commits
//    "chore: release vX.Y.Z" and tags `vX.Y.Z`.
//
// It never pushes: it prints the push command so the commit can be checked
// first. Pushing the tag starts release.yml (crates.io, npm staging, GitHub
// Release). With --dry-run it stops before committing and leaves the changes
// in the working tree.
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const path = (p) => new URL(p, root);
const read = (p) => readFileSync(path(p), 'utf8');
const write = (p, s) => writeFileSync(path(p), s);
const run = (cmd, args, opts = {}) =>
  execFileSync(cmd, args, {
    cwd: root,
    encoding: 'utf8',
    stdio: opts.quiet ? 'pipe' : 'inherit',
  });
const fail = (msg) => {
  console.error(`release: ${msg}`);
  process.exit(1);
};

const PKG = 'packages/tauri-plugin-better-auth/package.json';
// Where `changeset version` writes its notes; they move to the root CHANGELOG.md.
const PKG_CHANGELOG = 'packages/tauri-plugin-better-auth/CHANGELOG.md';
const CRATE = 'crates/tauri-plugin-better-auth/Cargo.toml';
const VERSION_TS = 'packages/tauri-plugin-better-auth/src/version.ts';
const CHANGELOG = 'CHANGELOG.md';
const BRANCHES = ['main', 'v3'];
const SEMVER = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/;

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const requested = args.find((a) => !a.startsWith('--'))?.replace(/^v/, '');
if (requested !== undefined && !SEMVER.test(requested)) {
  fail(`"${requested}" is not a version like 0.1.1 or 0.2.0-alpha.1`);
}

// 1. Clean tree on a release branch.
const branch = run('git', ['branch', '--show-current'], { quiet: true }).trim();
if (!BRANCHES.includes(branch)) {
  fail(`release from ${BRANCHES.join(' or ')}, not "${branch}"`);
}
if (run('git', ['status', '--porcelain'], { quiet: true }).trim()) {
  fail('the working tree has uncommitted changes; commit or stash them first');
}

const current = JSON.parse(read(PKG)).version;

// The tree was clean, so undoing everything this run changed is safe.
const abort = (msg) => {
  run('git', ['checkout', '--', '.'], { quiet: true });
  run('git', ['clean', '-fdq'], { quiet: true });
  fail(msg);
};

// 2. Pending changesets decide the version; otherwise the argument does.
const pending = existsSync(path('.changeset/'))
  ? readdirSync(path('.changeset/')).filter(
      (f) => f.endsWith('.md') && f !== 'README.md',
    )
  : [];
let version;
if (pending.length > 0) {
  console.log(`applying ${pending.length} changeset(s)…`);
  run('bun', ['x', 'changeset', 'version']);
  version = JSON.parse(read(PKG)).version;
  if (requested && requested !== version) {
    abort(
      `the changesets give ${version}, not ${requested}; run without a version, or adjust the changesets`,
    );
  }
  moveChangesetNotes(version);
} else {
  if (!requested) {
    fail(
      'no pending changesets: pass the version, e.g. `bun run release 0.1.1`',
    );
  }
  version = requested;
  const pkg = JSON.parse(read(PKG));
  pkg.version = version;
  write(PKG, `${JSON.stringify(pkg, null, 2)}\n`);
}

if (version === current) abort(`the version is already ${current}`);
const tag = `v${version}`;
if (run('git', ['tag', '--list', tag], { quiet: true }).trim()) {
  abort(`tag ${tag} already exists`);
}

// 3. Same version everywhere, and a dated changelog heading.
const crate = read(CRATE);
if (!/^version = "[^"]*"/m.test(crate)) abort(`no version line in ${CRATE}`);
write(CRATE, crate.replace(/^version = "[^"]*"/m, `version = "${version}"`));
write(
  VERSION_TS,
  read(VERSION_TS).replace(/VERSION = '[^']*'/, `VERSION = '${version}'`),
);

const today = new Date().toISOString().slice(0, 10);
const lines = read(CHANGELOG).split('\n');
const at = lines.findIndex(
  (l) => l === `## ${version}` || l.startsWith(`## ${version} `),
);
if (at === -1) {
  abort(
    `${CHANGELOG} has no "## ${version}" section; add one (or a changeset) describing the release`,
  );
}
const heading = lines[at];
if (heading === `## ${version}`) {
  lines[at] = `## ${version} (${today})`;
} else if (heading.includes('(unreleased')) {
  lines[at] = heading.replace('(unreleased', `(${today}`);
}
write(CHANGELOG, lines.join('\n'));

// Cargo.lock follows the crate version.
run('cargo', [
  'update',
  '-p',
  'tauri-plugin-better-auth',
  '--offline',
  '--quiet',
]);

// 4. Checks, then commit and tag.
run('node', ['scripts/check-versions.mjs']);
run('bunx', ['oxfmt', CHANGELOG, PKG], { quiet: true });
run('bun', ['run', 'check'], { quiet: true });

if (dryRun) {
  console.log(
    `\ndry run: ${tag} prepared in the working tree, nothing committed.\n` +
      'Inspect with `git diff`, then discard with `git checkout -- . && git clean -fd .changeset`.',
  );
  process.exit(0);
}

run('git', ['add', '-A']);
run('git', ['commit', '-q', '-m', `chore: release ${tag}`]);
run('git', ['tag', tag]);
console.log(
  `\n${tag} committed and tagged on ${branch}. Check it, then publish with:\n\n` +
    `  git push origin ${branch} ${tag}\n\n` +
    'Then approve the staged npm version with 2FA (npmjs.com → Staged Packages).',
);

/**
 * `changeset version` writes "## <version>" plus its notes into the package's
 * own CHANGELOG.md. This repo keeps one CHANGELOG.md at the root (the crate
 * and the npm package share it), so the section moves there, above the
 * previous release, and the package file goes away again.
 */
function moveChangesetNotes(version) {
  if (!existsSync(path(PKG_CHANGELOG))) return;
  const pkgLines = read(PKG_CHANGELOG).split('\n');
  const start = pkgLines.findIndex((l) => l === `## ${version}`);
  if (start === -1) return;
  const next = pkgLines.findIndex((l, i) => i > start && l.startsWith('## '));
  const section = pkgLines
    .slice(start, next === -1 ? undefined : next)
    .join('\n')
    .trimEnd();
  const tracked = run('git', ['ls-files', PKG_CHANGELOG], {
    quiet: true,
  }).trim();
  if (tracked) run('git', ['checkout', '--', PKG_CHANGELOG], { quiet: true });
  else run('git', ['clean', '-fq', '--', PKG_CHANGELOG], { quiet: true });

  const rootLines = read(CHANGELOG).split('\n');
  const first = rootLines.findIndex((l) => l.startsWith('## '));
  const at = first === -1 ? rootLines.length : first;
  rootLines.splice(at, 0, ...section.split('\n'), '');
  write(CHANGELOG, rootLines.join('\n'));
}
