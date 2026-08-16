#!/usr/bin/env node
// @ts-check
/**
 * verify-release — the pre-publication checklist.
 *
 * Publishing is the one operation in this repository that cannot be undone: an
 * npm version number is permanent, and a package published with the wrong
 * `files` list ships whatever happened to be on disk. CLAUDE.md §8 already says
 * a release needs a human decision; this script is what that human reads before
 * making it.
 *
 * Every check here exists because its failure mode is expensive rather than
 * merely untidy:
 *
 *  - versions that disagree across the workspace produce a release where
 *    `@bx-labs/agent-secrets` depends on a core version that was never published;
 *  - a published package that depends on a private one installs and then fails at
 *    require time on a user's machine;
 *  - a missing `files` field publishes the whole working tree, including any
 *    stray local config;
 *  - a missing LICENSE or SECURITY.md means the first thing a security
 *    researcher looks for is not there.
 *
 * Usage: node scripts/verify-release.mjs [--json]
 * Exit codes: 0 all checks pass, 1 at least one failed, 2 the checker failed.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '..', '..');
const WORKSPACE_DIRECTORIES = ['packages', 'apps'];

/** Fields a package must declare before it is allowed anywhere near `npm publish`. */
const REQUIRED_PUBLISHED_FIELDS = [
  'version',
  'description',
  'license',
  'files',
  'exports',
  'engines',
];

/** @typedef {{ level: 'fail' | 'warn' | 'ok', title: string, detail: string }} CheckResult */

/** @type {CheckResult[]} */
const results = [];

function ok(title, detail = '') {
  results.push({ level: 'ok', title, detail });
}
function warn(title, detail) {
  results.push({ level: 'warn', title, detail });
}
function fail(title, detail) {
  results.push({ level: 'fail', title, detail });
}

async function exists(relativePath) {
  try {
    await stat(join(REPO_ROOT, relativePath));
    return true;
  } catch {
    return false;
  }
}

async function readJson(relativePath) {
  return JSON.parse(await readFile(join(REPO_ROOT, relativePath), 'utf8'));
}

/** Every workspace package, keyed by npm name. */
async function loadWorkspace() {
  /** @type {Map<string, { dir: string, manifest: any }>} */
  const packages = new Map();
  for (const root of WORKSPACE_DIRECTORIES) {
    let entries;
    try {
      entries = await readdir(join(REPO_ROOT, root), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      const dir = `${root}/${entry.name}`;
      if (!(await exists(`${dir}/package.json`))) {
        continue;
      }
      const manifest = await readJson(`${dir}/package.json`);
      packages.set(manifest.name, { dir, manifest });
    }
  }
  return packages;
}

const isPublished = (manifest) => manifest.private !== true;

async function main() {
  const json = process.argv.includes('--json');
  const packages = await loadWorkspace();

  if (packages.size === 0) {
    fail('workspace', 'no workspace packages found; is this the repository root?');
  } else {
    ok('workspace', `${packages.size} package(s) discovered`);
  }

  const published = [...packages.values()].filter((entry) => isPublished(entry.manifest));
  const privatePackages = [...packages.values()].filter((entry) => !isPublished(entry.manifest));

  // 1. Legal and disclosure files.
  for (const file of ['LICENSE', 'NOTICE', 'SECURITY.md']) {
    if (await exists(file)) {
      ok(`${file} present`);
    } else {
      fail(`${file} missing`, `create ${file} at the repository root before publishing`);
    }
  }

  // 2. Version agreement. A mixed-version release is the failure that produces
  // an unresolvable dependency graph on the registry.
  const versions = new Map();
  for (const { dir, manifest } of packages.values()) {
    if (typeof manifest.version !== 'string') {
      fail(`${dir} version`, 'package.json has no version field');
      continue;
    }
    const seen = versions.get(manifest.version) ?? [];
    seen.push(manifest.name);
    versions.set(manifest.version, seen);
  }
  if (versions.size === 1) {
    ok('versions agree', `every workspace package is at ${[...versions.keys()][0]}`);
  } else if (versions.size > 1) {
    const summary = [...versions.entries()]
      .map(([version, names]) => `${version}: ${names.join(', ')}`)
      .join(' | ');
    fail('versions disagree', summary);
  }

  // 3. Published packages carry everything npm needs.
  for (const { dir, manifest } of published) {
    const missing = REQUIRED_PUBLISHED_FIELDS.filter((field) => manifest[field] === undefined);
    if (missing.length > 0) {
      fail(`${manifest.name} manifest`, `missing field(s): ${missing.join(', ')}`);
    } else {
      ok(`${manifest.name} manifest`, 'version, description, license, files, exports, engines');
    }
    if (manifest.license !== 'Apache-2.0') {
      fail(`${manifest.name} license`, `expected Apache-2.0, found ${String(manifest.license)}`);
    }
    if (manifest.publishConfig?.access !== 'public') {
      fail(
        `${manifest.name} access`,
        'publishConfig.access must be "public"; a scoped package defaults to restricted',
      );
    }
    if (Array.isArray(manifest.files) && !manifest.files.includes('dist')) {
      fail(`${manifest.name} files`, 'the files list does not include dist');
    }
    if (!(await exists(`${dir}/README.md`))) {
      warn(`${manifest.name} README`, `${dir}/README.md is listed in files but does not exist yet`);
    }
    if (!(await exists(`${dir}/LICENSE`))) {
      warn(
        `${manifest.name} LICENSE`,
        'no per-package LICENSE; the tarball will ship without the license text',
      );
    }
  }

  // 4. Nothing private is about to be published, and nothing published depends on
  // something private. The second half is the one that reaches a user's machine.
  for (const { dir, manifest } of privatePackages) {
    if (manifest.publishConfig?.access === 'public') {
      fail(
        `${manifest.name} is private`,
        `${dir} sets private:true and publishConfig.access:public — one of the two is a mistake`,
      );
    } else {
      ok(`${manifest.name} stays unpublished`, 'private:true, no public publishConfig');
    }
  }
  for (const { manifest } of published) {
    for (const dependency of Object.keys(manifest.dependencies ?? {})) {
      const target = packages.get(dependency);
      if (!target) {
        continue; // third-party, resolved from the registry
      }
      if (!isPublished(target.manifest)) {
        fail(
          `${manifest.name} dependency`,
          `depends on ${dependency}, which is private and will never exist on the registry`,
        );
      }
    }
  }

  // 5. Workspace protocol sanity: pnpm rewrites `workspace:*` at pack time, but
  // only for packages it can see.
  for (const { manifest } of published) {
    for (const [dependency, range] of Object.entries({
      ...(manifest.dependencies ?? {}),
      ...(manifest.peerDependencies ?? {}),
    })) {
      if (
        typeof range === 'string' &&
        range.startsWith('workspace:') &&
        !packages.has(dependency)
      ) {
        fail(
          `${manifest.name} dependency`,
          `${dependency} is declared workspace: but is not a package in this workspace`,
        );
      }
    }
  }

  // 6. The gates that must have run. Their absence from package.json means the
  // release workflow would silently skip them.
  const root = await readJson('package.json');
  for (const script of ['lint', 'typecheck', 'test', 'test:integration', 'scan:secrets']) {
    if (root.scripts?.[script] === undefined) {
      fail(`root script ${script}`, 'the release gate depends on this script existing');
    }
  }
  if (results.every((result) => result.level !== 'fail')) {
    ok('release gate scripts', 'lint, typecheck, test, test:integration, scan:secrets');
  }

  const failures = results.filter((result) => result.level === 'fail');
  const warnings = results.filter((result) => result.level === 'warn');

  if (json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          schemaVersion: 1,
          ok: failures.length === 0,
          published: published.map((entry) => entry.manifest.name),
          private: privatePackages.map((entry) => entry.manifest.name),
          results,
        },
        null,
        2,
      )}\n`,
    );
    return failures.length === 0 ? 0 : 1;
  }

  process.stdout.write('Agent Secrets — release checklist\n\n');
  for (const result of results) {
    const marker =
      result.level === 'ok' ? '  [ok]  ' : result.level === 'warn' ? '  [warn]' : '  [FAIL]';
    process.stdout.write(
      `${marker} ${result.title}${result.detail ? ` — ${result.detail}` : ''}\n`,
    );
  }
  process.stdout.write(
    `\n${published.length} package(s) would be published: ${published.map((entry) => entry.manifest.name).join(', ') || 'none'}\n`,
  );
  if (failures.length === 0) {
    process.stdout.write(
      `All checks passed${warnings.length > 0 ? ` (${warnings.length} warning(s))` : ''}. ` +
        'Publication still requires the human approval described in CLAUDE.md §8.\n',
    );
    return 0;
  }
  process.stdout.write(`${failures.length} check(s) failed. Do not publish.\n`);
  return 1;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    process.stderr.write(
      `verify-release failed: ${error instanceof Error ? error.message : 'unknown error'}\n`,
    );
    process.exitCode = 2;
  });
