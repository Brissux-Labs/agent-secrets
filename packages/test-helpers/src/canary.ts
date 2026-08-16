import { randomBytes } from 'node:crypto';
import type { Dirent } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { findRepoRoot, runProcess } from './capture.js';

/**
 * Canary helpers.
 *
 * A canary is a random, greppable string used as a stand-in for a secret value.
 * Running a flow with a canary and then proving the canary appears nowhere it
 * should not is the only leak test that generalises: it catches the sink nobody
 * thought to mock.
 *
 * TODO(agent-secrets#redaction): these primitives belong in
 * `@bx-labs/agent-secrets-redaction`, and `canary.ts` is meant to re-export them
 * so there is exactly one definition of the canary format. That package is not
 * a dependency of this one yet (it is being written in parallel and adding it
 * would mean editing package.json, which this task may not do), so the format
 * is duplicated here. When the dependency exists, delete the local definitions
 * below and re-export instead — the prefix and length must stay byte-identical
 * or the scanner in scripts/scan-secrets.mjs will stop matching.
 */

export const CANARY_PREFIX = 'ASECRET_CANARY_';

/** Hex characters after the prefix. 24 hex = 96 bits: no accidental collision. */
export const CANARY_BODY_LENGTH = 24;

const CANARY_PATTERN = new RegExp(`${CANARY_PREFIX}[0-9a-f]{${CANARY_BODY_LENGTH}}`, 'g');

export function makeCanary(): string {
  return CANARY_PREFIX + randomBytes(CANARY_BODY_LENGTH / 2).toString('hex');
}

export function isCanary(candidate: string): boolean {
  return new RegExp(`^${CANARY_PREFIX}[0-9a-f]{${CANARY_BODY_LENGTH}}$`).test(candidate);
}

export function containsCanary(haystack: string, canary: string): boolean {
  return canary.length > 0 && haystack.includes(canary);
}

/** Every canary-shaped string in the haystack, whatever its body. */
export function findCanaries(haystack: string): string[] {
  return [...new Set(haystack.match(CANARY_PATTERN) ?? [])];
}

export interface CanaryHit {
  /** Where the canary was found: a file path, or a named stream. */
  readonly location: string;
  readonly kind: 'file' | 'stream';
  /** How many times it occurred. The canary itself is never reported back. */
  readonly occurrences: number;
}

export interface CanarySweepRoots {
  /** A temp home directory, or anything exposing `{ path }`. Scanned recursively. */
  readonly home?: string | { readonly path: string };
  /** Individual files: the SQLite database, an audit log, a generated config. */
  readonly files?: readonly string[];
  /** Additional directories to walk. */
  readonly dirs?: readonly string[];
  /** Captured output, keyed by a name that ends up in the hit location. */
  readonly streams?: Readonly<Record<string, string>>;
  /**
   * Scan the git working tree (tracked plus untracked, honouring .gitignore).
   * `true` resolves the repository root automatically.
   */
  readonly repo?: string | boolean;
  /**
   * Paths the canary is *allowed* to appear in — in practice the fake vault
   * state file, which is the one legitimate destination for a test value.
   * Absolute paths, or any path a hit location starts with.
   */
  readonly allow?: readonly string[];
  /** Skip files larger than this. 16 MiB default. */
  readonly maxFileBytes?: number;
}

export interface CanarySweepResult {
  readonly clean: boolean;
  readonly hits: readonly CanaryHit[];
  /** How many files and streams were actually read. */
  readonly scanned: number;
  /** Locations that matched but were listed in `allow`. */
  readonly allowed: readonly string[];
}

const DEFAULT_MAX_FILE_BYTES = 16 * 1024 * 1024;

/**
 * Scan every place a value could have escaped to, in one call.
 *
 * Returns a result rather than throwing, so a test can assert on the exact set
 * of hits; `assertNoCanary` is the throwing wrapper. Neither ever puts the
 * canary itself into a message: a failing assertion that prints the value would
 * write it to the CI log, which is the leak the test exists to prevent.
 */
export async function sweepForCanary(
  canary: string,
  roots: CanarySweepRoots = {},
): Promise<CanarySweepResult> {
  if (canary.length === 0) {
    throw new Error('sweepForCanary requires a non-empty canary.');
  }

  const maxFileBytes = roots.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const allow = (roots.allow ?? []).map((entry) => resolve(entry));
  const hits: CanaryHit[] = [];
  const allowed: string[] = [];
  let scanned = 0;

  const candidates = new Set<string>();

  const homePath = typeof roots.home === 'string' ? roots.home : roots.home?.path;
  for (const directory of [homePath, ...(roots.dirs ?? [])]) {
    if (directory !== undefined) {
      for (const file of await walkFiles(directory)) {
        candidates.add(file);
      }
    }
  }
  for (const file of roots.files ?? []) {
    candidates.add(resolve(file));
  }
  if (roots.repo !== undefined && roots.repo !== false) {
    const repoRoot = typeof roots.repo === 'string' ? roots.repo : undefined;
    for (const file of await listGitWorkingTree(repoRoot)) {
      candidates.add(file);
    }
  }

  for (const file of candidates) {
    let content: string;
    try {
      const info = await stat(file);
      if (!info.isFile() || info.size > maxFileBytes) {
        continue;
      }
      // UTF-8 even for binary artefacts: an ASCII canary survives lossy
      // decoding, and that is the whole requirement.
      content = await readFile(file, 'utf8');
    } catch {
      // A file that vanished between listing and reading cannot be leaking.
      continue;
    }
    scanned += 1;
    const occurrences = countOccurrences(content, canary);
    if (occurrences === 0) {
      continue;
    }
    if (allow.some((prefix) => file === prefix || file.startsWith(`${prefix}/`))) {
      allowed.push(file);
      continue;
    }
    hits.push({ location: file, kind: 'file', occurrences });
  }

  for (const [name, content] of Object.entries(roots.streams ?? {})) {
    scanned += 1;
    const occurrences = countOccurrences(content, canary);
    if (occurrences > 0) {
      hits.push({ location: name, kind: 'stream', occurrences });
    }
  }

  return { clean: hits.length === 0, hits, scanned, allowed };
}

/** Throws with the leaking locations — never with the canary itself. */
export async function assertNoCanary(
  canary: string,
  roots: CanarySweepRoots = {},
): Promise<CanarySweepResult> {
  const result = await sweepForCanary(canary, roots);
  if (!result.clean) {
    const locations = result.hits.map((hit) => `${hit.kind}:${hit.location}`).join(', ');
    throw new Error(`Canary leaked into ${result.hits.length} location(s): ${locations}`);
  }
  return result;
}

function countOccurrences(haystack: string, needle: string): number {
  let count = 0;
  let index = haystack.indexOf(needle);
  while (index !== -1) {
    count += 1;
    index = haystack.indexOf(needle, index + needle.length);
  }
  return count;
}

async function walkFiles(root: string): Promise<string[]> {
  const found: string[] = [];
  let entries: Dirent[];
  try {
    entries = await readdir(resolve(root), { withFileTypes: true });
  } catch {
    return found;
  }
  for (const entry of entries) {
    const absolute = join(resolve(root), entry.name);
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      found.push(...(await walkFiles(absolute)));
      continue;
    }
    found.push(absolute);
  }
  return found;
}

/**
 * Tracked plus untracked-but-not-ignored files. `git ls-files` is used instead
 * of a manual walk so that `node_modules` and `dist` are excluded by the same
 * rules the repository already declares.
 */
async function listGitWorkingTree(repoRoot?: string): Promise<string[]> {
  const root = repoRoot ?? findRepoRoot();
  const result = await runProcess(
    'git',
    ['-C', root, 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    { timeoutMs: 30_000 },
  );
  if (result.code !== 0) {
    return [];
  }
  return result.stdout
    .split('\u0000')
    .filter((entry) => entry.length > 0)
    .map((entry) => (isAbsolute(entry) ? entry : join(root, entry)));
}
