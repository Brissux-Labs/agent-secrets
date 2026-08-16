import { randomBytes } from 'node:crypto';
import type { Stats } from 'node:fs';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { derivedForms } from './scope.js';

/**
 * Canary harness.
 *
 * The redaction rules in this package are assertions about behaviour; canaries
 * are how every other package proves them. A test generates a unique, obviously
 * synthetic value, pushes it through a real flow, and then asserts it is absent
 * from every place a value could have escaped to: stdout, stderr, the audit log,
 * the SQLite file, generated config, the git working tree.
 *
 * This inverts the usual test: instead of asserting that the right thing
 * happened, it asserts that the wrong thing did not happen anywhere. It is the
 * only technique that catches a leak through a channel nobody thought to check.
 */

/** Recognisable at a glance in a diff, a log, or a secret scanner's output. */
export const CANARY_PREFIX = 'ASECRET_CANARY_';

const CANARY_PATTERN = /^ASECRET_CANARY_[0-9a-f]{32}$/;

/**
 * Files above this are not searched.
 *
 * A leak scan runs over a working tree that may contain build artefacts, test
 * fixtures, or a multi-gigabyte database. Reading those into memory would turn
 * the safety net into an out-of-memory failure. 16 MiB comfortably covers every
 * artefact this product produces; anything larger is reported by the caller's
 * own inventory checks, not here.
 */
export const MAX_SCANNED_FILE_BYTES = 16 * 1024 * 1024;

const SKIPPED_DIRECTORIES = new Set(['node_modules', '.git', 'dist', 'coverage', '.turbo']);

/**
 * A fresh canary. 128 bits of randomness from the CSPRNG, so two concurrent
 * tests can never collide and a match can never be a coincidence.
 */
export function newCanary(): string {
  return CANARY_PREFIX + randomBytes(16).toString('hex');
}

export function isCanary(candidate: string): boolean {
  return CANARY_PATTERN.test(candidate);
}

export type Haystacks = Record<string, string | Buffer | undefined>;

/**
 * Assert a canary appears in none of the named haystacks.
 *
 * The thrown error names the haystacks that matched and nothing else. It
 * deliberately prints no excerpt, no offset and no surrounding context: the
 * bytes next to a leaked canary are, by construction, whatever the flow was
 * handling at the time, and a failing assertion that dumps them would leak the
 * very thing the test exists to prevent — into CI logs, which are usually more
 * widely readable than the process that leaked.
 */
export function assertNoCanary(canary: string, haystacks: Haystacks): void {
  assertIsCanary(canary);

  const leaked: string[] = [];
  for (const [name, haystack] of Object.entries(haystacks)) {
    if (haystack === undefined) {
      continue;
    }
    if (contains(haystack, canary)) {
      leaked.push(name);
    }
  }

  if (leaked.length > 0) {
    throw new Error(
      `Canary leak: the test value appeared in ${leaked.length} of ${Object.keys(haystacks).length} ` +
        `checked outputs: ${leaked.join(', ')}. ` +
        'Content is withheld deliberately — inspect the flow, not this message.',
    );
  }
}

/**
 * Recursively search paths for a canary, returning the files that contain it.
 *
 * Returns rather than throws so a caller can scan several roots and report all
 * of them at once. Unreadable entries, dangling symlinks and races with a
 * concurrent build are skipped rather than failing the scan: a leak scanner that
 * aborts on the first permission error stops being run.
 */
export async function scanPathsForCanary(canary: string, paths: string[]): Promise<string[]> {
  assertIsCanary(canary);

  const needles = canaryNeedles(canary);
  const hits: string[] = [];
  const visited = new Set<string>();

  for (const path of paths) {
    await scanEntry(resolve(path), needles, hits, visited);
  }
  return hits.sort();
}

async function scanEntry(
  path: string,
  needles: readonly Buffer[],
  hits: string[],
  visited: Set<string>,
): Promise<void> {
  if (visited.has(path)) {
    return;
  }
  visited.add(path);

  let stats: Stats;
  try {
    // `lstat`, not `stat`: symlinks are not followed. Following them would let a
    // link in a fixture directory walk the scanner out of the tree under test,
    // and would make a symlink loop hang it.
    stats = await lstat(path);
  } catch {
    return;
  }

  if (stats.isDirectory()) {
    if (SKIPPED_DIRECTORIES.has(basename(path))) {
      return;
    }
    let entries: string[];
    try {
      entries = await readdir(path);
    } catch {
      return;
    }
    for (const entry of entries) {
      await scanEntry(join(path, entry), needles, hits, visited);
    }
    return;
  }

  if (!stats.isFile() || stats.size === 0 || stats.size > MAX_SCANNED_FILE_BYTES) {
    return;
  }

  let content: Buffer;
  try {
    // Read as bytes, never as a decoded string: decoding a binary file can throw
    // or silently mangle the very bytes we are looking for. `Buffer.includes` is
    // a byte search, so it is safe on any content.
    content = await readFile(path);
  } catch {
    return;
  }

  if (needles.some((needle) => content.includes(needle))) {
    hits.push(path);
  }
}

/**
 * Every spelling of the canary that a leak could take.
 *
 * A canary that arrives base64'd into an Authorization header, or UTF-16LE into
 * a plist, has leaked exactly as much as one printed verbatim — so the harness
 * searches for the same derived forms redaction knows about, plus the wide
 * encoding. False positives are not a concern: these are 128-bit random strings,
 * so any match is the real thing.
 */
function canaryNeedleStrings(canary: string): readonly string[] {
  return derivedForms(canary);
}

function canaryNeedles(canary: string): readonly Buffer[] {
  const needles = canaryNeedleStrings(canary).map((form) => Buffer.from(form, 'utf8'));
  return [...needles, Buffer.from(canary, 'utf16le')];
}

function contains(haystack: string | Buffer, canary: string): boolean {
  return typeof haystack === 'string'
    ? canaryNeedleStrings(canary).some((needle) => haystack.includes(needle))
    : canaryNeedles(canary).some((needle) => haystack.includes(needle));
}

/**
 * Refuse to search for anything that is not a canary.
 *
 * Without this guard these helpers are a general-purpose "find this string in
 * the filesystem" tool, and the obvious next step is to pass a real secret to
 * it — which would mean writing that secret into a test file, a CI command line
 * and a process argument list. Restricting the needle to the canary shape closes
 * that path.
 */
function assertIsCanary(canary: string): void {
  if (!isCanary(canary)) {
    throw new TypeError(
      'Expected a canary from newCanary(). These helpers refuse arbitrary needles ' +
        'so they can never be pointed at a real secret value.',
    );
  }
}
