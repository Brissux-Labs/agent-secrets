#!/usr/bin/env node
// @ts-check
/**
 * check-no-raw-getter — the structural gate against the one feature this product
 * must never grow.
 *
 * CLAUDE.md §2 forbids adding a raw-value getter to the CLI JSON output, the MCP
 * toolset, or the HTTP API. That prohibition is easy to state and easy to erode:
 * it arrives as a helpful `get_secret` tool "just for debugging", as a
 * `JSON.stringify(secret)` in an error path, or as an `expose()` call nobody
 * explained. Each is individually defensible in a pull request and collectively
 * fatal.
 *
 * So the rule is enforced by a script that runs in CI rather than by reviewer
 * memory. There is deliberately **no suppression comment** for the naming and
 * serialization rules: the only way past this gate is to change this file, which
 * is a visible, arguable diff — exactly the conversation that should happen
 * before a raw getter exists.
 *
 * The single escape hatch is the one the contract already defines: an
 * `.expose()` call is legal when the line, or one of the three lines above it,
 * carries a `// expose: <reason>` justification.
 *
 * Usage: node scripts/check-no-raw-getter.mjs [--json]
 * Exit codes: 0 clean, 1 violations, 2 the checker itself failed.
 */

import { readdir, readFile } from 'node:fs/promises';
import { extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '..', '..');

/** Only first-party source. Tests legitimately expose values to assert on them,
 * and a test file cannot ship a getter to a user. */
const SOURCE_ROOTS = ['packages', 'apps'];
const SOURCE_EXTENSIONS = new Set(['.ts', '.mts', '.cts', '.js', '.mjs', '.cjs', '.tsx']);
const SKIP_DIRECTORIES = new Set(['node_modules', 'dist', 'coverage', '.git', 'test', '__tests__']);

/** Verbs that promise to hand something back. */
const RETRIEVAL_VERBS = new Set([
  'get',
  'read',
  'show',
  'reveal',
  'print',
  'dump',
  'expose',
  'unwrap',
  'extract',
  'peek',
  'disclose',
  'output',
  'render',
]);
/** Nouns that name a raw value rather than a description of one. */
const VALUE_NOUNS = new Set([
  'secret',
  'secrets',
  'value',
  'values',
  'credential',
  'credentials',
  'token',
  'tokens',
  'password',
  'passwords',
  'passphrase',
  'plaintext',
]);
/** Words that promise disclosure with no help from a noun. */
const STANDALONE_FORBIDDEN = new Set(['reveal', 'unmask', 'disclose', 'plaintext']);

/**
 * `getSecretMetadata` is fine; `getSecret` is not. The difference is entirely in
 * what follows the noun, so the check looks at the trailing word and clears the
 * name when it names a *description* of a secret, or an argument bag rather than
 * a return.
 */
const SAFE_TRAILING_WORDS = new Set([
  'options',
  'option',
  'opts',
  'params',
  'args',
  'arguments',
  'input',
  'inputs',
  'request',
  'flags',
  'metadata',
  'meta',
  'ref',
  'refs',
  'reference',
  'references',
  'name',
  'names',
  'scope',
  'scopes',
  'schema',
  'schemas',
  'backend',
  'backends',
  'rules',
  'rule',
  'type',
  'types',
  'id',
  'ids',
  'path',
  'paths',
  'dir',
  'file',
  'files',
  'config',
  'policy',
  'manifest',
  'list',
  'count',
  'error',
  'errors',
  'sink',
  'store',
  'prefix',
  'fields',
  'shape',
  'summary',
  'description',
  'status',
  'health',
  'version',
]);

/** Split camelCase / snake_case / kebab-case into lowercase words. */
function words(identifier) {
  return identifier
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

/**
 * True when the identifier reads as "hand me the raw value".
 *
 * Matching is done on normalised words, so `get_secret`, `getSecret`,
 * `secret-get` and `secretValue` are one shape. The judgement is positional: a
 * disclosure pair at the end of a name *is* the promise (`getSecret`), a pair
 * followed by one qualifying word is cleared only when that word names a
 * description or an argument bag (`getSecretMetadata`, `ReadValueOptions`), and
 * a pair followed by two or more words has been qualified into something else
 * entirely (`readValueFromTty` — a constructor of `SecretValue`, not a getter).
 *
 * This is a tripwire, not a proof. It catches the shapes a contributor reaches
 * for when they want a raw getter; it is not a defence against someone naming
 * one `harmlessHelper`, which is what review is for.
 */
function suggestsValueReturn(identifier) {
  const parts = words(identifier);
  if (parts.length === 1 && STANDALONE_FORBIDDEN.has(parts[0])) {
    return true;
  }
  for (let i = 0; i < parts.length - 1; i += 1) {
    const [first, second] = [parts[i], parts[i + 1]];
    const isDisclosurePair =
      (RETRIEVAL_VERBS.has(first) && VALUE_NOUNS.has(second)) ||
      (VALUE_NOUNS.has(first) && RETRIEVAL_VERBS.has(second)) ||
      // `secretValue` / `credential_plaintext`: two nouns already promise the
      // thing itself rather than a description of it.
      (/^(secret|secrets|credential|credentials)$/.test(first) &&
        /^(value|values|plaintext|raw)$/.test(second));
    if (!isDisclosurePair) {
      continue;
    }
    const rest = parts.slice(i + 2);
    if (rest.length === 0) {
      return true;
    }
    if (rest.length === 1 && !SAFE_TRAILING_WORDS.has(rest[0])) {
      return true;
    }
  }
  return false;
}

/**
 * Names that are part of the frozen core contract and are *about* keeping values
 * contained, not about handing them out. Each one is listed individually: a
 * blanket exemption would let the next `SecretValue`-adjacent name in for free.
 */
const ALLOWED_IDENTIFIERS = new Set([
  'SecretValue',
  'isSecretValue',
  'secretValuesEqual',
  'validateSecretValue',
  'secretValueSchema',
  'SecretDisclosureError',
  'ResolvedSecret',
  'FORBIDDEN_METADATA_FIELDS',
  'assertNoValueFields',
  'MAX_VALUE_BYTES',
  'ValueRules',
]);

/** @typedef {{ file: string, line: number, rule: string, symbol: string, detail: string }} Violation */

/**
 * @param {string} relativePath
 * @param {string} text
 * @returns {Violation[]}
 */
function checkText(relativePath, text) {
  /** @type {Violation[]} */
  const violations = [];
  const lines = text.split('\n');

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const at = i + 1;

    // 1. Exported symbols whose name promises a value.
    for (const match of line.matchAll(
      /\bexport\s+(?:default\s+)?(?:async\s+)?(?:function\*?|const|let|var|class|type|interface)\s+([A-Za-z0-9_$]+)/g,
    )) {
      const symbol = match[1];
      if (!ALLOWED_IDENTIFIERS.has(symbol) && suggestsValueReturn(symbol)) {
        violations.push({
          file: relativePath,
          line: at,
          rule: 'raw-value-getter-name',
          symbol,
          detail: 'exported name promises a raw value; the public surface carries metadata only',
        });
      }
    }
    // Re-export lists: `export { a, b as c }`.
    const exportList = /\bexport\s*\{([^}]*)\}/.exec(line);
    if (exportList) {
      for (const entry of exportList[1].split(',')) {
        const symbol =
          entry
            .trim()
            .split(/\s+as\s+/)
            .pop()
            ?.trim() ?? '';
        if (symbol && !ALLOWED_IDENTIFIERS.has(symbol) && suggestsValueReturn(symbol)) {
          violations.push({
            file: relativePath,
            line: at,
            rule: 'raw-value-getter-name',
            symbol,
            detail: 'exported name promises a raw value',
          });
        }
      }
    }

    // 2. Tool, command and route names declared as string literals. An MCP tool
    // called `secret_get` is a raw getter no matter how its handler is written.
    for (const match of line.matchAll(
      /(?:\.(?:tool|registerTool|command|addTool)\(|\bname\s*:\s*|\.(?:get|post|put)\(\s*)['"`]([A-Za-z0-9_./:-]{3,64})['"`]/g,
    )) {
      const literal = match[1].replace(/^\/+/, '').replace(/[/:]/g, '_');
      if (suggestsValueReturn(literal)) {
        violations.push({
          file: relativePath,
          line: at,
          rule: 'raw-value-tool-name',
          symbol: match[1],
          detail: 'tool, command or route name promises a raw value',
        });
      }
    }

    // 3. `.expose()` without an adjacent justification. The comment is the whole
    // point: it makes every legitimate disclosure a sentence somebody had to
    // write and a reviewer can disagree with.
    if (/\.expose\s*\(/.test(line)) {
      const window = lines.slice(Math.max(0, i - 3), i + 1).join('\n');
      if (!/\/\/\s*expose:\s*\S/.test(window) && !/\*\s*expose:\s*\S/.test(window)) {
        violations.push({
          file: relativePath,
          line: at,
          rule: 'unjustified-expose',
          symbol: '.expose()',
          detail: 'add a `// expose: <reason>` comment on or above this call',
        });
      }
    }

    // 4. Serializing something value-shaped. `SecretValue.toJSON` throws, so this
    // would fail at runtime — but only on the path that happens to execute, which
    // may be the error path nobody tests.
    //
    // The test is on the *name*: an argument has to actually be called a secret
    // for a name-based rule to have anything to say. `JSON.stringify(raw)` inside
    // the redaction engine — which must serialize a value precisely in order to
    // recognise its escaped form later — is out of reach here, and is guarded by
    // that package's own canary tests instead.
    for (const match of line.matchAll(/JSON\.stringify\(\s*([A-Za-z0-9_$.[\]]{1,64})/g)) {
      const argument = match[1];
      const tail = argument.split('.').pop() ?? argument;
      const parts = words(tail);
      const namesAValue =
        parts.some((part) => VALUE_NOUNS.has(part) && part !== 'value' && part !== 'values') ||
        (parts.length === 1 && (parts[0] === 'value' || parts[0] === 'values'));
      if (namesAValue || suggestsValueReturn(tail)) {
        violations.push({
          file: relativePath,
          line: at,
          rule: 'stringify-secret',
          symbol: argument,
          detail: 'a value-named binding must never reach a serializer',
        });
      }
    }
  }

  return violations;
}

async function* walk(directory) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRECTORIES.has(entry.name)) {
        yield* walk(join(directory, entry.name));
      }
      continue;
    }
    if (entry.isFile() && SOURCE_EXTENSIONS.has(extname(entry.name))) {
      yield join(directory, entry.name);
    }
  }
}

/**
 * Self-check: the detector must still fire on the canonical bad shapes. A
 * checker that has been regexed into permanence of "clean" is worse than none.
 */
function selfTest() {
  const bad = [
    'getSecret',
    'get_secret',
    'secret_get',
    'secret_value',
    'revealValue',
    'showSecret',
    'secretValue',
    'getValue',
    'reveal',
    'dumpCredentials',
  ];
  const good = [
    'getSecretMetadata',
    'listSecrets',
    'describeSecret',
    'secretNameSchema',
    'resolveMany',
    'readValueFromTty',
    'ReadValueOptions',
  ];
  return (
    bad.every((name) => suggestsValueReturn(name)) &&
    good.every((name) => !suggestsValueReturn(name))
  );
}

async function main() {
  const json = process.argv.includes('--json');

  if (!selfTest()) {
    process.stderr.write(
      'check-no-raw-getter: self-test failed; refusing to report a clean tree.\n',
    );
    return 2;
  }

  /** @type {Violation[]} */
  const violations = [];
  let filesChecked = 0;
  for (const root of SOURCE_ROOTS) {
    for await (const absolute of walk(join(REPO_ROOT, root))) {
      const relativePath = relative(REPO_ROOT, absolute);
      filesChecked += 1;
      violations.push(...checkText(relativePath, await readFile(absolute, 'utf8')));
    }
  }
  violations.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);

  if (json) {
    process.stdout.write(
      `${JSON.stringify({ schemaVersion: 1, ok: violations.length === 0, filesChecked, violations }, null, 2)}\n`,
    );
    return violations.length === 0 ? 0 : 1;
  }

  for (const violation of violations) {
    process.stdout.write(
      `${violation.file}:${violation.line}  ${violation.rule}  ${violation.symbol} — ${violation.detail}\n`,
    );
  }
  if (violations.length === 0) {
    process.stdout.write(`check-no-raw-getter: clean — ${filesChecked} source file(s)\n`);
    return 0;
  }
  process.stdout.write(
    `\ncheck-no-raw-getter: ${violations.length} violation(s). These shapes are prohibited by CLAUDE.md §2 ` +
      'and §3; they are not waived by editing this script without a human-approved PRD amendment.\n',
  );
  return 1;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    process.stderr.write(
      `check-no-raw-getter failed: ${error instanceof Error ? error.message : 'unknown error'}\n`,
    );
    process.exitCode = 2;
  });
