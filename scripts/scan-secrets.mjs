#!/usr/bin/env node
// @ts-check
/**
 * scan-secrets — the working-tree leak gate.
 *
 * Runs on every commit (pre-commit hook, `--staged`) and in CI (whole tree). It
 * answers one question: did anything value-shaped reach a file we are about to
 * publish to a git object?
 *
 * Design commitments, all of them consequences of CLAUDE.md §1:
 *
 *  - **The scanner never prints what it found.** A leak report that quotes the
 *    leaked string copies the secret into CI logs, terminal scrollback, and the
 *    reviewer's clipboard — turning a detector into a second disclosure channel.
 *    Output is FILE:LINE:COLUMN plus a rule name, and nothing else.
 *  - **Zero dependencies.** This gate must run before `pnpm install` has been
 *    trusted, and it must not itself be a supply-chain surface.
 *  - **Canaries are non-negotiable.** A generated `ASECRET_CANARY_<random>` in a
 *    committed file means a test's fake value escaped its sandbox; that is
 *    exactly the failure the canary exists to prove impossible, so it cannot be
 *    suppressed. Documentation refers to the placeholder form
 *    `ASECRET_CANARY_<random>` (angle brackets), which is not a canary and does
 *    not match.
 *  - **Suppression is explicit and reviewable.** Docs legitimately show
 *    credential *shapes*. They opt out with
 *    `agent-secrets:allow-secret-scan <reason>` on the line itself or the line
 *    before, the reason is mandatory, and every honoured suppression is counted
 *    in the summary so a reviewer sees the gate being relaxed in the diff.
 *
 * Usage:
 *   node scripts/scan-secrets.mjs [--staged] [--json] [--help]
 *
 * Exit codes: 0 clean, 1 findings, 2 the scanner itself failed.
 */

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { open, readdir, stat } from 'node:fs/promises';
import { basename, extname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPO_ROOT = resolve(SCRIPT_PATH, '..', '..');

/** Files above this size are almost never hand-written config; scanning them all
 * would make the pre-commit hook slow enough that someone disables it. */
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const READ_CHUNK_BYTES = 64 * 1024;
/** Minified bundles and data blobs put megabytes on one line. Cap the entropy
 * pass per line so a pathological file cannot dominate the run. */
const MAX_LINE_CHARS_FOR_ENTROPY = 4096;
const CONCURRENCY = 16;

const SKIP_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  'dist',
  'coverage',
  '.turbo',
  '.next',
  '.pnpm-store',
  '.vercel',
  'build',
  'out',
]);

/** Generated files whose high-entropy content is integrity data, not credentials. */
const GENERATED_FILES = new Set([
  'pnpm-lock.yaml',
  'package-lock.json',
  'yarn.lock',
  'bun.lockb',
  'Cargo.lock',
]);

const SKIP_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.ico',
  '.pdf',
  '.zip',
  '.gz',
  '.tgz',
  '.woff',
  '.woff2',
  '.ttf',
  '.otf',
  '.mp4',
  '.mov',
  '.wasm',
  '.tsbuildinfo',
  '.map',
]);

/**
 * Credential shapes.
 *
 * MUST BE KEPT IN SYNC with `packages/redaction/src/patterns.ts`, which does the
 * same job at runtime for log sinks. They are duplicated on purpose: this script
 * has to run with no build step and no dependencies, including on a checkout
 * where TypeScript has never been compiled. `checkPatternDrift()` below reads the
 * TypeScript file when it exists and reports names that have diverged.
 *
 * `entropyFloor` guards the loose prefixes (`sk-`, `xox…`) against matching
 * hyphenated English in documentation. `placeholderOk` is applied to every match
 * regardless — see `looksLikePlaceholder`.
 */
const CREDENTIAL_PATTERNS = [
  // --- Shapes shared with packages/redaction/src/patterns.ts. Names and regexes
  // are copied from it verbatim so that a match here and a redaction there mean
  // the same thing; `checkPatternDrift()` flags divergence.
  { name: 'anthropic-api-key', regex: /\bsk-ant-[A-Za-z0-9_-]{20,200}/g, entropyFloor: 3.4 },
  {
    // The classic form deliberately excludes `-`, which is what keeps
    // `sk-a-hyphenated-phrase-in-prose` out of the results.
    name: 'openai-api-key',
    regex: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,200}|\bsk-[A-Za-z0-9]{32,200}/g,
    entropyFloor: 3.4,
  },
  {
    name: 'github-token',
    regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g,
    entropyFloor: 3.2,
  },
  { name: 'aws-access-key-id', regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g, entropyFloor: 0 },
  { name: 'slack-token', regex: /\bxox[baprse]-[A-Za-z0-9-]{10,255}/g, entropyFloor: 3.0 },
  {
    name: 'stripe-secret-key',
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,120}\b/g,
    entropyFloor: 3.2,
  },
  {
    name: 'google-api-key',
    regex: /\bAIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g,
    entropyFloor: 3.2,
  },
  {
    name: 'telegram-bot-token',
    regex: /\b\d{6,12}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g,
    entropyFloor: 3.4,
  },
  // `private-key-pem` is handled by the whole-file pass below: it is the one
  // shape that spans lines.
  {
    name: 'jwt',
    regex: /\beyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{0,4096}/g,
    entropyFloor: 3.6,
  },
  {
    // `bws` machine-account token: the one credential this product itself holds.
    name: 'bitwarden-access-token',
    regex:
      /\b0\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[A-Za-z0-9+/=_-]{20,512}/g,
    entropyFloor: 3.4,
  },
  {
    name: 'authorization-header',
    regex: /(?:(?:Proxy-)?Authorization\s*:\s*)?(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{16,4096}/gi,
    entropyFloor: 3.2,
  },

  // --- Additional shapes that matter at rest but not in a log stream. These
  // have no runtime counterpart: they are credentials for the *release* path
  // (npm, CI, package registries) or for services a contributor might paste into
  // a config file, none of which a redacting log sink would ever see.
  { name: 'gitlab-pat', regex: /\bglpat-[A-Za-z0-9_-]{20,64}/g, entropyFloor: 3.2 },
  { name: 'npm-token', regex: /\bnpm_[A-Za-z0-9]{36}\b/g, entropyFloor: 3.2 },
  { name: 'huggingface-token', regex: /\bhf_[A-Za-z0-9]{30,64}\b/g, entropyFloor: 3.2 },
  {
    name: 'sendgrid-api-key',
    regex: /\bSG\.[A-Za-z0-9_-]{16,64}\.[A-Za-z0-9_-]{16,64}/g,
    entropyFloor: 3.4,
  },
  {
    name: 'gcp-service-account-json',
    regex: /"type"\s*:\s*"service_account"/g,
    entropyFloor: 0,
  },
  {
    name: 'slack-webhook-url',
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/]{20,255}/g,
    entropyFloor: 3.0,
  },
  {
    // A password embedded in a connection string. Committed far more often than
    // a vendor token, and just as fatal.
    name: 'credentialed-url',
    regex:
      /\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp):\/\/[^\s:@/]{1,128}:[^\s:@/]{6,128}@/g,
    entropyFloor: 0,
  },
];

/** Key names that make a high-entropy value on the same line suspicious. */
const SUSPICIOUS_KEY =
  /(secret|token|passwo?rd|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|client[_-]?secret|auth|signing[_-]?key|salt|bearer|dsn|connection[_-]?string|session[_-]?key)/i;

/**
 * Substrings that mark a string as deliberately fake. Documentation and examples
 * must use one of these; the list is the contract between this scanner and every
 * doc author in the repo.
 */
const PLACEHOLDER_MARKERS = [
  'example',
  'placeholder',
  'changeme',
  'change-me',
  'replace',
  'redacted',
  'dummy',
  'sample',
  'your',
  'yours',
  'xxxx',
  'aaaa',
  'not-a-real',
  'fake',
  'test-only',
  'paste',
  'here',
  '...',
];

const CONFIG_EXTENSIONS = new Set([
  '.env',
  '.yaml',
  '.yml',
  '.json',
  '.jsonc',
  '.toml',
  '.ini',
  '.cfg',
  '.conf',
  '.properties',
  '.tfvars',
  '.plist',
  '.sh',
  '.bash',
  '.zsh',
  '.fish',
  '.service',
]);

const CONFIG_FILENAME =
  /^(?:\.env(?:\..+)?|dockerfile|docker-compose(?:\..+)?\.ya?ml|makefile|procfile)$/i;

const SUPPRESSION_MARKER = /agent-secrets:allow-secret-scan(.*)$/;

/**
 * A real canary is `ASECRET_CANARY_` followed by generated hex —
 * `packages/test-helpers/src/canary.ts` emits 24 hex characters. Matching that
 * shape rather than the bare prefix is what lets prose say
 * `ASECRET_CANARY_<random>` and lets a test assert on a negative case like
 * `ASECRET_CANARY_nothex`, while every genuinely generated canary still fails
 * the gate. The floor is 16 rather than 24 so that shortening the body in
 * canary.ts cannot silently blind this rule; `checkPatternDrift` warns if it
 * drops below that.
 */
const CANARY_REGEX = /ASECRET_CANARY_[0-9a-f]{16,}/g;

/**
 * Matched against the whole file rather than line by line: a PEM block puts its
 * header and its key material on different lines. The header alone is a *shape*
 * — tests and docs legitimately contain one — so a finding also requires real
 * base64 key material close behind it.
 */
const PEM_HEADER_REGEX = /-----BEGIN [A-Z ]{0,32}PRIVATE KEY-----/g;
const PEM_BODY_REGEX = /[A-Za-z0-9+/=]{40,}/;
const PEM_WINDOW_CHARS = 200;

/* ------------------------------------------------------------------ helpers */

/** Shannon entropy in bits per character. */
function entropy(value) {
  if (value.length === 0) {
    return 0;
  }
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

function looksLikePlaceholder(value) {
  const lowered = value.toLowerCase();
  if (lowered.includes('<') || lowered.includes('>')) {
    return true;
  }
  if (lowered.includes('${') || lowered.includes('$(') || lowered.includes('{{')) {
    return true;
  }
  return PLACEHOLDER_MARKERS.some((marker) => lowered.includes(marker));
}

function isConfigLike(relativePath) {
  const name = basename(relativePath).toLowerCase();
  if (GENERATED_FILES.has(basename(relativePath))) {
    return false;
  }
  if (CONFIG_FILENAME.test(name)) {
    return true;
  }
  return CONFIG_EXTENSIONS.has(extname(name));
}

/**
 * Parse `KEY=value` / `key: value` out of a config line.
 * Returns null when the line is not an assignment or the value cannot be a
 * credential (it has whitespace, it is an interpolation, it is a URL path).
 */
function extractAssignedValue(line) {
  const match = /^[\s#-]*(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*(.+)$/.exec(
    line,
  );
  if (!match) {
    return null;
  }
  const key = match[1];
  let value = match[2].trim();
  // Strip a trailing comment only when the value is quoted; an unquoted `#` may
  // legitimately be part of a token.
  const quoted = /^(['"])([\s\S]*?)\1/.exec(value);
  if (quoted) {
    value = quoted[2];
  } else {
    value = value
      .replace(/\s+[#;].*$/, '')
      .replace(/[,;]$/, '')
      .trim();
  }
  if (value.length === 0 || /\s/.test(value)) {
    return null;
  }
  return { key, value };
}

/** True when the string is structured data rather than a random token. */
function isStructuredNotRandom(value) {
  if (/^[a-z]+:\/\//i.test(value)) {
    return true; // a URL; the credentialed-url rule owns those
  }
  if (value.includes('/') && !value.includes('=')) {
    return true; // a path or a package spec
  }
  if (/^v?\d+(?:\.\d+)+/.test(value)) {
    return true; // a version
  }
  if (/^\d{4}-\d{2}-\d{2}/.test(value)) {
    return true; // a date
  }
  if (/^[0-9a-f]{7,10}$/i.test(value)) {
    return true; // a short git sha
  }
  return false;
}

/* ------------------------------------------------------------------ scanning */

/**
 * @typedef {{ file: string, line: number, column: number, rule: string, detail: string }} Finding
 */

/**
 * Scan one file's text. Returns findings plus the number of honoured
 * suppressions, so the summary can surface how often the gate was relaxed.
 *
 * @param {string} relativePath
 * @param {string} text
 */
function scanText(relativePath, text) {
  /** @type {Finding[]} */
  const findings = [];
  let suppressionsHonoured = 0;
  const lines = text.split('\n');
  const configLike = isConfigLike(relativePath);

  /** @type {(index: number) => { active: boolean, reason: string } | null} */
  const suppressionFor = (index) => {
    for (const candidate of [lines[index], index > 0 ? lines[index - 1] : undefined]) {
      if (candidate === undefined) {
        continue;
      }
      const match = SUPPRESSION_MARKER.exec(candidate);
      if (!match) {
        continue;
      }
      const reason = match[1]
        .replace(/-->\s*$/, '')
        .replace(/\*\/\s*$/, '')
        .trim();
      return { active: true, reason };
    }
    return null;
  };

  // Whole-file pass: a PEM block spans lines, so it cannot be judged one line at
  // a time. A header with no key material behind it is a shape, not a key.
  PEM_HEADER_REGEX.lastIndex = 0;
  for (const match of text.matchAll(PEM_HEADER_REGEX)) {
    const start = match.index ?? 0;
    const window = text.slice(start, start + PEM_WINDOW_CHARS);
    if (looksLikePlaceholder(window)) {
      continue;
    }
    if (!PEM_BODY_REGEX.test(window.slice(match[0].length))) {
      continue;
    }
    const lineIndex = text.slice(0, start).split('\n').length - 1;
    const suppression = suppressionFor(lineIndex);
    if (suppression) {
      suppressionsHonoured += 1;
      continue;
    }
    findings.push({
      file: relativePath,
      line: lineIndex + 1,
      column: start - text.lastIndexOf('\n', start - 1),
      rule: 'private-key-pem',
      detail: 'a PEM private key block with key material',
    });
  }

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.length === 0) {
      continue;
    }

    // A suppression without a stated reason is itself a finding: "allow" with no
    // justification is how a gate quietly stops meaning anything.
    const selfMarker = SUPPRESSION_MARKER.exec(line);
    if (selfMarker) {
      const reason = selfMarker[1]
        .replace(/-->\s*$/, '')
        .replace(/\*\/\s*$/, '')
        .trim();
      if (reason.length < 4) {
        findings.push({
          file: relativePath,
          line: i + 1,
          column: line.indexOf('agent-secrets:allow-secret-scan') + 1,
          rule: 'suppression-without-reason',
          detail: 'allow-secret-scan requires a written justification',
        });
      }
    }

    // 1. Canaries. Never suppressible.
    CANARY_REGEX.lastIndex = 0;
    for (const match of line.matchAll(CANARY_REGEX)) {
      findings.push({
        file: relativePath,
        line: i + 1,
        column: (match.index ?? 0) + 1,
        rule: 'leaked-canary',
        detail: 'a generated canary reached a file in the working tree',
      });
    }

    // 2. Known credential shapes.
    for (const pattern of CREDENTIAL_PATTERNS) {
      pattern.regex.lastIndex = 0;
      for (const match of line.matchAll(pattern.regex)) {
        const hit = match[0];
        if (looksLikePlaceholder(hit)) {
          continue;
        }
        if (pattern.entropyFloor > 0 && entropy(hit) < pattern.entropyFloor) {
          continue;
        }
        const suppression = suppressionFor(i);
        if (suppression) {
          suppressionsHonoured += 1;
          continue;
        }
        findings.push({
          file: relativePath,
          line: i + 1,
          column: (match.index ?? 0) + 1,
          rule: pattern.name,
          detail: 'string matches a known credential shape',
        });
      }
    }

    // 3. High-entropy assignments in config-shaped files. Deliberately requires
    // all three signals — config file, credential-sounding key, high entropy —
    // because a noisy entropy rule is a rule people learn to ignore.
    if (!configLike || line.length > MAX_LINE_CHARS_FOR_ENTROPY) {
      continue;
    }
    const assignment = extractAssignedValue(line);
    if (!assignment) {
      continue;
    }
    const { key, value } = assignment;
    if (!SUSPICIOUS_KEY.test(key)) {
      continue;
    }
    if (value.length < 20 || looksLikePlaceholder(value) || isStructuredNotRandom(value)) {
      continue;
    }
    if (entropy(value) < 3.5) {
      continue;
    }
    const suppression = suppressionFor(i);
    if (suppression) {
      suppressionsHonoured += 1;
      continue;
    }
    findings.push({
      file: relativePath,
      line: i + 1,
      column: line.indexOf(value) + 1,
      rule: 'high-entropy-assignment',
      detail: `key "${key}" is assigned a high-entropy literal`,
    });
  }

  return { findings, suppressionsHonoured };
}

/**
 * Read at most `MAX_FILE_BYTES` of a file, giving up on anything binary. Reading
 * in chunks keeps peak memory bounded no matter what lands in the tree.
 */
async function readCapped(absolutePath) {
  const handle = await open(absolutePath, 'r');
  try {
    /** @type {Buffer[]} */
    const chunks = [];
    let total = 0;
    let first = true;
    for (;;) {
      const buffer = Buffer.allocUnsafe(READ_CHUNK_BYTES);
      const { bytesRead } = await handle.read(buffer, 0, READ_CHUNK_BYTES, null);
      if (bytesRead === 0) {
        break;
      }
      const slice = buffer.subarray(0, bytesRead);
      if (first && slice.includes(0)) {
        return null; // binary
      }
      first = false;
      chunks.push(slice);
      total += bytesRead;
      if (total >= MAX_FILE_BYTES) {
        break;
      }
    }
    return Buffer.concat(chunks).toString('utf8');
  } finally {
    await handle.close();
  }
}

/** Depth-first walk yielding repo-relative paths, pruning the skip list. */
async function* walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const absolute = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRECTORIES.has(entry.name)) {
        continue;
      }
      yield* walk(absolute);
      continue;
    }
    if (!entry.isFile()) {
      continue; // symlinks are not followed: they can point outside the tree
    }
    yield relative(REPO_ROOT, absolute);
  }
}

function isScannable(relativePath) {
  if (relativePath === join('scripts', 'scan-secrets.mjs')) {
    return false; // this file holds the pattern table by definition
  }
  if (relativePath.split(sep).some((segment) => SKIP_DIRECTORIES.has(segment))) {
    return false;
  }
  return !SKIP_EXTENSIONS.has(extname(relativePath).toLowerCase());
}

async function collectWorktreeFiles() {
  /** @type {string[]} */
  const files = [];
  for await (const relativePath of walk(REPO_ROOT)) {
    if (isScannable(relativePath)) {
      files.push(relativePath);
    }
  }
  return files;
}

/** Staged mode reads blobs from the index, not the working tree: the hook must
 * judge exactly the bytes that are about to become a git object. */
async function collectStagedFiles() {
  const { stdout } = await execFileAsync(
    'git',
    ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'],
    { cwd: REPO_ROOT, maxBuffer: 32 * 1024 * 1024 },
  );
  return stdout
    .split('\0')
    .filter((entry) => entry.length > 0)
    .filter(isScannable);
}

async function readStaged(relativePath) {
  const { stdout } = await execFileAsync('git', ['show', `:${relativePath}`], {
    cwd: REPO_ROOT,
    maxBuffer: MAX_FILE_BYTES,
    encoding: 'buffer',
  });
  const buffer = /** @type {Buffer} */ (/** @type {unknown} */ (stdout));
  if (buffer.subarray(0, READ_CHUNK_BYTES).includes(0)) {
    return null;
  }
  return buffer.subarray(0, MAX_FILE_BYTES).toString('utf8');
}

/**
 * Report drift against the two files this scanner duplicates by necessity: the
 * runtime redaction patterns and the canary generator. Warnings rather than
 * failures — the lists are allowed to name things differently — but silent
 * divergence is how a shape stops being detected without anyone noticing.
 *
 * @returns {Promise<{ missingHere: string[], notes: string[] }>}
 */
async function checkPatternDrift() {
  /** @type {string[]} */
  const notes = [];
  /** @type {string[]} */
  let missingHere = [];

  const patternsFile = join(REPO_ROOT, 'packages', 'redaction', 'src', 'patterns.ts');
  const patternsText = (await exists(patternsFile)) ? await readCapped(patternsFile) : null;
  if (patternsText !== null) {
    const names = new Set();
    for (const match of patternsText.matchAll(/\b(?:name|id)\s*:\s*'([a-z0-9][a-z0-9-]{2,})'/g)) {
      names.add(match[1]);
    }
    const known = new Set([
      ...CREDENTIAL_PATTERNS.map((pattern) => pattern.name),
      'private-key-pem',
    ]);
    missingHere = [...names].filter((name) => !known.has(name)).sort();
  }

  // The canary rule matches at least 16 hex characters. If the generator ever
  // emits fewer, the rule stops seeing real canaries — the one failure this
  // script exists to make impossible.
  const canaryFile = join(REPO_ROOT, 'packages', 'test-helpers', 'src', 'canary.ts');
  const canaryText = (await exists(canaryFile)) ? await readCapped(canaryFile) : null;
  if (canaryText !== null) {
    const declared = /CANARY_BODY_LENGTH\s*=\s*(\d+)/.exec(canaryText);
    if (declared && Number(declared[1]) < 16) {
      notes.push(
        `canary body length is ${declared[1]}; the scanner requires 16+ hex characters and will miss real canaries`,
      );
    }
    const prefix = /CANARY_PREFIX\s*=\s*'([^']+)'/.exec(canaryText);
    if (prefix && prefix[1] !== 'ASECRET_CANARY_') {
      notes.push(`canary prefix is now "${prefix[1]}"; update CANARY_REGEX in this script`);
    }
  }

  return { missingHere, notes };
}

async function exists(absolutePath) {
  try {
    await stat(absolutePath);
    return true;
  } catch {
    return false;
  }
}

/** Bounded-concurrency map; keeps the hook fast without spawning workers. */
async function mapWithConcurrency(items, limit, worker) {
  const results = [];
  let cursor = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) {
        return;
      }
      results[index] = await worker(items[index]);
    }
  });
  await Promise.all(runners);
  return results;
}

/* ---------------------------------------------------------------------- main */

/**
 * Prove, on every run, that the detector still fires on a shape it built itself.
 * A pattern table that has been edited into uselessness would otherwise report a
 * clean tree — the most dangerous possible output from this script. The probe
 * string is derived from a hash of a fixed label, so it is deterministic, obvious
 * nonsense, and never written to disk.
 */
function selfTest() {
  const synthetic = `ghp_${createHash('sha256').update('agent-secrets-self-test').digest('hex').slice(0, 36)}`;
  const { findings } = scanText('self-test.env', `TOKEN=${synthetic}`);
  return findings.some((finding) => finding.rule === 'github-token');
}

function parseArgv(argv) {
  const options = { staged: false, json: false, help: false };
  for (const arg of argv) {
    switch (arg) {
      case '--staged':
        options.staged = true;
        break;
      case '--json':
        options.json = true;
        break;
      case '-h':
      case '--help':
        options.help = true;
        break;
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return options;
}

const HELP = `scan-secrets — credential and canary scanner for the Agent Secrets working tree

  node scripts/scan-secrets.mjs [options]

  --staged   scan the staged blobs only (pre-commit hook)
  --json     machine-readable output on stdout
  --help     this text

Exit code 0 when clean, 1 when anything was found, 2 on scanner failure.
Matched strings are never printed: only FILE:LINE:COLUMN and a rule name.

Exempt a documentation example with, on the same or the preceding line:
  agent-secrets:allow-secret-scan <why this is not a real credential>
Leaked canaries can never be exempted.
`;

async function main() {
  let options;
  try {
    options = parseArgv(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'bad arguments'}\n\n${HELP}`);
    return 2;
  }
  if (options.help) {
    process.stdout.write(HELP);
    return 0;
  }

  if (!selfTest()) {
    process.stderr.write(
      'scan-secrets: self-test failed — the pattern table no longer detects a known ' +
        'credential shape. Refusing to report a clean tree.\n',
    );
    return 2;
  }

  const started = Date.now();
  const files = options.staged ? await collectStagedFiles() : await collectWorktreeFiles();

  const perFile = await mapWithConcurrency(files, CONCURRENCY, async (relativePath) => {
    let text;
    try {
      text = options.staged
        ? await readStaged(relativePath)
        : await readCapped(join(REPO_ROOT, relativePath));
    } catch {
      return { findings: [], suppressionsHonoured: 0 }; // unreadable or vanished
    }
    if (text === null) {
      return { findings: [], suppressionsHonoured: 0 };
    }
    return scanText(relativePath, text);
  });

  /** @type {Finding[]} */
  const findings = [];
  let suppressions = 0;
  for (const result of perFile) {
    findings.push(...result.findings);
    suppressions += result.suppressionsHonoured;
  }
  findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);

  const drift = await checkPatternDrift();
  const durationMs = Date.now() - started;

  if (options.json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          schemaVersion: 1,
          mode: options.staged ? 'staged' : 'worktree',
          ok: findings.length === 0,
          filesScanned: files.length,
          durationMs,
          suppressionsHonoured: suppressions,
          patternDrift: drift.missingHere,
          driftNotes: drift.notes,
          findings,
        },
        null,
        2,
      )}\n`,
    );
    return findings.length === 0 ? 0 : 1;
  }

  for (const finding of findings) {
    process.stdout.write(
      `${finding.file}:${finding.line}:${finding.column}  ${finding.rule}  — ${finding.detail}\n`,
    );
  }
  if (drift.missingHere.length > 0) {
    process.stderr.write(
      `warning: packages/redaction/src/patterns.ts defines rules absent from this scanner: ${drift.missingHere.join(', ')}\n`,
    );
  }
  for (const note of drift.notes) {
    process.stderr.write(`warning: ${note}\n`);
  }
  const scope = options.staged ? 'staged file(s)' : 'working-tree file(s)';
  if (findings.length === 0) {
    process.stdout.write(
      `scan-secrets: clean — ${files.length} ${scope} in ${durationMs}ms` +
        (suppressions > 0 ? `, ${suppressions} suppression(s) honoured` : '') +
        '\n',
    );
    return 0;
  }
  process.stdout.write(
    `\nscan-secrets: ${findings.length} finding(s) across ${files.length} ${scope}. ` +
      'Nothing above quotes the matched text on purpose — open the file to inspect it.\n',
  );
  return 1;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    // The scanner failing open would be worse than a false positive: a crash must
    // block the commit, not wave it through.
    process.stderr.write(
      `scan-secrets failed: ${error instanceof Error ? error.message : 'unknown error'}\n`,
    );
    process.exitCode = 2;
  });
