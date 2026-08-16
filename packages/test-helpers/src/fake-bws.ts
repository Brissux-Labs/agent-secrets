import { randomBytes, randomUUID } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * A fake Bitwarden Secrets Manager CLI.
 *
 * The real `bws` is a Rust binary invoked as a subprocess. It is not installed
 * on developer machines here and will never be installed in CI, so every test
 * that exercises the Bitwarden adapter needs a stand-in that is a *real
 * executable* rather than a module mock: the adapter's security properties live
 * in how it spawns a process (argument array, environment block, stderr
 * handling), and a module mock would test none of them.
 *
 * The generated script is CommonJS on purpose. It is materialised into a bare
 * temp directory with no `package.json`, and Node resolves an extensionless
 * executable as CommonJS; using `require` avoids depending on how the ambient
 * module type is inferred. It is not part of the repository's ESM build.
 *
 * ## Where a value is allowed to land
 *
 * The fake vault (`state.json`) is the only file a test value may legitimately
 * reach. `calls.jsonl` is deliberately a *detection surface*: it records the
 * verbatim argument vector of every invocation, so a canary appearing there
 * proves the adapter let a value travel as a process argument.
 *
 * Real `bws secret create` genuinely takes the value as a positional argument,
 * so a test that drives that path can register the canary in
 * `options.redactArgv`; the recorded argv then stores `[redacted]` plus the
 * indexes that were redacted, which keeps the sweep clean while still allowing
 * an assertion about *which* positions carried the value.
 */

export type FakeBwsOperation = 'list' | 'get' | 'create' | 'update' | 'delete';

export type FakeBwsFailureMode = 'network' | 'auth' | 'ratelimit' | 'garbage-output' | 'hang';

/** Modelled on the `bws` 1.x JSON representation of a secret. */
export interface FakeBwsSecret {
  id: string;
  organizationId: string;
  projectId: string;
  key: string;
  value: string;
  note: string;
  creationDate: string;
  revisionDate: string;
}

/** Modelled on the `bws` 1.x JSON representation of a project. */
export interface FakeBwsProject {
  id: string;
  organizationId: string;
  name: string;
  creationDate: string;
  revisionDate: string;
}

export interface FakeBwsState {
  /** Tokens the fake accepts. Multiple entries model multiple devices. */
  tokens: string[];
  /** Tokens that were accepted once and have since been revoked. */
  revokedTokens: string[];
  organizationId: string;
  projects: FakeBwsProject[];
  secrets: FakeBwsSecret[];
  failOn: FakeBwsOperation | null;
  failureMode: FakeBwsFailureMode | null;
  /** Printed on stderr on every invocation, to prove adapters sanitise it. */
  stderrCanary: string | null;
  /** Literal strings masked out of the recorded argv. See the module comment. */
  redactArgv: string[];
  version: string;
  hangMs: number;
}

export interface RecordedCall {
  timestamp: string;
  /** Arguments after the executable, with `redactArgv` needles masked. */
  argv: string[];
  /** Indexes of `argv` that were masked. Empty when nothing was redacted. */
  argvRedactions: number[];
  cwd: string;
  /** Whether BWS_ACCESS_TOKEN was set and non-empty. Never the token itself. */
  tokenPresent: boolean;
  /** Whether the token matched a currently valid one. */
  tokenMatched: boolean;
}

export interface FakeBwsOptions {
  /** Valid access tokens. Defaults to a single generated fake token. */
  tokens?: string[];
  organizationId?: string;
  projects?: FakeBwsProject[];
  secrets?: FakeBwsSecret[];
  failOn?: FakeBwsOperation;
  failureMode?: FakeBwsFailureMode;
  stderrCanary?: string;
  redactArgv?: string[];
  version?: string;
  /** How long `failureMode: 'hang'` stalls before exiting. */
  hangMs?: number;
}

export interface FakeBws {
  /** Absolute path to the executable, mode 0o755. Basename is `bws`. */
  readonly path: string;
  readonly statePath: string;
  readonly callsPath: string;
  readonly dir: string;
  /** The primary valid token; hand it to a child through BWS_ACCESS_TOKEN. */
  readonly token: string;
  readonly organizationId: string;
  /** The seeded project, the one `secret create` accepts by default. */
  readonly projectId: string;
  /** Environment overlay a child needs to authenticate against this fake. */
  readonly env: Readonly<Record<string, string>>;
  readState(): Promise<FakeBwsState>;
  writeState(state: FakeBwsState): Promise<void>;
  calls(): Promise<RecordedCall[]>;
  /** Invalidate one token while leaving the others working (device revocation). */
  revokeToken(token: string): Promise<void>;
  /** Turn an injected failure on or off between invocations. */
  setFailure(failOn: FakeBwsOperation | null, failureMode?: FakeBwsFailureMode): Promise<void>;
  /** Add a secret directly to the vault, bypassing the CLI surface. */
  seedSecret(input: SeedSecretInput): Promise<FakeBwsSecret>;
  cleanup(): Promise<void>;
}

export interface SeedSecretInput {
  key: string;
  value: string;
  projectId?: string;
  note?: string;
}

/**
 * The exact stderr text each injected failure produces, so a test can assert on
 * it without hardcoding a copy that drifts.
 */
export const FAKE_BWS_FAILURE_MESSAGES: Record<
  Exclude<FakeBwsFailureMode, 'garbage-output' | 'hang'>,
  string
> = {
  network: 'error: error sending request: connection refused',
  auth: 'error: Access token is not valid.',
  ratelimit: 'error: 429 Too Many Requests',
};

/** Every injected failure exits 1, matching `bws`, which has no code taxonomy. */
export const FAKE_BWS_FAILURE_EXIT = 1;

/** Stdout produced by `failureMode: 'garbage-output'`: valid HTTP, invalid JSON. */
// Assembled from fragments rather than written as one literal: Biome's noSecrets
// entropy heuristic reads any long unbroken string as a possible credential, and a
// blanket suppression here would also cover anything a future edit adds below it.
export const FAKE_BWS_GARBAGE_OUTPUT = [
  '<!DOCTYPE html>\n',
  '<html><head>',
  '<title>502 Bad Gateway</title>',
  '</head></html>\n',
].join('');

export const FAKE_BWS_VERSION = 'bws 1.0.0-fake';

/** Deterministic-looking but obviously fake token, generated per instance. */
function generateFakeToken(): string {
  return `0.${randomUUID()}.${'fake'.repeat(8)}${randomBytes(4).toString('hex')}:ZmFrZQ==`;
}

function isoMicros(date: Date): string {
  // `bws` is a Rust program and serialises chrono timestamps with sub-millisecond
  // precision. Imitating that is not cosmetic: a parser that assumes exactly
  // three fractional digits breaks against the real binary and not against a
  // naive fake.
  return date.toISOString().replace('Z', '000Z');
}

export async function createFakeBws(options: FakeBwsOptions = {}): Promise<FakeBws> {
  const dir = await mkdtemp(join(tmpdir(), 'agent-secrets-fake-bws-'));
  const executablePath = join(dir, 'bws');
  const statePath = join(dir, 'state.json');
  const callsPath = join(dir, 'calls.jsonl');

  const organizationId = options.organizationId ?? randomUUID();
  const now = isoMicros(new Date());
  const defaultProject: FakeBwsProject = {
    id: randomUUID(),
    organizationId,
    name: 'agent-secrets-test',
    creationDate: now,
    revisionDate: now,
  };
  const projects = options.projects ?? [defaultProject];
  const primaryProject = projects[0] ?? defaultProject;
  const tokens = options.tokens ?? [generateFakeToken()];
  const primaryToken = tokens[0] ?? generateFakeToken();

  const state: FakeBwsState = {
    tokens: [...tokens],
    revokedTokens: [],
    organizationId,
    projects: [...projects],
    secrets: options.secrets ? [...options.secrets] : [],
    failOn: options.failOn ?? null,
    failureMode: options.failureMode ?? null,
    stderrCanary: options.stderrCanary ?? null,
    redactArgv: options.redactArgv ? [...options.redactArgv] : [],
    version: options.version ?? FAKE_BWS_VERSION,
    hangMs: options.hangMs ?? 60_000,
  };

  const writeStateFile = async (next: FakeBwsState): Promise<void> => {
    await writeFile(statePath, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
  };
  const readStateFile = async (): Promise<FakeBwsState> => {
    return JSON.parse(await readFile(statePath, 'utf8')) as FakeBwsState;
  };

  await writeStateFile(state);
  await writeFile(callsPath, '', { mode: 0o600 });
  await writeFile(executablePath, renderScript(statePath, callsPath), { mode: 0o755 });
  // mkdtemp honours umask, and writeFile's mode is advisory if the file already
  // exists, so make the executable bit explicit rather than assumed.
  await chmod(executablePath, 0o755);

  return {
    path: executablePath,
    statePath,
    callsPath,
    dir,
    token: primaryToken,
    organizationId,
    projectId: primaryProject.id,
    env: Object.freeze({ BWS_ACCESS_TOKEN: primaryToken }),
    readState: readStateFile,
    writeState: writeStateFile,

    async calls(): Promise<RecordedCall[]> {
      const raw = await readFile(callsPath, 'utf8');
      return raw
        .split('\n')
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as RecordedCall);
    },

    async revokeToken(token: string): Promise<void> {
      const current = await readStateFile();
      current.tokens = current.tokens.filter((candidate) => candidate !== token);
      if (!current.revokedTokens.includes(token)) {
        current.revokedTokens.push(token);
      }
      await writeStateFile(current);
    },

    async setFailure(
      failOn: FakeBwsOperation | null,
      failureMode?: FakeBwsFailureMode,
    ): Promise<void> {
      const current = await readStateFile();
      current.failOn = failOn;
      current.failureMode = failOn === null ? null : (failureMode ?? 'network');
      await writeStateFile(current);
    },

    async seedSecret(input: SeedSecretInput): Promise<FakeBwsSecret> {
      const current = await readStateFile();
      const stamp = isoMicros(new Date());
      const secret: FakeBwsSecret = {
        id: randomUUID(),
        organizationId: current.organizationId,
        projectId: input.projectId ?? primaryProject.id,
        key: input.key,
        value: input.value,
        note: input.note ?? '',
        creationDate: stamp,
        revisionDate: stamp,
      };
      current.secrets.push(secret);
      await writeStateFile(current);
      return secret;
    },

    async cleanup(): Promise<void> {
      await rm(dir, { recursive: true, force: true });
    },
  };
}

function renderScript(statePath: string, callsPath: string): string {
  return [
    // The interpreter is pinned to the Node binary running the test rather than
    // `/usr/bin/env node`: the child that spawns this fake is given a minimal
    // PATH on purpose, and on macOS `node` lives outside /usr/bin, so a PATH
    // lookup would fail for reasons that have nothing to do with the test.
    `#!${process.execPath}`,
    '// Generated by @bx-labs/agent-secrets-test-helpers. This is NOT the real',
    '// Bitwarden Secrets Manager CLI and never contacts a network.',
    "'use strict';",
    `const STATE_PATH = ${JSON.stringify(statePath)};`,
    `const CALLS_PATH = ${JSON.stringify(callsPath)};`,
    SCRIPT_BODY,
  ].join('\n');
}

/**
 * The body of the generated executable.
 *
 * Kept as a plain string rather than a separate `.js` asset because the package
 * publishes only `dist/`, and a copied asset is one more thing to get out of
 * sync with the types above.
 */
const SCRIPT_BODY = `
const fs = require('node:fs');
const crypto = require('node:crypto');

const NOT_FOUND = 'Resource not found.';
const BAD_TOKEN = 'Access token is not valid.';
const FAILURE_MESSAGES = {
  network: 'error sending request: connection refused',
  auth: BAD_TOKEN,
  ratelimit: '429 Too Many Requests',
};
const GARBAGE_OUTPUT =
  '<!DOCTYPE html>\\n<html><head><title>502 Bad Gateway</title></head></html>\\n';

function readState() {
  return JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
}

function writeState(state) {
  fs.writeFileSync(STATE_PATH, JSON.stringify(state, null, 2) + '\\n', { mode: 0o600 });
}

function isoMicros() {
  return new Date().toISOString().replace('Z', '000Z');
}

function out(payload) {
  process.stdout.write(JSON.stringify(payload, null, 2) + '\\n');
}

function fail(message, code) {
  process.stderr.write('error: ' + message + '\\n');
  process.exit(code === undefined ? 1 : code);
}

function recordCall(argv, state) {
  const needles = Array.isArray(state.redactArgv) ? state.redactArgv : [];
  const redactions = [];
  const masked = argv.map(function (arg, index) {
    for (let i = 0; i < needles.length; i += 1) {
      if (needles[i].length > 0 && arg.indexOf(needles[i]) !== -1) {
        redactions.push(index);
        return '[redacted]';
      }
    }
    return arg;
  });
  const token = process.env.BWS_ACCESS_TOKEN;
  const entry = {
    timestamp: new Date().toISOString(),
    argv: masked,
    argvRedactions: redactions,
    cwd: process.cwd(),
    tokenPresent: typeof token === 'string' && token.length > 0,
    tokenMatched: typeof token === 'string' && state.tokens.indexOf(token) !== -1,
  };
  fs.appendFileSync(CALLS_PATH, JSON.stringify(entry) + '\\n', { mode: 0o600 });
}

function parseGlobals(argv) {
  const rest = [];
  let output = 'json';
  let tokenOnArgv = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '-o' || arg === '--output') {
      output = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg.indexOf('--output=') === 0) {
      output = arg.slice('--output='.length);
      continue;
    }
    if (arg === '-t' || arg === '--access-token') {
      tokenOnArgv = true;
      i += 1;
      continue;
    }
    if (arg.indexOf('--access-token=') === 0) {
      tokenOnArgv = true;
      continue;
    }
    rest.push(arg);
  }
  return { output: output, rest: rest, tokenOnArgv: tokenOnArgv };
}

function flagValue(args, name) {
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === name) {
      return args[i + 1];
    }
    if (args[i].indexOf(name + '=') === 0) {
      return args[i].slice(name.length + 1);
    }
  }
  return undefined;
}

function positionals(args) {
  const values = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i].indexOf('-') === 0) {
      if (args[i].indexOf('=') === -1) {
        i += 1;
      }
      continue;
    }
    values.push(args[i]);
  }
  return values;
}

function resolveOperation(args) {
  if (args[0] === 'secret') {
    if (args[1] === 'list') return 'list';
    if (args[1] === 'get') return 'get';
    if (args[1] === 'create') return 'create';
    if (args[1] === 'edit') return 'update';
    if (args[1] === 'delete') return 'delete';
    return null;
  }
  if (args[0] === 'project' && args[1] === 'list') return 'list';
  return null;
}

function main() {
  const rawArgv = process.argv.slice(2);
  const state = readState();
  recordCall(rawArgv, state);

  const parsed = parseGlobals(rawArgv);
  const args = parsed.rest;

  if (args[0] === '--version' || args[0] === '-V') {
    process.stdout.write(state.version + '\\n');
    return;
  }

  if (parsed.tokenOnArgv) {
    // The real bws accepts --access-token. This fake refuses it so that any
    // adapter putting a credential on the command line fails loudly in tests.
    fail('fake-bws refuses an access token on the command line; use BWS_ACCESS_TOKEN.', 2);
  }

  if (state.stderrCanary) {
    // Emitted on every invocation, including successful ones: backend stderr
    // must be sanitised on the happy path too, not only on failures.
    process.stderr.write('fake-bws diagnostic: ' + state.stderrCanary + '\\n');
  }

  if (parsed.output !== 'json') {
    fail('fake-bws only implements --output json.', 2);
  }

  const token = process.env.BWS_ACCESS_TOKEN;
  if (typeof token !== 'string' || token.length === 0) {
    fail('The access token is not set. Set BWS_ACCESS_TOKEN.', 1);
  }
  if (state.tokens.indexOf(token) === -1) {
    fail(BAD_TOKEN, 1);
  }

  const operation = resolveOperation(args);
  if (operation === null) {
    fail('fake-bws does not implement that command.', 2);
  }

  if (state.failOn === operation && state.failureMode) {
    if (state.failureMode === 'hang') {
      // Stall without exiting so the caller's own timeout is what fires.
      setTimeout(function () {
        process.exit(1);
      }, state.hangMs);
      return;
    }
    if (state.failureMode === 'garbage-output') {
      // Exit 0 with non-JSON on stdout: the shape that defeats a parser which
      // only checks the exit code.
      process.stdout.write(GARBAGE_OUTPUT);
      return;
    }
    fail(FAILURE_MESSAGES[state.failureMode] || 'unknown failure', 1);
  }

  if (args[0] === 'project') {
    out(state.projects);
    return;
  }

  const rest = positionals(args).slice(2);

  if (operation === 'list') {
    const projectId = rest[0];
    out(
      state.secrets.filter(function (secret) {
        return projectId === undefined || secret.projectId === projectId;
      }),
    );
    return;
  }

  if (operation === 'get') {
    const id = rest[0];
    const found = state.secrets.filter(function (secret) {
      return secret.id === id;
    })[0];
    if (!found) {
      fail(NOT_FOUND, 1);
    }
    out(found);
    return;
  }

  if (operation === 'create') {
    const key = rest[0];
    const value = rest[1];
    const projectId = rest[2];
    if (key === undefined || value === undefined || projectId === undefined) {
      fail('usage: bws secret create <key> <value> <project-id>', 2);
    }
    const knownProject = state.projects.filter(function (project) {
      return project.id === projectId;
    })[0];
    if (!knownProject) {
      fail(NOT_FOUND, 1);
    }
    const stamp = isoMicros();
    const secret = {
      id: crypto.randomUUID(),
      organizationId: state.organizationId,
      projectId: projectId,
      key: key,
      value: value,
      note: flagValue(args, '--note') || '',
      creationDate: stamp,
      revisionDate: stamp,
    };
    // The real bws permits duplicate keys inside a project; uniqueness is the
    // adapter's problem, so the fake does not invent a constraint.
    state.secrets.push(secret);
    writeState(state);
    out(secret);
    return;
  }

  if (operation === 'update') {
    const id = rest[0];
    const index = state.secrets.findIndex(function (secret) {
      return secret.id === id;
    });
    if (index === -1) {
      fail(NOT_FOUND, 1);
    }
    const secret = state.secrets[index];
    const key = flagValue(args, '--key');
    const value = flagValue(args, '--value');
    const note = flagValue(args, '--note');
    const projectId = flagValue(args, '--project-id');
    if (key !== undefined) secret.key = key;
    if (value !== undefined) secret.value = value;
    if (note !== undefined) secret.note = note;
    if (projectId !== undefined) secret.projectId = projectId;
    secret.revisionDate = isoMicros();
    writeState(state);
    out(secret);
    return;
  }

  if (operation === 'delete') {
    const ids = rest;
    if (ids.length === 0) {
      fail('usage: bws secret delete <secret-id>...', 2);
    }
    const results = [];
    let failed = false;
    for (let i = 0; i < ids.length; i += 1) {
      const index = state.secrets.findIndex(function (secret) {
        return secret.id === ids[i];
      });
      if (index === -1) {
        failed = true;
        results.push({ id: ids[i], error: NOT_FOUND });
      } else {
        state.secrets.splice(index, 1);
        results.push({ id: ids[i], error: null });
      }
    }
    writeState(state);
    out(results);
    if (failed) {
      process.exit(1);
    }
    return;
  }
}

main();
`;
