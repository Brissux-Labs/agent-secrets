import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Two ways to observe output, for two different classes of test.
 *
 * `captureStreams` patches the in-process streams: cheap, good for asserting
 * that a formatter never renders a value.
 *
 * `runCli` spawns a child. It is the slower one and it is the one that matters,
 * because the properties we care about are process-level: `process.exit` with a
 * contract-bound code, TTY detection deciding whether a prompt is offered,
 * stderr never being interleaved into stdout's JSON, and — above all — the
 * environment block the child is given. An in-process harness silently shares
 * the parent's `process.env`, so a test could pass while the code under test
 * was reading the developer's real `BWS_ACCESS_TOKEN`.
 */

export interface CapturedStreams {
  /** Everything written to process.stdout since capture began. */
  readonly stdout: string;
  /** Everything written to process.stderr since capture began. */
  readonly stderr: string;
  clear(): void;
  restore(): void;
}

type WriteFn = typeof process.stdout.write;

export function captureStreams(): CapturedStreams {
  const chunks = { stdout: [] as string[], stderr: [] as string[] };
  const originals = {
    stdout: process.stdout.write.bind(process.stdout) as WriteFn,
    stderr: process.stderr.write.bind(process.stderr) as WriteFn,
  };
  let restored = false;

  const patch = (stream: NodeJS.WriteStream, sink: string[]): void => {
    const patched: WriteFn = (
      chunk: string | Uint8Array,
      encoding?: BufferEncoding | ((error?: Error | null) => void),
      callback?: (error?: Error | null) => void,
    ): boolean => {
      const done = typeof encoding === 'function' ? encoding : callback;
      sink.push(
        typeof chunk === 'string'
          ? chunk
          : Buffer.from(chunk).toString(typeof encoding === 'string' ? encoding : 'utf8'),
      );
      done?.(null);
      return true;
    };
    stream.write = patched;
  };

  patch(process.stdout, chunks.stdout);
  patch(process.stderr, chunks.stderr);

  return {
    get stdout(): string {
      return chunks.stdout.join('');
    },
    get stderr(): string {
      return chunks.stderr.join('');
    },
    clear(): void {
      chunks.stdout.length = 0;
      chunks.stderr.length = 0;
    },
    restore(): void {
      // Idempotent: a `finally` block and an `afterEach` both calling restore
      // must not reinstate a patched write as the "original".
      if (restored) {
        return;
      }
      restored = true;
      process.stdout.write = originals.stdout;
      process.stderr.write = originals.stderr;
    },
  };
}

export interface RunOptions {
  /**
   * The child's complete environment. Nothing is inherited from the parent —
   * see the module comment. Defaults to a bare, deterministic environment.
   */
  env?: Record<string, string>;
  cwd?: string;
  /** Written to the child's stdin, which is then closed. */
  stdin?: string;
  /** Kills the child after this many milliseconds. */
  timeoutMs?: number;
  /** Signal used when the timeout fires. */
  killSignal?: NodeJS.Signals;
}

export interface RunResult {
  /** Exit code, or -1 when the child died from a signal. */
  code: number;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface RunCliOptions extends RunOptions {
  /** Override the CLI entry point. Defaults to `packages/cli/dist/bin.js`. */
  entry?: string;
  /** Node binary to run it with. Defaults to the current one. */
  nodePath?: string;
}

/** The minimum a Node child needs; deliberately free of anything user-specific. */
const BASE_ENV: Readonly<Record<string, string>> = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
  NO_COLOR: '1',
  CI: '1',
  TZ: 'UTC',
  LANG: 'C.UTF-8',
  NODE_ENV: 'test',
  AGENT_SECRETS_TELEMETRY: '0',
});

/**
 * Spawn any executable with an explicit environment.
 *
 * `shell` is never enabled and the arguments are always an array: string
 * interpolation into a shell is the single most reliable way to turn a secret
 * into a `ps` line and a shell history entry (CLAUDE.md §2).
 */
export function runProcess(
  command: string,
  args: readonly string[] = [],
  options: RunOptions = {},
): Promise<RunResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, [...args], {
      env: { ...BASE_ENV, ...options.env },
      ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
    });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let timedOut = false;
    let settled = false;

    const timer =
      options.timeoutMs === undefined
        ? undefined
        : setTimeout(() => {
            timedOut = true;
            child.kill(options.killSignal ?? 'SIGKILL');
          }, options.timeoutMs);

    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));

    child.on('error', (error: Error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      rejectPromise(error);
    });

    child.on('close', (code: number | null, signal: NodeJS.Signals | null) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolvePromise({
        code: code ?? -1,
        signal,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
        timedOut,
      });
    });

    if (options.stdin !== undefined) {
      child.stdin.end(options.stdin);
    } else {
      // Close stdin rather than leaving it open: a CLI that prompts when stdin
      // is a pipe should hit EOF and fail, not hang the test suite.
      child.stdin.end();
    }
  });
}

/**
 * Walk up from this module until the workspace root. Used to locate the built
 * CLI without hardcoding a path relative to `dist/` versus `src/`.
 */
export function findRepoRoot(from: string = dirname(fileURLToPath(import.meta.url))): string {
  let current = resolve(from);
  for (;;) {
    if (existsSync(join(current, 'pnpm-workspace.yaml'))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) {
      throw new Error(
        'Could not locate the workspace root (no pnpm-workspace.yaml above this file).',
      );
    }
    current = parent;
  }
}

export function defaultCliEntry(): string {
  return join(findRepoRoot(), 'packages', 'cli', 'dist', 'bin.js');
}

/** Run the built CLI in a child process. Requires `tsc --build packages/cli`. */
export function runCli(argv: readonly string[], options: RunCliOptions = {}): Promise<RunResult> {
  const entry = options.entry ?? defaultCliEntry();
  if (!existsSync(entry)) {
    return Promise.reject(
      new Error(
        `CLI entry point not found at ${entry}. Build it first: npx tsc --build packages/cli`,
      ),
    );
  }
  const { entry: _entry, nodePath, ...runOptions } = options;
  return runProcess(nodePath ?? process.execPath, [entry, ...argv], runOptions);
}
