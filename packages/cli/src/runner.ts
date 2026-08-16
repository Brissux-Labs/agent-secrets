import { spawn } from 'node:child_process';
import {
  ChildFailedError,
  formatRef,
  InvalidInputError,
  type ResolvedSecret,
  type SecretRef,
} from '@bx-labs/agent-secrets-core';
import {
  createRedactingStream,
  RedactionScope,
  redactText,
  truncate,
} from '@bx-labs/agent-secrets-redaction';

/**
 * Controlled execution: `agent-secrets run -- npm run dev`.
 *
 * This is the only place a value legitimately leaves this process, and the
 * design of the whole product rests on it being narrow:
 *
 *  - the child receives *only* the secrets named on the command line or in an
 *    approved manifest (FR-RUN-001);
 *  - the values travel in the environment block, never in argv, so they are
 *    invisible to `ps` (FR-RUN-003);
 *  - the parent prints nothing derived from them, in any verbosity mode
 *    (FR-RUN-002, FR-RUN-006);
 *  - the in-memory map is cleared immediately after spawn (FR-RUN-005);
 *  - exit code and terminating signal are propagated faithfully (FR-RUN-004).
 *
 * What it cannot do is bound the child. Once a process holds a value in its
 * environment, it and its descendants can do whatever they like with it — print
 * it, POST it, write it to a file. `docs/threat-model.md` says this plainly:
 * the guarantee is about *this* tool's behaviour, and real isolation requires a
 * container or a narrowly scoped credential.
 */

export interface RunSpec {
  readonly executable: string;
  readonly args: readonly string[];
  readonly secrets: readonly ResolvedSecret[];
  readonly cwd?: string;
  /**
   * Inherit the caller's environment. True by default, because `npm run dev`
   * needs PATH, HOME and the rest to work at all. `false` gives the child a
   * minimal block — useful when the command is untrusted.
   */
  readonly inheritEnv?: boolean;
  /**
   * Capture output instead of streaming it to the terminal. Used by the MCP
   * server, which must return redacted, size-capped text to a model rather than
   * letting the child write straight to a TTY it does not have.
   */
  readonly capture?: boolean;
  readonly maxCapturedBytes?: number;
  readonly signal?: AbortSignal;
}

export interface RunOutcome {
  readonly code: number;
  readonly signal: NodeJS.Signals | null;
  /** Present only when `capture` was set. Already redacted and truncated. */
  readonly stdout?: string;
  readonly stderr?: string;
  readonly durationMs: number;
  readonly injected: readonly string[];
  /** Names that already existed in the inherited environment and were replaced. */
  readonly overridden: readonly string[];
}

const MINIMAL_ENV_KEYS = [
  'PATH',
  'HOME',
  'LANG',
  'LC_ALL',
  'TZ',
  'TERM',
  'SHELL',
  'USER',
  'TMPDIR',
];

export async function runWithSecrets(spec: RunSpec): Promise<RunOutcome> {
  if (spec.executable.length === 0) {
    throw new InvalidInputError('No command was given to run.', {
      field: 'command',
      hint: 'Put the command after `--`, e.g. `agent-secrets run ... -- npm run dev`.',
    });
  }

  const scope = new RedactionScope();
  const startedAt = Date.now();

  // Build the child environment. Assembled in a local that is cleared right
  // after spawn, so the values do not sit in a long-lived object graph.
  const childEnv: Record<string, string> = {};

  if (spec.inheritEnv === false) {
    for (const key of MINIMAL_ENV_KEYS) {
      const value = process.env[key];
      if (value !== undefined) {
        childEnv[key] = value;
      }
    }
  } else {
    for (const [key, value] of Object.entries(process.env)) {
      if (value !== undefined) {
        childEnv[key] = value;
      }
    }
  }

  const injected: string[] = [];
  const duplicates = new Set<string>();

  for (const resolved of spec.secrets) {
    if (childEnv[resolved.ref.name] !== undefined && !injected.includes(resolved.ref.name)) {
      // A variable of the same name already existed in the inherited
      // environment. We overwrite it — the vault is the source of truth — but
      // the operator is told, because a silent override is how a developer ends
      // up debugging the wrong credential for an hour.
      duplicates.add(resolved.ref.name);
    }
    scope.track(resolved.value);
    // expose: building the child's environment block, one of the three
    // legitimate destinations for a value.
    childEnv[resolved.ref.name] = resolved.value.expose();
    injected.push(resolved.ref.name);
  }

  const stdio = spec.capture ? 'pipe' : 'inherit';

  const child = spawn(spec.executable, [...spec.args], {
    env: childEnv,
    ...(spec.cwd === undefined ? {} : { cwd: spec.cwd }),
    // No shell, ever: the command comes from a manifest or an agent, and a
    // shell would turn `npm run dev; curl …` into two commands.
    shell: false,
    stdio: [spec.capture ? 'ignore' : 'inherit', stdio, stdio],
    ...(spec.signal === undefined ? {} : { signal: spec.signal }),
  });

  // FR-RUN-005. The child holds its own copy from this point; ours is dead
  // weight that could show up in a heap snapshot or a crash dump.
  for (const key of Object.keys(childEnv)) {
    childEnv[key] = '';
    delete childEnv[key];
  }
  for (const resolved of spec.secrets) {
    resolved.value.dispose();
  }

  let capturedStdout = '';
  let capturedStderr = '';
  const maxCaptured = spec.maxCapturedBytes ?? 256 * 1024;

  if (spec.capture) {
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      capturedStdout = appendCapped(capturedStdout, chunk, maxCaptured);
    });
    child.stderr?.on('data', (chunk: string) => {
      capturedStderr = appendCapped(capturedStderr, chunk, maxCaptured);
    });
  }

  const forwardSignal = (signal: NodeJS.Signals) => {
    if (!child.killed) {
      child.kill(signal);
    }
  };
  process.on('SIGINT', forwardSignal);
  process.on('SIGTERM', forwardSignal);

  try {
    const { code, signal } = await new Promise<{ code: number; signal: NodeJS.Signals | null }>(
      (resolve, reject) => {
        child.on('error', (error) => {
          const nodeError = error as NodeJS.ErrnoException;
          if (nodeError.code === 'ENOENT') {
            reject(
              new InvalidInputError(`Command not found: ${spec.executable}`, {
                field: 'command',
                hint: 'Check the executable name and that it is on PATH.',
              }),
            );
            return;
          }
          reject(new ChildFailedError('The command could not be started.', { cause: error }));
        });
        child.on('close', (exitCode, exitSignal) => {
          resolve({ code: exitCode ?? 0, signal: exitSignal });
        });
      },
    );

    const outcome: RunOutcome = {
      code,
      signal,
      durationMs: Date.now() - startedAt,
      injected,
      overridden: [...duplicates],
      ...(spec.capture
        ? {
            // Redact against the values we injected before anything sees this.
            // A child that echoes its own environment is not hypothetical:
            // `npm run` prints the command, and plenty of tools log config on
            // startup.
            stdout: truncate(redactText(capturedStdout, scope), maxCaptured),
            stderr: truncate(redactText(capturedStderr, scope), maxCaptured),
          }
        : {}),
    };
    return outcome;
  } finally {
    process.off('SIGINT', forwardSignal);
    process.off('SIGTERM', forwardSignal);
    scope.dispose();
  }
}

function appendCapped(current: string, chunk: string, max: number): string {
  if (current.length >= max) {
    return current;
  }
  return current + chunk.slice(0, max - current.length);
}

/** FR-RUN-007: names only, never values. */
export function describeDryRun(
  refs: readonly SecretRef[],
  executable: string,
  args: readonly string[],
): {
  command: string;
  secretNames: string[];
  references: string[];
} {
  return {
    command: [executable, ...args].join(' '),
    secretNames: refs.map((ref) => ref.name),
    references: refs.map(formatRef),
  };
}

export { createRedactingStream };
