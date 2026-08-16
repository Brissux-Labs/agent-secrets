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
  /**
   * Hand the child our own stdout and stderr instead of filtering them.
   *
   * This turns off output redaction, so it exists for one reason only: a piped
   * child has no TTY, and some commands genuinely need one — a dev server with
   * an interactive prompt, a tool whose progress rendering requires a terminal.
   * The CLI surfaces it as `--pass-through-output` and warns when it is used.
   * Ignored when `capture` is set, which has no terminal to pass through to.
   */
  readonly passThroughOutput?: boolean;
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

/**
 * Variables stripped from the inherited environment before a child runs.
 *
 * `run_with_secrets` lets an agent choose the command, and an inherited
 * environment is a read channel: the MCP server's own process carries
 * `AGENT_SECRETS_ADAPTER_TOKEN` (which mints vault-write links) and a
 * deployment may carry `BWS_ACCESS_TOKEN` (which opens the vault outright).
 * Handing those to a child the agent selected, whose output is then returned to
 * the model, would make the whole no-raw-values design moot.
 *
 * Matching is exact or by prefix; the values are also tracked in the redaction
 * scope so an occurrence surviving some other path is still scrubbed.
 */
const STRIPPED_ENV_KEYS = ['BWS_ACCESS_TOKEN', 'BWS_SERVER_URL'];
const STRIPPED_ENV_PREFIXES = ['AGENT_SECRETS_'];

/** Left in place: they configure the child, not us, and carry no credential. */
const STRIPPED_ENV_EXCEPTIONS = ['AGENT_SECRETS_TELEMETRY'];

function isStrippedEnvKey(key: string): boolean {
  if (STRIPPED_ENV_EXCEPTIONS.includes(key)) {
    return false;
  }
  return (
    STRIPPED_ENV_KEYS.includes(key) ||
    STRIPPED_ENV_PREFIXES.some((prefix) => key.startsWith(prefix))
  );
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
      if (value === undefined) {
        continue;
      }
      if (isStrippedEnvKey(key)) {
        // Track before dropping: if this credential reaches the child's output
        // through any other route, redaction still catches it.
        if (value.length > 0) {
          scope.trackString(value);
        }
        continue;
      }
      childEnv[key] = value;
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

  // stdout and stderr are always piped, never inherited.
  //
  // Handing the child our own file descriptors would mean a child that prints
  // its own environment prints it straight to the terminal, the CI job log, and
  // any agent transcript wrapping the CLI — with this process never seeing a
  // byte it could filter. `npm run` echoing its command line, a framework boot
  // banner, a crash dump: none of these are hypothetical.
  //
  // The cost is real and worth stating: a piped child does not have a TTY, so
  // it may disable colour and cannot drive an interactive prompt on stdout.
  // `passThroughOutput` restores inheritance for the cases where that matters,
  // and the CLI warns when it is used.
  const passThrough = spec.passThroughOutput === true && spec.capture !== true;
  const outputStdio = passThrough ? 'inherit' : 'pipe';

  const child = spawn(spec.executable, [...spec.args], {
    env: childEnv,
    ...(spec.cwd === undefined ? {} : { cwd: spec.cwd }),
    // No shell, ever: the command comes from a manifest or an agent, and a
    // shell would turn `npm run dev; curl …` into two commands.
    shell: false,
    // stdin stays inherited on the streaming path so an interactive command
    // still reads from the terminal; only the outbound streams are filtered.
    stdio: [spec.capture ? 'ignore' : 'inherit', outputStdio, outputStdio],
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
  const headroom = scope.maxTrackedLength * 2 + 64;

  // Redacting transforms on the streaming path, kept so we can wait for them to
  // flush before the scope is disposed.
  const transforms: NodeJS.WritableStream[] = [];

  if (spec.capture) {
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');

    // Accumulate with headroom, then redact the whole buffer, then truncate.
    //
    // The ordering is the point. Capping the raw text first is a chosen-prefix
    // oracle: a caller that pads its output to one byte short of the budget
    // gets the first character of the value through, because exact-match
    // redaction can no longer see a complete occurrence to match. Repeat with
    // one more byte of padding and the prefix walks forward until the whole
    // credential is recovered.
    //
    // The headroom covers a value straddling the budget boundary, sized to the
    // longest tracked string and doubled because a base64 derivation of it is
    // longer than the original.
    child.stdout?.on('data', (chunk: string) => {
      capturedStdout = appendCapped(capturedStdout, chunk, maxCaptured + headroom);
    });
    child.stderr?.on('data', (chunk: string) => {
      capturedStderr = appendCapped(capturedStderr, chunk, maxCaptured + headroom);
    });
  } else if (!passThrough) {
    // Streaming path: interpose the redacting transform between the child and
    // the operator's terminal. The transform keeps an overlap buffer so a value
    // split across two writes is still caught.
    const outTransform = createRedactingStream(process.stdout, scope);
    const errTransform = createRedactingStream(process.stderr, scope);
    transforms.push(outTransform, errTransform);
    child.stdout?.pipe(outTransform);
    child.stderr?.pipe(errTransform);
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
            // Redaction runs on the intact buffer above; only then is the
            // result cut to the caller's budget.
          }
        : {}),
    };
    return outcome;
  } finally {
    process.off('SIGINT', forwardSignal);
    process.off('SIGTERM', forwardSignal);

    // Let the transforms flush their overlap buffers before the tracked values
    // disappear; disposing first would let the tail of the last chunk through
    // unredacted.
    await Promise.all(transforms.map(waitForFinish));
    scope.dispose();
  }
}

function waitForFinish(stream: NodeJS.WritableStream): Promise<void> {
  const writable = stream as NodeJS.WritableStream & {
    writableFinished?: boolean;
    destroyed?: boolean;
  };

  // Check the state before subscribing. By the time the child's 'close' fires,
  // the pipes have usually already ended, so 'finish' has been emitted and a
  // late `once('finish')` would wait forever — which showed up as the CLI
  // exiting 0 with no audit record, because the command never returned.
  if (writable.writableFinished === true || writable.destroyed === true) {
    return Promise.resolve();
  }

  return new Promise<void>((resolve) => {
    const done = (): void => resolve();
    // 'error' and 'close' resolve too: a broken pipe is not a reason to hang.
    stream.once('finish', done);
    stream.once('error', done);
    stream.once('close', done);
  });
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
