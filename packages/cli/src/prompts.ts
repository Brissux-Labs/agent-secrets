import { InvalidInputError, SecretValue, secretValuesEqual } from '@bx-labs/agent-secrets-core';
import { password } from '@inquirer/prompts';

/**
 * How a value gets into the process.
 *
 * FR-ADD-001 through FR-ADD-004 all reduce to one idea: there must be no way to
 * put a secret on a command line. Not as a positional argument, not as
 * `NAME=VALUE`, not as `--value`. Those forms end up in shell history, in `ps`
 * output, in CI logs, and — the case this product was built for — in the
 * transcript of a conversation with an AI agent that was asked to "just run
 * the command".
 *
 * So there are exactly two ways in:
 *
 *   1. a hidden TTY prompt, which is the default and requires a human;
 *   2. an explicit `--stdin` flag, for scripted use, which refuses to run when
 *      stdin is a terminal (that would mean a human is about to type into an
 *      unmasked prompt).
 */

export interface ReadValueOptions {
  /** Ask twice and compare. Default true for create, false for scripted input. */
  readonly confirm?: boolean;
  readonly promptLabel?: string;
  readonly confirmLabel?: string;
}

export async function readValueFromTty(options: ReadValueOptions = {}): Promise<SecretValue> {
  if (!process.stdin.isTTY) {
    throw new InvalidInputError('No terminal is available to read the value securely.', {
      field: 'value',
      hint: 'Run this command in a terminal, or pipe the value with `--stdin` (documented in DOC.md).',
    });
  }

  const first = SecretValue.from(
    await password({ message: options.promptLabel ?? 'Secret value:', mask: '*' }),
  );

  if (options.confirm === false) {
    return first;
  }

  const second = SecretValue.from(
    await password({ message: options.confirmLabel ?? 'Confirm:', mask: '*' }),
  );

  const identical = secretValuesEqual(first, second);
  // The second copy has served its purpose either way; drop it before the
  // comparison result decides what happens next.
  second.dispose();

  if (!identical) {
    first.dispose();
    throw new InvalidInputError('The two entries did not match.', {
      field: 'value',
      hint: 'Run the command again and enter the same value twice.',
    });
  }
  return first;
}

/**
 * FR-ADD-003 / FR-ADD-004: the documented secure stdin mode.
 *
 * Refusing when stdin is a TTY is not pedantry. If it were allowed, a user
 * typing at that prompt would see their key echoed on screen and left in the
 * terminal's scrollback — the exact failure the hidden prompt exists to prevent.
 */
export async function readValueFromStdin(
  stream: NodeJS.ReadableStream = process.stdin,
): Promise<SecretValue> {
  if ((stream as NodeJS.ReadStream).isTTY) {
    throw new InvalidInputError('`--stdin` was used but stdin is a terminal.', {
      field: 'value',
      hint: 'Pipe the value in, or omit `--stdin` to use the hidden prompt.',
    });
  }

  const chunks: Buffer[] = [];
  let total = 0;
  const limit = 1024 * 1024;

  for await (const chunk of stream) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8');
    total += buffer.length;
    if (total > limit) {
      for (const previous of chunks) {
        previous.fill(0);
      }
      throw new InvalidInputError('The piped value exceeded the maximum accepted size.', {
        field: 'value',
      });
    }
    chunks.push(buffer);
  }

  const joined = Buffer.concat(chunks);
  // A single trailing newline is what `echo` adds and what every user means to
  // omit. Anything more is left alone so that value-rules can reject it and the
  // human can decide.
  const text = joined.toString('utf8').replace(/\r?\n$/, '');

  joined.fill(0);
  for (const chunk of chunks) {
    chunk.fill(0);
  }

  return SecretValue.from(text);
}

/**
 * FR-MUTATE-003: deletion asks the operator to type the canonical reference.
 *
 * A y/n prompt is muscle memory; typing `bitwarden/ezjob/production/STRIPE_KEY`
 * is not. The friction is the feature.
 */
export async function confirmByTyping(expected: string, message: string): Promise<boolean> {
  if (!process.stdin.isTTY) {
    throw new InvalidInputError('Confirmation requires a terminal.', {
      hint: 'Pass `--yes` with the exact reference to confirm non-interactively.',
    });
  }
  const { input } = await import('@inquirer/prompts');
  const answer = await input({ message });
  return answer.trim() === expected;
}
