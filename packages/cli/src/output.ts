import type { SafeErrorShape } from '@bx-labs/agent-secrets-core';
import {
  assertNoValueFields,
  isAgentSecretsError,
  JSON_SCHEMA_VERSION,
} from '@bx-labs/agent-secrets-core';
import { redactText } from '@bx-labs/agent-secrets-redaction';

/**
 * Everything the CLI prints goes through here.
 *
 * A single choke point is what makes "no value ever reaches stdout" checkable
 * rather than aspirational: `assertNoValueFields` walks each payload before it
 * is serialized, and `redactText` sweeps the final string. Two independent
 * mechanisms, because the interesting failures are the ones a single check
 * misses — a hand-built object that never went through a schema, or a value
 * embedded mid-sentence in a message.
 */

export type OutputMode = 'human' | 'json';

export interface JsonEnvelope<T> {
  readonly schemaVersion: typeof JSON_SCHEMA_VERSION;
  readonly status: 'ok' | 'error';
  readonly data: T;
}

export interface WriterOptions {
  readonly mode: OutputMode;
  readonly color: boolean;
  readonly stdout?: NodeJS.WritableStream;
  readonly stderr?: NodeJS.WritableStream;
}

export class Writer {
  readonly #mode: OutputMode;
  readonly #color: boolean;
  readonly #stdout: NodeJS.WritableStream;
  readonly #stderr: NodeJS.WritableStream;

  constructor(options: WriterOptions) {
    this.#mode = options.mode;
    this.#color = options.color;
    this.#stdout = options.stdout ?? process.stdout;
    this.#stderr = options.stderr ?? process.stderr;
  }

  get mode(): OutputMode {
    return this.#mode;
  }

  get isJson(): boolean {
    return this.#mode === 'json';
  }

  /**
   * Emit a successful result.
   *
   * `human` is a callback rather than a string so the human rendering is never
   * computed in JSON mode — a rendering function is exactly the sort of place
   * where someone eventually interpolates a value for debugging.
   */
  ok<T>(data: T, human: (fmt: Formatter) => string): void {
    if (this.#mode === 'json') {
      this.#writeJson(this.#stdout, { schemaVersion: JSON_SCHEMA_VERSION, status: 'ok', data });
      return;
    }
    this.#writeLine(this.#stdout, human(this.#formatter()));
  }

  /** Progress and advisory text. Suppressed entirely in JSON mode. */
  note(human: (fmt: Formatter) => string): void {
    if (this.#mode === 'json') {
      return;
    }
    this.#writeLine(this.#stderr, human(this.#formatter()));
  }

  fail(error: unknown): void {
    const shape: SafeErrorShape = isAgentSecretsError(error)
      ? error.toSafeJSON()
      : {
          code: 'INTERNAL',
          message:
            'An internal error occurred. Details were withheld to avoid leaking a secret value.',
        };

    if (this.#mode === 'json') {
      this.#writeJson(this.#stderr, {
        schemaVersion: JSON_SCHEMA_VERSION,
        status: 'error',
        data: shape,
      });
      return;
    }

    const fmt = this.#formatter();
    const lines = [`${fmt.error('✗')} ${shape.message}`];
    if (shape.reference) {
      lines.push(`  reference: ${shape.reference}`);
    }
    // FR-ACCESSIBILITY: an error always tells the operator what to do next, and
    // the symbol is never the only signal — the word is there too.
    if (shape.hint) {
      lines.push(`  ${fmt.dim('next:')} ${shape.hint}`);
    }
    this.#writeLine(this.#stderr, lines.join('\n'));
  }

  #writeJson(stream: NodeJS.WritableStream, envelope: JsonEnvelope<unknown>): void {
    // Throws rather than strips: a forbidden field here means some code path
    // built a payload it should not have, and silently dropping it would hide
    // the defect until a version that forgets the check.
    assertNoValueFields(envelope);
    this.#writeLine(stream, JSON.stringify(envelope));
  }

  #writeLine(stream: NodeJS.WritableStream, text: string): void {
    stream.write(`${redactText(text)}\n`);
  }

  #formatter(): Formatter {
    return this.#color ? colorFormatter : plainFormatter;
  }
}

export interface Formatter {
  bold(text: string): string;
  dim(text: string): string;
  success(text: string): string;
  error(text: string): string;
  warn(text: string): string;
}

const plainFormatter: Formatter = {
  bold: (t) => t,
  dim: (t) => t,
  success: (t) => t,
  error: (t) => t,
  warn: (t) => t,
};

const colorFormatter: Formatter = {
  bold: (t) => `[1m${t}[22m`,
  dim: (t) => `[2m${t}[22m`,
  success: (t) => `[32m${t}[39m`,
  error: (t) => `[31m${t}[39m`,
  warn: (t) => `[33m${t}[39m`,
};

/**
 * Honour NO_COLOR, `--no-color`, and a non-TTY stdout.
 *
 * The last one matters here beyond aesthetics: ANSI escapes interleaved with
 * text can split a string across escape sequences and defeat naive redaction of
 * captured output.
 */
export function shouldUseColor(argv: readonly string[], env: NodeJS.ProcessEnv): boolean {
  if (argv.includes('--no-color') || env['NO_COLOR'] !== undefined) {
    return false;
  }
  return process.stdout.isTTY === true;
}
