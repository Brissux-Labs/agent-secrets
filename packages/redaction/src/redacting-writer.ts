import { Writable } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';
import { redactText } from './redact.js';
import { defaultRedactionScope, MIN_TRACKED_LENGTH, type RedactionScope } from './scope.js';

/**
 * A Writable that redacts everything passing through it before forwarding.
 *
 * This is what `agent-secrets run` puts between a child process and the
 * operator's terminal, and what the MCP server puts in front of captured output.
 * It exists because a child process holds the values in its environment and can
 * print them at any moment, deliberately or by accident — `set -x`, a crash
 * dump, a verbose HTTP client.
 *
 * Two boundary problems have to be solved for this to be worth anything:
 *
 *  1. **Byte boundaries.** A chunk can end in the middle of a multi-byte UTF-8
 *     sequence. `StringDecoder` holds the partial sequence until the rest
 *     arrives, so we never decode a broken character into U+FFFD.
 *  2. **Value boundaries.** A secret can straddle two chunks: a 40-character
 *     token arrives as 12 characters in one write and 28 in the next, and
 *     neither half matches on its own. That is not a hypothetical — pipes split
 *     wherever the kernel buffer happened to fill. The fix is the overlap buffer
 *     below.
 */

/**
 * Small floor for the overlap so that the stream still behaves sensibly before
 * anything is tracked, and so a scope tracking only short values does not shrink
 * the window to nothing.
 */
const MIN_OVERLAP = MIN_TRACKED_LENGTH;

export interface RedactingStreamOptions {
  /**
   * Forward the target's `end()` when this stream ends. Off by default: the
   * usual target is `process.stdout`, and ending that would break every later
   * write in the process.
   */
  readonly endTarget?: boolean;
}

export function createRedactingStream(
  target: NodeJS.WritableStream,
  scope: RedactionScope = defaultRedactionScope,
  options: RedactingStreamOptions = {},
): NodeJS.WritableStream {
  const decoder = new StringDecoder('utf8');

  /**
   * The tail of the last redacted chunk, withheld from the target.
   *
   * Any occurrence of a tracked value that straddles a chunk boundary must begin
   * within the last (longest tracked value − 1) characters of the earlier chunk;
   * holding exactly that many back and re-prepending them guarantees the whole
   * value is present in a single string when we run redaction. Re-running
   * redaction over already-redacted carry is harmless: the token contains no
   * tracked form, so the pass is idempotent.
   */
  let carry = '';

  const flush = (text: string, hold: number, done: (error?: Error | null) => void): void => {
    const redacted = redactText(text, scope);
    const keep = Math.min(hold, redacted.length);
    let cut = redacted.length - keep;

    // JavaScript strings are UTF-16, so an astral character occupies two units.
    // Cutting between them would emit a lone surrogate, which Node encodes as
    // U+FFFD on the way to the target — silently corrupting the child's output.
    if (
      cut > 0 &&
      isHighSurrogate(redacted.charCodeAt(cut - 1)) &&
      isLowSurrogate(redacted.charCodeAt(cut))
    ) {
      cut -= 1;
    }

    const emit = redacted.slice(0, cut);
    carry = redacted.slice(cut);
    if (emit.length === 0) {
      done();
      return;
    }
    target.write(emit, (error) => done(error));
  };

  return new Writable({
    // Always hand `_write` a Buffer so the decoder sees bytes, whatever the
    // caller wrote.
    decodeStrings: true,

    write(chunk: Buffer, _encoding, callback): void {
      // Recomputed per write: the scope may start tracking a value part-way
      // through a stream's life, and the window has to grow with it.
      const overlap = Math.max(MIN_OVERLAP, scope.maxTrackedLength) - 1;
      flush(carry + decoder.write(chunk), overlap, callback);
    },

    final(callback): void {
      // End of input: nothing more can arrive to complete a straddling value, so
      // the carry is redacted one last time and released in full.
      const tail = carry + decoder.end();
      carry = '';
      if (tail.length === 0) {
        finish(target, options.endTarget === true, callback);
        return;
      }
      target.write(redactText(tail, scope), (error) => {
        if (error) {
          callback(error);
          return;
        }
        finish(target, options.endTarget === true, callback);
      });
    },
  });
}

function isHighSurrogate(code: number): boolean {
  return code >= 0xd800 && code <= 0xdbff;
}

function isLowSurrogate(code: number): boolean {
  return code >= 0xdc00 && code <= 0xdfff;
}

function finish(
  target: NodeJS.WritableStream,
  endTarget: boolean,
  callback: (error?: Error | null) => void,
): void {
  if (!endTarget) {
    callback();
    return;
  }
  target.end(() => callback());
}
