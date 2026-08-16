import type { SecretValue } from '@bx-labs/agent-secrets-core';
import { SecretDisclosureError } from '@bx-labs/agent-secrets-core';
import { redactDeep, type TextTransform } from './walk.js';

/**
 * Exact-match redaction.
 *
 * Pattern redaction (patterns.ts) catches credential *shapes* we recognise. This
 * module catches the values we actually hold: for the duration of an operation
 * we know the exact strings that must never appear in output, so we can scrub
 * them literally instead of guessing.
 *
 * The registry is per-operation and short-lived by design. A process-wide set of
 * every secret ever resolved would itself become an attractive in-memory target,
 * and would make one command's values leak into another command's error
 * messages.
 */

export const REDACTION_TOKEN = '[REDACTED]';

/**
 * Values shorter than this are never tracked.
 *
 * The tradeoff is deliberate and one-directional: tracking a 1-3 character value
 * would rewrite ordinary prose ("a", "the", "id") into `[REDACTED]` everywhere,
 * which destroys the diagnostic value of every log line and error message in the
 * product — a self-inflicted denial of service — while protecting a value that
 * has almost no entropy to protect. Anything that short is not a credential; if
 * one ever is, the correct fix is to reject it at input validation, not to make
 * redaction unusable.
 */
export const MIN_TRACKED_LENGTH = 4;

/**
 * Upper bound on how much of a string we will hold in the stream overlap buffer
 * (redacting-writer.ts). Independent of how long a tracked value is, so a single
 * huge value cannot make every stream write buffer megabytes.
 */
export const MAX_OVERLAP_CHARS = 4096;

export class RedactionScope {
  /**
   * Every literal string to search for: the raw values plus their derived
   * encodings. A Set because the same operation frequently tracks the same value
   * twice (resolved once, re-wrapped once).
   */
  readonly #forms = new Set<string>();

  /**
   * Forms sorted longest-first, rebuilt lazily. Longest-first matters: when two
   * tracked forms overlap, replacing the longer one first prevents a partial
   * replacement from breaking up the longer match.
   */
  #sorted: string[] | undefined;

  /** Registers a wrapped value and every encoding of it we know how to derive. */
  track(value: SecretValue): void {
    let raw: string;
    try {
      // expose: registering the exact string so that redaction can scrub it from
      // logs, errors and captured subprocess output. The string never leaves
      // this object; `redact` only ever emits the constant token.
      raw = value.expose();
    } catch (error) {
      // A disposed value has nothing left to track. Any other failure is a real
      // defect and must not be swallowed.
      if (error instanceof SecretDisclosureError) {
        return;
      }
      throw error;
    }
    this.trackString(raw);
  }

  /** For strings not yet wrapped: form field bodies, `bws` stdout fragments. */
  trackString(raw: string): void {
    if (typeof raw !== 'string' || raw.length < MIN_TRACKED_LENGTH) {
      return;
    }
    for (const form of derivedForms(raw)) {
      if (form.length >= MIN_TRACKED_LENGTH) {
        this.#forms.add(form);
      }
    }
    this.#sorted = undefined;
  }

  /**
   * Replace every tracked form with the constant token.
   *
   * Implemented as one native `replaceAll` per form rather than a compiled
   * alternation regex: `replaceAll` with a string needle is a linear substring
   * search with no backtracking, so the cost is O(text × forms) with a very small
   * constant and no ReDoS surface at all. A regex built from attacker-influenced
   * values would have both problems.
   */
  redact(text: string): string {
    if (typeof text !== 'string' || text.length === 0 || this.#forms.size === 0) {
      return text;
    }
    let out = text;
    for (const form of this.#sortedForms()) {
      out = out.replaceAll(form, REDACTION_TOKEN);
    }
    return out;
  }

  /** Deep-walks objects, arrays, Maps, Sets, Errors and Buffers. */
  redactUnknown(input: unknown): unknown {
    return redactDeep(input, this.transform);
  }

  /** Bound transform, safe to hand to a stream or a walker. */
  readonly transform: TextTransform = (text: string): string => this.redact(text);

  /** Empties the registry. Idempotent: calling it twice is a no-op. */
  dispose(): void {
    this.#forms.clear();
    this.#sorted = undefined;
  }

  /** Number of distinct forms tracked, including derived encodings. */
  get size(): number {
    return this.#forms.size;
  }

  /**
   * Length of the longest tracked form, capped. The redacting stream uses it to
   * size the overlap buffer that catches a value split across two chunks.
   */
  get maxTrackedLength(): number {
    let max = 0;
    for (const form of this.#forms) {
      if (form.length > max) {
        max = form.length;
      }
    }
    return Math.min(max, MAX_OVERLAP_CHARS);
  }

  #sortedForms(): readonly string[] {
    if (this.#sorted === undefined) {
      this.#sorted = [...this.#forms].sort((a, b) => b.length - a.length);
    }
    return this.#sorted;
  }
}

/**
 * The encodings a value passes through on its way into a sink.
 *
 * A value is rarely logged verbatim. It gets percent-encoded into a URL, base64'd
 * into an Authorization header, or backslash-escaped by `JSON.stringify` on its
 * way into a structured log line. Each of those is a distinct byte sequence that
 * exact-match redaction would otherwise walk straight past, so each is registered
 * as its own form.
 */
export function derivedForms(raw: string): string[] {
  const forms = [raw];

  // URL / query-string encoding, in both the RFC 3986 and the
  // application/x-www-form-urlencoded spellings (space as %20 vs +).
  const percent = encodeURIComponent(raw);
  forms.push(percent, percent.replaceAll('%20', '+'));

  // Base64, standard and URL-safe alphabets. Note the honest limitation: this
  // only catches the value base64'd on its own, not the value embedded inside a
  // larger base64 blob, where its encoding depends on the 3-byte alignment.
  const bytes = Buffer.from(raw, 'utf8');
  forms.push(bytes.toString('base64'), bytes.toString('base64url'));

  // JSON string escaping: the body of `JSON.stringify(raw)` without its quotes.
  // This is what a value containing a quote, a backslash or a newline looks like
  // once a structured logger has serialized it.
  forms.push(JSON.stringify(raw).slice(1, -1));

  return forms;
}

/**
 * Process-wide fallback scope.
 *
 * It exists so that a sink with no operation context still redacts something,
 * and so that `redactText(text)` has a sensible default. Library code that runs
 * per-operation should construct its own `RedactionScope` and dispose it: two
 * concurrent operations sharing this instance would each be able to scrub — and
 * therefore to observe the effect of — the other's values.
 */
export const defaultRedactionScope = new RedactionScope();
