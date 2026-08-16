import { timingSafeEqual } from 'node:crypto';
import { inspect } from 'node:util';

/**
 * The only type in this codebase allowed to carry a raw secret value.
 *
 * Everything about it is designed to make accidental disclosure a loud failure
 * rather than a silent one:
 *
 *  - the value lives in a `#private` field, so it survives neither object
 *    spread, `Object.keys`, `structuredClone`, nor `JSON.stringify`;
 *  - `toString` and `util.inspect` return a constant placeholder, so template
 *    literals and `console.log` cannot leak it;
 *  - `toJSON` throws instead of returning a placeholder, because a serializer
 *    reaching a secret is a bug we want surfaced in tests, not papered over;
 *  - reading the value requires the explicit, greppable `expose()` call.
 *
 * Honest limitation: JavaScript strings are immutable and garbage-collected, so
 * `dispose()` cannot guarantee the bytes leave process memory. It drops our own
 * reference — best effort, as documented in docs/threat-model.md.
 */

const PLACEHOLDER = '[secret]';

export class SecretDisclosureError extends Error {
  override readonly name = 'SecretDisclosureError';
}

export class SecretValue {
  #value: string | undefined;
  readonly #createdAt: number;

  private constructor(value: string) {
    this.#value = value;
    this.#createdAt = Date.now();
    Object.freeze(this);
  }

  /**
   * Wrap a raw string. The caller is responsible for having obtained it from a
   * legitimate source (hidden TTY prompt, secure form body, backend adapter).
   */
  static from(raw: string): SecretValue {
    if (typeof raw !== 'string') {
      throw new TypeError('SecretValue.from expects a string');
    }
    return new SecretValue(raw);
  }

  /**
   * Read the underlying string.
   *
   * Legitimate call sites are limited to the three destinations listed in
   * CLAUDE.md §1. Every call must carry a `// expose: <reason>` comment; code
   * review greps for `expose(` before anything else.
   */
  expose(): string {
    if (this.#value === undefined) {
      throw new SecretDisclosureError('SecretValue was disposed and can no longer be exposed');
    }
    return this.#value;
  }

  /** True once `dispose()` has run. Carries no information about the value. */
  get disposed(): boolean {
    return this.#value === undefined;
  }

  /** Epoch millis at creation. Used by scope bookkeeping, never logged. */
  get createdAt(): number {
    return this.#createdAt;
  }

  /**
   * Drop our reference to the value. Idempotent. Best effort only — see the
   * class comment.
   */
  dispose(): void {
    this.#value = undefined;
  }

  toString(): string {
    return PLACEHOLDER;
  }

  toJSON(): never {
    throw new SecretDisclosureError(
      'Refusing to serialize a SecretValue. A secret reached a JSON boundary; ' +
        'this is a defect, not something to work around.',
    );
  }

  [Symbol.toPrimitive](): string {
    return PLACEHOLDER;
  }

  [inspect.custom](): string {
    return PLACEHOLDER;
  }

  get [Symbol.toStringTag](): string {
    return 'SecretValue';
  }
}

export function isSecretValue(candidate: unknown): candidate is SecretValue {
  return candidate instanceof SecretValue;
}

/**
 * Constant-time equality between two secret values. Used by the CLI's
 * "confirm the value" prompt, never for authentication.
 */
export function secretValuesEqual(a: SecretValue, b: SecretValue): boolean {
  // expose: comparing two values the same human just typed, result is a boolean
  const left = Buffer.from(a.expose(), 'utf8');
  // expose: see above
  const right = Buffer.from(b.expose(), 'utf8');
  try {
    if (left.length !== right.length) {
      // timingSafeEqual requires equal lengths; both operands are local input
      // from the same human, so the length side-channel is not meaningful here.
      return false;
    }
    return timingSafeEqual(left, right);
  } finally {
    left.fill(0);
    right.fill(0);
  }
}
