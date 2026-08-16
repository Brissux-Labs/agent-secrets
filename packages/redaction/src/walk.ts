import { isSecretValue } from '@bx-labs/agent-secrets-core';

/**
 * Structure-preserving redaction walkers.
 *
 * These are the shared mechanics behind `RedactionScope.redactUnknown` and
 * `redactError`: both need to rebuild an arbitrary value with every string in it
 * rewritten, and neither may mutate its input. They are parameterised by the
 * text transform so that exact-match-only redaction and the composed
 * exact-plus-pattern redaction share one implementation — a second copy of this
 * logic would be a second place for a leak to hide.
 */

export type TextTransform = (text: string) => string;

/**
 * Depth cap. A log payload nested deeper than this is either a bug or an attempt
 * to blow the stack inside the redactor; either way, refusing to descend is the
 * fail-closed answer because the replacement string carries no data.
 */
const MAX_DEPTH = 32;

const TOO_DEEP = '[redaction: depth limit]';
const CIRCULAR = '[redaction: circular]';

export function redactDeep(input: unknown, transform: TextTransform): unknown {
  return walk(input, transform, 0, new WeakSet<object>());
}

function walk(
  input: unknown,
  transform: TextTransform,
  depth: number,
  seen: WeakSet<object>,
): unknown {
  if (typeof input === 'string') {
    return transform(input);
  }
  if (input === null || typeof input !== 'object') {
    // Numbers, booleans, bigints, symbols, undefined and functions carry no
    // string to scrub. A function is passed through by reference rather than
    // invoked: calling it here could have side effects.
    return input;
  }
  if (depth >= MAX_DEPTH) {
    return TOO_DEEP;
  }
  if (seen.has(input)) {
    return CIRCULAR;
  }

  // A SecretValue is already safe by construction — it has no enumerable fields
  // and refuses to serialize — so it is passed through untouched. Walking into
  // it would only strip the wrapper that protects it.
  if (isSecretValue(input)) {
    return input;
  }

  seen.add(input);
  try {
    return walkObject(input, transform, depth, seen);
  } finally {
    // Sibling references to the same object are legitimate; only cycles are not.
    seen.delete(input);
  }
}

function walkObject(
  input: object,
  transform: TextTransform,
  depth: number,
  seen: WeakSet<object>,
): unknown {
  if (Array.isArray(input)) {
    return input.map((item) => walk(item, transform, depth + 1, seen));
  }
  if (isErrorLike(input)) {
    // Nested errors get one shallow pass: their own `cause` is walked as data,
    // which terminates the recursion at this depth budget.
    return redactErrorLike(input, transform, 0);
  }
  if (Buffer.isBuffer(input)) {
    return redactBuffer(input, transform);
  }
  if (input instanceof Map) {
    const out = new Map<unknown, unknown>();
    for (const [key, value] of input) {
      out.set(walk(key, transform, depth + 1, seen), walk(value, transform, depth + 1, seen));
    }
    return out;
  }
  if (input instanceof Set) {
    const out = new Set<unknown>();
    for (const value of input) {
      out.add(walk(value, transform, depth + 1, seen));
    }
    return out;
  }
  if (input instanceof Date || input instanceof RegExp) {
    return input;
  }

  // Plain objects and class instances alike are rebuilt as plain objects. Keys
  // are redacted too: an environment-shaped map can carry the value as a key.
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    out[transform(key)] = walk(value, transform, depth + 1, seen);
  }
  return out;
}

/**
 * Redact a Buffer without corrupting binary content.
 *
 * Subprocess output arrives as Buffers, so skipping them would leave the widest
 * leak channel in the product unredacted. But decoding arbitrary bytes as UTF-8
 * is lossy — invalid sequences become U+FFFD — so the result is only used when
 * the decode round-trips to the identical bytes. Genuinely binary buffers are
 * returned untouched: that is a real, deliberate gap — a value embedded in a
 * gzip stream or a core dump is not scrubbed here, and must be caught by not
 * capturing such a stream in the first place.
 */
function redactBuffer(input: Buffer, transform: TextTransform): Buffer {
  const text = input.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(input)) {
    return input;
  }
  const redacted = transform(text);
  return redacted === text ? input : Buffer.from(redacted, 'utf8');
}

export function isErrorLike(candidate: unknown): candidate is Error {
  return candidate instanceof Error;
}

/**
 * Rebuild an error with every string field redacted.
 *
 * The original is never touched: an error object is frequently rethrown or
 * inspected by a caller that did not ask for a sanitized copy, and mutating it
 * in a logging path would be an action at a distance.
 *
 * `depth` is the number of `cause` links still allowed to receive full error
 * treatment. One is enough in practice: wrappers add a single layer, and a
 * deeper chain is walked as inert data instead.
 */
export function redactErrorLike(error: unknown, transform: TextTransform, depth = 1): unknown {
  if (!isErrorLike(error)) {
    // Non-Error throwables are common: `throw 'string'`, a rejected object from
    // a JSON API, a DOMException-shaped thing. They are redacted as plain data.
    return redactDeep(error, transform);
  }

  const clone = new Error(transform(error.message));

  // `name` is on the prototype for built-ins and an own field for the core error
  // classes; read it through the instance so both cases are preserved.
  Object.defineProperty(clone, 'name', {
    value: transform(error.name),
    writable: true,
    enumerable: false,
    configurable: true,
  });

  // `new Error` above captured this function's stack. Overwrite it with the
  // redacted original, which is the one an operator actually needs. Stacks embed
  // the message, so an unredacted stack is a leak on its own.
  if (typeof error.stack === 'string') {
    clone.stack = transform(error.stack);
  }

  for (const [key, value] of Object.entries(error)) {
    if (key === 'message' || key === 'stack' || key === 'cause') {
      continue;
    }
    // Preserves the parts of AgentSecretsError that callers branch on — `code`,
    // `exitCode`, `field`, `reference`, `hint` — after redacting them.
    Object.defineProperty(clone, key, {
      value: redactDeep(value, transform),
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }

  // Following the chain only while `depth` remains is what makes this
  // terminate: an error whose `cause` is itself, or a mutually referential pair,
  // would otherwise recurse forever inside a logging path.
  if (depth > 0 && 'cause' in error && error.cause !== undefined) {
    const cause = isErrorLike(error.cause)
      ? redactErrorLike(error.cause, transform, depth - 1)
      : redactDeep(error.cause, transform);
    Object.defineProperty(clone, 'cause', {
      value: cause,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  }

  return clone;
}
