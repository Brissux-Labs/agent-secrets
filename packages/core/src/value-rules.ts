import { InvalidInputError } from './errors.js';
import type { SecretValue } from './secret-value.js';

/** FR-ADD-009. Configurable at the call site, 64 KiB by default. */
export const MAX_VALUE_BYTES = 64 * 1024;

export interface ValueRules {
  readonly maxBytes?: number;
  /** FR-ADD-008: empty values are rejected by default. */
  readonly allowEmpty?: boolean;
  /** Surrounding whitespace is rejected by default; see below for why. */
  readonly allowWhitespace?: boolean;
}

/**
 * Validate a value without disclosing anything about it.
 *
 * Note what the error messages deliberately omit: the actual byte count, the
 * offending character, and any excerpt. "too large" is all the operator needs,
 * and all an attacker reading a log should get.
 */
export function validateSecretValue(value: SecretValue, rules: ValueRules = {}): void {
  const maxBytes = rules.maxBytes ?? MAX_VALUE_BYTES;
  // expose: measuring the value against policy limits; the result never leaves
  // this function as anything other than a boolean-shaped decision.
  const raw = value.expose();

  if (!rules.allowEmpty && raw.length === 0) {
    throw new InvalidInputError('Secret value is empty.', {
      field: 'value',
      hint: 'Enter a non-empty value, or pass --allow-empty if an empty value is genuinely intended.',
    });
  }

  if (Buffer.byteLength(raw, 'utf8') > maxBytes) {
    throw new InvalidInputError('Secret value exceeds the configured maximum size.', {
      field: 'value',
      hint: `The limit is ${maxBytes} bytes. Raise it with --max-bytes if this is expected.`,
    });
  }

  // A trailing newline is almost always a paste artefact and silently breaks
  // downstream consumers. Reject rather than trim: trimming would mean storing
  // something different from what the human confirmed.
  if (!rules.allowWhitespace && raw !== raw.trim()) {
    throw new InvalidInputError('Secret value has leading or trailing whitespace.', {
      field: 'value',
      hint: 'This is usually a copy-paste artefact. Re-enter the value, or pass --allow-whitespace.',
    });
  }
}
