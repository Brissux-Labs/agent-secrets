/**
 * Defence in depth in front of every sink.
 *
 * Nothing in this package is the primary control. The primary control is that a
 * raw value only ever travels between the three destinations named in
 * CLAUDE.md §1. This package is what catches the day that invariant is broken by
 * a refactor, a dependency, or a child process nobody controls — so it is
 * written to be always-on, allocation-cheap, and impossible to accidentally
 * bypass, rather than clever.
 */

export type { Haystacks } from './canary.js';
export {
  assertNoCanary,
  CANARY_PREFIX,
  isCanary,
  MAX_SCANNED_FILE_BYTES,
  newCanary,
  scanPathsForCanary,
} from './canary.js';
export type { CredentialPattern } from './patterns.js';
export { PATTERNS, redactPatterns } from './patterns.js';
export {
  redactAny,
  redactError,
  redactText,
  TRUNCATION_MARKER,
  textTransformFor,
  truncate,
} from './redact.js';
export type { RedactingStreamOptions } from './redacting-writer.js';
export { createRedactingStream } from './redacting-writer.js';
export {
  defaultRedactionScope,
  derivedForms,
  MAX_OVERLAP_CHARS,
  MIN_TRACKED_LENGTH,
  REDACTION_TOKEN,
  RedactionScope,
} from './scope.js';
export type { TextTransform } from './walk.js';
export { isErrorLike, redactDeep, redactErrorLike } from './walk.js';
