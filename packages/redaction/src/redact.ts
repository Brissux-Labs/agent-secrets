import { redactPatterns } from './patterns.js';
import { defaultRedactionScope, type RedactionScope } from './scope.js';
import { redactDeep, redactErrorLike, type TextTransform } from './walk.js';

/**
 * The composed entry point. Everything that writes to a log sink, builds an
 * error for another process, or hands captured output back to an agent goes
 * through here.
 *
 * The order is not arbitrary. Exact-match redaction runs first so that a value
 * we actually hold is scrubbed even when it does not look like any known
 * credential shape — most of them do not. Pattern redaction runs second, over
 * text that already contains `[REDACTED]` tokens, as a net for credentials this
 * process was never told about.
 */

export function redactText(text: string, scope: RedactionScope = defaultRedactionScope): string {
  if (typeof text !== 'string' || text.length === 0) {
    return text;
  }
  return redactPatterns(scope.redact(text));
}

/** A bound transform for callers that need to hand redaction to something else. */
export function textTransformFor(scope: RedactionScope = defaultRedactionScope): TextTransform {
  return (text: string): string => redactText(text, scope);
}

/**
 * Sanitize anything thrown, without mutating it.
 *
 * Returns a *new* Error whose message, name, stack and own fields are redacted,
 * following `cause` one level. Non-Error throwables — `throw 'string'`, a
 * rejected plain object, a subprocess result — are redacted as data.
 *
 * The original is left intact on purpose: a caller further up the stack may
 * still need to inspect it, and a logging call is the wrong place to change the
 * meaning of an error that is still propagating.
 */
export function redactError(
  error: unknown,
  scope: RedactionScope = defaultRedactionScope,
): unknown {
  return redactErrorLike(error, textTransformFor(scope));
}

/** Deep-redact an arbitrary payload: objects, arrays, Maps, Sets, Buffers. */
export function redactAny(input: unknown, scope: RedactionScope = defaultRedactionScope): unknown {
  return redactDeep(input, textTransformFor(scope));
}

export const TRUNCATION_MARKER = '... [truncated]';

/**
 * Cap a string at a byte budget (FR-MCP-004).
 *
 * Bytes, not characters: the limits that matter downstream are model context
 * windows and pipe buffers, both of which count bytes. Truncation happens on a
 * UTF-8 sequence boundary so that the result is always valid text — a chopped
 * multi-byte character would become U+FFFD and, worse, could split a tracked
 * value in a way that leaves half of it visible.
 *
 * The marker is included in the budget: a caller that says 4096 gets at most
 * 4096 bytes back.
 */
export function truncate(text: string, maxBytes: number): string {
  if (typeof text !== 'string') {
    return text;
  }
  if (!Number.isFinite(maxBytes) || maxBytes <= 0) {
    return '';
  }
  const bytes = Buffer.from(text, 'utf8');
  if (bytes.length <= maxBytes) {
    return text;
  }

  const markerBytes = Buffer.byteLength(TRUNCATION_MARKER, 'utf8');
  if (maxBytes <= markerBytes) {
    // The budget cannot hold both content and the marker. Returning the marker
    // alone is the only answer that does not disclose a prefix of the content.
    return TRUNCATION_MARKER.slice(0, maxBytes);
  }

  let end = maxBytes - markerBytes;
  // Walk back off any UTF-8 continuation byte (0b10xxxxxx) so we never cut a
  // code point in half.
  while (end > 0 && ((bytes[end] ?? 0) & 0xc0) === 0x80) {
    end -= 1;
  }
  return bytes.subarray(0, end).toString('utf8') + TRUNCATION_MARKER;
}
