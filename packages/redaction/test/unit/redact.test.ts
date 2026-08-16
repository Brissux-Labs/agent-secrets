import { InvalidInputError } from '@bx-labs/agent-secrets-core';
import { describe, expect, it } from 'vitest';
import {
  newCanary,
  REDACTION_TOKEN,
  RedactionScope,
  redactAny,
  redactError,
  redactText,
  TRUNCATION_MARKER,
  truncate,
} from '../../src/index.js';

describe('redactText', () => {
  it('applies exact-match redaction and pattern redaction together', () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    const line = `used ${canary} then fell back to ghp_${'examplenotarealtoken'.padEnd(36, '0')}`;
    const redacted = redactText(line, scope);

    expect(redacted).not.toContain(canary);
    expect(redacted).not.toContain('ghp_');
    expect(redacted.split(REDACTION_TOKEN)).toHaveLength(3);
  });

  it('still catches unknown credential shapes with no scope of its own', () => {
    const scope = new RedactionScope();
    const sample = `ghp_${'examplenotarealtoken'.padEnd(36, '0')}`;

    expect(redactText(sample, scope)).toBe(REDACTION_TOKEN);
  });

  it('leaves an empty string alone', () => {
    expect(redactText('', new RedactionScope())).toBe('');
  });
});

describe('redactError', () => {
  it('redacts message, stack and cause chain without touching the original', () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    const root = new Error(`backend rejected ${canary}`);
    const wrapper = new Error(`resolve failed for ${canary}`, { cause: root });
    const originalMessage = wrapper.message;
    const originalStack = wrapper.stack;

    const redacted = redactError(wrapper, scope) as Error & { cause?: Error };

    expect(redacted).not.toBe(wrapper);
    expect(redacted.message).not.toContain(canary);
    expect(redacted.stack).not.toContain(canary);
    expect(redacted.cause?.message).not.toContain(canary);
    expect(redacted.cause?.stack).not.toContain(canary);

    // The original is still intact: a logging call must not change the meaning
    // of an error that is still propagating.
    expect(wrapper.message).toBe(originalMessage);
    expect(wrapper.stack).toBe(originalStack);
    expect(wrapper.cause).toBe(root);
    expect(root.message).toContain(canary);
  });

  it('keeps the error name and the fields callers branch on', () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    const original = new InvalidInputError('value rejected', {
      field: 'value',
      hint: `retry without ${canary}`,
    });

    const redacted = redactError(original, scope) as Error & { code?: string; hint?: string };

    expect(redacted.name).toBe('InvalidInputError');
    expect(redacted.code).toBe('INVALID_INPUT');
    expect(redacted.hint).not.toContain(canary);
    expect(redacted.hint).toContain(REDACTION_TOKEN);
  });

  it('handles non-Error throwables', () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    expect(redactError(`thrown ${canary}`, scope)).toBe(`thrown ${REDACTION_TOKEN}`);
    expect(redactError({ token: canary }, scope)).toEqual({ token: REDACTION_TOKEN });
    expect(redactError(undefined, scope)).toBeUndefined();
    expect(redactError(42, scope)).toBe(42);
  });

  it('terminates on a self-referential cause', () => {
    const scope = new RedactionScope();
    const error = new Error('loop');
    Object.defineProperty(error, 'cause', { value: error, configurable: true });

    expect(() => redactError(error, scope)).not.toThrow();
  });

  it('redacts a JSON log line assembled from a redacted error', () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    const redacted = redactError(new Error(`failed: ${canary}`), scope) as Error;
    const line = JSON.stringify({ level: 'error', message: redacted.message });

    expect(line).not.toContain(canary);
  });
});

describe('redactAny', () => {
  it('redacts a nested payload with both tracked and pattern-matched values', () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    const payload = {
      env: { TOKEN: canary, GITHUB_TOKEN: `ghp_${'examplenotarealtoken'.padEnd(36, '0')}` },
      args: ['--flag', canary],
    };

    const serialized = JSON.stringify(redactAny(payload, scope));

    expect(serialized).not.toContain(canary);
    expect(serialized).not.toContain('ghp_');
  });
});

describe('truncate', () => {
  it('returns short text unchanged', () => {
    expect(truncate('hello', 100)).toBe('hello');
  });

  it('caps the result at the byte budget, marker included', () => {
    const text = 'x'.repeat(1000);
    const result = truncate(text, 64);

    expect(Buffer.byteLength(result, 'utf8')).toBeLessThanOrEqual(64);
    expect(result.endsWith(TRUNCATION_MARKER)).toBe(true);
  });

  it('counts bytes, not characters', () => {
    // 200 bytes of content in 100 characters: a character-based cap would let
    // twice the intended volume through.
    const text = 'é'.repeat(100);
    const result = truncate(text, 40);

    expect(Buffer.byteLength(result, 'utf8')).toBeLessThanOrEqual(40);
    expect(result).not.toContain('�');
  });

  it('never splits a multi-byte sequence', () => {
    const text = '😀'.repeat(50); // four bytes per code point
    for (let budget = 16; budget < 64; budget += 1) {
      const result = truncate(text, budget);
      expect(result).not.toContain('�');
      expect(Buffer.byteLength(result, 'utf8')).toBeLessThanOrEqual(budget);
    }
  });

  it('returns no content at all when the budget cannot hold the marker', () => {
    const result = truncate('secret-ish content', 8);

    expect(result).toBe(TRUNCATION_MARKER.slice(0, 8));
    expect(truncate('anything', 0)).toBe('');
  });
});
