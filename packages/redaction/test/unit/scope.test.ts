import { SecretValue } from '@bx-labs/agent-secrets-core';
import { describe, expect, it } from 'vitest';
import { MIN_TRACKED_LENGTH, newCanary, REDACTION_TOKEN, RedactionScope } from '../../src/index.js';

describe('RedactionScope', () => {
  it('scrubs a tracked SecretValue from plain text', () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.track(SecretValue.from(canary));

    const redacted = scope.redact(`connecting with ${canary} now`);

    expect(redacted).not.toContain(canary);
    expect(redacted).toBe(`connecting with ${REDACTION_TOKEN} now`);
  });

  it('replaces every occurrence, not just the first', () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    const redacted = scope.redact(`${canary} ${canary} ${canary}`);

    expect(redacted).not.toContain(canary);
    expect(redacted.split(REDACTION_TOKEN)).toHaveLength(4);
  });

  it('refuses to track values shorter than the minimum, to stay usable on prose', () => {
    const scope = new RedactionScope();
    scope.trackString('a');
    scope.trackString('id');
    scope.trackString('the');

    expect(scope.size).toBe(0);
    expect(scope.redact('the id of a thing')).toBe('the id of a thing');
  });

  it('tracks a value exactly at the minimum length', () => {
    const scope = new RedactionScope();
    scope.trackString('abcd');

    expect('abcd'.length).toBe(MIN_TRACKED_LENGTH);
    expect(scope.redact('xx abcd xx')).toBe(`xx ${REDACTION_TOKEN} xx`);
  });

  it('ignores a disposed SecretValue instead of throwing', () => {
    const secret = SecretValue.from(newCanary());
    secret.dispose();
    const scope = new RedactionScope();

    expect(() => scope.track(secret)).not.toThrow();
    expect(scope.size).toBe(0);
  });

  describe('derived encodings', () => {
    it('catches the URL-encoded form', () => {
      const raw = `${newCanary()} a/b?c=d&e`;
      const scope = new RedactionScope();
      scope.trackString(raw);

      const url = `https://example.invalid/callback?token=${encodeURIComponent(raw)}`;
      const redacted = scope.redact(url);

      expect(redacted).not.toContain(encodeURIComponent(raw));
      expect(redacted).toContain(REDACTION_TOKEN);
    });

    it('catches the form-encoded (plus-for-space) spelling', () => {
      const raw = `${newCanary()} with spaces`;
      const scope = new RedactionScope();
      scope.trackString(raw);

      const body = `value=${encodeURIComponent(raw).replaceAll('%20', '+')}`;

      expect(scope.redact(body)).toBe(`value=${REDACTION_TOKEN}`);
    });

    it('catches the base64 and base64url forms', () => {
      const raw = newCanary();
      const scope = new RedactionScope();
      scope.trackString(raw);

      const standard = Buffer.from(raw, 'utf8').toString('base64');
      const urlSafe = Buffer.from(raw, 'utf8').toString('base64url');

      expect(scope.redact(`Basic ${standard}`)).not.toContain(standard);
      expect(scope.redact(`?t=${urlSafe}`)).not.toContain(urlSafe);
    });

    it('catches the value once a JSON logger has escaped it', () => {
      const canary = newCanary();
      // A value carrying a quote and a newline: exactly the shape that survives
      // naive exact-match redaction because the sink rewrote it on the way in.
      const raw = `${canary}\n"quoted"`;
      const scope = new RedactionScope();
      scope.trackString(raw);

      const line = JSON.stringify({ level: 'error', msg: `backend rejected ${raw}` });

      expect(line).not.toContain(raw); // the logger escaped it
      const redacted = scope.redact(line);
      expect(redacted).not.toContain(canary);
      expect(redacted).toContain(REDACTION_TOKEN);
      expect(() => JSON.parse(redacted)).not.toThrow();
    });
  });

  describe('redactUnknown', () => {
    it('walks nested objects, arrays, Maps and Sets', () => {
      const canary = newCanary();
      const scope = new RedactionScope();
      scope.trackString(canary);

      const payload = {
        request: {
          headers: [{ name: 'authorization', value: `Bearer ${canary}` }],
          meta: new Map([['token', canary]]),
          seen: new Set([`prefix-${canary}`]),
        },
      };

      const redacted = JSON.stringify(scope.redactUnknown(payload), replacer);

      expect(redacted).not.toContain(canary);
      expect(redacted).toContain(REDACTION_TOKEN);
    });

    it('redacts object keys as well as values', () => {
      const canary = newCanary();
      const scope = new RedactionScope();
      scope.trackString(canary);

      const redacted = scope.redactUnknown({ [canary]: 'ok' }) as Record<string, unknown>;

      expect(Object.keys(redacted)).toEqual([REDACTION_TOKEN]);
    });

    it('does not unwrap a SecretValue it walks past', () => {
      const scope = new RedactionScope();
      const secret = SecretValue.from(newCanary());

      const redacted = scope.redactUnknown({ secret }) as { secret: unknown };

      expect(redacted.secret).toBe(secret);
    });

    it('survives a circular structure', () => {
      const canary = newCanary();
      const scope = new RedactionScope();
      scope.trackString(canary);

      const node: Record<string, unknown> = { token: canary };
      node.self = node;

      const redacted = scope.redactUnknown(node) as Record<string, unknown>;

      expect(redacted.token).toBe(REDACTION_TOKEN);
      expect(String(redacted.self)).toContain('circular');
    });

    it('redacts a Buffer of text without corrupting a binary one', () => {
      const canary = newCanary();
      const scope = new RedactionScope();
      scope.trackString(canary);

      const text = Buffer.from(`stdout: ${canary}\n`, 'utf8');
      const binary = Buffer.from([0x00, 0xff, 0xfe, 0x80, 0x01]);

      const redactedText = scope.redactUnknown(text) as Buffer;
      const redactedBinary = scope.redactUnknown(binary) as Buffer;

      expect(redactedText.toString('utf8')).not.toContain(canary);
      expect(redactedBinary.equals(binary)).toBe(true);
    });
  });

  describe('isolation', () => {
    it('keeps two scopes from seeing each other’s values', () => {
      const first = newCanary();
      const second = newCanary();
      const scopeA = new RedactionScope();
      const scopeB = new RedactionScope();
      scopeA.trackString(first);
      scopeB.trackString(second);

      expect(scopeA.redact(second)).toBe(second);
      expect(scopeB.redact(first)).toBe(first);
      expect(scopeA.redact(first)).toBe(REDACTION_TOKEN);
      expect(scopeB.redact(second)).toBe(REDACTION_TOKEN);
    });

    it('dispose empties the registry and is safe to call twice', () => {
      const canary = newCanary();
      const scope = new RedactionScope();
      scope.trackString(canary);
      expect(scope.size).toBeGreaterThan(0);

      scope.dispose();
      expect(scope.size).toBe(0);
      expect(() => scope.dispose()).not.toThrow();
      expect(scope.size).toBe(0);
      expect(scope.redact(canary)).toBe(canary);
    });
  });

  it('redacts a 1 MB document with 50 tracked values without going quadratic', () => {
    const scope = new RedactionScope();
    const canaries = Array.from({ length: 50 }, () => newCanary());
    for (const canary of canaries) {
      scope.trackString(canary);
    }

    const filler = 'lorem ipsum dolor sit amet consectetur adipiscing elit '.repeat(400);
    const text = canaries.map((canary) => `${filler}${canary}`).join('\n');
    expect(text.length).toBeGreaterThan(1_000_000);

    const startedAt = performance.now();
    const redacted = scope.redact(text);
    const elapsed = performance.now() - startedAt;

    for (const canary of canaries) {
      expect(redacted).not.toContain(canary);
    }
    expect(elapsed).toBeLessThan(3000);
  });
});

/** Maps and Sets are not JSON-serializable; expand them so the assertion sees them. */
function replacer(_key: string, value: unknown): unknown {
  if (value instanceof Map) {
    return [...value.entries()];
  }
  if (value instanceof Set) {
    return [...value.values()];
  }
  return value;
}
