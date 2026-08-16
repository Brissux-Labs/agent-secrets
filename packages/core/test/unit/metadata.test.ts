import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  assertNoValueFields,
  FORBIDDEN_METADATA_FIELDS,
  inputMetadataSchema,
  JSON_SCHEMA_VERSION,
  jsonEnvelopeSchema,
  type SecretMetadata,
  secretMetadataSchema,
} from '../../src/metadata.js';

/**
 * FR-SCOPE-006 / FR-LIST-002. The point of these tests is that "no value ever
 * crosses a public schema" is enforced structurally, not by reviewer vigilance:
 * a future contributor who adds `length` "just for the progress bar" must get a
 * red test, not a passing build.
 */

const VALID_METADATA: SecretMetadata = {
  backend: 'bitwarden',
  project: 'ezjob',
  environment: 'development',
  name: 'OPENAI_API_KEY',
  reference: 'bitwarden/ezjob/development/OPENAI_API_KEY',
  backendId: 'a7f0c2de-0000-4000-8000-000000000000',
  version: '3',
  description: 'Key used by the scheduler worker',
  provider: 'openai',
  tags: ['worker', 'llm'],
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-02-01T00:00:00.000Z',
};

function canary(): string {
  return `ASECRET_CANARY_${randomBytes(12).toString('hex').toUpperCase()}`;
}

describe('secretMetadataSchema', () => {
  it('accepts a complete, legitimate record', () => {
    expect(secretMetadataSchema.parse(VALID_METADATA)).toEqual(VALID_METADATA);
  });

  it('accepts the minimal record', () => {
    const minimal = {
      backend: 'bitwarden',
      project: 'ezjob',
      environment: 'production',
      name: 'A',
      reference: 'bitwarden/ezjob/production/A',
    };
    expect(secretMetadataSchema.parse(minimal)).toEqual(minimal);
  });

  it('rejects an extra value field because it is strict', () => {
    const payload = { ...VALID_METADATA, value: canary() };
    expect(secretMetadataSchema.safeParse(payload).success).toBe(false);
  });

  it('rejects every field name on the forbidden list', () => {
    for (const field of FORBIDDEN_METADATA_FIELDS) {
      const payload = { ...VALID_METADATA, [field]: 'anything' };
      expect(secretMetadataSchema.safeParse(payload).success, `field ${field}`).toBe(false);
    }
  });

  it('rejects an invalid scope coordinate', () => {
    expect(secretMetadataSchema.safeParse({ ...VALID_METADATA, name: 'lowercase' }).success).toBe(
      false,
    );
    expect(secretMetadataSchema.safeParse({ ...VALID_METADATA, project: 'Ezjob' }).success).toBe(
      false,
    );
    expect(
      secretMetadataSchema.safeParse({ ...VALID_METADATA, environment: 'staging' }).success,
    ).toBe(false);
  });

  it('rejects a non-ISO timestamp and an oversized description', () => {
    expect(
      secretMetadataSchema.safeParse({ ...VALID_METADATA, createdAt: 'yesterday' }).success,
    ).toBe(false);
    expect(
      secretMetadataSchema.safeParse({ ...VALID_METADATA, description: 'x'.repeat(513) }).success,
    ).toBe(false);
  });
});

describe('inputMetadataSchema', () => {
  it('accepts the three supported fields and an empty object', () => {
    expect(inputMetadataSchema.parse({})).toEqual({});
    expect(
      inputMetadataSchema.parse({ description: 'notes', provider: 'openai', tags: ['llm'] }),
    ).toEqual({ description: 'notes', provider: 'openai', tags: ['llm'] });
  });

  it('rejects unknown keys', () => {
    expect(inputMetadataSchema.safeParse({ note: 'hello' }).success).toBe(false);
    expect(inputMetadataSchema.safeParse({ description: 'ok', extra: 1 }).success).toBe(false);
  });

  it('rejects a value-bearing key even when it looks like metadata', () => {
    expect(inputMetadataSchema.safeParse({ value: canary() }).success).toBe(false);
    expect(inputMetadataSchema.safeParse({ preview: 'sk-…' }).success).toBe(false);
    expect(inputMetadataSchema.safeParse({ length: 51 }).success).toBe(false);
  });

  it('rejects malformed tags and providers', () => {
    expect(inputMetadataSchema.safeParse({ tags: ['Worker'] }).success).toBe(false);
    expect(inputMetadataSchema.safeParse({ tags: ['-worker'] }).success).toBe(false);
    expect(
      inputMetadataSchema.safeParse({ tags: Array.from({ length: 17 }, () => 'a') }).success,
    ).toBe(false);
    expect(inputMetadataSchema.safeParse({ provider: 'OpenAI' }).success).toBe(false);
  });
});

describe('jsonEnvelopeSchema', () => {
  it('pins the schema version and rejects unknown envelope keys', () => {
    const envelope = jsonEnvelopeSchema(secretMetadataSchema);
    expect(
      envelope.parse({ schemaVersion: JSON_SCHEMA_VERSION, status: 'ok', data: VALID_METADATA }),
    ).toEqual({ schemaVersion: 1, status: 'ok', data: VALID_METADATA });

    expect(
      envelope.safeParse({ schemaVersion: 2, status: 'ok', data: VALID_METADATA }).success,
    ).toBe(false);
    expect(
      envelope.safeParse({
        schemaVersion: 1,
        status: 'ok',
        data: VALID_METADATA,
        value: canary(),
      }).success,
    ).toBe(false);
  });

  it('carries the forbidden-field guard into the wrapped data', () => {
    const envelope = jsonEnvelopeSchema(z.array(secretMetadataSchema));
    expect(
      envelope.safeParse({
        schemaVersion: 1,
        status: 'ok',
        data: [{ ...VALID_METADATA, hash: 'deadbeef' }],
      }).success,
    ).toBe(false);
  });
});

describe('assertNoValueFields', () => {
  it('passes for a legitimate SecretMetadata', () => {
    expect(() => assertNoValueFields(VALID_METADATA)).not.toThrow();
    expect(() => assertNoValueFields([VALID_METADATA, VALID_METADATA])).not.toThrow();
    expect(() =>
      assertNoValueFields({ schemaVersion: 1, status: 'ok', data: [VALID_METADATA] }),
    ).not.toThrow();
  });

  const forbidden = ['value', 'hash', 'length', 'preview', 'prefix', 'entropy'];

  for (const field of forbidden) {
    it(`throws for "${field}" at the top level`, () => {
      expect(() => assertNoValueFields({ [field]: 'x' })).toThrow(/forbidden field/);
    });

    it(`throws for "${field}" nested in an object`, () => {
      expect(() => assertNoValueFields({ result: { meta: { [field]: 'x' } } })).toThrow(
        /forbidden field/,
      );
    });

    it(`throws for "${field}" nested inside an array`, () => {
      expect(() => assertNoValueFields({ items: [VALID_METADATA, { [field]: 'x' }] })).toThrow(
        /forbidden field/,
      );
    });
  }

  it('matches case-insensitively', () => {
    for (const field of ['Value', 'VALUE', 'HASH', 'Hash', 'Length', 'PreView', 'ENTROPY']) {
      expect(() => assertNoValueFields({ [field]: 'x' }), field).toThrow(/forbidden field/);
    }
  });

  it('covers the whole published forbidden list', () => {
    for (const field of FORBIDDEN_METADATA_FIELDS) {
      expect(() => assertNoValueFields({ [field]: 'x' }), field).toThrow(/forbidden field/);
    }
  });

  it('reports the path but never the offending content', () => {
    const leak = canary();
    try {
      assertNoValueFields({ results: [{ meta: { value: leak } }] });
      expect.unreachable('assertNoValueFields must throw');
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain('$.results[0].meta');
      expect(message).not.toContain(leak);
    }
  });

  it('throws even when the field carries a harmless-looking payload', () => {
    // The guard is about the *name*: a `length: 0` is still a length.
    expect(() => assertNoValueFields({ length: 0 })).toThrow();
    expect(() => assertNoValueFields({ hash: null })).toThrow();
    expect(() => assertNoValueFields({ preview: undefined })).toThrow();
  });

  it('ignores null, undefined and primitives', () => {
    for (const payload of [null, undefined, 'value', 42, true, Symbol('value'), 10n]) {
      expect(() => assertNoValueFields(payload)).not.toThrow();
    }
  });

  it('accepts a forbidden name appearing as a string value rather than a key', () => {
    expect(() =>
      assertNoValueFields({ description: 'the value of the token', tags: ['hash'] }),
    ).not.toThrow();
  });

  it('walks a deep plain structure without recursing forever', () => {
    // 200 levels: deep enough to catch an accidental unbounded walk, shallow
    // enough that the engine's own stack limit is not what we are measuring.
    let node: Record<string, unknown> = { leaf: true };
    for (let depth = 0; depth < 200; depth += 1) {
      node = { child: node, siblings: [{ ...VALID_METADATA }] };
    }
    expect(() => assertNoValueFields(node)).not.toThrow();
  });

  it('walks a wide structure without throwing', () => {
    const wide = Array.from({ length: 500 }, () => ({ ...VALID_METADATA }));
    expect(() => assertNoValueFields(wide)).not.toThrow();
  });
});
