import { z } from 'zod';
import {
  backendIdSchema,
  environmentSchema,
  projectSlugSchema,
  secretNameSchema,
} from './scope.js';

/**
 * Metadata schemas. FR-SCOPE-006 and FR-LIST-002 are enforced structurally
 * rather than by convention: these objects are `.strict()`, so a field named
 * `value`, `preview`, `length`, or `hash` fails to parse instead of quietly
 * riding along to a JSON sink.
 *
 * The guard is not merely stylistic. Value length and value hash are the two
 * fields most often added "for debugging"; both narrow an offline search space
 * considerably, so both are treated as disclosure.
 */

/** Field names that must never appear on a metadata or audit object. */
export const FORBIDDEN_METADATA_FIELDS = [
  'value',
  'secret',
  'secretValue',
  'plaintext',
  'preview',
  'prefix',
  'suffix',
  'length',
  'size',
  'hash',
  'digest',
  'checksum',
  'entropy',
  'fingerprint',
] as const;

/**
 * The comparison set. Lowercased once here because the published list above is
 * written in the camelCase a contributor would actually type (`secretValue`),
 * while the walk below lowercases each key it inspects: comparing the two
 * directly let `secretValue` — the single most obvious name for a leak — slip
 * through the guard entirely.
 */
const FORBIDDEN_METADATA_FIELDS_LOWERCASE: ReadonlySet<string> = new Set(
  FORBIDDEN_METADATA_FIELDS.map((field) => field.toLowerCase()),
);

export const tagSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/, 'invalid tag');

export const providerSchema = z.string().regex(/^[a-z0-9][a-z0-9.-]{0,63}$/, 'invalid provider');

/** Free-text description. Escaped at every render site; length-capped here. */
export const descriptionSchema = z.string().max(512);

export const inputMetadataSchema = z
  .object({
    description: descriptionSchema.optional(),
    provider: providerSchema.optional(),
    tags: z.array(tagSchema).max(16).optional(),
  })
  .strict();

export type InputMetadata = z.infer<typeof inputMetadataSchema>;

export const secretMetadataSchema = z
  .object({
    backend: backendIdSchema,
    project: projectSlugSchema,
    environment: environmentSchema,
    name: secretNameSchema,
    /** Canonical `backend/project/environment/name`. */
    reference: z.string(),
    /** Backend record identifier. Safe: it addresses a record, not a value. */
    backendId: z.string().optional(),
    /** Backend revision marker when available. Never derived from the value. */
    version: z.string().optional(),
    description: descriptionSchema.optional(),
    provider: providerSchema.optional(),
    tags: z.array(tagSchema).optional(),
    createdAt: z.iso.datetime().optional(),
    updatedAt: z.iso.datetime().optional(),
  })
  .strict();

export type SecretMetadata = z.infer<typeof secretMetadataSchema>;

/** Schema version for every agent-facing JSON payload. FR-LIST-003. */
export const JSON_SCHEMA_VERSION = 1 as const;

export const jsonEnvelopeSchema = <T extends z.ZodType>(data: T) =>
  z
    .object({
      schemaVersion: z.literal(JSON_SCHEMA_VERSION),
      status: z.enum(['ok', 'error']),
      data,
    })
    .strict();

/**
 * Runtime assertion that a payload about to be serialized carries no
 * value-bearing field, at any depth.
 *
 * This is defence in depth behind `.strict()` schemas: it also catches objects
 * assembled by hand on their way to `console.log` or an MCP tool result.
 * Throws rather than stripping — a payload that reached here with a forbidden
 * field is a defect that must be fixed at the source.
 */
export function assertNoValueFields(payload: unknown, path = '$'): void {
  // A visited set and a depth cap, because this walker runs on structures
  // parsed from `bws` output and from MCP tool arguments. Without them,
  // `obj.self = obj` — or a deeply nested payload — turns a defensive check
  // into a remotely triggerable RangeError, which is a worse outcome than the
  // thing it was guarding against.
  walk(payload, path, new WeakSet<object>(), 0);
}

/**
 * Depth cap for the walk.
 *
 * Real metadata is five or six levels deep at most; 512 is far beyond anything
 * legitimate while staying well under the engine's own stack limit, so a
 * pathological payload produces a domain error rather than a RangeError.
 */
const MAX_WALK_DEPTH = 512;

function walk(payload: unknown, path: string, seen: WeakSet<object>, depth: number): void {
  if (payload === null || typeof payload !== 'object') {
    return;
  }
  if (depth > MAX_WALK_DEPTH) {
    throw new Error(
      `Refusing to serialize: payload nests deeper than ${MAX_WALK_DEPTH} levels at ${path}.`,
    );
  }
  if (seen.has(payload)) {
    // Already inspected on this walk. A cycle proves nothing new about which
    // fields are present.
    return;
  }
  seen.add(payload);

  if (Array.isArray(payload)) {
    for (const [index, item] of payload.entries()) {
      walk(item, `${path}[${index}]`, seen, depth + 1);
    }
    return;
  }

  // `Reflect.ownKeys` rather than `Object.entries`: a non-enumerable `value`
  // property, or one defined with a getter, is invisible to `Object.entries`
  // but visible to `util.inspect({ showHidden })` and to most serializers that
  // are not `JSON.stringify`. The guard should not depend on which serializer
  // happens to be downstream.
  for (const key of Reflect.ownKeys(payload)) {
    if (typeof key !== 'string') {
      continue;
    }
    if (FORBIDDEN_METADATA_FIELDS_LOWERCASE.has(key.toLowerCase())) {
      throw new Error(
        `Refusing to serialize: forbidden field "${key}" at ${path}. ` +
          'Value-derived data must not cross a public result schema.',
      );
    }

    // Read through the descriptor so a getter is never invoked: calling an
    // unknown getter while validating untrusted data is its own hazard.
    const descriptor = Object.getOwnPropertyDescriptor(payload, key);
    if (descriptor && 'value' in descriptor) {
      walk(descriptor.value, `${path}.${key}`, seen, depth + 1);
    }
  }
}
