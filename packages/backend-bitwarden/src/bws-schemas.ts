import { z } from 'zod';

/**
 * Schemas for everything `bws` prints.
 *
 * Parsing backend output with a strict schema is a security control, not
 * ergonomics. Three things go wrong without it:
 *
 *  1. a `bws` upgrade changes a field name and the adapter silently starts
 *     reading `undefined` where a record identifier should be, deleting or
 *     overwriting the wrong secret;
 *  2. an error path prints a human sentence where JSON was expected, and a
 *     permissive parser turns it into a half-populated object;
 *  3. output we did not expect flows onward into a log or a tool result.
 *     Everything not described here is dropped at the boundary.
 *
 * `bwsSecretSchema` is the one shape that carries a value. It is deliberately
 * kept out of every other module's reach: `parseSecretWithValue` is the only
 * exported way to touch it, and it hands back a `SecretValue`.
 */

const isoish = z.string().min(1);

export const bwsProjectSchema = z
  .object({
    id: z.uuid(),
    organizationId: z.uuid(),
    name: z.string(),
    creationDate: isoish.optional(),
    revisionDate: isoish.optional(),
  })
  .loose();

export type BwsProject = z.infer<typeof bwsProjectSchema>;

/**
 * A secret as listed.
 *
 * `bws secret list` **includes the value** — that is what its `-o env` output
 * format is built on, and it is true of every version we have tested, 2.1.0
 * included. Not declaring `value` here is therefore only half of the guarantee:
 * this schema is in Zod's default *strip* mode rather than `.loose()`, so an
 * undeclared key is dropped at the parse boundary instead of riding along on
 * the objects the adapter caches in its lookup index.
 *
 * Strip also keeps the forward compatibility `.loose()` was chosen for: a field
 * a future `bws` adds is ignored, not rejected. The difference is only whether
 * we keep a copy of it, and for a field that may be a credential the answer is
 * no. `bws secret get` is the one path allowed to receive a value, and it wraps
 * it in a `SecretValue` in the same expression that parses it.
 */
export const bwsSecretListItemSchema = z.object({
  id: z.uuid(),
  organizationId: z.uuid(),
  projectId: z.uuid().nullable().optional(),
  key: z.string(),
  note: z.string().nullable().optional(),
  creationDate: isoish.optional(),
  revisionDate: isoish.optional(),
});

export type BwsSecretListItem = z.infer<typeof bwsSecretListItemSchema>;

/**
 * A secret as returned by `secret get`, `secret create`, `secret edit`.
 *
 * The only shape that declares a value, and the only one entitled to. It
 * inherits strip mode from the schema above, so an unknown field is tolerated
 * without being retained: a `bws` release that adds a field must not break the
 * adapter, and must not smuggle anything into it either.
 */
export const bwsSecretSchema = bwsSecretListItemSchema.extend({
  value: z.string(),
});

export type BwsSecret = z.infer<typeof bwsSecretSchema>;

export const bwsSecretListSchema = z.array(bwsSecretListItemSchema);
export const bwsProjectListSchema = z.array(bwsProjectSchema);

/**
 * Metadata we store in the Bitwarden `note` field.
 *
 * The note is not a secret field in Bitwarden's model, so only non-secret
 * metadata goes here — enforced by `.strict()`, which rejects a `value` key
 * that some future code path might try to stash alongside.
 */
export const noteMetadataSchema = z
  .object({
    v: z.literal(1),
    description: z.string().max(512).optional(),
    provider: z.string().max(64).optional(),
    tags: z.array(z.string().max(32)).max(16).optional(),
  })
  .strict();

export type NoteMetadata = z.infer<typeof noteMetadataSchema>;

export function parseNote(note: string | null | undefined): NoteMetadata | null {
  if (!note) {
    return null;
  }
  try {
    const parsed = noteMetadataSchema.safeParse(JSON.parse(note));
    return parsed.success ? parsed.data : null;
  } catch {
    // A note written by hand in the Bitwarden web UI is not JSON. That is a
    // legitimate state, not an error: we simply have no structured metadata.
    return null;
  }
}

export function serializeNote(metadata: NoteMetadata): string {
  return JSON.stringify(noteMetadataSchema.parse(metadata));
}
