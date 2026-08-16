import { z } from 'zod';
import { assertNoValueFields } from './metadata.js';
import { secretNameSchema } from './scope.js';

/**
 * Audit events. Metadata only, by construction: the schema is `.strict()`, so
 * an added `value` / `hash` / `preview` field fails to parse, and
 * `assertNoValueFields` runs before any sink writes.
 *
 * `commandExecutable` holds the executable name alone — never the full argument
 * vector, which routinely carries tokens (FR-RUN-010).
 */

export const auditOperations = [
  'init',
  'logout',
  'doctor',
  'create',
  'rotate',
  'delete',
  'list',
  'describe',
  'run',
  'request-create',
  'request-rotate',
  'request-consume',
] as const;

export type AuditOperation = (typeof auditOperations)[number];

export const auditEventSchema = z
  .object({
    id: z.string().min(1),
    timestamp: z.iso.datetime(),
    actorType: z.enum(['human', 'agent', 'device', 'telegram']),
    /** Opaque actor identifier: device id, Telegram user id, MCP client name. */
    actorId: z.string().max(128),
    deviceId: z.string().max(128).optional(),
    operation: z.enum(auditOperations),
    /** Canonical reference or scope. Empty string for device-level operations. */
    reference: z.string().max(512),
    secretNames: z.array(secretNameSchema).max(128).optional(),
    commandExecutable: z.string().max(256).optional(),
    outcome: z.enum(['success', 'denied', 'failure']),
    errorCode: z.string().max(64).optional(),
    /** Duration of the operation in milliseconds. Not value-derived. */
    durationMs: z.number().int().nonnegative().optional(),
  })
  .strict();

export type AuditEvent = z.infer<typeof auditEventSchema>;

export type AuditEventInput = Omit<AuditEvent, 'id' | 'timestamp'> & {
  id?: string;
  timestamp?: string;
};

/**
 * Where audit events go. The CLI writes JSONL to a 0600 file under the user's
 * config directory; the API writes rows to SQLite. Both go through this
 * interface so the no-value assertion happens exactly once.
 */
export interface AuditSink {
  record(event: AuditEvent): Promise<void>;
}

export function buildAuditEvent(input: AuditEventInput, now: Date = new Date()): AuditEvent {
  const candidate = {
    ...input,
    id: input.id ?? randomAuditId(),
    timestamp: input.timestamp ?? now.toISOString(),
  };
  // Belt and braces: `.strict()` rejects unknown keys, and this rejects a
  // forbidden key that someone legitimised by adding it to the schema.
  assertNoValueFields(candidate);
  return auditEventSchema.parse(candidate);
}

function randomAuditId(): string {
  return `evt_${crypto.randomUUID().replaceAll('-', '')}`;
}

/** Discards every event. Used by tests and by `--no-audit`. */
export const nullAuditSink: AuditSink = {
  async record(): Promise<void> {
    /* intentionally empty */
  },
};
