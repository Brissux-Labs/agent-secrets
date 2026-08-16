import { type AuditEvent, type AuditSink, assertNoValueFields } from '@bx-labs/agent-secrets-core';
import type { Database } from 'better-sqlite3';

/**
 * Audit sink backed by the same SQLite file as the request store.
 *
 * The columns are enumerated explicitly rather than derived from the event
 * object. That is the point: if someone adds a field to `AuditEvent`, it does
 * not silently start being persisted here — a reviewer has to add a column and
 * think about whether it belongs in durable storage.
 *
 * `secretNames` and `commandExecutable` are deliberately absent from this
 * table. The API only ever handles one reference per request, which the
 * `reference` column already carries, and the API never runs commands.
 */
export class SqliteAuditSink implements AuditSink {
  readonly #db: Database;

  constructor(db: Database) {
    this.#db = db;
  }

  async record(event: AuditEvent): Promise<void> {
    assertNoValueFields(event);
    this.#db
      .prepare(
        `INSERT INTO audit_events
           (id, timestamp, actor_type, actor_id, device_id, operation, reference, outcome, error_code, duration_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        event.id,
        event.timestamp,
        event.actorType,
        event.actorId,
        event.deviceId ?? null,
        event.operation,
        event.reference,
        event.outcome,
        event.errorCode ?? null,
        event.durationMs ?? null,
      );
  }
}
