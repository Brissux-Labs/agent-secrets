import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { type Environment, ExpiredOrConsumedError } from '@bx-labs/agent-secrets-core';
import type { Database } from 'better-sqlite3';
import DatabaseConstructor from 'better-sqlite3';

/**
 * One-time secure input requests.
 *
 * The whole Telegram flow reduces to this table being correct. Its properties,
 * and why each one is not optional:
 *
 *  - **256 bits of CSPRNG randomness.** The token is the only thing standing
 *    between a URL and a write to the vault, so it must be unguessable even
 *    against an attacker who has seen many previous tokens.
 *  - **Only a hash is stored.** A dump of this database — a backup, a stolen
 *    disk, a `SELECT *` in a support session — must not yield usable links.
 *    SHA-256 without a salt is right here rather than a password hash: the
 *    input is already 256 bits of uniform randomness, so there is no dictionary
 *    to defend against, and a slow KDF would only slow the legitimate request.
 *  - **Bound to its purpose.** A token carries the user, project, environment,
 *    name and action it was issued for. A link for
 *    `ezjob/development/OPENAI_API_KEY` cannot be turned into a write to
 *    `payments/production/STRIPE_SECRET_KEY`.
 *  - **Consumed atomically.** Claiming is a conditional UPDATE, so two
 *    simultaneous submissions cannot both win. This is the concurrency test the
 *    milestone acceptance criteria call for.
 *  - **No value column exists.** Not "is never written to" — does not exist. A
 *    future contributor cannot store a value here without a schema migration
 *    that a reviewer will see.
 */

export type RequestAction = 'create' | 'rotate';
export type RequestStatus = 'pending' | 'processing' | 'succeeded' | 'failed' | 'expired';

export interface OneTimeRequest {
  readonly id: string;
  readonly action: RequestAction;
  readonly telegramUserId: string | null;
  readonly project: string;
  readonly environment: Environment;
  readonly secretName: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly consumedAt: string | null;
  readonly status: RequestStatus;
  readonly attempts: number;
}

export interface CreateRequestInput {
  readonly action: RequestAction;
  readonly telegramUserId?: string | undefined;
  readonly project: string;
  readonly environment: Environment;
  readonly secretName: string;
  readonly ttlMs?: number;
}

export interface IssuedRequest {
  readonly request: OneTimeRequest;
  /**
   * The raw token. Returned exactly once, held only long enough to build the
   * URL, and never persisted — that is the point of storing the hash.
   */
  readonly token: string;
}

/** FR-TG-005: two minutes, short enough that a leaked link is usually already dead. */
export const DEFAULT_TTL_MS = 2 * 60 * 1000;

/**
 * Clock skew tolerance when validating expiry.
 *
 * The API and the browser can disagree by a few seconds. Being strict would
 * reject legitimate submissions made at second 119; being generous would extend
 * an attacker's window. Five seconds is the smallest value that removes the
 * false rejections we can actually observe.
 */
export const CLOCK_SKEW_MS = 5_000;

export class RequestStore {
  readonly #db: Database;

  constructor(databasePath: string) {
    if (databasePath !== ':memory:') {
      mkdirSync(dirname(databasePath), { recursive: true, mode: 0o700 });
    }
    this.#db = new DatabaseConstructor(databasePath);
    // SQLite creates its file — and its WAL/SHM sidecars — with the process
    // umask, which is 0644 by default. These rows record which credentials were
    // requested for which project and environment, which is architectural
    // information about the deployment, so they are not readable by other
    // accounts on the host.
    this.#restrictPermissions(databasePath);
    // WAL keeps a reader from blocking the writer that claims a token, which is
    // the operation that must never be delayed.
    this.#db.pragma('journal_mode = WAL');
    this.#db.pragma('foreign_keys = ON');
    // Durability matters more than throughput: a request marked consumed must
    // stay consumed across a crash, or a replay becomes possible.
    this.#db.pragma('synchronous = FULL');
    this.#migrate();
    // WAL and SHM only come into existence once journal mode is set and the
    // first write lands, so the tightening runs a second time here.
    this.#restrictPermissions(databasePath);
  }

  /**
   * Tighten permissions on the database and its sidecars.
   *
   * Called after opening and again after the first write, because WAL and SHM
   * appear when journal mode is set rather than at open time.
   */
  #restrictPermissions(databasePath: string): void {
    if (databasePath === ':memory:') {
      return;
    }
    for (const suffix of ['', '-wal', '-shm', '-journal']) {
      const path = `${databasePath}${suffix}`;
      try {
        if (existsSync(path)) {
          chmodSync(path, 0o600);
        }
      } catch {
        // A chmod failure on a volume that does not support it is not a reason
        // to refuse to start; `doctor` and the deployment docs cover the rest.
      }
    }
  }

  #migrate(): void {
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS one_time_requests (
        id            TEXT PRIMARY KEY,
        token_hash    TEXT NOT NULL UNIQUE,
        action        TEXT NOT NULL CHECK (action IN ('create','rotate')),
        telegram_user_id TEXT,
        project       TEXT NOT NULL,
        environment   TEXT NOT NULL CHECK (environment IN ('development','preview','production')),
        secret_name   TEXT NOT NULL,
        created_at    TEXT NOT NULL,
        expires_at    TEXT NOT NULL,
        consumed_at   TEXT,
        status        TEXT NOT NULL CHECK (status IN ('pending','processing','succeeded','failed','expired')),
        attempts      INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_requests_expires ON one_time_requests(expires_at);
      CREATE INDEX IF NOT EXISTS idx_requests_status ON one_time_requests(status);

      CREATE TABLE IF NOT EXISTS audit_events (
        id          TEXT PRIMARY KEY,
        timestamp   TEXT NOT NULL,
        actor_type  TEXT NOT NULL,
        actor_id    TEXT NOT NULL,
        device_id   TEXT,
        operation   TEXT NOT NULL,
        reference   TEXT NOT NULL,
        outcome     TEXT NOT NULL,
        error_code  TEXT,
        duration_ms INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
    `);
  }

  /** Issue a request and return the raw token exactly once. */
  create(input: CreateRequestInput, now: Date = new Date()): IssuedRequest {
    const token = randomBytes(32).toString('base64url');
    const tokenHash = hashToken(token);
    const id = `req_${randomBytes(12).toString('hex')}`;
    const expiresAt = new Date(now.getTime() + (input.ttlMs ?? DEFAULT_TTL_MS)).toISOString();

    const request: OneTimeRequest = {
      id,
      action: input.action,
      telegramUserId: input.telegramUserId ?? null,
      project: input.project,
      environment: input.environment,
      secretName: input.secretName,
      createdAt: now.toISOString(),
      expiresAt,
      consumedAt: null,
      status: 'pending',
      attempts: 0,
    };

    this.#db
      .prepare(
        `INSERT INTO one_time_requests
           (id, token_hash, action, telegram_user_id, project, environment, secret_name,
            created_at, expires_at, consumed_at, status, attempts)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'pending', 0)`,
      )
      .run(
        id,
        tokenHash,
        request.action,
        request.telegramUserId,
        request.project,
        request.environment,
        request.secretName,
        request.createdAt,
        request.expiresAt,
      );

    return { request, token };
  }

  /**
   * Look a request up without consuming it — used to render the form.
   *
   * Rendering must not consume, or a user who opens the link and then reloads
   * the page would be locked out of their own request.
   */
  peek(token: string, now: Date = new Date()): OneTimeRequest | null {
    const row = this.#findByHash(hashToken(token));
    if (!row) {
      return null;
    }
    if (row.status !== 'pending' || isExpired(row, now)) {
      return null;
    }
    return row;
  }

  /**
   * Atomically claim a request for processing.
   *
   * The conditional UPDATE is the concurrency control: SQLite serialises
   * writers, so of two simultaneous submissions exactly one sees
   * `changes === 1`. The loser gets `ExpiredOrConsumedError`, identical to what
   * a replay attacker gets — the two cases are indistinguishable from outside,
   * which is deliberate.
   */
  claim(token: string, now: Date = new Date()): OneTimeRequest {
    const tokenHash = hashToken(token);
    const nowIso = now.toISOString();
    const cutoff = new Date(now.getTime() - CLOCK_SKEW_MS).toISOString();

    const result = this.#db
      .prepare(
        `UPDATE one_time_requests
            SET status = 'processing', consumed_at = ?, attempts = attempts + 1
          WHERE token_hash = ?
            AND status = 'pending'
            AND expires_at > ?`,
      )
      .run(nowIso, tokenHash, cutoff);

    if (result.changes !== 1) {
      // One message for "never existed", "already used", and "expired". Telling
      // them apart would let an attacker probe which tokens were ever valid.
      throw new ExpiredOrConsumedError('This link is no longer valid.', {
        hint: 'Request a new link. Links work once and expire after two minutes.',
      });
    }

    const row = this.#findByHash(tokenHash);
    if (!row) {
      throw new ExpiredOrConsumedError('This link is no longer valid.', {});
    }
    return row;
  }

  /** Record the outcome of a claimed request. */
  settle(id: string, status: 'succeeded' | 'failed'): void {
    this.#db.prepare(`UPDATE one_time_requests SET status = ? WHERE id = ?`).run(status, id);
  }

  status(id: string): OneTimeRequest | null {
    const row = this.#db.prepare(`SELECT * FROM one_time_requests WHERE id = ?`).get(id) as
      | RawRow
      | undefined;
    return row ? toRequest(row) : null;
  }

  /**
   * Mark timed-out requests as expired and delete old ones.
   *
   * Retention is short on purpose. These rows record that someone was asked for
   * a credential named `STRIPE_SECRET_KEY` in `payments/production`, which is
   * architectural information worth keeping only as long as it is operationally
   * useful.
   */
  sweep(
    now: Date = new Date(),
    retentionMs = 7 * 24 * 60 * 60 * 1000,
  ): { expired: number; deleted: number } {
    const nowIso = now.toISOString();
    const expired = this.#db
      .prepare(
        `UPDATE one_time_requests SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?`,
      )
      .run(nowIso).changes;

    const cutoff = new Date(now.getTime() - retentionMs).toISOString();
    const deleted = this.#db
      .prepare(`DELETE FROM one_time_requests WHERE created_at < ?`)
      .run(cutoff).changes;

    return { expired, deleted };
  }

  close(): void {
    this.#db.close();
  }

  /** Exposed for the audit sink; the API writes metadata-only rows here. */
  get database(): Database {
    return this.#db;
  }

  #findByHash(tokenHash: string): OneTimeRequest | null {
    const row = this.#db
      .prepare(`SELECT * FROM one_time_requests WHERE token_hash = ?`)
      .get(tokenHash) as RawRow | undefined;
    return row ? toRequest(row) : null;
  }
}

interface RawRow {
  id: string;
  token_hash: string;
  action: RequestAction;
  telegram_user_id: string | null;
  project: string;
  environment: Environment;
  secret_name: string;
  created_at: string;
  expires_at: string;
  consumed_at: string | null;
  status: RequestStatus;
  attempts: number;
}

function toRequest(row: RawRow): OneTimeRequest {
  return {
    id: row.id,
    action: row.action,
    telegramUserId: row.telegram_user_id,
    project: row.project,
    environment: row.environment,
    secretName: row.secret_name,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    consumedAt: row.consumed_at,
    status: row.status,
    attempts: row.attempts,
  };
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Constant-time hash comparison.
 *
 * The claim path compares in SQL, where a timing side channel is not
 * meaningfully exploitable, but any code that compares hashes in JavaScript
 * should use this rather than `===`.
 */
export function hashesEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  return left.length === right.length && timingSafeEqual(left, right);
}

function isExpired(request: OneTimeRequest, now: Date): boolean {
  return new Date(request.expiresAt).getTime() + CLOCK_SKEW_MS <= now.getTime();
}
