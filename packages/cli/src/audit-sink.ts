import { appendFile, chmod, mkdir, rename, stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { type AuditEvent, type AuditSink, assertNoValueFields } from '@bx-labs/agent-secrets-core';

/**
 * Append-only JSONL audit log for the CLI.
 *
 * JSONL rather than SQLite on purpose: the CLI is installed globally with
 * `npm i -g`, and a native database dependency would mean a compiler toolchain
 * on every machine that wants to manage secrets. A line-oriented file is also
 * trivially greppable by the canary scanner, which matters more here than query
 * power — this log exists to answer "what happened", not "how often".
 *
 * Writes are `appendFile` with O_APPEND, which is atomic for writes below
 * PIPE_BUF on POSIX. Audit lines are far below it, so two concurrent
 * `agent-secrets` processes cannot interleave a partial record.
 */
export class JsonlAuditSink implements AuditSink {
  readonly #path: string;
  readonly #maxBytes: number;

  constructor(path: string, maxBytes = 5 * 1024 * 1024) {
    this.#path = path;
    this.#maxBytes = maxBytes;
  }

  async record(event: AuditEvent): Promise<void> {
    // The event was built by `buildAuditEvent`, which already validates. This
    // second check guards the path where someone constructs an event literal
    // and calls the sink directly.
    assertNoValueFields(event);

    await mkdir(dirname(this.#path), { recursive: true, mode: 0o700 });
    await this.#rotateIfNeeded();
    await appendFile(this.#path, `${JSON.stringify(event)}\n`, { mode: 0o600, encoding: 'utf8' });
    await chmod(this.#path, 0o600).catch(() => {
      // The file exists and was appended to; a failed chmod is worth neither
      // failing the operation nor a message the user cannot act on. `doctor`
      // reports permissions properly.
    });
  }

  async #rotateIfNeeded(): Promise<void> {
    try {
      const stats = await stat(this.#path);
      if (stats.size < this.#maxBytes) {
        return;
      }
      // One generation only. This is a local operational record, not a
      // compliance archive; unbounded history would quietly grow forever.
      await rename(this.#path, `${this.#path}.1`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw error;
      }
    }
  }
}

/**
 * Records nothing but never fails.
 *
 * Used when audit is disabled in config. The distinction from `nullAuditSink`
 * in core is intent: this one exists because a user turned auditing off, and
 * `doctor` reports that state so it is never a silent surprise.
 */
export const disabledAuditSink: AuditSink = {
  async record(): Promise<void> {
    /* audit disabled in configuration */
  },
};
