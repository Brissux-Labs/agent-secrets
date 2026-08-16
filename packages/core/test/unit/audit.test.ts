import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  type AuditEvent,
  type AuditEventInput,
  auditEventSchema,
  auditOperations,
  buildAuditEvent,
  nullAuditSink,
} from '../../src/audit.js';

/**
 * The audit trail is the one artefact that is written to disk on every run, so
 * it is the highest-value place for a value to end up by accident. These tests
 * assert the two structural guarantees: the schema is closed, and no field on
 * it is shaped to hold an argument vector (FR-RUN-010).
 */

const BASE_INPUT: AuditEventInput = {
  actorType: 'agent',
  actorId: 'mcp-client-01',
  operation: 'list',
  reference: 'bitwarden/ezjob/development',
  outcome: 'success',
};

function canary(): string {
  return `ASECRET_CANARY_${randomBytes(12).toString('hex').toUpperCase()}`;
}

describe('buildAuditEvent', () => {
  it('produces a valid event with a generated id and ISO timestamp', () => {
    const event = buildAuditEvent(BASE_INPUT);

    expect(auditEventSchema.safeParse(event).success).toBe(true);
    expect(event.id).toMatch(/^evt_[0-9a-f]{32}$/);
    expect(event.timestamp).toBe(new Date(event.timestamp).toISOString());
    expect(Number.isNaN(Date.parse(event.timestamp))).toBe(false);
  });

  it('generates a distinct id per event', () => {
    const ids = new Set(Array.from({ length: 200 }, () => buildAuditEvent(BASE_INPUT).id));
    expect(ids.size).toBe(200);
  });

  it('uses the injected clock and honours a caller-supplied id and timestamp', () => {
    const now = new Date('2026-08-16T12:34:56.000Z');
    expect(buildAuditEvent(BASE_INPUT, now).timestamp).toBe('2026-08-16T12:34:56.000Z');

    const explicit = buildAuditEvent(
      { ...BASE_INPUT, id: 'evt_fixed', timestamp: '2026-01-02T03:04:05.000Z' },
      now,
    );
    expect(explicit.id).toBe('evt_fixed');
    expect(explicit.timestamp).toBe('2026-01-02T03:04:05.000Z');
  });

  it('carries the optional non-secret fields through', () => {
    const event = buildAuditEvent({
      ...BASE_INPUT,
      operation: 'run',
      deviceId: 'device-7',
      secretNames: ['OPENAI_API_KEY', 'STRIPE_SECRET_KEY'],
      commandExecutable: 'node',
      durationMs: 120,
      errorCode: 'BACKEND_UNAVAILABLE',
      outcome: 'failure',
    });
    expect(event.commandExecutable).toBe('node');
    expect(event.secretNames).toEqual(['OPENAI_API_KEY', 'STRIPE_SECRET_KEY']);
    expect(event.durationMs).toBe(120);
  });

  it('rejects an event carrying a forbidden field before it can reach a sink', () => {
    const smuggled = { ...BASE_INPUT, value: canary() } as unknown as AuditEventInput;
    expect(() => buildAuditEvent(smuggled)).toThrow(/forbidden field/);

    const hashed = { ...BASE_INPUT, hash: 'deadbeef' } as unknown as AuditEventInput;
    expect(() => buildAuditEvent(hashed)).toThrow(/forbidden field/);

    const nested = {
      ...BASE_INPUT,
      errorCode: 'X',
      // A nested object is the realistic accident: someone attaches "context".
      context: { preview: canary() },
    } as unknown as AuditEventInput;
    expect(() => buildAuditEvent(nested)).toThrow(/forbidden field/);
  });

  it('does not leak the smuggled value through the rejection message', () => {
    const leak = canary();
    const smuggled = { ...BASE_INPUT, value: leak } as unknown as AuditEventInput;
    try {
      buildAuditEvent(smuggled);
      expect.unreachable('buildAuditEvent must reject a forbidden field');
    } catch (error) {
      expect((error as Error).message).not.toContain(leak);
    }
  });

  it('rejects an unknown key that is merely unexpected', () => {
    const extra = { ...BASE_INPUT, note: 'harmless' } as unknown as AuditEventInput;
    expect(() => buildAuditEvent(extra)).toThrow();
  });
});

describe('auditEventSchema', () => {
  const VALID_EVENT: AuditEvent = {
    id: 'evt_0123456789abcdef0123456789abcdef',
    timestamp: '2026-08-16T00:00:00.000Z',
    actorType: 'human',
    actorId: 'device-1',
    operation: 'create',
    reference: 'bitwarden/ezjob/development/OPENAI_API_KEY',
    outcome: 'success',
  };

  it('accepts a minimal valid event', () => {
    expect(auditEventSchema.parse(VALID_EVENT)).toEqual(VALID_EVENT);
  });

  it('accepts every declared operation', () => {
    for (const operation of auditOperations) {
      expect(auditEventSchema.safeParse({ ...VALID_EVENT, operation }).success, operation).toBe(
        true,
      );
    }
  });

  it('rejects unknown keys', () => {
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, extra: 1 }).success).toBe(false);
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, args: ['--token', 'x'] }).success).toBe(
      false,
    );
  });

  it('rejects an invalid operation', () => {
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, operation: 'exfiltrate' }).success).toBe(
      false,
    );
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, operation: '' }).success).toBe(false);
  });

  it('rejects an invalid secret name, including a newline-injected one', () => {
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, secretNames: ['lowercase'] }).success).toBe(
      false,
    );
    // A name carrying a newline would forge an extra record in the JSONL file.
    expect(
      auditEventSchema.safeParse({ ...VALID_EVENT, secretNames: ['OK\n{"forged":true}'] }).success,
    ).toBe(false);
    expect(
      auditEventSchema.safeParse({
        ...VALID_EVENT,
        secretNames: Array.from({ length: 129 }, () => 'A'),
      }).success,
    ).toBe(false);
  });

  it('rejects malformed actor, outcome and duration fields', () => {
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, id: '' }).success).toBe(false);
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, timestamp: 'now' }).success).toBe(false);
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, actorType: 'robot' }).success).toBe(false);
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, outcome: 'partial' }).success).toBe(false);
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, durationMs: -1 }).success).toBe(false);
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, durationMs: 1.5 }).success).toBe(false);
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, actorId: 'a'.repeat(129) }).success).toBe(
      false,
    );
    expect(auditEventSchema.safeParse({ ...VALID_EVENT, reference: 'r'.repeat(513) }).success).toBe(
      false,
    );
  });

  it('accepts commandExecutable but offers no field able to carry a full argv', () => {
    expect(
      auditEventSchema.safeParse({ ...VALID_EVENT, operation: 'run', commandExecutable: 'node' })
        .success,
    ).toBe(true);

    const fields = Object.keys(auditEventSchema.shape);
    expect(fields).toContain('commandExecutable');

    // An argument vector routinely carries `--token <value>`; there must be no
    // home for it on the event, and no array-of-strings field other than the
    // validated secret-name list.
    for (const forbidden of [
      'args',
      'argv',
      'command',
      'commandArgs',
      'commandLine',
      'cmd',
      'env',
      'environmentBlock',
      'stdout',
      'stderr',
    ]) {
      expect(fields, forbidden).not.toContain(forbidden);
    }

    // `commandExecutable` is a single capped string, not a list.
    expect(
      auditEventSchema.safeParse({ ...VALID_EVENT, commandExecutable: ['node', '--token', 'x'] })
        .success,
    ).toBe(false);
    expect(
      auditEventSchema.safeParse({ ...VALID_EVENT, commandExecutable: 'x'.repeat(257) }).success,
    ).toBe(false);
  });
});

describe('nullAuditSink', () => {
  it('resolves and discards the event', async () => {
    const event = buildAuditEvent(BASE_INPUT);
    await expect(nullAuditSink.record(event)).resolves.toBeUndefined();
    await expect(
      Promise.all([nullAuditSink.record(event), nullAuditSink.record(event)]),
    ).resolves.toEqual([undefined, undefined]);
  });
});
