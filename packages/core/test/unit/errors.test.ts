import { randomBytes } from 'node:crypto';
import { format, inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import type { ErrorCode, ErrorDetails } from '../../src/errors.js';
import {
  AgentSecretsError,
  AuthRequiredError,
  BackendUnavailableError,
  ChildFailedError,
  ConflictError,
  ERROR_CODES,
  EXIT_CODES,
  ExpiredOrConsumedError,
  InternalError,
  InvalidInputError,
  isAgentSecretsError,
  NotFoundError,
  PolicyDeniedError,
  toSafeError,
} from '../../src/errors.js';

/**
 * Exit codes are a published contract (docs/exit-codes.md): scripts and agents
 * branch on them, so a renumbering is a breaking change. This table is written
 * out longhand on purpose — deriving it from EXIT_CODES would make the test
 * agree with any future typo.
 */
interface ErrorTableEntry {
  readonly Ctor: new (message: string, details?: ErrorDetails) => AgentSecretsError;
  readonly name: string;
  readonly code: ErrorCode;
  readonly exitCode: number;
}

const ERROR_TABLE: readonly ErrorTableEntry[] = [
  { Ctor: InvalidInputError, name: 'InvalidInputError', code: 'INVALID_INPUT', exitCode: 2 },
  { Ctor: AuthRequiredError, name: 'AuthRequiredError', code: 'AUTH_REQUIRED', exitCode: 3 },
  { Ctor: PolicyDeniedError, name: 'PolicyDeniedError', code: 'POLICY_DENIED', exitCode: 4 },
  { Ctor: NotFoundError, name: 'NotFoundError', code: 'NOT_FOUND', exitCode: 5 },
  { Ctor: ConflictError, name: 'ConflictError', code: 'CONFLICT', exitCode: 6 },
  {
    Ctor: BackendUnavailableError,
    name: 'BackendUnavailableError',
    code: 'BACKEND_UNAVAILABLE',
    exitCode: 7,
  },
  {
    Ctor: ExpiredOrConsumedError,
    name: 'ExpiredOrConsumedError',
    code: 'EXPIRED_OR_CONSUMED',
    exitCode: 8,
  },
  { Ctor: ChildFailedError, name: 'ChildFailedError', code: 'CHILD_FAILED', exitCode: 9 },
  { Ctor: InternalError, name: 'InternalError', code: 'INTERNAL', exitCode: 10 },
];

function canary(): string {
  return `ASECRET_CANARY_${randomBytes(12).toString('hex').toUpperCase()}`;
}

describe('the error taxonomy', () => {
  it('covers every declared error code exactly once', () => {
    expect(ERROR_TABLE.map((entry) => entry.code).sort()).toEqual([...ERROR_CODES].sort());
  });

  it('agrees with the EXIT_CODES table', () => {
    expect(EXIT_CODES).toEqual({
      success: 0,
      invalidInput: 2,
      authRequired: 3,
      policyDenied: 4,
      notFound: 5,
      conflict: 6,
      backendUnavailable: 7,
      expiredOrConsumed: 8,
      childFailed: 9,
      internal: 10,
    });
  });

  it('assigns a distinct non-zero exit code to every error', () => {
    const codes = ERROR_TABLE.map((entry) => entry.exitCode);
    expect(new Set(codes).size).toBe(codes.length);
    for (const code of codes) {
      expect(code).not.toBe(EXIT_CODES.success);
    }
  });

  for (const { Ctor, name, code, exitCode } of ERROR_TABLE) {
    describe(name, () => {
      it('carries the contracted code, exit code and name', () => {
        const error = new Ctor('something went wrong');
        expect(error).toBeInstanceOf(AgentSecretsError);
        expect(error).toBeInstanceOf(Error);
        expect(error.name).toBe(name);
        expect(error.code).toBe(code);
        expect(error.exitCode).toBe(exitCode);
        expect(error.message).toBe('something went wrong');
      });

      it('exposes the optional details and defaults them to undefined', () => {
        const bare = new Ctor('bare');
        expect(bare.field).toBeUndefined();
        expect(bare.reference).toBeUndefined();
        expect(bare.hint).toBeUndefined();
        expect(bare.cause).toBeUndefined();

        const detailed = new Ctor('detailed', {
          field: 'name',
          reference: 'bitwarden/ezjob/development/API_KEY',
          hint: 'run `agent-secrets init`',
        });
        expect(detailed.field).toBe('name');
        expect(detailed.reference).toBe('bitwarden/ezjob/development/API_KEY');
        expect(detailed.hint).toBe('run `agent-secrets init`');
      });
    });
  }
});

describe('toSafeJSON', () => {
  it('emits only the contracted keys and never the cause', () => {
    const secretish = canary();
    const error = new NotFoundError('Secret not found.', {
      field: 'name',
      reference: 'bitwarden/ezjob/development/API_KEY',
      hint: 'run `agent-secrets list`',
      cause: new Error(`bws stderr: ${secretish}`),
    });

    const safe = error.toSafeJSON();
    expect(Object.keys(safe).sort()).toEqual(['code', 'field', 'hint', 'message', 'reference']);
    expect(safe).toEqual({
      code: 'NOT_FOUND',
      message: 'Secret not found.',
      field: 'name',
      reference: 'bitwarden/ezjob/development/API_KEY',
      hint: 'run `agent-secrets list`',
    });

    // The cause is attached for a local debugger, never for a sink.
    expect(Object.keys(safe)).not.toContain('cause');
    expect(Object.keys(safe)).not.toContain('stack');
    expect(JSON.stringify(safe)).not.toContain(secretish);
  });

  it('omits absent details rather than emitting explicit nulls', () => {
    const safe = new ConflictError('Already exists.').toSafeJSON();
    expect(Object.keys(safe)).toEqual(['code', 'message']);
    expect(JSON.stringify(safe)).toBe('{"code":"CONFLICT","message":"Already exists."}');
  });

  it('is serializable for every error in the table', () => {
    for (const { Ctor, code } of ERROR_TABLE) {
      const safe = new Ctor('message', { cause: new Error('raw cause') }).toSafeJSON();
      expect(safe.code).toBe(code);
      expect(JSON.stringify(safe)).not.toContain('raw cause');
    }
  });
});

describe('toSafeError', () => {
  it('wraps an unknown Error as InternalError without borrowing its message', () => {
    const leak = canary();
    // Shape it like a real `bws` failure: those embed the access token or the
    // value in stderr, which is exactly what must not reach the message.
    const original = new Error(`bws failed: could not store value ${leak} (token ${leak})`);
    const safe = toSafeError(original);

    expect(safe).toBeInstanceOf(InternalError);
    expect(safe.code).toBe('INTERNAL');
    expect(safe.exitCode).toBe(EXIT_CODES.internal);
    expect(safe.cause).toBe(original);

    expect(safe.message).not.toContain(leak);
    expect(safe.message).not.toContain('bws failed');
    expect(safe.message).not.toContain(original.message);
    expect(JSON.stringify(safe.toSafeJSON())).not.toContain(leak);
  });

  it('keeps the canary out of the message for every throwable shape', () => {
    const leak = canary();
    const throwables: unknown[] = [
      leak,
      new Error(leak),
      new TypeError(leak),
      { message: leak },
      { toString: () => leak },
      [leak],
      Symbol(leak),
      new Error('outer', { cause: new Error(leak) }),
    ];

    for (const throwable of throwables) {
      const safe = toSafeError(throwable);
      expect(safe).toBeInstanceOf(InternalError);
      expect(safe.message).not.toContain(leak);
      expect(JSON.stringify(safe.toSafeJSON())).not.toContain(leak);
      expect(safe.cause).toBe(throwable);
    }
  });

  it('preserves the caller-supplied non-secret details', () => {
    const safe = toSafeError(new Error(canary()), {
      field: 'value',
      reference: 'bitwarden/ezjob/production/API_KEY',
      hint: 'retry',
    });
    expect(safe.field).toBe('value');
    expect(safe.reference).toBe('bitwarden/ezjob/production/API_KEY');
    expect(safe.hint).toBe('retry');
  });

  it('returns an existing domain error untouched, preserving its exit code', () => {
    const original = new PolicyDeniedError('Action "delete" is not allowed in ezjob/production.');
    expect(toSafeError(original)).toBe(original);
    expect(toSafeError(original).exitCode).toBe(4);

    for (const { Ctor } of ERROR_TABLE) {
      const domain = new Ctor('already sanitized');
      expect(toSafeError(domain)).toBe(domain);
    }
  });

  it('does not treat a non-domain error as sanitized just because it looks like one', () => {
    // A plain object with a `code` field must still be wrapped: only a real
    // instance of the sanitized hierarchy is trusted to have a safe message.
    const leak = canary();
    const impostor = { code: 'NOT_FOUND', message: leak, exitCode: 5 };
    const safe = toSafeError(impostor);
    expect(safe).toBeInstanceOf(InternalError);
    expect(safe.message).not.toContain(leak);
  });
});

describe('isAgentSecretsError', () => {
  it('accepts every error in the taxonomy', () => {
    for (const { Ctor } of ERROR_TABLE) {
      expect(isAgentSecretsError(new Ctor('x'))).toBe(true);
    }
  });

  it('rejects everything else', () => {
    expect(isAgentSecretsError(new Error('x'))).toBe(false);
    expect(isAgentSecretsError(new TypeError('x'))).toBe(false);
    expect(isAgentSecretsError({ code: 'INVALID_INPUT', exitCode: 2 })).toBe(false);
    expect(isAgentSecretsError('INVALID_INPUT')).toBe(false);
    expect(isAgentSecretsError(null)).toBe(false);
    expect(isAgentSecretsError(undefined)).toBe(false);
  });
});

/**
 * Regression: the most likely real-world leak path in this package.
 *
 * `toSafeError` sanitizes the *message*, but `Error.cause` is enumerable by
 * default, so `console.error(error)` — the single most natural line to write in
 * a catch block — printed the original `bws` stderr verbatim through
 * util.inspect. Both holes are closed below; these tests keep them shut.
 */
describe('errors do not leak through inspection', () => {
  // Generated per run, never literal: a canary written into a committed file is
  // exactly what scripts/scan-secrets.mjs exists to catch, and it is right to
  // catch it.
  const leaked = canary();

  it('does not print the cause when inspected', () => {
    const wrapped = toSafeError(new Error(`bws failed: ${leaked}`));

    expect(inspect(wrapped)).not.toContain(leaked);
    expect(inspect(wrapped, { depth: 10 })).not.toContain(leaked);
    expect(format('%s', wrapped)).not.toContain(leaked);
    expect(format('%o', wrapped)).not.toContain(leaked);
    expect(`${wrapped}`).not.toContain(leaked);
  });

  it('keeps the cause reachable for a debugger but out of enumeration', () => {
    const original = new Error(`bws failed: ${leaked}`);
    const wrapped = toSafeError(original);

    // Still there when you go looking on purpose...
    expect(wrapped.cause).toBe(original);
    // ...but invisible to everything that enumerates.
    expect(Object.keys(wrapped)).not.toContain('cause');
    expect(JSON.stringify({ ...wrapped })).not.toContain(leaked);
    expect(Object.propertyIsEnumerable.call(wrapped, 'cause')).toBe(false);
  });

  it('keeps a nested error out of an inspected object graph', () => {
    const wrapped = toSafeError(new Error(leaked), { reference: 'bitwarden/p/development/K' });

    expect(inspect({ context: 'while adding', error: wrapped }, { depth: 10 })).not.toContain(
      leaked,
    );
  });
});
