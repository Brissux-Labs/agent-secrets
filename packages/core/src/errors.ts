import { inspect } from 'node:util';

/**
 * Sanitized domain errors.
 *
 * Two invariants hold across this file:
 *
 *  1. An `AgentSecretsError` message is built from constants and from validated
 *     scope identifiers — never from a raw backend message, a subprocess
 *     stderr, or a submitted value. Raw causes may be attached to `cause` for
 *     local debugging, but `cause` is never rendered by any sink.
 *  2. Every error maps to a stable exit code from docs/exit-codes.md. The codes
 *     are part of the public contract: scripts and agents branch on them.
 */

export const EXIT_CODES = {
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
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

export const ERROR_CODES = [
  'INVALID_INPUT',
  'AUTH_REQUIRED',
  'POLICY_DENIED',
  'NOT_FOUND',
  'CONFLICT',
  'BACKEND_UNAVAILABLE',
  'EXPIRED_OR_CONSUMED',
  'CHILD_FAILED',
  'INTERNAL',
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export interface ErrorDetails {
  /** Which input field was rejected. Never the field's content. */
  readonly field?: string;
  /** Canonical reference or scope the operation targeted. */
  readonly reference?: string;
  /** Original error, kept for local debugging. Never rendered or logged. */
  readonly cause?: unknown;
  /** Operator-facing next step, e.g. "run `agent-secrets init`". */
  readonly hint?: string;
}

export abstract class AgentSecretsError extends Error {
  abstract readonly code: ErrorCode;
  abstract readonly exitCode: ExitCode;
  readonly field: string | undefined;
  readonly reference: string | undefined;
  readonly hint: string | undefined;

  constructor(message: string, details: ErrorDetails = {}) {
    super(message, details.cause === undefined ? undefined : { cause: details.cause });
    this.field = details.field;
    this.reference = details.reference;
    this.hint = details.hint;

    // `cause` holds the original throwable — a `bws` failure whose message can
    // embed the value or the access token. `Error`'s own `cause` is enumerable,
    // which means the most natural line anyone writes in a catch block,
    // `console.error(error)`, prints it verbatim through util.inspect.
    //
    // Making it non-enumerable keeps it reachable for a debugger while removing
    // it from inspect, spread, and Object.entries. The custom inspect below
    // closes the same hole for the error as a whole.
    if (details.cause !== undefined) {
      Object.defineProperty(this, 'cause', {
        value: details.cause,
        enumerable: false,
        writable: true,
        configurable: true,
      });
    }
  }

  /**
   * What `console.error(error)` and `util.inspect(error)` print.
   *
   * Deliberately the same safe shape as `toSafeJSON`, so a sink that never
   * learned about `toSafeJSON` still cannot print a raw backend message.
   */
  [inspect.custom](): string {
    const parts = [`${this.name}(${this.code}): ${this.message}`];
    if (this.reference !== undefined) {
      parts.push(`reference=${this.reference}`);
    }
    if (this.field !== undefined) {
      parts.push(`field=${this.field}`);
    }
    return parts.join(' ');
  }

  /**
   * The only representation allowed to cross a process boundary: a stable code,
   * a message built from constants, and non-secret scope identifiers.
   */
  toSafeJSON(): SafeErrorShape {
    return {
      code: this.code,
      message: this.message,
      ...(this.field === undefined ? {} : { field: this.field }),
      ...(this.reference === undefined ? {} : { reference: this.reference }),
      ...(this.hint === undefined ? {} : { hint: this.hint }),
    };
  }
}

export interface SafeErrorShape {
  readonly code: ErrorCode;
  readonly message: string;
  readonly field?: string;
  readonly reference?: string;
  readonly hint?: string;
}

export class InvalidInputError extends AgentSecretsError {
  override readonly name = 'InvalidInputError';
  readonly code = 'INVALID_INPUT' as const;
  readonly exitCode = EXIT_CODES.invalidInput;
}

export class AuthRequiredError extends AgentSecretsError {
  override readonly name = 'AuthRequiredError';
  readonly code = 'AUTH_REQUIRED' as const;
  readonly exitCode = EXIT_CODES.authRequired;
}

export class PolicyDeniedError extends AgentSecretsError {
  override readonly name = 'PolicyDeniedError';
  readonly code = 'POLICY_DENIED' as const;
  readonly exitCode = EXIT_CODES.policyDenied;
}

export class NotFoundError extends AgentSecretsError {
  override readonly name = 'NotFoundError';
  readonly code = 'NOT_FOUND' as const;
  readonly exitCode = EXIT_CODES.notFound;
}

export class ConflictError extends AgentSecretsError {
  override readonly name = 'ConflictError';
  readonly code = 'CONFLICT' as const;
  readonly exitCode = EXIT_CODES.conflict;
}

export class BackendUnavailableError extends AgentSecretsError {
  override readonly name = 'BackendUnavailableError';
  readonly code = 'BACKEND_UNAVAILABLE' as const;
  readonly exitCode = EXIT_CODES.backendUnavailable;
}

export class ExpiredOrConsumedError extends AgentSecretsError {
  override readonly name = 'ExpiredOrConsumedError';
  readonly code = 'EXPIRED_OR_CONSUMED' as const;
  readonly exitCode = EXIT_CODES.expiredOrConsumed;
}

export class ChildFailedError extends AgentSecretsError {
  override readonly name = 'ChildFailedError';
  readonly code = 'CHILD_FAILED' as const;
  readonly exitCode = EXIT_CODES.childFailed;
}

export class InternalError extends AgentSecretsError {
  override readonly name = 'InternalError';
  readonly code = 'INTERNAL' as const;
  readonly exitCode = EXIT_CODES.internal;
}

export function isAgentSecretsError(error: unknown): error is AgentSecretsError {
  return error instanceof AgentSecretsError;
}

/**
 * Convert anything thrown into a sanitized domain error.
 *
 * Unknown throwables keep their original object on `cause` but contribute
 * nothing to the message: a `bws` failure or a `spawn` error can embed the
 * value or the access token in its message, so it must never be surfaced.
 */
export function toSafeError(error: unknown, details: ErrorDetails = {}): AgentSecretsError {
  if (isAgentSecretsError(error)) {
    return error;
  }
  return new InternalError(
    'An internal error occurred. Details were withheld to avoid leaking a secret value.',
    {
      ...details,
      cause: error,
    },
  );
}
