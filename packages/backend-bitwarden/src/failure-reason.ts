/**
 * Why a backend call failed, in one machine-readable word.
 *
 * The stable `code` on an `AgentSecretsError` answers "what should the process
 * exit with"; it does not answer "what should the operator do next".
 * `BACKEND_UNAVAILABLE` covers a `bws` binary that is not on the search path, a
 * network that is down, an endpoint pointed at the wrong region, and a response
 * this version cannot parse — four problems with four different remedies. Every
 * one of them used to reach the operator as "the backend rejected this token,
 * or is unreachable", which named the only cause they could not verify without
 * pasting a credential somewhere.
 *
 * The reason is a closed vocabulary of constants. It is derived from the shape
 * of the failure — never from backend text, which is exactly what must not
 * travel: `bws` stderr can echo a request payload.
 */
export type BackendFailureReason =
  | 'executable-not-found'
  | 'timeout'
  | 'unauthenticated'
  | 'permission-denied'
  | 'not-found'
  | 'conflict'
  | 'rate-limited'
  | 'unreachable'
  | 'incompatible-response'
  | 'unknown';

/**
 * Carried on a symbol-keyed, non-enumerable property.
 *
 * A plain field would show up in `util.inspect`, in a spread, and in anything
 * that walks `Object.entries` on an error — the same surfaces the non-enumerable
 * `cause` exists to stay out of. `Symbol.for` rather than a module-local symbol
 * so that two copies of this package in one dependency tree still agree.
 */
const REASON = Symbol.for('agent-secrets.backend-failure-reason');

export function tagFailureReason<E>(error: E, reason: BackendFailureReason): E {
  if (typeof error === 'object' && error !== null) {
    Object.defineProperty(error, REASON, {
      value: reason,
      enumerable: false,
      writable: true,
      configurable: true,
    });
  }
  return error;
}

export function failureReasonOf(error: unknown): BackendFailureReason {
  if (typeof error === 'object' && error !== null) {
    const tagged = (error as Record<symbol, unknown>)[REASON];
    if (typeof tagged === 'string') {
      return tagged as BackendFailureReason;
    }
  }
  return 'unknown';
}
