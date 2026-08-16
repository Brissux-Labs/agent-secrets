import type { InputMetadata, SecretMetadata } from './metadata.js';
import type { SecretRef, SecretScope } from './scope.js';
import type { SecretValue } from './secret-value.js';

/**
 * The contract every storage backend implements. Bitwarden Secrets Manager is
 * the only implementation required for V1; the interface stays deliberately
 * narrow so that a second backend never becomes a redesign.
 *
 * Implementations must:
 *  - map every failure to an `AgentSecretsError` (see errors.ts);
 *  - never log a raw backend response from a value-bearing operation;
 *  - return `SecretValue` instances from `resolveMany`, never plain strings;
 *  - treat `describe` on a missing secret as `null`, not as an error.
 */
export interface SecretBackend {
  readonly id: string;

  health(): Promise<BackendHealth>;

  list(scope: SecretScope): Promise<SecretMetadata[]>;

  describe(ref: SecretRef): Promise<SecretMetadata | null>;

  create(ref: SecretRef, value: SecretValue, metadata?: InputMetadata): Promise<SecretMetadata>;

  update(ref: SecretRef, value: SecretValue): Promise<SecretMetadata>;

  delete(ref: SecretRef): Promise<void>;

  /**
   * The single read path for values. Used only by `agent-secrets run` to build
   * a child environment block. There is intentionally no `resolveOne`: a
   * batch-only API makes "resolve one and print it" an awkward thing to write.
   */
  resolveMany(refs: SecretRef[]): Promise<ResolvedSecret[]>;
}

export interface BackendHealth {
  readonly reachable: boolean;
  /** Whether the device credential can read metadata in the configured scope. */
  readonly canRead: boolean;
  /** Whether it can write. Probed without creating a durable record when possible. */
  readonly canWrite: boolean;
  /** Round-trip latency of the probe, in milliseconds. Safe to log. */
  readonly latencyMs: number;
  /** Backend software version when the adapter can obtain it cheaply. */
  readonly backendVersion?: string;
  /** Stable code when unhealthy. Never a raw backend message. */
  readonly errorCode?: string;
}

export interface ResolvedSecret {
  readonly ref: SecretRef;
  readonly value: SecretValue;
  readonly version?: string;
}
