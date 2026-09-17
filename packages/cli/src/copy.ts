import {
  ConflictError,
  formatRef,
  type InputMetadata,
  InvalidInputError,
  NotFoundError,
  type PolicyEngine,
  type SecretBackend,
  type SecretMetadata,
  type SecretRef,
  type SecretValue,
} from '@bx-labs/agent-secrets-core';

/**
 * Vault-to-vault promotion, shared by `agent-secrets copy` and the MCP
 * `secret_copy` tool so that both surfaces make exactly the same decisions in
 * exactly the same order.
 *
 * The case it exists for: the same provider key serves development and
 * production, the operator already typed it once at a hidden prompt, and the
 * alternative is fetching it from the provider a second time — or, worse, from
 * wherever they kept it in between. The value goes backend → backend through
 * the adapter and is disposed the moment the write returns. Like `add`, it
 * never overwrites: an existing target is a `ConflictError`.
 */

/**
 * Environments in order of how much a leak there costs. A copy only moves a
 * value *up* this ladder: promoting a development credential to production is
 * the operator reusing one key twice, while copying a production credential
 * down would put it somewhere the policy guards less.
 */
const ENVIRONMENT_RANK: Record<string, number> = { development: 0, preview: 1, production: 2 };

export interface CopySecretOptions {
  readonly backend: SecretBackend;
  readonly policy: PolicyEngine;
  readonly source: SecretRef;
  readonly target: SecretRef;
  /**
   * Called with the resolved value before it is written, so a caller with an
   * output redaction scope can register it. The value is disposed after the
   * write regardless.
   */
  readonly track?: (value: SecretValue) => void;
}

export function assertUpward(source: SecretRef, target: SecretRef): void {
  const fromRank = ENVIRONMENT_RANK[source.environment] ?? -1;
  const toRank = ENVIRONMENT_RANK[target.environment] ?? -1;
  if (source.project !== target.project || source.name !== target.name) {
    throw new InvalidInputError(
      'A copy keeps the project and the name; only the environment changes.',
      {
        field: 'to',
        reference: formatRef(target),
      },
    );
  }
  if (fromRank < 0 || toRank < 0 || fromRank >= toRank) {
    throw new InvalidInputError('A copy only goes upward: development → preview → production.', {
      field: 'to',
      reference: formatRef(target),
      hint: 'Name a source environment below the target. A production value is never copied down.',
    });
  }
}

export async function copySecret(options: CopySecretOptions): Promise<SecretMetadata> {
  const { backend, policy, source, target } = options;

  assertUpward(source, target);

  // Policy on the target: that is where a name gets added. Asserted before
  // the backend is read, so a denied copy never resolves a value at all.
  policy.assert({ action: 'copy', target });

  const sourceMetadata = await backend.describe(source);
  if (!sourceMetadata) {
    throw new NotFoundError('The source secret does not exist.', {
      reference: formatRef(source),
      hint: `Run \`agent-secrets list --project ${source.project} --env ${source.environment}\` to see what exists.`,
    });
  }

  const existing = await backend.describe(target);
  if (existing) {
    throw new ConflictError('The target secret already exists.', {
      reference: formatRef(target),
      hint: `Use \`agent-secrets rotate ${target.name} --project ${target.project} --env ${target.environment}\` to replace it.`,
    });
  }

  const [resolved] = await backend.resolveMany([source]);
  if (!resolved) {
    throw new NotFoundError('The source secret could not be resolved.', {
      reference: formatRef(source),
    });
  }
  const value = resolved.value;

  try {
    options.track?.(value);

    const metadata: InputMetadata = {
      ...(sourceMetadata.description === undefined
        ? {}
        : { description: sourceMetadata.description }),
      ...(sourceMetadata.provider === undefined ? {} : { provider: sourceMetadata.provider }),
      ...(sourceMetadata.tags === undefined || sourceMetadata.tags.length === 0
        ? {}
        : { tags: sourceMetadata.tags }),
    };

    return await backend.create(target, value, metadata);
  } finally {
    // Whether the write succeeded or threw, our copy stops existing here.
    value.dispose();
  }
}
