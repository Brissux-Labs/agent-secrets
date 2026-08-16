import {
  buildAuditEvent,
  ConflictError,
  formatRef,
  formatScope,
  type InputMetadata,
  InvalidInputError,
  isProduction,
  makeRef,
  makeScope,
  NotFoundError,
  PolicyDeniedError,
  type SecretRef,
  validateSecretValue,
} from '@bx-labs/agent-secrets-core';
import type { Context } from '../context.js';
import { confirmByTyping, readValueFromStdin, readValueFromTty } from '../prompts.js';

/**
 * The secret lifecycle commands: `add`, `list`, `describe`, `rotate`, `delete`.
 *
 * Every one of them follows the same order — validate the reference, evaluate
 * policy, then act — and none of them has a code path that prints, returns, or
 * stores anything derived from a value. `add` and `rotate` read one; the moment
 * the backend accepts it, they dispose of it.
 */

export interface ScopeOptions {
  readonly project: string;
  readonly env: string;
  readonly json?: boolean;
}

export interface AddOptions extends ScopeOptions {
  readonly stdin?: boolean;
  readonly rotate?: boolean;
  readonly description?: string;
  readonly provider?: string;
  readonly tag?: string[];
  readonly maxBytes?: number;
  readonly allowEmpty?: boolean;
  readonly allowWhitespace?: boolean;
}

export async function runAdd(context: Context, name: string, options: AddOptions): Promise<number> {
  const ref = makeRef({ project: options.project, environment: options.env, name });
  const backend = await context.requireBackend();

  context.policy.assert({ action: options.rotate ? 'rotate' : 'create', target: ref });

  const existing = await backend.describe(ref);

  if (existing && !options.rotate) {
    // FR-ADD-005. Overwriting on a plain `add` is exactly the silent
    // destructive behaviour the product principles forbid.
    throw new ConflictError('That secret already exists.', {
      reference: formatRef(ref),
      hint: `Use \`agent-secrets rotate ${name} --project ${ref.project} --env ${ref.environment}\` to replace it.`,
    });
  }
  if (!existing && options.rotate) {
    throw new NotFoundError('That secret does not exist yet.', {
      reference: formatRef(ref),
      hint: `Use \`agent-secrets add ${name} --project ${ref.project} --env ${ref.environment}\` to create it.`,
    });
  }

  const value = options.stdin
    ? await readValueFromStdin()
    : await readValueFromTty({ confirm: !existing });

  try {
    context.redaction.track(value);
    validateSecretValue(value, {
      ...(options.maxBytes === undefined ? {} : { maxBytes: options.maxBytes }),
      ...(options.allowEmpty === undefined ? {} : { allowEmpty: options.allowEmpty }),
      ...(options.allowWhitespace === undefined
        ? {}
        : { allowWhitespace: options.allowWhitespace }),
    });

    const metadata: InputMetadata = {
      ...(options.description === undefined ? {} : { description: options.description }),
      ...(options.provider === undefined ? {} : { provider: options.provider }),
      ...(options.tag === undefined || options.tag.length === 0 ? {} : { tags: options.tag }),
    };

    const result = existing
      ? await backend.update(ref, value)
      : await backend.create(ref, value, metadata);

    await context.audit.record(
      buildAuditEvent({
        actorType: 'human',
        actorId: context.config?.deviceId ?? 'unknown',
        ...(context.config?.deviceId === undefined ? {} : { deviceId: context.config.deviceId }),
        operation: existing ? 'rotate' : 'create',
        reference: formatRef(ref),
        secretNames: [ref.name],
        outcome: 'success',
      }),
    );

    context.writer.ok(
      {
        status: existing ? 'rotated' : 'created',
        reference: result.reference,
        ...(result.version === undefined ? {} : { version: result.version }),
        ...(result.createdAt === undefined ? {} : { createdAt: result.createdAt }),
        ...(result.updatedAt === undefined ? {} : { updatedAt: result.updatedAt }),
      },
      (fmt) => `${fmt.success('✓')} ${result.reference} ${existing ? 'rotated' : 'created'}`,
    );
    return 0;
  } finally {
    // Whether the write succeeded or threw, our copy stops existing here.
    value.dispose();
  }
}

export async function runList(context: Context, options: ScopeOptions): Promise<number> {
  const scope = makeScope({ project: options.project, environment: options.env });
  const backend = await context.requireBackend();

  context.policy.assert({ action: 'list', target: scope });

  const secrets = await backend.list(scope);

  await context.audit.record(
    buildAuditEvent({
      actorType: 'human',
      actorId: context.config?.deviceId ?? 'unknown',
      operation: 'list',
      reference: formatScope(scope),
      outcome: 'success',
    }),
  );

  context.writer.ok({ scope: formatScope(scope), count: secrets.length, secrets }, (fmt) => {
    if (secrets.length === 0) {
      return `No secrets in ${formatScope(scope)}.`;
    }
    const width = Math.max(...secrets.map((secret) => secret.name.length));
    const rows = secrets.map((secret) => {
      const details = [secret.provider, secret.tags?.join(',')].filter(Boolean).join(' · ');
      return `  ${secret.name.padEnd(width)}  ${fmt.dim(details || '')}`;
    });
    return [`${fmt.bold(formatScope(scope))} — ${secrets.length} secret(s)`, ...rows].join('\n');
  });
  return 0;
}

export async function runDescribe(
  context: Context,
  name: string,
  options: ScopeOptions,
): Promise<number> {
  const ref = makeRef({ project: options.project, environment: options.env, name });
  const backend = await context.requireBackend();

  context.policy.assert({ action: 'describe', target: ref });

  const metadata = await backend.describe(ref);
  if (!metadata) {
    throw new NotFoundError('No such secret.', {
      reference: formatRef(ref),
      hint: `Run \`agent-secrets list --project ${ref.project} --env ${ref.environment}\` to see what exists.`,
    });
  }

  context.writer.ok(metadata, (fmt) =>
    [
      `${fmt.bold(metadata.reference)}`,
      metadata.provider ? `  provider   ${metadata.provider}` : null,
      metadata.description ? `  description ${metadata.description}` : null,
      metadata.tags?.length ? `  tags       ${metadata.tags.join(', ')}` : null,
      metadata.createdAt ? `  created    ${metadata.createdAt}` : null,
      metadata.updatedAt ? `  updated    ${metadata.updatedAt}` : null,
      // Said out loud, because "describe" invites the expectation of a preview.
      fmt.dim('  (no value, length, or fingerprint is available by design)'),
    ]
      .filter(Boolean)
      .join('\n'),
  );
  return 0;
}

export interface DeleteOptions extends ScopeOptions {
  /** Non-interactive confirmation: must be the exact canonical reference. */
  readonly yes?: string;
}

export async function runDelete(
  context: Context,
  name: string,
  options: DeleteOptions,
): Promise<number> {
  const ref = makeRef({ project: options.project, environment: options.env, name });
  const backend = await context.requireBackend();

  context.policy.assert({ action: 'delete', target: ref });

  // FR-MUTATE-004: production deletion needs a gate beyond the policy check,
  // because policy can be edited by whoever is asking.
  if (isProduction(ref) && options.yes === undefined && context.writer.isJson) {
    throw new PolicyDeniedError('Deleting a production secret cannot be confirmed in JSON mode.', {
      reference: formatRef(ref),
      hint: 'Run it interactively, or pass --yes with the exact canonical reference.',
    });
  }

  const expected = formatRef(ref);
  const existing = await backend.describe(ref);
  if (!existing) {
    throw new NotFoundError('No such secret.', { reference: expected });
  }

  if (options.yes !== undefined) {
    if (options.yes !== expected) {
      throw new InvalidInputError('The confirmation did not match the canonical reference.', {
        field: 'yes',
        hint: `Pass --yes "${expected}" to confirm.`,
      });
    }
  } else {
    const confirmed = await confirmByTyping(
      expected,
      `Type the full reference to delete it (${expected}):`,
    );
    if (!confirmed) {
      context.writer.note(() => 'Cancelled. Nothing was deleted.');
      return 0;
    }
  }

  await backend.delete(ref);

  await context.audit.record(
    buildAuditEvent({
      actorType: 'human',
      actorId: context.config?.deviceId ?? 'unknown',
      operation: 'delete',
      reference: expected,
      secretNames: [ref.name],
      outcome: 'success',
    }),
  );

  context.writer.ok(
    { status: 'deleted', reference: expected },
    (fmt) => `${fmt.success('✓')} ${expected} deleted`,
  );
  return 0;
}

export function refFor(options: ScopeOptions, name: string): SecretRef {
  return makeRef({ project: options.project, environment: options.env, name });
}
