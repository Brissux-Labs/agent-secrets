import {
  buildAuditEvent,
  ChildFailedError,
  formatScope,
  InvalidInputError,
  isProduction,
  makeRef,
  makeScope,
  PolicyDeniedError,
} from '@bx-labs/agent-secrets-core';
import { confirm } from '@inquirer/prompts';
import type { Context } from '../context.js';
import { isApproved, loadManifest, selectCommand } from '../manifest.js';
import { describeDryRun, runWithSecrets } from '../runner.js';

/**
 * `agent-secrets run` — controlled execution.
 *
 * Two entry shapes, one code path:
 *
 *   agent-secrets run --project p --env development --keys A,B -- npm run dev
 *   agent-secrets run --manifest dev
 *
 * The manifest form is the one intended for agents, because the command and the
 * secret list are then fixed by a file a human reviewed, rather than assembled
 * from whatever the model decided. That is also why an unapproved manifest
 * stops and asks: the file arrived with a repository, and the repository is not
 * trusted.
 */

export interface RunOptions {
  readonly project?: string;
  readonly env?: string;
  readonly keys?: string;
  readonly manifest?: string;
  readonly dryRun?: boolean;
  readonly isolatedEnv?: boolean;
  readonly yes?: boolean;
  readonly cwd?: string;
}

export async function runRun(
  context: Context,
  command: readonly string[],
  options: RunOptions,
): Promise<number> {
  const plan = options.manifest
    ? await planFromManifest(context, options)
    : planFromFlags(command, options);

  const scope = makeScope({ project: plan.project, environment: plan.environment });
  const [executable, ...args] = plan.command as [string, ...string[]];

  // Policy first, before the backend is even contacted. A denied run must not
  // cause a vault read.
  context.policy.assert({ action: 'run', target: scope, executable });

  const refs = plan.secretNames.map((name) =>
    makeRef({ project: plan.project, environment: plan.environment, name }),
  );

  if (options.dryRun) {
    const description = describeDryRun(refs, executable, args);
    context.writer.ok({ dryRun: true, ...description }, (fmt) =>
      [
        `${fmt.bold('Dry run')} — nothing was executed.`,
        `  command: ${description.command}`,
        `  would inject: ${description.secretNames.join(', ') || '(none)'}`,
      ].join('\n'),
    );
    return 0;
  }

  // FR-RUN-008. Production execution asks a human, outside anything a model
  // controls, unless the operator explicitly waived it on this invocation.
  if (isProduction(scope) && !options.yes) {
    if (context.writer.isJson || !process.stdin.isTTY) {
      throw new PolicyDeniedError('Running against production requires human confirmation.', {
        reference: formatScope(scope),
        hint: 'Run it interactively, or pass --yes if you are the human and you mean it.',
      });
    }
    const confirmed = await confirm({
      message: `Inject ${refs.length} production secret(s) into "${plan.command.join(' ')}"?`,
      default: false,
    });
    if (!confirmed) {
      context.writer.note(() => 'Cancelled. Nothing was executed.');
      return 0;
    }
  }

  const backend = await context.requireBackend();
  const resolved = await backend.resolveMany(refs);

  context.writer.note(
    (fmt) =>
      `${fmt.dim(`Injecting ${resolved.length} named secret(s) into: ${plan.command.join(' ')}`)}`,
  );

  const outcome = await runWithSecrets({
    executable,
    args,
    secrets: resolved,
    ...(options.isolatedEnv ? { inheritEnv: false } : {}),
    ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
  });

  if (outcome.overridden.length > 0) {
    context.writer.note(
      (fmt) =>
        `${fmt.warn('!')} Replaced ${outcome.overridden.join(', ')} from the inherited environment.`,
    );
  }

  await context.audit.record(
    buildAuditEvent({
      actorType: 'human',
      actorId: context.config?.deviceId ?? 'unknown',
      operation: 'run',
      reference: formatScope(scope),
      secretNames: [...outcome.injected],
      // FR-RUN-010: the executable, never the argument vector, which routinely
      // carries tokens of its own.
      commandExecutable: executable,
      outcome: outcome.code === 0 ? 'success' : 'failure',
      durationMs: outcome.durationMs,
    }),
  );

  if (context.writer.isJson) {
    context.writer.ok(
      {
        status: outcome.code === 0 ? 'ok' : 'failed',
        exitCode: outcome.code,
        signal: outcome.signal,
        injected: outcome.injected,
        durationMs: outcome.durationMs,
      },
      () => '',
    );
  }

  // FR-RUN-004. The child's exit code is ours, so scripts and agents see what
  // actually happened rather than a wrapper's opinion of it.
  if (outcome.signal) {
    throw new ChildFailedError(`The command was terminated by ${outcome.signal}.`, {});
  }
  return outcome.code;
}

interface RunPlan {
  readonly project: string;
  readonly environment: string;
  readonly secretNames: readonly string[];
  readonly command: readonly string[];
}

function planFromFlags(command: readonly string[], options: RunOptions): RunPlan {
  if (!options.project || !options.env) {
    throw new InvalidInputError('`run` needs --project and --env.', {
      field: 'scope',
      hint: 'For example: agent-secrets run --project ezjob --env development --keys API_KEY -- npm run dev',
    });
  }
  if (command.length === 0) {
    throw new InvalidInputError('No command was given.', {
      field: 'command',
      hint: 'Put the command after `--`, e.g. `-- npm run dev`.',
    });
  }

  const secretNames = (options.keys ?? '')
    .split(',')
    .map((key) => key.trim())
    .filter(Boolean);

  if (secretNames.length === 0) {
    // FR-RUN-009. There is deliberately no "inject everything" mode: an empty
    // --keys is a mistake, and guessing what the user meant is how a command
    // ends up holding credentials it never needed.
    throw new InvalidInputError('No secrets were named.', {
      field: 'keys',
      hint: 'Pass --keys NAME1,NAME2. There is no option to inject every secret in a scope.',
    });
  }

  return {
    project: options.project,
    environment: options.env,
    secretNames,
    command,
  };
}

async function planFromManifest(context: Context, options: RunOptions): Promise<RunPlan> {
  const loaded = await loadManifest(options.cwd ?? process.cwd());
  if (!loaded) {
    throw new InvalidInputError('No agent-secrets.yaml was found here.', {
      field: 'manifest',
      hint: 'Create one (see docs/manifests.md), or use --project/--env/--keys instead.',
    });
  }

  const commandName = options.manifest as string;
  const entry = selectCommand(loaded, commandName);

  // Approval is keyed by the manifest's content hash, so editing a command
  // invalidates the approval it previously carried.
  const approvals = { version: 1 as const, approvals: [] };
  if (entry.approval === 'required' && !isApproved(approvals, loaded, commandName)) {
    if (!options.yes) {
      if (!process.stdin.isTTY || context.writer.isJson) {
        throw new PolicyDeniedError(`The manifest command "${commandName}" requires approval.`, {
          hint: 'Run it interactively to review and approve it, or pass --yes.',
        });
      }
      const confirmed = await confirm({
        message: `Run "${entry.command.join(' ')}" in ${loaded.manifest.project}/${entry.environment} with ${entry.secrets.length} secret(s)?`,
        default: false,
      });
      if (!confirmed) {
        throw new PolicyDeniedError('Not approved.', {
          hint: 'The command was not run.',
        });
      }
    }
  }

  return {
    project: loaded.manifest.project,
    environment: entry.environment,
    secretNames: entry.secrets,
    command: entry.command,
  };
}
