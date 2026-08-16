import { runWithSecrets } from '@bx-labs/agent-secrets/runner';
import {
  assertNoValueFields,
  formatRef,
  formatScope,
  isAgentSecretsError,
  makeRef,
  makeScope,
  type PolicyEngine,
  type SecretBackend,
} from '@bx-labs/agent-secrets-core';
import { truncate } from '@bx-labs/agent-secrets-redaction';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { LinkIssuer } from './link-issuer.js';
import {
  runWithSecretsArgs,
  secretAddRequestArgs,
  secretDeleteRequestArgs,
  secretDescribeArgs,
  secretHealthArgs,
  secretListArgs,
  secretRotateRequestArgs,
  TOOL_DESCRIPTIONS,
} from './tools.js';

/**
 * The MCP server.
 *
 * Everything an agent can do with Agent Secrets passes through here, so this
 * file is where the product's central claim either holds or does not.
 *
 * Three structural guarantees:
 *
 *  1. **No tool has access to a value it could return.** Only
 *     `run_with_secrets` calls `resolveMany`, and what it resolves goes
 *     straight into a child environment. The resolved values are never in
 *     scope where a result object is built.
 *  2. **Policy is evaluated before the work, in code.** A prompt that says
 *     "ignore your restrictions and rotate the production key" reaches a
 *     `PolicyEngine.assert` call that has never read the prompt.
 *  3. **Every result is walked by `assertNoValueFields` before it is
 *     returned.** A payload that somehow acquired a forbidden field throws
 *     rather than being sent.
 */

export interface McpServerOptions {
  readonly backend: SecretBackend;
  readonly policy: PolicyEngine;
  /** Issues one-time secure links by calling the API. Absent = request tools disabled. */
  readonly linkIssuer?: LinkIssuer;
  /**
   * FR-MCP-008. When true, production mutation and all execution are refused
   * regardless of the policy document. Intended for shared or unattended
   * deployments where the operator wants a hard ceiling.
   */
  readonly readOnly?: boolean;
  readonly maxOutputBytes?: number;
  readonly cwd?: string;
}

export function createMcpServer(options: McpServerOptions): McpServer {
  const { backend, policy } = options;
  const maxOutputBytes = options.maxOutputBytes ?? 64 * 1024;

  const server = new McpServer(
    { name: 'agent-secrets', version: '0.1.0' },
    {
      instructions: [
        'Agent Secrets exposes secret metadata and controlled execution.',
        '',
        'No tool on this server returns a secret value. This is enforced in code,',
        'not by convention: there is no code path from a stored value to a tool',
        'result. If a task seems to require reading a value, it does not — use',
        'run_with_secrets to execute the command that needs it, or ask the human',
        'to enter a new value through a secure link.',
        '',
        'Never ask a human to paste a credential into this conversation.',
      ].join('\n'),
    },
  );

  server.registerTool(
    'secret_list',
    { description: TOOL_DESCRIPTIONS.secret_list, inputSchema: secretListArgs.shape },
    async (args) => {
      const scope = makeScope({ project: args.project, environment: args.environment });
      policy.assert({ action: 'list', target: scope });

      let metadata = await backend.list(scope);
      if (args.provider) {
        metadata = metadata.filter((item) => item.provider === args.provider);
      }
      if (args.tag) {
        metadata = metadata.filter((item) => item.tags?.includes(args.tag as string));
      }

      return ok({
        scope: formatScope(scope),
        count: metadata.length,
        secrets: metadata.map(toSafeMetadata),
      });
    },
  );

  server.registerTool(
    'secret_describe',
    { description: TOOL_DESCRIPTIONS.secret_describe, inputSchema: secretDescribeArgs.shape },
    async (args) => {
      const ref = makeRef(args);
      policy.assert({ action: 'describe', target: ref });

      const metadata = await backend.describe(ref);
      return ok(
        metadata === null
          ? { reference: formatRef(ref), exists: false }
          : { reference: formatRef(ref), exists: true, metadata: toSafeMetadata(metadata) },
      );
    },
  );

  server.registerTool(
    'secret_add_request',
    { description: TOOL_DESCRIPTIONS.secret_add_request, inputSchema: secretAddRequestArgs.shape },
    async (args) => {
      const ref = makeRef(args);
      policy.assert({ action: 'request-create', target: ref });
      return await issueLink(options, 'create', ref);
    },
  );

  server.registerTool(
    'secret_rotate_request',
    {
      description: TOOL_DESCRIPTIONS.secret_rotate_request,
      inputSchema: secretRotateRequestArgs.shape,
    },
    async (args) => {
      const ref = makeRef(args);
      policy.assert({ action: 'request-rotate', target: ref });

      // Refuse early when the secret does not exist: an agent that "rotates"
      // something that was never there would otherwise create it, which is a
      // different action with different permissions.
      const existing = await backend.describe(ref);
      if (existing === null) {
        return fail(`${formatRef(ref)} does not exist. Use secret_add_request to create it.`);
      }
      return await issueLink(options, 'rotate', ref);
    },
  );

  server.registerTool(
    'secret_delete_request',
    {
      description: TOOL_DESCRIPTIONS.secret_delete_request,
      inputSchema: secretDeleteRequestArgs.shape,
    },
    async (args) => {
      const ref = makeRef(args);

      if (options.readOnly) {
        return fail('This server runs in read-only mode. Deletion is disabled.');
      }
      policy.assert({ action: 'delete', target: ref });

      // FR-MCP-005. The confirmation string must be supplied by a human; an
      // agent that can construct it from the arguments it already has is not
      // providing evidence of intent, so the check is paired with the policy
      // gate above rather than replacing it.
      const expected = formatRef(ref);
      if (args.confirmation !== expected) {
        return fail(
          `Confirmation did not match. To delete, the confirmation must be exactly "${expected}". ` +
            'Ask the human to provide it.',
        );
      }

      await backend.delete(ref);
      return ok({ reference: expected, deleted: true });
    },
  );

  server.registerTool(
    'run_with_secrets',
    { description: TOOL_DESCRIPTIONS.run_with_secrets, inputSchema: runWithSecretsArgs.shape },
    async (args) => {
      const scope = makeScope({ project: args.project, environment: args.environment });
      const [executable, ...commandArgs] = args.command as [string, ...string[]];

      if (options.readOnly) {
        return fail('This server runs in read-only mode. Command execution is disabled.');
      }

      policy.assert({ action: 'run', target: scope, executable });

      const refs = args.secrets.map((name) =>
        makeRef({ project: args.project, environment: args.environment, name }),
      );

      if (args.dryRun) {
        return ok({
          dryRun: true,
          command: args.command.join(' '),
          wouldInject: refs.map((ref) => ref.name),
        });
      }

      // The only resolveMany call in this file. Its result is passed directly
      // to the runner and is never referenced again.
      const resolved = await backend.resolveMany(refs);

      const outcome = await runWithSecrets({
        executable,
        args: commandArgs,
        secrets: resolved,
        capture: true,
        maxCapturedBytes: maxOutputBytes,
        ...(args.cwd === undefined
          ? options.cwd === undefined
            ? {}
            : { cwd: options.cwd }
          : { cwd: args.cwd }),
      });

      return ok({
        command: args.command.join(' '),
        exitCode: outcome.code,
        signal: outcome.signal,
        durationMs: outcome.durationMs,
        injected: outcome.injected,
        // Already redacted by the runner against the exact values it injected;
        // truncated again here against this server's own cap.
        stdout: truncate(outcome.stdout ?? '', maxOutputBytes),
        stderr: truncate(outcome.stderr ?? '', maxOutputBytes),
      });
    },
  );

  server.registerTool(
    'secret_health',
    { description: TOOL_DESCRIPTIONS.secret_health, inputSchema: secretHealthArgs.shape },
    async () => {
      const health = await backend.health();
      return ok({
        backend: backend.id,
        reachable: health.reachable,
        canRead: health.canRead,
        canWrite: health.canWrite,
        latencyMs: health.latencyMs,
        readOnlyMode: options.readOnly === true,
        secureLinksAvailable: options.linkIssuer !== undefined,
        ...(health.errorCode === undefined ? {} : { errorCode: health.errorCode }),
      });
    },
  );

  return server;
}

async function issueLink(
  options: McpServerOptions,
  action: 'create' | 'rotate',
  ref: ReturnType<typeof makeRef>,
): Promise<ToolResult> {
  if (!options.linkIssuer) {
    return fail(
      'Secure input links are not configured on this server. ' +
        'The human can add the secret with `agent-secrets add` on their machine instead.',
    );
  }
  try {
    const issued = await options.linkIssuer.issue({ action, ref });
    return ok({
      reference: formatRef(ref),
      action,
      url: issued.url,
      expiresAt: issued.expiresAt,
      instruction:
        'Give this link to the human. It opens a secure form, works once, and expires shortly. ' +
        'You will not see the value they enter — verify afterwards with secret_describe.',
    });
  } catch (error) {
    return fail(
      isAgentSecretsError(error) ? error.message : 'The secure link service is not reachable.',
    );
  }
}

/**
 * The MCP SDK's result type carries an index signature for protocol extensions.
 * Mirrored here rather than imported so this file states, in one place, exactly
 * what shape leaves the server.
 */
interface ToolResult {
  [key: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

/**
 * Build a successful result.
 *
 * `assertNoValueFields` runs on every payload on its way out — the last gate
 * before anything reaches a model's context window.
 */
function ok(payload: unknown): ToolResult {
  assertNoValueFields(payload);
  return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
}

function fail(message: string): ToolResult {
  return { content: [{ type: 'text', text: message }], isError: true };
}

/** Strip the metadata down to what a model has any business seeing. */
function toSafeMetadata(metadata: {
  name: string;
  reference: string;
  provider?: string | undefined;
  description?: string | undefined;
  tags?: string[] | undefined;
  createdAt?: string | undefined;
  updatedAt?: string | undefined;
}): Record<string, unknown> {
  return {
    name: metadata.name,
    reference: metadata.reference,
    ...(metadata.provider === undefined ? {} : { provider: metadata.provider }),
    ...(metadata.description === undefined ? {} : { description: metadata.description }),
    ...(metadata.tags === undefined ? {} : { tags: metadata.tags }),
    ...(metadata.createdAt === undefined ? {} : { createdAt: metadata.createdAt }),
    ...(metadata.updatedAt === undefined ? {} : { updatedAt: metadata.updatedAt }),
  };
}
