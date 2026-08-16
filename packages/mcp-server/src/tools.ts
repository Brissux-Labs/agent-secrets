import { ENVIRONMENTS, SECRET_NAME_PATTERN, SLUG_PATTERN } from '@bx-labs/agent-secrets-core';
import { z } from 'zod';

/**
 * Tool argument schemas and descriptions.
 *
 * The descriptions are part of the security design, not documentation. A model
 * decides what to call based on them, so each one states — in the plainest
 * language available — that values are never returned. FR-MCP-007 requires
 * this, and the reason is practical: a model that believes a value might be
 * obtainable will keep trying, and its attempts end up in a transcript.
 *
 * What matters more is that the *code* enforces it. If a future edit made a
 * description lie, the tool implementations would still not have a value to
 * return: `run_with_secrets` is the only one that touches `resolveMany`, and it
 * hands what it resolves to a child process, never to a result.
 */

const projectArg = z
  .string()
  .regex(SLUG_PATTERN, 'lowercase letters, digits and hyphens')
  .describe('Project slug, e.g. "ezjob".');

const environmentArg = z
  .enum(ENVIRONMENTS)
  .describe(
    'Environment. Never inferred: you must state it. "production" is restricted by policy.',
  );

const nameArg = z
  .string()
  .regex(SECRET_NAME_PATTERN, 'UPPER_SNAKE_CASE')
  .describe('Secret name in UPPER_SNAKE_CASE, e.g. "OPENAI_API_KEY".');

export const secretListArgs = z.object({
  project: projectArg,
  environment: environmentArg,
  provider: z.string().optional().describe('Filter by provider metadata.'),
  tag: z.string().optional().describe('Filter by tag.'),
});

export const secretDescribeArgs = z.object({
  project: projectArg,
  environment: environmentArg,
  name: nameArg,
});

export const secretAddRequestArgs = z.object({
  project: projectArg,
  environment: environmentArg,
  name: nameArg,
  description: z
    .string()
    .max(256)
    .optional()
    .describe('Optional non-secret note about what this credential is for.'),
});

export const secretRotateRequestArgs = secretAddRequestArgs;

export const secretDeleteRequestArgs = z.object({
  project: projectArg,
  environment: environmentArg,
  name: nameArg,
  confirmation: z
    .string()
    .describe(
      'The exact canonical reference, e.g. "bitwarden/ezjob/development/OPENAI_API_KEY". ' +
        'Deletion proceeds only if this matches exactly. Ask the human for it; do not construct it yourself.',
    ),
});

export const runWithSecretsArgs = z.object({
  project: projectArg,
  environment: environmentArg,
  secrets: z
    .array(nameArg)
    .min(1)
    .max(32)
    .describe('Exact names to inject. Only these are provided; there is no "all secrets" option.'),
  command: z
    .array(z.string().min(1))
    .min(1)
    .describe('The command as an argument array, e.g. ["npm", "run", "test"]. Not a shell string.'),
  cwd: z.string().optional().describe("Working directory. Defaults to the server's directory."),
  timeoutMs: z.number().int().min(1000).max(600_000).optional(),
  dryRun: z
    .boolean()
    .optional()
    .describe('When true, reports which names would be injected and runs nothing.'),
});

export const secretHealthArgs = z.object({});

/**
 * The default tool inventory.
 *
 * Seven tools. There is no eighth that returns a value, and adding one requires
 * a human-approved design change — `scripts/check-no-raw-getter.mjs` fails the
 * build if a tool name starts to look like a getter.
 */
export const TOOL_DESCRIPTIONS = {
  secret_list:
    'List the NAMES and non-secret metadata of secrets in a project/environment. ' +
    'Never returns values. There is no way to obtain a value through this server; ' +
    'if you need one to run something, use run_with_secrets instead.',

  secret_describe:
    'Check whether a named secret exists and read its non-secret metadata ' +
    '(provider, tags, description, timestamps). Never returns the value, its length, ' +
    'or any fingerprint of it.',

  secret_add_request:
    'Ask a human to supply a NEW secret value. A one-time secure link is sent to them ' +
    'out of band; it is never returned to you, so do not ask for it or try to open it. ' +
    'You will never see the value they enter, and you should not ask them to paste it ' +
    'into this conversation. After calling this, tell the human to check for the link ' +
    'and wait; use secret_describe to confirm the record appeared.',

  secret_rotate_request:
    'Ask a human to replace an EXISTING secret value. Same flow and same guarantee: the ' +
    'link goes to them out of band, the value goes from their browser to the vault, and ' +
    'neither reaches you.',

  secret_delete_request:
    'Request deletion of a secret. Requires the exact canonical reference as confirmation, ' +
    'and is denied outright in production unless policy explicitly permits it. ' +
    'Ask the human to supply the confirmation string.',

  run_with_secrets:
    'Run a command with the named secrets injected into its environment. ' +
    'The values go to the child process only; the output returned to you is redacted ' +
    'and size-capped. Use this instead of trying to read a value.',

  secret_health:
    'Report whether the backend is reachable and what this device is permitted to do. ' +
    'Returns no credentials and no project inventory.',
} as const;

export type ToolName = keyof typeof TOOL_DESCRIPTIONS;
