import { randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { homedir, hostname } from 'node:os';
import { join } from 'node:path';
import {
  backendIdSchema,
  environmentSchema,
  InvalidInputError,
  projectSlugSchema,
} from '@bx-labs/agent-secrets-core';
import { z } from 'zod';

/**
 * Local configuration.
 *
 * The split enforced here is the one that makes multi-device work: this file
 * holds only things that are safe to read, copy, and even commit — backend
 * type, Bitwarden project id, device name, defaults. The access token lives in
 * the OS credential store and never appears in it.
 *
 * The Bitwarden *project id* is intentionally kept here rather than treated as
 * a secret. It is an opaque record locator that is useless without a token, and
 * making it a secret would mean a second thing to enrol on every machine.
 */

export const configSchema = z
  .object({
    version: z.literal(1),
    backend: backendIdSchema,
    /** Stable random identifier for this installation. FR-DEVICE-001. */
    deviceId: z.uuid(),
    /** Human-readable, shown in audit records and `doctor`. */
    deviceName: z.string().min(1).max(64),
    bitwarden: z
      .object({
        projectId: z.uuid(),
        /** Self-hosted deployments override the API base. */
        serverUrl: z.url().optional(),
        /** Absolute path when `bws` is not on the default PATH. */
        executablePath: z.string().min(1).optional(),
      })
      .strict()
      .optional(),
    defaults: z
      .object({
        project: projectSlugSchema.optional(),
        /**
         * Note what is missing: there is no default environment. FR-SCOPE-005
         * forbids inferring one, and a configurable default would be exactly
         * the mechanism by which someone eventually writes to production while
         * believing they are in development.
         */
      })
      .strict()
      .default({}),
    audit: z
      .object({
        enabled: z.boolean().default(true),
        /** Rotate the JSONL file once it exceeds this many bytes. */
        maxBytes: z
          .number()
          .int()
          .positive()
          .default(5 * 1024 * 1024),
      })
      .strict()
      .default({ enabled: true, maxBytes: 5 * 1024 * 1024 }),
    createdAt: z.iso.datetime(),
  })
  .strict();

export type Config = z.infer<typeof configSchema>;

export interface Paths {
  readonly home: string;
  readonly configFile: string;
  readonly auditFile: string;
  readonly policyFile: string;
}

/**
 * Resolve where state lives.
 *
 * `AGENT_SECRETS_HOME` exists so that tests — and users who keep dotfiles
 * elsewhere — can redirect everything with one variable. Every path derives
 * from it, so a test that sets it is guaranteed to leave no trace in the real
 * home directory.
 */
export function resolvePaths(env: NodeJS.ProcessEnv = process.env): Paths {
  const home =
    env['AGENT_SECRETS_HOME'] ??
    join(env['XDG_CONFIG_HOME'] ?? join(env['HOME'] ?? homedir(), '.config'), 'agent-secrets');

  return {
    home,
    configFile: join(home, 'config.json'),
    auditFile: join(home, 'audit.jsonl'),
    policyFile: join(home, 'policy.yaml'),
  };
}

export async function loadConfig(paths: Paths): Promise<Config | null> {
  let raw: string;
  try {
    raw = await readFile(paths.configFile, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw new InvalidInputError('The configuration file could not be read.', {
      hint: `Check permissions on ${paths.configFile}.`,
    });
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(raw);
  } catch {
    throw new InvalidInputError('The configuration file is not valid JSON.', {
      hint: `Fix or delete ${paths.configFile}, then run \`agent-secrets init\`.`,
    });
  }

  const parsed = configSchema.safeParse(parsedJson);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    // Fail closed on an unrecognised config rather than filling in defaults: a
    // config we do not understand may have been written by a different version
    // with different security assumptions.
    throw new InvalidInputError(
      `The configuration file is invalid at "${first?.path.join('.') ?? 'root'}".`,
      { hint: `Fix ${paths.configFile}, or delete it and run \`agent-secrets init\`.` },
    );
  }
  return parsed.data;
}

export async function saveConfig(paths: Paths, config: Config): Promise<void> {
  await mkdir(paths.home, { recursive: true, mode: 0o700 });
  await chmod(paths.home, 0o700);
  const serialized = `${JSON.stringify(configSchema.parse(config), null, 2)}\n`;
  await writeFile(paths.configFile, serialized, { mode: 0o600, encoding: 'utf8' });
  await chmod(paths.configFile, 0o600);
}

export async function deleteConfig(paths: Paths): Promise<void> {
  await rm(paths.configFile, { force: true });
}

export function newDeviceConfig(input: {
  deviceName?: string;
  projectId: string;
  serverUrl?: string;
  executablePath?: string;
}): Config {
  return configSchema.parse({
    version: 1,
    backend: 'bitwarden',
    deviceId: randomUUID(),
    deviceName: input.deviceName ?? defaultDeviceName(),
    bitwarden: {
      projectId: input.projectId,
      ...(input.serverUrl === undefined ? {} : { serverUrl: input.serverUrl }),
      ...(input.executablePath === undefined ? {} : { executablePath: input.executablePath }),
    },
    defaults: {},
    audit: { enabled: true, maxBytes: 5 * 1024 * 1024 },
    createdAt: new Date().toISOString(),
  });
}

/**
 * Where the `bws` binary is, when it is not somewhere the adapter looks.
 *
 * The adapter resolves a bare `bws` against its own fixed list of directories
 * rather than the caller's `PATH`, so that a poisoned PATH entry cannot
 * substitute a program that captures the access token. The cost is that a
 * perfectly ordinary install — `~/.local/bin`, `~/bin`, a release tarball
 * unpacked into a project — is invisible to this tool while `which bws` reports
 * success. `AGENT_SECRETS_BWS_PATH` is the documented way out
 * (DOC.md §8.1); `--executable-path` is the same thing for one invocation.
 *
 * Both are explicit acts by the operator, which is what separates them from
 * silently trusting `PATH`.
 *
 * `explicit` wins: at enrolment it is `--executable-path`, and afterwards it is
 * the path `init` recorded in `config.json`. A pinned path is a reviewed
 * decision in a 0600 file; the environment variable is ambient and inherited,
 * so it fills a gap rather than overriding a choice.
 */
export function resolveBwsExecutable(
  env: NodeJS.ProcessEnv = process.env,
  explicit?: string,
): string | undefined {
  const candidate = explicit?.trim() || env['AGENT_SECRETS_BWS_PATH'];
  const trimmed = candidate?.trim();
  return trimmed === undefined || trimmed.length === 0 ? undefined : trimmed;
}

export function defaultDeviceName(): string {
  // `hostname()` on macOS returns things like "Antoine-Mac-mini.local"; the
  // suffix is noise in an audit record.
  return (
    hostname()
      .replace(/\.local$/, '')
      .slice(0, 64) || 'unnamed-device'
  );
}

/**
 * FR-DEVICE-004. Config is not a secret, but a world-writable config file lets
 * an attacker point this tool at a backend they control, which is a credible
 * path to capturing the next secret the user adds.
 */
export interface PermissionReport {
  readonly path: string;
  readonly mode: string;
  readonly ok: boolean;
  readonly expected: string;
}

export async function checkPermissions(paths: Paths): Promise<PermissionReport[]> {
  const targets: Array<{ path: string; expected: number }> = [
    { path: paths.home, expected: 0o700 },
    { path: paths.configFile, expected: 0o600 },
    { path: paths.auditFile, expected: 0o600 },
  ];

  const reports: PermissionReport[] = [];
  for (const target of targets) {
    try {
      const stats = await stat(target.path);
      const mode = stats.mode & 0o777;
      reports.push({
        path: target.path,
        mode: mode.toString(8).padStart(3, '0'),
        // Stricter than expected is fine; looser is not.
        ok: (mode & ~target.expected) === 0,
        expected: target.expected.toString(8).padStart(3, '0'),
      });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw error;
      }
    }
  }
  return reports;
}

export const environmentValues = environmentSchema.options;
