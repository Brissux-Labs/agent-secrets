import { readFile } from 'node:fs/promises';
import { BitwardenBackend } from '@bx-labs/agent-secrets-backend-bitwarden';
import {
  type AuditSink,
  AuthRequiredError,
  defaultPolicy,
  PolicyEngine,
  parsePolicy,
  type SecretBackend,
} from '@bx-labs/agent-secrets-core';
import { RedactionScope } from '@bx-labs/agent-secrets-redaction';
import { parse as parseYaml } from 'yaml';
import { disabledAuditSink, JsonlAuditSink } from './audit-sink.js';
import {
  type Config,
  loadConfig,
  type Paths,
  resolveBwsExecutable,
  resolvePaths,
} from './config.js';
import {
  type CredentialStore,
  defaultCredentialStore,
  KEYCHAIN_SERVICE,
  keychainAccount,
} from './credential-store.js';
import type { Writer } from './output.js';

/**
 * Everything a command needs, assembled once.
 *
 * Building the context is also where enrolment is enforced: a command that
 * needs the backend calls `requireBackend()`, which fails with exit code 3 and
 * a next step rather than a stack trace when the device has no token. The
 * distinction matters for agents, which branch on the exit code.
 */
export interface Context {
  readonly paths: Paths;
  readonly config: Config | null;
  readonly writer: Writer;
  readonly credentials: CredentialStore;
  readonly redaction: RedactionScope;
  readonly policy: PolicyEngine;
  readonly audit: AuditSink;
  readonly env: NodeJS.ProcessEnv;
  requireConfig(): Config;
  requireBackend(): Promise<SecretBackend>;
  dispose(): void;
}

export interface CreateContextOptions {
  readonly writer: Writer;
  readonly env?: NodeJS.ProcessEnv;
  /** Injected by tests so no real Keychain or backend is touched. */
  readonly credentials?: CredentialStore;
  readonly backendFactory?: (config: Config, accessToken: string) => SecretBackend;
}

export async function createContext(options: CreateContextOptions): Promise<Context> {
  const env = options.env ?? process.env;
  const paths = resolvePaths(env);
  const config = await loadConfig(paths);
  const credentials = options.credentials ?? defaultCredentialStore(paths.home, env);
  const redaction = new RedactionScope();
  const policy = new PolicyEngine(await loadPolicy(paths));

  const audit: AuditSink =
    config?.audit.enabled === false
      ? disabledAuditSink
      : new JsonlAuditSink(paths.auditFile, config?.audit.maxBytes);

  let backend: SecretBackend | undefined;

  const context: Context = {
    paths,
    config,
    writer: options.writer,
    credentials,
    redaction,
    policy,
    audit,
    env,

    requireConfig(): Config {
      if (!config) {
        throw new AuthRequiredError('This device is not enrolled.', {
          hint: 'Run `agent-secrets init` to enrol it.',
        });
      }
      return config;
    },

    async requireBackend(): Promise<SecretBackend> {
      if (backend) {
        return backend;
      }
      const resolved = context.requireConfig();
      if (!resolved.bitwarden) {
        throw new AuthRequiredError('This device has no backend configured.', {
          hint: 'Run `agent-secrets init` to configure Bitwarden Secrets Manager.',
        });
      }

      const account = keychainAccount(resolved.deviceId, resolved.bitwarden.projectId);
      const token = await credentials.get(KEYCHAIN_SERVICE, account);
      if (!token) {
        // The config exists but the credential does not: the usual cause is
        // that the user ran `logout`, or restored a config from a backup onto a
        // machine that was never enrolled. Both need the same next step.
        throw new AuthRequiredError('No access token is stored for this device.', {
          hint: 'Run `agent-secrets init` to enrol this device again.',
        });
      }
      // The token is tracked so that if it ever surfaces in a backend error or
      // a captured output, redaction removes it before anything prints.
      redaction.trackString(token);

      if (options.backendFactory) {
        backend = options.backendFactory(resolved, token);
        return backend;
      }

      // The enrolled path wins over the environment, not the other way round.
      // `config.json` is 0600 and was written by a deliberate `init`; an
      // environment variable is ambient and inherited. Letting the ambient one
      // override a pinned path would mean anything that can set a variable in
      // this shell chooses which binary receives the access token — the exact
      // substitution SAFE_PATH exists to prevent. The variable still applies
      // when no path was pinned, which is the case this fixes.
      const executablePath = resolveBwsExecutable(env, resolved.bitwarden.executablePath);

      backend = new BitwardenBackend({
        accessToken: token,
        projectId: resolved.bitwarden.projectId,
        redactionScope: redaction,
        // The environment variable wins over the enrolled path: a binary that
        // moved is a thing the operator fixes without re-enrolling.
        ...(executablePath === undefined ? {} : { executable: executablePath }),
        ...(resolved.bitwarden.serverUrl === undefined
          ? {}
          : { serverUrl: resolved.bitwarden.serverUrl }),
      });
      return backend;
    },

    dispose(): void {
      redaction.dispose();
    },
  };

  return context;
}

/**
 * Load `policy.yaml` from the CLI's own config directory.
 *
 * Note where it is NOT loaded from: the current working directory. A policy
 * file that ships with a cloned repository could otherwise grant that
 * repository's commands access to production — the exact inversion of what a
 * policy is for. Project-local intent belongs in a manifest, which requires
 * explicit approval.
 */
async function loadPolicy(paths: Paths): Promise<ReturnType<typeof defaultPolicy>> {
  try {
    const raw = await readFile(paths.policyFile, 'utf8');
    return parsePolicy(parseYaml(raw, { maxAliasCount: 100 }));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return defaultPolicy();
    }
    throw error;
  }
}
