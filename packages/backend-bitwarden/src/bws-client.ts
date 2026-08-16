import {
  AuthRequiredError,
  BackendUnavailableError,
  ConflictError,
  InternalError,
  NotFoundError,
  SecretValue,
} from '@bx-labs/agent-secrets-core';
import type { RedactionScope } from '@bx-labs/agent-secrets-redaction';
import type { z } from 'zod';
import {
  type BwsProject,
  type BwsSecret,
  type BwsSecretListItem,
  bwsProjectListSchema,
  bwsSecretListSchema,
  bwsSecretSchema,
} from './bws-schemas.js';
import { DEFAULT_TIMEOUT_MS, minimalEnv, type RunResult, run } from './subprocess.js';

/**
 * A typed wrapper around the `bws` executable.
 *
 * ── The argv problem, stated plainly ────────────────────────────────────────
 * `bws secret create <key> <value> <project-id>` takes the value as a
 * command-line argument. On macOS and Linux, `ps` shows the argument vector of
 * any process owned by the same user, so during the milliseconds that `bws`
 * runs, a concurrent process under that user could observe the value.
 *
 * We do not paper over this. Three things are true about it:
 *
 *  1. It applies to `create` and `update` only. Read paths (`list`, `get`,
 *     `delete`) never carry a value in argv, and `run` never invokes `bws` with
 *     one either.
 *  2. The adversary it helps is one already executing code as the same OS user
 *     — who can equally read the access token out of the Keychain and query the
 *     whole vault directly. It grants no capability that attacker lacks.
 *  3. It is nevertheless a real narrowing we would rather not ship. The client
 *     probes `bws` for a stdin-based value transport at runtime and prefers it
 *     when available; `valueTransport` reports which one was used so the CLI
 *     can tell the operator, and so tests can assert the preference.
 *
 * docs/threat-model.md carries the same statement for users who never read
 * this file.
 */

export interface BwsClientOptions {
  /** Absolute path or bare name resolved against the safe PATH. */
  readonly executable?: string;
  /** Machine-account access token. Passed by environment, never by argv. */
  readonly accessToken: string;
  /** Bitwarden project (UUID) holding every record for this installation. */
  readonly projectId: string;
  readonly timeoutMs?: number;
  readonly redactionScope?: RedactionScope;
  /** Overrides capability probing. Mainly for tests. */
  readonly valueTransport?: ValueTransport;
  readonly serverUrl?: string;
}

export type ValueTransport = 'argv' | 'stdin';

export class BwsClient {
  readonly #executable: string;
  readonly #accessToken: string;
  readonly #projectId: string;
  readonly #timeoutMs: number;
  readonly #redactionScope: RedactionScope | undefined;
  readonly #serverUrl: string | undefined;
  #valueTransport: ValueTransport | undefined;

  constructor(options: BwsClientOptions) {
    this.#executable = options.executable ?? 'bws';
    this.#accessToken = options.accessToken;
    this.#projectId = options.projectId;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#redactionScope = options.redactionScope;
    this.#serverUrl = options.serverUrl;
    this.#valueTransport = options.valueTransport;
  }

  get projectId(): string {
    return this.#projectId;
  }

  /** Which transport the last value-bearing call used. `undefined` before any. */
  get valueTransport(): ValueTransport | undefined {
    return this.#valueTransport;
  }

  async version(): Promise<string> {
    const result = await this.#exec(['--version'], { json: false });
    return result.stdout.trim();
  }

  async listProjects(): Promise<BwsProject[]> {
    const result = await this.#exec(['project', 'list']);
    return this.#parse(bwsProjectListSchema, result, 'project list');
  }

  async listSecrets(): Promise<BwsSecretListItem[]> {
    const result = await this.#exec(['secret', 'list', this.#projectId]);
    return this.#parse(bwsSecretListSchema, result, 'secret list');
  }

  /**
   * Fetch one record including its value.
   *
   * The value is wrapped before this function returns, and the parsed JSON
   * object holding the plain string is dropped immediately: nothing that could
   * be logged ever holds it.
   */
  async getSecret(id: string): Promise<{ meta: BwsSecretListItem; value: SecretValue }> {
    const result = await this.#exec(['secret', 'get', id]);
    const parsed = this.#parse(bwsSecretSchema, result, 'secret get');
    return splitValue(parsed);
  }

  async createSecret(args: {
    key: string;
    value: SecretValue;
    note?: string;
  }): Promise<{ meta: BwsSecretListItem; value: SecretValue }> {
    const transport = await this.#resolveValueTransport();
    // expose: handing the value to the storage backend — one of the three
    // legitimate destinations. It is never assigned to an intermediate that
    // outlives this call.
    const raw = args.value.expose();

    const argv = ['secret', 'create', args.key];
    const options: { json?: boolean; stdin?: string } = {};

    if (transport === 'stdin') {
      argv.push('--value-stdin', this.#projectId);
      options.stdin = raw;
    } else {
      argv.push(raw, this.#projectId);
    }
    if (args.note !== undefined) {
      argv.push('--note', args.note);
    }

    const result = await this.#exec(argv, options);
    const parsed = this.#parse(bwsSecretSchema, result, 'secret create');
    return splitValue(parsed);
  }

  async editSecret(args: {
    id: string;
    value?: SecretValue;
    key?: string;
    note?: string;
  }): Promise<{ meta: BwsSecretListItem; value: SecretValue }> {
    const argv = ['secret', 'edit', args.id];
    const options: { stdin?: string } = {};

    if (args.value !== undefined) {
      const transport = await this.#resolveValueTransport();
      // expose: writing the rotated value to the storage backend.
      const raw = args.value.expose();
      if (transport === 'stdin') {
        argv.push('--value-stdin');
        options.stdin = raw;
      } else {
        argv.push('--value', raw);
      }
    }
    if (args.key !== undefined) {
      argv.push('--key', args.key);
    }
    if (args.note !== undefined) {
      argv.push('--note', args.note);
    }

    const result = await this.#exec(argv, options);
    const parsed = this.#parse(bwsSecretSchema, result, 'secret edit');
    return splitValue(parsed);
  }

  async deleteSecret(id: string): Promise<void> {
    await this.#exec(['secret', 'delete', id], { json: false });
  }

  /**
   * Ask `bws` whether it can read a value from stdin.
   *
   * Probed once, lazily, from `--help` output. If the probe itself fails we
   * fall back to argv rather than failing the operation: a degraded but working
   * write beats an outage, and the exposure is bounded as described above.
   */
  async #resolveValueTransport(): Promise<ValueTransport> {
    if (this.#valueTransport !== undefined) {
      return this.#valueTransport;
    }
    try {
      const help = await this.#exec(['secret', 'create', '--help'], { json: false });
      this.#valueTransport = /--value-stdin\b/.test(help.stdout) ? 'stdin' : 'argv';
    } catch {
      this.#valueTransport = 'argv';
    }
    return this.#valueTransport;
  }

  async #exec(
    args: string[],
    options: { json?: boolean; stdin?: string } = {},
  ): Promise<RunResult> {
    const argv = options.json === false ? args : [...args, '--output', 'json'];

    const env = minimalEnv({
      // The token travels by environment because argv is world-readable to the
      // same user. This is the single most important line in this file.
      BWS_ACCESS_TOKEN: this.#accessToken,
      ...(this.#serverUrl === undefined ? {} : { BWS_SERVER_URL: this.#serverUrl }),
    });

    const result = await run({
      file: this.#executable,
      args: argv,
      env,
      timeoutMs: this.#timeoutMs,
      ...(this.#redactionScope === undefined ? {} : { redactionScope: this.#redactionScope }),
      ...(options.stdin === undefined ? {} : { stdin: options.stdin }),
    });

    if (result.code !== 0) {
      throw classifyFailure(result, args);
    }
    return result;
  }

  #parse<T>(schema: z.ZodType<T>, result: RunResult, operation: string): T {
    let json: unknown;
    try {
      json = JSON.parse(result.stdout);
    } catch {
      // Deliberately does not include the output: on a value-bearing call, a
      // malformed response may be a partially written record containing it.
      throw new BackendUnavailableError(
        `Backend returned output that is not valid JSON for "${operation}".`,
        { hint: 'Check that the bws version installed is supported.' },
      );
    }
    const parsed = schema.safeParse(json);
    if (!parsed.success) {
      throw new BackendUnavailableError(
        `Backend response for "${operation}" did not match the expected shape.`,
        { hint: 'This usually means the installed bws version changed its output format.' },
      );
    }
    return parsed.data;
  }
}

/**
 * Map a non-zero `bws` exit into a sanitized domain error.
 *
 * The classification reads the already-redacted stderr for well-known phrases.
 * Note what is not done: the stderr text is never embedded in the resulting
 * message. Bitwarden's error output has been observed to echo request payloads,
 * and this is the boundary where that would become a leak.
 */
function classifyFailure(result: RunResult, args: readonly string[]): Error {
  const stderr = result.stderr.toLowerCase();
  const operation = args.slice(0, 2).join(' ');

  if (/unauthor|401|invalid.*(token|credential)|access token/.test(stderr)) {
    return new AuthRequiredError('The backend rejected this device access token.', {
      hint: 'Run `agent-secrets init` to re-enrol this device, or check that the token was not revoked.',
    });
  }
  if (/not found|404|no secret|does not exist/.test(stderr)) {
    return new NotFoundError('The backend has no record matching that reference.', {});
  }
  if (/already exists|409|conflict|duplicate/.test(stderr)) {
    return new ConflictError('A record with that key already exists in the backend.', {
      hint: 'Use `agent-secrets rotate` to replace an existing secret.',
    });
  }
  if (/rate limit|429|too many requests/.test(stderr)) {
    return new BackendUnavailableError('The backend is rate limiting this device.', {
      hint: 'Wait a moment and retry.',
    });
  }
  if (/network|timeout|dns|connection|unreachable|tls|certificate/.test(stderr)) {
    return new BackendUnavailableError('The backend is unreachable.', {
      hint: 'Check network connectivity. Agent Secrets fails closed rather than serving stale values.',
    });
  }
  if (/forbidden|403|permission/.test(stderr)) {
    return new AuthRequiredError('This device token lacks permission for that operation.', {
      hint: 'Grant the machine account read/write access to the project in Bitwarden.',
    });
  }
  return new InternalError(
    `The backend command "${operation}" failed with exit code ${result.code}. Details were withheld to avoid leaking a secret value.`,
    { hint: 'Run `agent-secrets doctor` to check backend reachability and permissions.' },
  );
}

/**
 * Split a parsed record into non-secret metadata and a wrapped value, so the
 * object carrying the plain string has the shortest possible lifetime.
 */
function splitValue(secret: BwsSecret): { meta: BwsSecretListItem; value: SecretValue } {
  const { value, ...meta } = secret;
  return { meta, value: SecretValue.from(value) };
}
