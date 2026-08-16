import {
  type BackendHealth,
  ConflictError,
  formatRef,
  type InputMetadata,
  makeRef,
  NotFoundError,
  type ResolvedSecret,
  type SecretBackend,
  type SecretMetadata,
  type SecretRef,
  type SecretScope,
  type SecretValue,
} from '@bx-labs/agent-secrets-core';
import { BwsClient, type BwsClientOptions } from './bws-client.js';
import { type BwsSecretListItem, parseNote, serializeNote } from './bws-schemas.js';

/**
 * Bitwarden Secrets Manager backend.
 *
 * ── Storage layout ──────────────────────────────────────────────────────────
 * A single Bitwarden project holds every record for an installation. The
 * canonical scope is encoded in the Bitwarden secret key:
 *
 *     <project>/<environment>/<name>     e.g. ezjob/development/OPENAI_API_KEY
 *
 * Encoding the scope in the key, rather than creating one Bitwarden project per
 * scope, is what lets two Macs share one project with independent machine
 * tokens — which is the multi-device model this product is built around. The
 * cost is that Bitwarden-side permissions are per-project, so environment
 * isolation is enforced by our policy engine rather than by the vault. That
 * limitation is stated in docs/threat-model.md rather than hidden here.
 *
 * The scope grammar guarantees the three components contain no `/`, so the key
 * parses back unambiguously.
 */
export class BitwardenBackend implements SecretBackend {
  readonly id = 'bitwarden';
  readonly #client: BwsClient;
  /**
   * key -> record id, filled from `listSecrets`. Bitwarden addresses records by
   * UUID, so every operation on a named secret needs a lookup first. Cached for
   * the lifetime of one command only: a longer-lived cache would serve stale
   * ids after another device rotated a secret.
   */
  #index: Map<string, BwsSecretListItem> | undefined;

  constructor(options: BwsClientOptions | { client: BwsClient }) {
    this.#client = 'client' in options ? options.client : new BwsClient(options);
  }

  async health(): Promise<BackendHealth> {
    const startedAt = Date.now();
    try {
      const projects = await this.#client.listProjects();
      const canRead = projects.some((project) => project.id === this.#client.projectId);
      // Listing secrets in the configured project is the cheapest read probe
      // that exercises the actual permission we need.
      await this.#client.listSecrets();
      return {
        reachable: true,
        canRead,
        // A write probe would create a durable record, so we report the
        // permission we can observe rather than guessing. `doctor` explains
        // this to the operator instead of pretending to know.
        canWrite: canRead,
        latencyMs: Date.now() - startedAt,
      };
    } catch (error) {
      return {
        reachable: false,
        canRead: false,
        canWrite: false,
        latencyMs: Date.now() - startedAt,
        errorCode: errorCodeOf(error),
      };
    }
  }

  async list(scope: SecretScope): Promise<SecretMetadata[]> {
    const items = await this.#loadIndex();
    const prefix = `${scope.project}/${scope.environment}/`;
    const results: SecretMetadata[] = [];

    for (const item of items.values()) {
      if (!item.key.startsWith(prefix)) {
        continue;
      }
      const ref = refFromKey(item.key);
      // A key that does not parse back into a valid reference was written by
      // something other than this tool. Skipping it is safer than surfacing an
      // unvalidated name into JSON output that an agent will read.
      if (ref) {
        results.push(toMetadata(ref, item));
      }
    }
    return results.sort((a, b) => a.name.localeCompare(b.name));
  }

  async describe(ref: SecretRef): Promise<SecretMetadata | null> {
    const item = (await this.#loadIndex()).get(keyOf(ref));
    return item ? toMetadata(ref, item) : null;
  }

  async create(
    ref: SecretRef,
    value: SecretValue,
    metadata?: InputMetadata,
  ): Promise<SecretMetadata> {
    const key = keyOf(ref);
    if ((await this.#loadIndex()).has(key)) {
      throw new ConflictError('That secret already exists.', {
        reference: formatRef(ref),
        hint: 'Use `agent-secrets rotate` to replace its value.',
      });
    }

    const note = metadata ? serializeNote({ v: 1, ...metadata }) : undefined;
    const created = await this.#client.createSecret({
      key,
      value,
      ...(note === undefined ? {} : { note }),
    });

    // The wrapped value returned by the backend is not needed here; drop our
    // reference to it immediately rather than letting it live in a closure.
    created.value.dispose();
    this.#invalidate();
    return toMetadata(ref, created.meta);
  }

  async update(ref: SecretRef, value: SecretValue): Promise<SecretMetadata> {
    const existing = (await this.#loadIndex()).get(keyOf(ref));
    if (!existing) {
      throw new NotFoundError('That secret does not exist yet.', {
        reference: formatRef(ref),
        hint: 'Use `agent-secrets add` to create it.',
      });
    }
    const updated = await this.#client.editSecret({ id: existing.id, value });
    updated.value.dispose();
    this.#invalidate();
    return toMetadata(ref, updated.meta);
  }

  async delete(ref: SecretRef): Promise<void> {
    const existing = (await this.#loadIndex()).get(keyOf(ref));
    if (!existing) {
      throw new NotFoundError('That secret does not exist.', { reference: formatRef(ref) });
    }
    await this.#client.deleteSecret(existing.id);
    this.#invalidate();
  }

  async resolveMany(refs: SecretRef[]): Promise<ResolvedSecret[]> {
    const index = await this.#loadIndex();
    const resolved: ResolvedSecret[] = [];

    for (const ref of refs) {
      const item = index.get(keyOf(ref));
      if (!item) {
        // Fail closed and name the missing reference. The reference is not a
        // secret; failing silently, or substituting an empty string, would let
        // a child process start with a credential it needs missing.
        throw new NotFoundError('A requested secret does not exist.', {
          reference: formatRef(ref),
          hint: 'Run `agent-secrets list` to see what exists in that scope.',
        });
      }
      const { value } = await this.#client.getSecret(item.id);
      resolved.push({
        ref,
        value,
        ...(item.revisionDate === undefined ? {} : { version: item.revisionDate }),
      });
    }
    return resolved;
  }

  async #loadIndex(): Promise<Map<string, BwsSecretListItem>> {
    if (this.#index) {
      return this.#index;
    }
    const items = await this.#client.listSecrets();
    const index = new Map<string, BwsSecretListItem>();
    for (const item of items) {
      index.set(item.key, item);
    }
    this.#index = index;
    return index;
  }

  #invalidate(): void {
    this.#index = undefined;
  }
}

export function keyOf(ref: SecretRef): string {
  return `${ref.project}/${ref.environment}/${ref.name}`;
}

export function refFromKey(key: string): SecretRef | null {
  const parts = key.split('/');
  if (parts.length !== 3) {
    return null;
  }
  const [project, environment, name] = parts as [string, string, string];
  try {
    return makeRef({ project, environment, name });
  } catch {
    return null;
  }
}

function toMetadata(ref: SecretRef, item: BwsSecretListItem): SecretMetadata {
  const note = parseNote(item.note);
  return {
    backend: ref.backend,
    project: ref.project,
    environment: ref.environment,
    name: ref.name,
    reference: formatRef(ref),
    backendId: item.id,
    ...(item.revisionDate === undefined ? {} : { version: item.revisionDate }),
    ...(note?.description === undefined ? {} : { description: note.description }),
    ...(note?.provider === undefined ? {} : { provider: note.provider }),
    ...(note?.tags === undefined ? {} : { tags: note.tags }),
    ...(item.creationDate === undefined ? {} : { createdAt: normalizeDate(item.creationDate) }),
    ...(item.revisionDate === undefined ? {} : { updatedAt: normalizeDate(item.revisionDate) }),
  };
}

/** Bitwarden emits several ISO variants; the metadata schema wants a strict one. */
function normalizeDate(input: string): string {
  const parsed = new Date(input);
  return Number.isNaN(parsed.getTime()) ? new Date(0).toISOString() : parsed.toISOString();
}

function errorCodeOf(error: unknown): string {
  return typeof error === 'object' && error !== null && 'code' in error
    ? String((error as { code: unknown }).code)
    : 'INTERNAL';
}
