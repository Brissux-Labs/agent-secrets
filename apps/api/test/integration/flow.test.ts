import {
  formatRef,
  type SecretMetadata,
  type SecretRef,
  type SecretValue,
} from '@bx-labs/agent-secrets-core';
import { newCanary } from '@bx-labs/agent-secrets-redaction';
import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ApiConfig } from '../../src/config.js';
import { buildServer } from '../../src/server.js';
import { RequestStore } from '../../src/store.js';

/**
 * The one-time link flow, end to end, against an in-memory store and a fake
 * backend that records what it was handed.
 *
 * The acceptance criteria these encode are the ones that decide whether the
 * Telegram design holds: exactly one submission wins, a replay fails, an expired
 * link fails, and nothing anywhere holds the value except the backend call.
 */

const ADAPTER_TOKEN = 'fake-adapter-token-for-tests-0123456789abcdef';

interface RecordingBackend {
  created: Array<{ ref: SecretRef; value: string }>;
  updated: Array<{ ref: SecretRef; value: string }>;
}

function makeConfig(overrides: Partial<ApiConfig> = {}): ApiConfig {
  return {
    publicUrl: 'http://localhost:8787',
    host: '127.0.0.1',
    port: 8787,
    nodeEnv: 'development',
    adapterToken: ADAPTER_TOKEN,
    databasePath: ':memory:',
    bitwarden: {
      accessToken: 'fake-bws-token',
      projectId: '00000000-0000-4000-8000-000000000000',
    },
    ttlSeconds: 120,
    maxValueBytes: 64 * 1024,
    rateLimit: { max: 1000, windowMs: 60_000, maxAttemptsPerRequest: 1000 },
    trustProxy: false,
    ...overrides,
  } as ApiConfig;
}

describe('secure input flow', () => {
  let app: FastifyInstance;
  let store: RequestStore;
  let recorded: RecordingBackend;

  const metadataFor = (ref: SecretRef): SecretMetadata => ({
    backend: ref.backend,
    project: ref.project,
    environment: ref.environment,
    name: ref.name,
    reference: formatRef(ref),
  });

  const boot = async (config: ApiConfig = makeConfig()): Promise<void> => {
    store = new RequestStore(':memory:');
    recorded = { created: [], updated: [] };

    app = await buildServer({
      config,
      store,
      backendFactory: () =>
        ({
          async create(ref: SecretRef, value: SecretValue) {
            recorded.created.push({ ref, value: value.expose() });
            return metadataFor(ref);
          },
          async update(ref: SecretRef, value: SecretValue) {
            recorded.updated.push({ ref, value: value.expose() });
            return metadataFor(ref);
          },
          async describe(ref: SecretRef) {
            return metadataFor(ref);
          },
          async health() {
            return { reachable: true, canRead: true, canWrite: true, latencyMs: 1 };
          },
        }) as never,
    });
    await app.ready();
  };

  const issueLink = async (
    overrides: Record<string, unknown> = {},
  ): Promise<{ id: string; url: string; token: string; expiresAt: string }> => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/requests',
      headers: { authorization: `Bearer ${ADAPTER_TOKEN}` },
      payload: {
        action: 'create',
        project: 'ezjob',
        environment: 'development',
        name: 'OPENAI_API_KEY',
        telegramUserId: '123456',
        ...overrides,
      },
    });
    expect(response.statusCode).toBe(201);
    const body = response.json() as { id: string; url: string; expiresAt: string };
    return { ...body, token: body.url.split('/input/')[1] as string };
  };

  /** Fetch the form and pull out the CSRF pair the browser would submit. */
  const openForm = async (
    token: string,
  ): Promise<{ csrf: string; cookie: string; html: string }> => {
    const response = await app.inject({ method: 'GET', url: `/input/${token}` });
    expect(response.statusCode).toBe(200);
    const html = response.body;
    const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] as string;
    const cookie = response.headers['set-cookie'] as string;
    return { csrf, cookie: cookie.split(';')[0] as string, html };
  };

  const submit = async (token: string, value: string, form: { csrf: string; cookie: string }) =>
    await app.inject({
      method: 'POST',
      url: `/v1/input/${token}`,
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: 'http://localhost:8787',
        cookie: form.cookie,
      },
      payload: new URLSearchParams({ value, csrf: form.csrf }).toString(),
    });

  beforeEach(async () => {
    await boot();
  });

  afterEach(async () => {
    await app.close();
  });

  it('issues a link, renders the form, and writes the value exactly once', async () => {
    const canary = newCanary();
    const link = await issueLink();
    const form = await openForm(link.token);

    const response = await submit(link.token, canary, form);

    expect(response.statusCode).toBe(200);
    expect(recorded.created).toHaveLength(1);
    expect(recorded.created[0]?.value).toBe(canary);
    expect(recorded.created[0]?.ref.name).toBe('OPENAI_API_KEY');

    // Nothing in the response repeats the value back.
    expect(response.body).not.toContain(canary);
  });

  it('rejects a replayed submission', async () => {
    const link = await issueLink();
    const form = await openForm(link.token);

    expect((await submit(link.token, newCanary(), form)).statusCode).toBe(200);

    const replay = await submit(link.token, newCanary(), form);
    expect(replay.statusCode).toBe(410);
    expect(recorded.created).toHaveLength(1);
  });

  it('lets exactly one of two concurrent submissions win', async () => {
    const link = await issueLink();
    const form = await openForm(link.token);

    const results = await Promise.all([
      submit(link.token, newCanary(), form),
      submit(link.token, newCanary(), form),
      submit(link.token, newCanary(), form),
    ]);

    const succeeded = results.filter((result) => result.statusCode === 200);
    expect(succeeded).toHaveLength(1);
    expect(recorded.created).toHaveLength(1);
  });

  it('refuses a submission without the CSRF pair', async () => {
    const link = await issueLink();
    const form = await openForm(link.token);

    const noCookie = await app.inject({
      method: 'POST',
      url: `/v1/input/${link.token}`,
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: 'http://localhost:8787',
      },
      payload: new URLSearchParams({ value: newCanary(), csrf: form.csrf }).toString(),
    });
    expect(noCookie.statusCode).toBe(403);

    const wrongToken = await submit(link.token, newCanary(), {
      csrf: 'not-the-right-token',
      cookie: form.cookie,
    });
    expect(wrongToken.statusCode).toBe(403);
    expect(recorded.created).toHaveLength(0);
  });

  it('refuses a cross-origin submission', async () => {
    const link = await issueLink();
    const form = await openForm(link.token);

    const response = await app.inject({
      method: 'POST',
      url: `/v1/input/${link.token}`,
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: 'https://evil.example.com',
        cookie: form.cookie,
      },
      payload: new URLSearchParams({ value: newCanary(), csrf: form.csrf }).toString(),
    });

    expect(response.statusCode).toBe(403);
    expect(recorded.created).toHaveLength(0);
  });

  it('rejects an expired link', async () => {
    await app.close();
    await boot(makeConfig({ ttlSeconds: 30 }));

    const link = await issueLink();
    const form = await openForm(link.token);

    // Reach past the TTL by rewriting the stored expiry, which is what a clock
    // moving forward would look like from the store's point of view.
    store.database
      .prepare(`UPDATE one_time_requests SET expires_at = ? WHERE id = ?`)
      .run(new Date(Date.now() - 60_000).toISOString(), link.id);

    const response = await submit(link.token, newCanary(), form);
    expect(response.statusCode).toBe(410);
    expect(recorded.created).toHaveLength(0);
  });

  it('rejects an unknown token without revealing whether it ever existed', async () => {
    const unknown = await app.inject({ method: 'GET', url: '/input/definitely-not-a-real-token' });
    expect(unknown.statusCode).toBe(404);

    const link = await issueLink();
    const form = await openForm(link.token);
    await submit(link.token, newCanary(), form);

    const consumed = await app.inject({ method: 'GET', url: `/input/${link.token}` });
    // Same status and same page for "never existed" and "already used".
    expect(consumed.statusCode).toBe(404);
    expect(consumed.body).toBe(unknown.body);
  });

  it('requires the adapter credential to issue a link', async () => {
    const anonymous = await app.inject({
      method: 'POST',
      url: '/v1/requests',
      payload: { action: 'create', project: 'ezjob', environment: 'development', name: 'X_KEY' },
    });
    expect(anonymous.statusCode).toBe(401);

    const wrong = await app.inject({
      method: 'POST',
      url: '/v1/requests',
      // Marked as a placeholder rather than suppressed: the scanner only needs to see
      // that this is not a credential, and the test only needs a non-matching bearer.
      headers: { authorization: 'Bearer not-a-real-token-merely-the-wrong-one' },
      payload: { action: 'create', project: 'ezjob', environment: 'development', name: 'X_KEY' },
    });
    expect(wrong.statusCode).toBe(401);
  });

  it('serves the form with the required security headers', async () => {
    const link = await issueLink();
    const response = await app.inject({ method: 'GET', url: `/input/${link.token}` });

    expect(response.headers['cache-control']).toContain('no-store');
    expect(response.headers['referrer-policy']).toBe('no-referrer');
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-frame-options']).toBe('DENY');

    const csp = response.headers['content-security-policy'] as string;
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toMatch(/script-src 'nonce-/);
    // No unsafe-inline for scripts: the reveal toggle runs under a nonce.
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);
  });

  it('masks the value field by default and asks for no autocomplete', async () => {
    const link = await issueLink();
    const { html } = await openForm(link.token);

    expect(html).toContain('type="password"');
    expect(html).toContain('autocomplete="off"');
    expect(html).toContain('spellcheck="false"');
    expect(html).toContain('OPENAI_API_KEY');
  });

  it('rejects an oversized value without echoing it', async () => {
    await app.close();
    await boot(makeConfig({ maxValueBytes: 64 }));

    const link = await issueLink();
    const form = await openForm(link.token);
    const oversized = 'x'.repeat(200);

    const response = await submit(link.token, oversized, form);

    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain(oversized);
    expect(recorded.created).toHaveLength(0);
  });

  it('rejects an invalid reference at request creation', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/v1/requests',
      headers: { authorization: `Bearer ${ADAPTER_TOKEN}` },
      payload: {
        action: 'create',
        project: '../etc',
        environment: 'development',
        name: 'OPENAI_API_KEY',
      },
    });
    expect(response.statusCode).toBe(400);
  });

  it('never stores the value or the raw token in the database', async () => {
    const canary = newCanary();
    const link = await issueLink();
    const form = await openForm(link.token);
    await submit(link.token, canary, form);

    const rows = store.database.prepare('SELECT * FROM one_time_requests').all();
    const serialized = JSON.stringify(rows);

    expect(serialized).not.toContain(canary);
    expect(serialized).not.toContain(link.token);
    // Only the hash is there.
    expect(serialized).toMatch(/"token_hash":"[0-9a-f]{64}"/);

    const audit = store.database.prepare('SELECT * FROM audit_events').all();
    expect(JSON.stringify(audit)).not.toContain(canary);
  });

  it('reports request status as metadata only', async () => {
    const link = await issueLink();
    const response = await app.inject({
      method: 'GET',
      url: `/v1/requests/${link.id}/status`,
      headers: { authorization: `Bearer ${ADAPTER_TOKEN}` },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json() as Record<string, unknown>;
    expect(body['status']).toBe('pending');
    expect(Object.keys(body)).not.toContain('tokenHash');
    expect(Object.keys(body)).not.toContain('token');
  });
});
