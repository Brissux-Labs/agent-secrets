import { makeRef, makeScope, SecretValue } from '@bx-labs/agent-secrets-core';
import { newCanary } from '@bx-labs/agent-secrets-redaction';
import { createFakeBws, type FakeBws } from '@bx-labs/agent-secrets-test-helpers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { BitwardenBackend, BwsClient, keyOf } from '../../src/index.js';

/**
 * The Bitwarden adapter, driven against a fake `bws` executable.
 *
 * These tests are the ones that would catch the failures that matter: a value
 * reaching argv on a read path, a backend error message carrying a canary
 * through to a thrown error, a device token that was revoked still working.
 * They run entirely offline and never touch a real vault.
 */

const REF = makeRef({ project: 'ezjob', environment: 'development', name: 'OPENAI_API_KEY' });
const SCOPE = makeScope({ project: 'ezjob', environment: 'development' });

describe('BitwardenBackend against a fake bws', () => {
  let fake: FakeBws;

  const backendFor = (bws: FakeBws, overrides: Record<string, unknown> = {}) =>
    new BitwardenBackend({
      client: new BwsClient({
        executable: bws.path,
        accessToken: bws.token,
        projectId: bws.projectId,
        // Pinned so the capability probe does not run: the fake has no
        // `--value-stdin`, and we assert the argv behaviour deliberately below.
        valueTransport: 'argv',
        ...overrides,
      }),
    });

  beforeEach(async () => {
    fake = await createFakeBws();
  });

  afterEach(async () => {
    await fake.cleanup();
  });

  it('creates, describes, lists, updates and deletes a secret', async () => {
    const backend = backendFor(fake);
    const canary = newCanary();

    const created = await backend.create(REF, SecretValue.from(canary), {
      description: 'test key',
      provider: 'openai',
      tags: ['test'],
    });

    expect(created.name).toBe('OPENAI_API_KEY');
    expect(created.reference).toBe('bitwarden/ezjob/development/OPENAI_API_KEY');
    expect(created.description).toBe('test key');
    expect(created.provider).toBe('openai');
    // Metadata must not carry anything value-derived, whatever the backend sent.
    expect(JSON.stringify(created)).not.toContain(canary);

    const described = await backend.describe(REF);
    expect(described?.name).toBe('OPENAI_API_KEY');

    const listed = await backend.list(SCOPE);
    expect(listed.map((item) => item.name)).toEqual(['OPENAI_API_KEY']);

    const rotated = newCanary();
    await backend.update(REF, SecretValue.from(rotated));

    const [resolved] = await backend.resolveMany([REF]);
    expect(resolved?.value.expose()).toBe(rotated);

    await backend.delete(REF);
    expect(await backend.describe(REF)).toBeNull();
  });

  it('encodes the canonical scope in the Bitwarden key', async () => {
    const backend = backendFor(fake);
    await backend.create(REF, SecretValue.from(newCanary()));

    const state = await fake.readState();
    expect(state.secrets.map((secret) => secret.key)).toContain('ezjob/development/OPENAI_API_KEY');
    expect(keyOf(REF)).toBe('ezjob/development/OPENAI_API_KEY');
  });

  it('keeps different environments separate under the same project', async () => {
    const backend = backendFor(fake);
    const devRef = makeRef({ project: 'ezjob', environment: 'development', name: 'SHARED_KEY' });
    const prodRef = makeRef({ project: 'ezjob', environment: 'production', name: 'SHARED_KEY' });

    await backend.create(devRef, SecretValue.from(newCanary()));
    await backend.create(prodRef, SecretValue.from(newCanary()));

    const devList = await backend.list(SCOPE);
    expect(devList).toHaveLength(1);
    expect(devList[0]?.environment).toBe('development');
  });

  it('never puts a value in argv on a read path', async () => {
    const backend = backendFor(fake);
    const canary = newCanary();
    await backend.create(REF, SecretValue.from(canary));

    await backend.list(SCOPE);
    await backend.describe(REF);
    await backend.resolveMany([REF]);

    const calls = await fake.calls();
    const readCalls = calls.filter(
      (call) => call.argv[0] === 'secret' && call.argv[1] !== 'create' && call.argv[1] !== 'edit',
    );
    expect(readCalls.length).toBeGreaterThan(0);
    for (const call of readCalls) {
      expect(call.argv.join(' ')).not.toContain(canary);
    }
  });

  it('passes the access token by environment, never by argv', async () => {
    const backend = backendFor(fake);
    await backend.list(SCOPE);

    const calls = await fake.calls();
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      expect(call.argv.join(' ')).not.toContain(fake.token);
      expect(call.tokenPresent).toBe(true);
      expect(call.tokenMatched).toBe(true);
    }
  });

  it('rejects a revoked device token while another device keeps working', async () => {
    const twoDevices = await createFakeBws({
      tokens: ['fake-token-mac-mini', 'fake-token-macbook'],
    });
    try {
      const macMini = new BitwardenBackend({
        client: new BwsClient({
          executable: twoDevices.path,
          accessToken: 'fake-token-mac-mini',
          projectId: twoDevices.projectId,
          valueTransport: 'argv',
        }),
      });
      const macBook = new BitwardenBackend({
        client: new BwsClient({
          executable: twoDevices.path,
          accessToken: 'fake-token-macbook',
          projectId: twoDevices.projectId,
          valueTransport: 'argv',
        }),
      });

      await macMini.create(REF, SecretValue.from(newCanary()));
      expect(await macBook.describe(REF)).not.toBeNull();

      await twoDevices.revokeToken('fake-token-mac-mini');

      await expect(macMini.list(SCOPE)).rejects.toMatchObject({ code: 'AUTH_REQUIRED' });
      // The revocation is per device: the other Mac is untouched.
      expect(await macBook.describe(REF)).not.toBeNull();
    } finally {
      await twoDevices.cleanup();
    }
  });

  it('never surfaces a canary that the backend printed on stderr', async () => {
    const stderrCanary = newCanary();
    const leaky = await createFakeBws({
      failOn: 'list',
      failureMode: 'network',
      stderrCanary,
    });
    try {
      const backend = backendFor(leaky);
      const error = await backend.list(SCOPE).catch((caught: unknown) => caught);

      const serialized = `${String(error)} ${JSON.stringify(error, Object.getOwnPropertyNames(error))}`;
      expect(serialized).not.toContain(stderrCanary);
    } finally {
      await leaky.cleanup();
    }
  });

  it('fails closed when the backend returns output that is not JSON', async () => {
    const garbled = await createFakeBws({ failOn: 'list', failureMode: 'garbage-output' });
    try {
      const backend = backendFor(garbled);
      await expect(backend.list(SCOPE)).rejects.toMatchObject({ code: 'BACKEND_UNAVAILABLE' });
    } finally {
      await garbled.cleanup();
    }
  });

  it('reports an unreachable backend through health() rather than throwing', async () => {
    const down = await createFakeBws({ failOn: 'list', failureMode: 'network' });
    try {
      const health = await backendFor(down).health();
      expect(health.reachable).toBe(false);
      expect(health.canWrite).toBe(false);
    } finally {
      await down.cleanup();
    }
  });

  it('refuses to resolve a secret that does not exist instead of returning an empty value', async () => {
    const backend = backendFor(fake);
    await expect(backend.resolveMany([REF])).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('refuses to create a secret that already exists', async () => {
    const backend = backendFor(fake);
    await backend.create(REF, SecretValue.from(newCanary()));
    await expect(backend.create(REF, SecretValue.from(newCanary()))).rejects.toMatchObject({
      code: 'CONFLICT',
    });
  });

  it('refuses to update a secret that does not exist', async () => {
    const backend = backendFor(fake);
    await expect(backend.update(REF, SecretValue.from(newCanary()))).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
  });
});
