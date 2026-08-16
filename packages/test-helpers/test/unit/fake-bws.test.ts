import { afterEach, describe, expect, it } from 'vitest';
import { makeCanary, sweepForCanary } from '../../src/canary.js';
import { runProcess } from '../../src/capture.js';
import {
  createFakeBws,
  FAKE_BWS_FAILURE_MESSAGES,
  FAKE_BWS_VERSION,
  type FakeBws,
  type FakeBwsSecret,
} from '../../src/fake-bws.js';

const created: FakeBws[] = [];

async function fakeBws(...args: Parameters<typeof createFakeBws>): Promise<FakeBws> {
  const fake = await createFakeBws(...args);
  created.push(fake);
  return fake;
}

afterEach(async () => {
  while (created.length > 0) {
    const fake = created.pop();
    await fake?.cleanup();
  }
});

function bws(fake: FakeBws, args: string[], token: string = fake.token) {
  return runProcess(fake.path, args, { env: { BWS_ACCESS_TOKEN: token }, timeoutMs: 15_000 });
}

describe('createFakeBws — CRUD surface', () => {
  it('reports a version without needing a token', async () => {
    const fake = await fakeBws();
    const result = await runProcess(fake.path, ['--version'], { env: {} });
    expect(result.code).toBe(0);
    expect(result.stdout.trim()).toBe(FAKE_BWS_VERSION);
  });

  it('creates, lists, gets, edits and deletes a secret', async () => {
    const fake = await fakeBws();
    const canary = makeCanary();

    const createResult = await bws(fake, [
      'secret',
      'create',
      'OPENAI_API_KEY',
      canary,
      fake.projectId,
      '--output',
      'json',
    ]);
    expect(createResult.code).toBe(0);
    const createdSecret = JSON.parse(createResult.stdout) as FakeBwsSecret;
    expect(createdSecret.key).toBe('OPENAI_API_KEY');
    expect(createdSecret.value).toBe(canary);
    expect(createdSecret.projectId).toBe(fake.projectId);
    expect(createdSecret.organizationId).toBe(fake.organizationId);
    expect(createdSecret.note).toBe('');
    // Sub-millisecond precision, as the real Rust binary emits.
    expect(createdSecret.creationDate).toMatch(/\.\d{6}Z$/);

    const listResult = await bws(fake, ['secret', 'list', fake.projectId, '--output', 'json']);
    expect(listResult.code).toBe(0);
    const listed = JSON.parse(listResult.stdout) as FakeBwsSecret[];
    expect(listed.map((secret) => secret.id)).toEqual([createdSecret.id]);

    const getResult = await bws(fake, ['secret', 'get', createdSecret.id, '--output', 'json']);
    expect(getResult.code).toBe(0);
    expect((JSON.parse(getResult.stdout) as FakeBwsSecret).id).toBe(createdSecret.id);

    const rotated = makeCanary();
    const editResult = await bws(fake, [
      'secret',
      'edit',
      createdSecret.id,
      '--key',
      'OPENAI_API_KEY',
      '--value',
      rotated,
      '--output',
      'json',
    ]);
    expect(editResult.code).toBe(0);
    const editedSecret = JSON.parse(editResult.stdout) as FakeBwsSecret;
    expect(editedSecret.value).toBe(rotated);
    expect(editedSecret.id).toBe(createdSecret.id);
    expect((await fake.readState()).secrets[0]?.value).toBe(rotated);

    const deleteResult = await bws(fake, [
      'secret',
      'delete',
      createdSecret.id,
      '--output',
      'json',
    ]);
    expect(deleteResult.code).toBe(0);
    expect(JSON.parse(deleteResult.stdout)).toEqual([{ id: createdSecret.id, error: null }]);
    expect((await fake.readState()).secrets).toEqual([]);
  });

  it('lists projects and fails a get on an unknown id', async () => {
    const fake = await fakeBws();
    const projects = await bws(fake, ['project', 'list', '--output', 'json']);
    expect(projects.code).toBe(0);
    expect(JSON.parse(projects.stdout)).toHaveLength(1);

    const missing = await bws(fake, ['secret', 'get', 'no-such-id', '--output', 'json']);
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain('Resource not found.');
  });

  it('seeds a secret directly into the vault', async () => {
    const fake = await fakeBws();
    const seeded = await fake.seedSecret({ key: 'STRIPE_SECRET_KEY', value: makeCanary() });
    const listResult = await bws(fake, ['secret', 'list', '--output', 'json']);
    expect((JSON.parse(listResult.stdout) as FakeBwsSecret[])[0]?.id).toBe(seeded.id);
  });
});

describe('createFakeBws — authentication', () => {
  it('rejects a missing token', async () => {
    const fake = await fakeBws();
    const result = await runProcess(fake.path, ['secret', 'list', '--output', 'json'], { env: {} });
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('access token is not set');
    expect(result.stdout).toBe('');
  });

  it('rejects a token that is not configured', async () => {
    const fake = await fakeBws();
    const result = await bws(fake, ['secret', 'list', '--output', 'json'], 'not-the-token');
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('Access token is not valid.');
  });

  it('refuses a token passed as a command-line argument', async () => {
    const fake = await fakeBws();
    const result = await bws(fake, [
      'secret',
      'list',
      '--access-token',
      fake.token,
      '--output',
      'json',
    ]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('refuses an access token on the command line');
  });

  it('revokes one device token while the other keeps working', async () => {
    const fake = await fakeBws({ tokens: ['token-device-one', 'token-device-two'] });

    expect((await bws(fake, ['secret', 'list', '--output', 'json'], 'token-device-one')).code).toBe(
      0,
    );

    await fake.revokeToken('token-device-one');

    const revoked = await bws(fake, ['secret', 'list', '--output', 'json'], 'token-device-one');
    expect(revoked.code).toBe(1);
    expect(revoked.stderr).toContain('Access token is not valid.');

    const survivor = await bws(fake, ['secret', 'list', '--output', 'json'], 'token-device-two');
    expect(survivor.code).toBe(0);

    const state = await fake.readState();
    expect(state.tokens).toEqual(['token-device-two']);
    expect(state.revokedTokens).toEqual(['token-device-one']);
  });
});

describe('createFakeBws — call recording', () => {
  it('records argv, cwd and token presence for every invocation', async () => {
    const fake = await fakeBws();
    await bws(fake, ['secret', 'list', '--output', 'json']);
    await bws(fake, ['secret', 'get', 'missing', '--output', 'json'], 'wrong-token');

    const calls = await fake.calls();
    expect(calls).toHaveLength(2);
    expect(calls[0]?.argv).toEqual(['secret', 'list', '--output', 'json']);
    expect(calls[0]?.tokenPresent).toBe(true);
    expect(calls[0]?.tokenMatched).toBe(true);
    expect(calls[0]?.cwd.length).toBeGreaterThan(0);
    // A rejected invocation is still recorded: that is how a test proves the
    // adapter attempted the call at all.
    expect(calls[1]?.tokenPresent).toBe(true);
    expect(calls[1]?.tokenMatched).toBe(false);
    expect(calls[1]?.argv).toEqual(['secret', 'get', 'missing', '--output', 'json']);
  });

  it('never writes the access token into the call log', async () => {
    const fake = await fakeBws({ tokens: ['token-not-in-the-log'] });
    await bws(fake, ['secret', 'list', '--output', 'json'], 'token-not-in-the-log');
    const raw = await fake.calls();
    expect(JSON.stringify(raw)).not.toContain('token-not-in-the-log');
  });

  it('masks a registered value in the recorded argv and reports its position', async () => {
    const canary = makeCanary();
    const fake = await fakeBws({ redactArgv: [canary] });
    await bws(fake, ['secret', 'create', 'OPENAI_API_KEY', canary, fake.projectId]);

    const call = (await fake.calls())[0];
    expect(call?.argv).toEqual([
      'secret',
      'create',
      'OPENAI_API_KEY',
      '[redacted]',
      fake.projectId,
    ]);
    expect(call?.argvRedactions).toEqual([3]);
  });

  it('keeps the value out of every file except the vault state', async () => {
    const canary = makeCanary();
    const fake = await fakeBws({ redactArgv: [canary] });
    const create = await bws(fake, [
      'secret',
      'create',
      'OPENAI_API_KEY',
      canary,
      fake.projectId,
      '--output',
      'json',
    ]);

    const sweep = await sweepForCanary(canary, {
      dirs: [fake.dir],
      allow: [fake.statePath],
      streams: { stderr: create.stderr },
    });
    expect(sweep.hits).toEqual([]);
    expect(sweep.allowed).toEqual([fake.statePath]);
  });
});

describe('createFakeBws — injected failures', () => {
  it('emits a network failure only for the targeted operation', async () => {
    const fake = await fakeBws({ failOn: 'list', failureMode: 'network' });

    const failed = await bws(fake, ['secret', 'list', '--output', 'json']);
    expect(failed.code).toBe(1);
    expect(failed.stderr.trim()).toBe(FAKE_BWS_FAILURE_MESSAGES.network);

    const unaffected = await bws(fake, ['secret', 'get', 'missing', '--output', 'json']);
    expect(unaffected.stderr).toContain('Resource not found.');
  });

  it('emits an auth failure and a rate-limit failure', async () => {
    const fake = await fakeBws({ failOn: 'create', failureMode: 'auth' });
    const authFailure = await bws(fake, ['secret', 'create', 'K', 'v', fake.projectId]);
    expect(authFailure.code).toBe(1);
    expect(authFailure.stderr.trim()).toBe(FAKE_BWS_FAILURE_MESSAGES.auth);

    await fake.setFailure('delete', 'ratelimit');
    const rateLimited = await bws(fake, ['secret', 'delete', 'anything']);
    expect(rateLimited.code).toBe(1);
    expect(rateLimited.stderr.trim()).toBe(FAKE_BWS_FAILURE_MESSAGES.ratelimit);
  });

  it('emits non-JSON on stdout with a zero exit for garbage-output', async () => {
    const fake = await fakeBws({ failOn: 'list', failureMode: 'garbage-output' });
    const result = await bws(fake, ['secret', 'list', '--output', 'json']);
    // Exit 0 plus unparseable stdout: the shape that defeats a parser which only
    // checks the exit code.
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('502 Bad Gateway');
    expect(() => JSON.parse(result.stdout)).toThrow();
  });

  it('hangs until the caller gives up', async () => {
    const fake = await fakeBws({ failOn: 'update', failureMode: 'hang', hangMs: 30_000 });
    const result = await runProcess(fake.path, ['secret', 'edit', 'anything', '--value', 'x'], {
      env: { BWS_ACCESS_TOKEN: fake.token },
      timeoutMs: 400,
    });
    expect(result.timedOut).toBe(true);
    expect(result.stdout).toBe('');
  });

  it('can be turned off again', async () => {
    const fake = await fakeBws({ failOn: 'list', failureMode: 'network' });
    expect((await bws(fake, ['secret', 'list', '--output', 'json'])).code).toBe(1);
    await fake.setFailure(null);
    expect((await bws(fake, ['secret', 'list', '--output', 'json'])).code).toBe(0);
  });

  it('prints the stderr canary even on a successful invocation', async () => {
    const stderrCanary = makeCanary();
    const fake = await fakeBws({ stderrCanary });
    const result = await bws(fake, ['secret', 'list', '--output', 'json']);
    expect(result.code).toBe(0);
    expect(result.stderr).toContain(stderrCanary);
    // stdout stays clean, so an adapter that forwards stderr into its result is
    // the only way this canary can escape.
    expect(result.stdout).not.toContain(stderrCanary);
  });

  it('rejects an output format it does not implement', async () => {
    const fake = await fakeBws();
    const result = await bws(fake, ['secret', 'list', '--output', 'table']);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('only implements --output json');
  });
});
