import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFakeBws, type FakeBws } from '@bx-labs/agent-secrets-test-helpers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { BitwardenBackend, BwsClient, SAFE_PATH } from '../../src/index.js';

/**
 * How a missing `bws` is reported, and why it is not the same thing as a
 * rejected token.
 *
 * The adapter resolves a bare executable name against `SAFE_PATH`, never
 * against the caller's `PATH`. That is a deliberate control — a poisoned PATH
 * entry is a cheap way to substitute a program that captures the access token —
 * but it means an installation in a directory the list does not cover is
 * invisible to this tool while `which bws` says everything is fine.
 *
 * `health()` must therefore say *which* failure happened. Four very different
 * problems used to arrive at the operator as one sentence blaming the token:
 * the binary was absent, the credential was refused, the endpoint was wrong, or
 * the response did not parse.
 */

describe('bws executable resolution', () => {
  let fake: FakeBws;
  let pathDir: string;
  const originalPath = process.env['PATH'];

  beforeEach(async () => {
    fake = await createFakeBws();
    // A directory that is on the *caller's* PATH and holds an executable named
    // `bws` — the shape of a `~/.local/bin` install.
    pathDir = fake.dir;
    process.env['PATH'] = `${pathDir}:${originalPath ?? ''}`;
  });

  afterEach(async () => {
    process.env['PATH'] = originalPath;
    await fake.cleanup();
  });

  const backendWith = (executable: string | undefined) =>
    new BitwardenBackend({
      client: new BwsClient({
        ...(executable === undefined ? {} : { executable }),
        accessToken: fake.token,
        projectId: fake.projectId,
        valueTransport: 'argv',
      }),
    });

  it('does not resolve a bare name against the caller PATH', () => {
    // Guards the premise of the test below: if SAFE_PATH ever grows the temp
    // directory, the assertion after it would pass for the wrong reason.
    expect(SAFE_PATH.split(':')).not.toContain(pathDir);
  });

  it('reports executable-not-found rather than a rejected token', async () => {
    const health = await backendWith(undefined).health();

    expect(health.reachable).toBe(false);
    expect(health.errorCode).toBe('BACKEND_UNAVAILABLE');
    expect(health.reason).toBe('executable-not-found');
  });

  it('succeeds when the same binary is addressed by absolute path', async () => {
    const health = await backendWith(fake.path).health();

    expect(health.reachable).toBe(true);
    expect(health.canRead).toBe(true);
    expect(health.reason).toBeUndefined();
  });

  it('reports unauthenticated when the backend refuses the token', async () => {
    await fake.revokeToken(fake.token);
    const health = await backendWith(fake.path).health();

    expect(health.reachable).toBe(false);
    expect(health.errorCode).toBe('AUTH_REQUIRED');
    expect(health.reason).toBe('unauthenticated');
  });

  it('reports incompatible-response when bws answers in an unknown shape', async () => {
    await fake.setFailure('list', 'garbage-output');
    const health = await backendWith(fake.path).health();

    expect(health.reachable).toBe(false);
    expect(health.errorCode).toBe('BACKEND_UNAVAILABLE');
    expect(health.reason).toBe('incompatible-response');
  });

  describe('the access-token shapes bws 2.x rejects locally', () => {
    let stubDir: string;

    /**
     * bws parses the access token before it opens a connection. A truncated or
     * mistyped paste never reaches the network, and the wording it produces
     * contains none of the words a naive "is this an auth failure" match looks
     * for. Classified as INTERNAL, it told the operator to file a bug; the
     * actual remedy is to paste the token again.
     */
    const stubPrinting = async (stderrLine: string): Promise<string> => {
      stubDir = await mkdtemp(join(tmpdir(), 'agent-secrets-bws-stub-'));
      const stub = join(stubDir, 'bws');
      await writeFile(
        stub,
        ['#!/bin/sh', `echo ${JSON.stringify(stderrLine)} >&2`, 'exit 1', ''].join('\n'),
        { mode: 0o755 },
      );
      await chmod(stub, 0o755);
      return stub;
    };

    afterEach(async () => {
      if (stubDir) {
        await rm(stubDir, { recursive: true, force: true });
      }
    });

    for (const line of [
      "Error:\n   0: Doesn't contain a decryption key",
      'Error:\n   0: Has the wrong number of parts',
      'Error:\n   0: Invalid base64 length: expected 16, got 36',
      'Error:\n   0: Missing access token',
    ]) {
      it(`classifies ${JSON.stringify(line.split(': ').pop())} as unauthenticated`, async () => {
        const stub = await stubPrinting(line);
        const health = await new BitwardenBackend({
          client: new BwsClient({
            executable: stub,
            accessToken: fake.token,
            projectId: fake.projectId,
            valueTransport: 'argv',
          }),
        }).health();

        expect(health.errorCode).toBe('AUTH_REQUIRED');
        expect(health.reason).toBe('unauthenticated');
      });
    }
  });
});
