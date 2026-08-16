import type { BackendHealth } from '@bx-labs/agent-secrets-core';
import { describe, expect, it } from 'vitest';
import { enrolmentFailure, resolveBwsExecutable } from '../../src/index.js';

/**
 * `init` used to answer every failed probe with one sentence:
 *
 *     The backend rejected this token, or is unreachable.
 *     Check the token and the project ID. Nothing was saved.
 *
 * Four unrelated causes arrived there — the `bws` binary was not on the
 * adapter's search path, the credential was refused, the endpoint was wrong,
 * the response did not parse — and the sentence blamed the one thing the
 * operator cannot check without pasting it somewhere. It also exited 3
 * (AUTH_REQUIRED) for conditions that `docs/exit-codes.md` assigns to 7.
 *
 * These tests pin one message and one exit code per cause. What they must never
 * do is start carrying backend text: every message here is a constant.
 */

const health = (overrides: Partial<BackendHealth>): BackendHealth => ({
  reachable: false,
  canRead: false,
  canWrite: false,
  latencyMs: 1,
  ...overrides,
});

describe('enrolmentFailure', () => {
  it('names the missing executable, and exits 7 rather than 3', () => {
    const error = enrolmentFailure(
      health({ errorCode: 'BACKEND_UNAVAILABLE', reason: 'executable-not-found' }),
    );

    expect(error.exitCode).toBe(7);
    expect(error.code).toBe('BACKEND_UNAVAILABLE');
    expect(error.message).toContain('bws');
    expect(error.message).not.toMatch(/token/i);
    expect(error.hint).toMatch(/AGENT_SECRETS_BWS_PATH|--executable-path/);
  });

  it('blames the token only when the backend actually refused it', () => {
    const error = enrolmentFailure(
      health({ errorCode: 'AUTH_REQUIRED', reason: 'unauthenticated' }),
    );

    expect(error.exitCode).toBe(3);
    expect(error.message).toMatch(/token/i);
  });

  it('separates a grant problem from a bad token', () => {
    const error = enrolmentFailure(
      health({ errorCode: 'AUTH_REQUIRED', reason: 'permission-denied' }),
    );

    expect(error.exitCode).toBe(3);
    expect(error.message).toMatch(/permission/i);
    expect(error.hint).toMatch(/project/i);
  });

  it('points at the endpoint when the backend is unreachable', () => {
    const error = enrolmentFailure(
      health({ errorCode: 'BACKEND_UNAVAILABLE', reason: 'unreachable' }),
    );

    expect(error.exitCode).toBe(7);
    expect(error.message).not.toMatch(/rejected/i);
    expect(error.hint).toMatch(/--server-url/);
  });

  it('says so when the response shape is not understood', () => {
    const error = enrolmentFailure(
      health({ errorCode: 'BACKEND_UNAVAILABLE', reason: 'incompatible-response' }),
    );

    expect(error.exitCode).toBe(7);
    expect(error.message).toMatch(/format|shape/i);
    expect(error.hint).toMatch(/bws/);
  });

  it('reports a reachable backend that cannot see the configured project', () => {
    const error = enrolmentFailure(health({ reachable: true, canRead: false, latencyMs: 4 }));

    expect(error.exitCode).toBe(5);
    expect(error.message).toMatch(/project/i);
    expect(error.message).not.toMatch(/rejected/i);
  });

  it('returns null when the probe succeeded', () => {
    expect(enrolmentFailure(health({ reachable: true, canRead: true, canWrite: true }))).toBeNull();
  });

  it('never embeds a backend message, whatever the reason is', () => {
    const error = enrolmentFailure(health({ errorCode: 'INTERNAL', reason: 'unknown' }));

    expect(error).not.toBeNull();
    expect(error?.message).toMatch(/backend/i);
  });
});

describe('resolveBwsExecutable', () => {
  it('prefers an explicit --executable-path', () => {
    expect(resolveBwsExecutable({ AGENT_SECRETS_BWS_PATH: '/env/bws' }, '/flag/bws')).toBe(
      '/flag/bws',
    );
  });

  it('honours AGENT_SECRETS_BWS_PATH, which DOC.md has always documented', () => {
    expect(resolveBwsExecutable({ AGENT_SECRETS_BWS_PATH: '/env/bws' })).toBe('/env/bws');
  });

  it('falls back to undefined so the adapter keeps its own default', () => {
    expect(resolveBwsExecutable({})).toBeUndefined();
  });

  it('ignores a blank variable rather than spawning an empty path', () => {
    expect(resolveBwsExecutable({ AGENT_SECRETS_BWS_PATH: '   ' })).toBeUndefined();
  });

  it('falls back to the variable when the pinned path is blank', () => {
    expect(resolveBwsExecutable({ AGENT_SECRETS_BWS_PATH: '/env/bws' }, '  ')).toBe('/env/bws');
  });

  /**
   * The precedence that matters for security, pinned so it is not quietly
   * reversed: an enrolled path is a reviewed decision in a 0600 file, and an
   * environment variable — ambient, inherited by every process — must not be
   * able to redirect the binary that receives the access token. The variable
   * fills a gap; it does not override a choice.
   */
  it('does not let the environment override a path pinned at enrolment', () => {
    expect(resolveBwsExecutable({ AGENT_SECRETS_BWS_PATH: '/attacker/bws' }, '/enrolled/bws')).toBe(
      '/enrolled/bws',
    );
  });
});
