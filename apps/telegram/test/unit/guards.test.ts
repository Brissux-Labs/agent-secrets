import { newCanary } from '@bx-labs/agent-secrets-redaction';
import { describe, expect, it } from 'vitest';
import { isAllowedUser, isPrivateChat, looksLikeValue, RateLimiter } from '../../src/guards.js';

/**
 * The Telegram guards.
 *
 * `looksLikeValue` gets the most attention here because it is the check with
 * the worst failure mode in the product: a miss means a live credential is
 * already in Telegram's servers by the time we notice.
 */

describe('isPrivateChat', () => {
  it('accepts only private chats', () => {
    expect(isPrivateChat('private')).toBe(true);
    expect(isPrivateChat('group')).toBe(false);
    expect(isPrivateChat('supergroup')).toBe(false);
    expect(isPrivateChat('channel')).toBe(false);
    expect(isPrivateChat(undefined)).toBe(false);
  });
});

describe('isAllowedUser', () => {
  const allowlist = [123456, 789012];

  it('accepts a listed numeric id', () => {
    expect(isAllowedUser(123456, allowlist)).toBe(true);
  });

  it('rejects an unlisted id, an undefined id, and an empty allowlist', () => {
    expect(isAllowedUser(999999, allowlist)).toBe(false);
    expect(isAllowedUser(undefined, allowlist)).toBe(false);
    expect(isAllowedUser(123456, [])).toBe(false);
  });

  it('does not coerce a string id into a match', () => {
    // Telegram ids arrive as numbers; a string reaching here would mean
    // something upstream changed, and a loose comparison would let it through.
    expect(isAllowedUser('123456' as unknown as number, allowlist)).toBe(false);
  });
});

describe('looksLikeValue', () => {
  it('accepts a well-formed metadata-only command', () => {
    expect(looksLikeValue('/add_secret ezjob development OPENAI_API_KEY').suspicious).toBe(false);
    expect(looksLikeValue('/rotate_secret payments production STRIPE_SECRET_KEY').suspicious).toBe(
      false,
    );
    expect(looksLikeValue('/secret_status').suspicious).toBe(false);
    expect(looksLikeValue('/help').suspicious).toBe(false);
  });

  it('flags a fourth argument on an add command', () => {
    const result = looksLikeValue('/add_secret ezjob development OPENAI_API_KEY sk-something');
    expect(result.suspicious).toBe(true);
    expect(result.reason).toContain('three arguments');
  });

  it('flags NAME=VALUE syntax anywhere in the message', () => {
    expect(looksLikeValue('OPENAI_API_KEY=abc123def456').suspicious).toBe(true);
    expect(looksLikeValue('/add_secret OPENAI_API_KEY=abc123def456').suspicious).toBe(true);
  });

  // The four fixtures below are alphabet runs, not credentials. They keep the real
  // vendor prefixes on purpose: the guard matches on shape alone, so a fixture carrying
  // a placeholder marker would prove nothing about the shapes that actually leak.
  it.each([
    // agent-secrets:allow-secret-scan alphabet run behind a real prefix, no key material
    ['an OpenAI-shaped key', 'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'],
    // agent-secrets:allow-secret-scan alphabet run behind a real prefix, no key material
    ['a GitHub-shaped token', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789AB'],
    ['an AWS-shaped access key id', 'AKIAIOSFODNN7EXAMPLE'],
    // Assembled at runtime for the same reason as in patterns.test.ts: the
    // literal form matches GitHub's Slack detector.
    [
      'a Slack-shaped token',
      ['xoxb', '0'.repeat(12), '0'.repeat(12), 'abcdefghijklmnopqrstuvwx'].join('-'),
    ],
  ])('flags %s', (_label, sample) => {
    expect(looksLikeValue(`/add_secret ezjob development KEY ${sample}`).suspicious).toBe(true);
  });

  it('flags a long random-looking string even when the shape is unknown', () => {
    // The case that matters most: a credential from a provider we have never
    // heard of. Length and character class are all we have to go on.
    expect(looksLikeValue(newCanary()).suspicious).toBe(true);
  });

  it('does not flag ordinary prose or valid arguments', () => {
    expect(looksLikeValue('/list_secrets ezjob development').suspicious).toBe(false);
    expect(looksLikeValue('how do I add a secret?').suspicious).toBe(false);
    expect(
      looksLikeValue('/add_secret my-long-project-name production DATABASE_URL').suspicious,
    ).toBe(false);
  });

  it('never repeats the suspect text in the reason it gives', () => {
    // agent-secrets:allow-secret-scan alphabet run behind a real prefix, no key material
    const secret = 'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH';
    const result = looksLikeValue(`/add_secret ezjob development KEY ${secret}`);
    expect(result.reason).not.toContain(secret);
    expect(result.reason).not.toContain('sk-proj');
  });

  it('is not stateful across calls', () => {
    // A pattern carrying the global flag would keep `lastIndex` between calls
    // and start missing every other message.
    // agent-secrets:allow-secret-scan alphabet run behind a real prefix, no key material
    const message = '/add_secret ezjob development KEY ghp_abcdefghijklmnopqrstuvwxyz0123456789AB';
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(looksLikeValue(message).suspicious).toBe(true);
    }
  });
});

describe('RateLimiter', () => {
  it('allows up to the limit and then refuses', () => {
    const limiter = new RateLimiter(3, 60_000);
    const now = 1_000_000;

    expect(limiter.check(1, now).allowed).toBe(true);
    expect(limiter.check(1, now).allowed).toBe(true);
    expect(limiter.check(1, now).allowed).toBe(true);

    const refused = limiter.check(1, now);
    expect(refused.allowed).toBe(false);
    expect(refused.retryAfterMs).toBeGreaterThan(0);
  });

  it('tracks users independently', () => {
    const limiter = new RateLimiter(1, 60_000);
    const now = 1_000_000;

    expect(limiter.check(1, now).allowed).toBe(true);
    expect(limiter.check(2, now).allowed).toBe(true);
    expect(limiter.check(1, now).allowed).toBe(false);
  });

  it('resets after the window', () => {
    const limiter = new RateLimiter(1, 60_000);
    const now = 1_000_000;

    expect(limiter.check(1, now).allowed).toBe(true);
    expect(limiter.check(1, now).allowed).toBe(false);
    expect(limiter.check(1, now + 60_001).allowed).toBe(true);
  });

  it('drops expired windows on sweep so the map does not grow forever', () => {
    const limiter = new RateLimiter(1, 1000);
    const now = 1_000_000;
    for (let userId = 0; userId < 100; userId += 1) {
      limiter.check(userId, now);
    }
    limiter.sweep(now + 5000);
    // After a sweep, a previously-limited user starts fresh.
    expect(limiter.check(0, now + 5000).allowed).toBe(true);
  });
});
