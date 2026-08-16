import { PATTERNS } from '@bx-labs/agent-secrets-redaction';

/**
 * The checks that run before any Telegram message is acted upon.
 *
 * Each one exists because of a specific way this channel goes wrong.
 */

/** FR-TG-001. Group chats are refused outright, not just ignored. */
export function isPrivateChat(chatType: string | undefined): boolean {
  return chatType === 'private';
}

/**
 * FR-TG-002. The allowlist is numeric Telegram user ids, never usernames.
 *
 * Usernames are reassignable: a user who releases `@antoine` frees it for
 * someone else, who would then inherit access to this bot. The numeric id is
 * permanent.
 */
export function isAllowedUser(userId: number | undefined, allowlist: readonly number[]): boolean {
  return typeof userId === 'number' && allowlist.includes(userId);
}

export interface ValueSuspicion {
  readonly suspicious: boolean;
  /** Why we think so. Shown to the user; never contains the suspect text. */
  readonly reason: string;
}

/**
 * FR-TG-013. Detect a command that appears to carry a value.
 *
 * The failure this prevents is the most likely one in the whole product: a user
 * types `/add_secret ezjob development OPENAI_API_KEY sk-...` because that is
 * how every other bot works. By the time we see it, Telegram already has it —
 * so the response is to refuse, tell the user plainly that the value must now
 * be treated as compromised, and offer to delete the message knowing that
 * deletion does not undo the exposure.
 *
 * The detection is deliberately broad. A false positive costs the user one
 * retyped command; a false negative costs them a leaked credential.
 */
export function looksLikeValue(text: string): ValueSuspicion {
  const parts = text.trim().split(/\s+/);

  // `/add_secret <project> <environment> <name>` is exactly four tokens.
  // Anything beyond that is unexpected, and the most likely fifth token is a
  // credential.
  if (parts[0]?.startsWith('/add_secret') || parts[0]?.startsWith('/rotate_secret')) {
    if (parts.length > 4) {
      return {
        suspicious: true,
        reason: 'this command takes exactly three arguments and you sent more',
      };
    }
  }

  // `NAME=VALUE` anywhere in the message.
  if (/[A-Z][A-Z0-9_]{2,}=\S+/.test(text)) {
    return { suspicious: true, reason: 'it contains a NAME=VALUE pair' };
  }

  // Any of the credential shapes the redaction package knows about.
  for (const pattern of PATTERNS) {
    // Fresh regex per test: the shared ones may carry the global flag, whose
    // lastIndex would make this check stateful across messages.
    if (new RegExp(pattern.regex.source, pattern.regex.flags.replace('g', '')).test(text)) {
      return { suspicious: true, reason: `it looks like it contains ${pattern.name}` };
    }
  }

  // A long unbroken high-entropy-looking token that is not one of our
  // arguments. Conservative bounds so ordinary words never trip it.
  if (/\b[A-Za-z0-9_\-+/=]{28,}\b/.test(text)) {
    return { suspicious: true, reason: 'it contains a long random-looking string' };
  }

  return { suspicious: false, reason: '' };
}

/**
 * A simple fixed-window rate limiter, per Telegram user.
 *
 * FR-TG-012. In-memory rather than persisted: the bot is single-tenant and a
 * restart resetting the window is not a meaningful bypass, whereas a database
 * round-trip on every message would be.
 */
export class RateLimiter {
  readonly #max: number;
  readonly #windowMs: number;
  readonly #hits = new Map<number, { count: number; resetAt: number }>();

  constructor(max = 10, windowMs = 60_000) {
    this.#max = max;
    this.#windowMs = windowMs;
  }

  check(userId: number, now = Date.now()): { allowed: boolean; retryAfterMs: number } {
    const entry = this.#hits.get(userId);
    if (!entry || entry.resetAt <= now) {
      this.#hits.set(userId, { count: 1, resetAt: now + this.#windowMs });
      return { allowed: true, retryAfterMs: 0 };
    }
    entry.count += 1;
    if (entry.count > this.#max) {
      return { allowed: false, retryAfterMs: entry.resetAt - now };
    }
    return { allowed: true, retryAfterMs: 0 };
  }

  /** Drop expired windows so a long-running bot does not grow a map forever. */
  sweep(now = Date.now()): void {
    for (const [userId, entry] of this.#hits) {
      if (entry.resetAt <= now) {
        this.#hits.delete(userId);
      }
    }
  }
}
