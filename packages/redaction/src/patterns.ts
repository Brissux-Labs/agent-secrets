import { REDACTION_TOKEN } from './scope.js';

/**
 * Pattern redaction: the net for credentials we were never told about.
 *
 * Exact-match redaction (scope.ts) covers the values this process is brokering.
 * It cannot cover a token the agent obtained elsewhere and then echoed into a
 * log line, nor one that a subprocess printed on its own. That is what this file
 * is for.
 *
 * Two rules govern what is allowed in here:
 *
 *  1. **High confidence only.** Every entry keys off a vendor-assigned prefix or
 *     an unmistakable structure. There is no "long high-entropy string" rule:
 *     entropy heuristics redact commit hashes, UUIDs, minified code and base64
 *     images, and a product that mangles ordinary output gets its redaction
 *     turned off — which is a far worse outcome than missing an exotic token.
 *  2. **Bounded matching.** Every quantifier is either bounded or applied to a
 *     character class that cannot overlap with what follows it, so no input can
 *     drive the matcher into exponential backtracking. Redaction runs on
 *     attacker-influenced text (subprocess output, backend responses); a ReDoS
 *     here is a denial of service on the whole CLI.
 */

export interface CredentialPattern {
  /** Stable identifier, used in tests and never emitted into redacted output. */
  readonly name: string;
  /** Global-flagged matcher. Safe to share: `String.replace` resets lastIndex. */
  readonly regex: RegExp;
  /**
   * Replacement template. Defaults to the bare token. Patterns that match a
   * label plus its value keep the label (`$1`) so an operator can still tell
   * *which* header was scrubbed.
   */
  readonly replacement?: string;
}

export const PATTERNS: readonly CredentialPattern[] = [
  {
    // Ordered before the OpenAI rule: `sk-ant-...` also satisfies `sk-`, and
    // matching the more specific shape first keeps attribution honest.
    name: 'anthropic-api-key',
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,200}/g,
  },
  {
    // Two shapes. The project/service form allows `-` and `_` because the
    // segment separator is a hyphen; the classic form does not, which is what
    // stops `sk-this-is-just-a-hyphenated-word` from being redacted.
    name: 'openai-api-key',
    regex: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,200}|\bsk-[A-Za-z0-9]{32,200}/g,
  },
  {
    // Classic PATs are 40 chars total; fine-grained `github_pat_` tokens are 82+.
    name: 'github-token',
    regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g,
  },
  {
    // AWS key ids are exactly 20 characters: a 4-char type prefix plus 16.
    name: 'aws-access-key-id',
    regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
  },
  {
    name: 'slack-token',
    regex: /\bxox[baprse]-[A-Za-z0-9-]{10,255}/g,
  },
  {
    // Only the secret and restricted keys. `pk_live_` is publishable by design
    // and redacting it would corrupt legitimate configuration output.
    name: 'stripe-secret-key',
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,120}\b/g,
  },
  {
    // Fixed 39-char length. The trailing lookahead is used instead of `\b`
    // because the alphabet includes `-`, after which `\b` behaves inconsistently.
    name: 'google-api-key',
    regex: /\bAIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g,
  },
  {
    // `<bot id>:<35-char secret>`. The exact length plus the trailing lookahead
    // keeps ordinary `number:word` text (timestamps, ratios) out of the net.
    name: 'telegram-bot-token',
    regex: /\b\d{6,12}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g,
  },
  {
    // ReDoS note: the body is a lazy quantifier with an explicit 64 KiB bound, so
    // a stream of `-----BEGIN ... PRIVATE KEY-----` headers with no terminator
    // costs a bounded scan per header instead of running to end-of-input each
    // time. The `|$)` alternative deliberately still redacts a *truncated* block:
    // half a private key is as disclosing as all of it.
    name: 'private-key-pem',
    regex:
      /-----BEGIN [A-Z ]{0,32}PRIVATE KEY-----[\s\S]{0,65536}?(?:-----END [A-Z ]{0,32}PRIVATE KEY-----|$)/g,
  },
  {
    // Anchored on `eyJ`, the base64 of `{"`. A generic "three base64url segments"
    // rule matches ordinary dotted identifiers and file paths; the header anchor
    // is what makes this safe to run on arbitrary text. No ReDoS: the segment
    // class excludes `.`, so the separators partition the match unambiguously.
    name: 'jwt',
    regex: /\beyJ[A-Za-z0-9_-]{10,4096}\.[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{0,4096}/g,
  },
  {
    // Bitwarden Secrets Manager machine-account token: `0.<uuid>.<base64>`.
    name: 'bitwarden-access-token',
    regex:
      /\b0\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[A-Za-z0-9+/=_-]{20,512}/g,
  },
  {
    // Keeps the scheme and the header name, drops the credential. The header
    // prefix is optional because `-H "Authorization: Bearer ..."` is only one of
    // the shapes this appears in; the 16-character floor is what stops "Basic
    // authentication" style prose from matching.
    name: 'authorization-header',
    regex:
      /((?:(?:Proxy-)?Authorization\s*:\s*)?(?:Bearer|Basic)\s+)([A-Za-z0-9._~+/=-]{16,4096})/gi,
    replacement: `$1${REDACTION_TOKEN}`,
  },
] as const;

/**
 * Apply every pattern. Order is fixed by the array: a value matched by an
 * earlier, more specific rule is already a token by the time later rules run.
 */
export function redactPatterns(text: string): string {
  if (typeof text !== 'string' || text.length === 0) {
    return text;
  }
  let out = text;
  for (const pattern of PATTERNS) {
    out = out.replace(pattern.regex, pattern.replacement ?? REDACTION_TOKEN);
  }
  return out;
}
