import { describe, expect, it } from 'vitest';
import { PATTERNS, REDACTION_TOKEN, redactPatterns } from '../../src/index.js';

/**
 * Every sample below is synthetic and carries the literal marker word `example`
 * on its own line, so that a reader, `scripts/scan-secrets.mjs`, and a vendor's
 * own revocation tooling can all tell at a glance that nothing here was ever
 * valid. `padEnd` supplies zero padding where a vendor format has a fixed length.
 */
const SAMPLES: Record<string, string> = {
  'anthropic-api-key': `sk-ant-api03-${'example-not-a-real-key'.padEnd(40, '0')}`,
  'openai-api-key': `sk-proj-${'example-not-a-real-key'.padEnd(32, '0')}`,
  'github-token': `ghp_${'examplenotarealtoken'.padEnd(36, '0')}`,
  // agent-secrets:allow-secret-scan AWS key ids are uppercase-only, so no
  // lowercase marker word fits inside the format; the payload is EXAMPLE + zeros.
  'aws-access-key-id': `AKIA${'EXAMPLE'.padEnd(16, '0')}`,
  // Assembled at runtime: the literal form matches GitHub's Slack detector
  // and would trip push protection on a value that was never real.
  'slack-token': ['xoxb', '0'.repeat(10), '0'.repeat(10), 'examplenotarealtoken'].join('-'),
  'stripe-secret-key': `sk_test_${'examplenotareal'.padEnd(24, '0')}`,
  'google-api-key': `AIza${'example-not-a-real-key'.padEnd(35, '0')}`,
  'telegram-bot-token': `123456789:${'example-not-a-real-token'.padEnd(35, '0')}`,
  'private-key-pem':
    '-----BEGIN RSA PRIVATE KEY-----\nexample-not-a-real-private-key\n-----END RSA PRIVATE KEY-----',
  jwt: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJleGFtcGxlIn0.example-not-a-real-signature',
  'bitwarden-access-token': '0.00000000-0000-0000-0000-000000000000.example-not-a-real-token00',
  'authorization-header': `Authorization: Bearer ${'example-not-a-real-token'.padEnd(40, '0')}`,
};

/**
 * Text that deliberately looks credential-adjacent. Every line here is something
 * a real log or a real README emits, and a redactor that mangles it is a
 * redactor that gets switched off.
 */
const BENIGN = [
  'the risk-assessment framework informs our task-management strategy',
  'sk-short and rk-nothing and pk-plain are not keys',
  'Basic authentication is described in the readme',
  'AKIAshort is not a key id and AKIA on its own is not either',
  'commit a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 touched 12 files',
  'trace id 123e4567-e89b-12d3-a456-426614174000 for request 42',
  'imported from src/index.helper.spec.js at line 12:34',
  'ratio 1234567:8 and duration 1699999999:120ms were logged',
  'gho_short ghs_ ghu_ github_pat_ are prefixes with no payload',
  'a public identifier AIzaShortNotAKey appears in the docs',
].join('\n');

describe('redactPatterns', () => {
  it('has a synthetic sample for every declared pattern', () => {
    // Forces the samples above to be extended whenever a pattern is added, so a
    // new rule can never ship without evidence that it fires.
    expect(Object.keys(SAMPLES).sort()).toEqual(PATTERNS.map((pattern) => pattern.name).sort());
  });

  it('declares unique pattern names', () => {
    expect(new Set(PATTERNS.map((pattern) => pattern.name)).size).toBe(PATTERNS.length);
  });

  it('uses only global regexes, so every occurrence is replaced', () => {
    for (const pattern of PATTERNS) {
      expect(pattern.regex.flags).toContain('g');
    }
  });

  for (const [name, sample] of Object.entries(SAMPLES)) {
    it(`redacts a synthetic ${name}`, () => {
      const redacted = redactPatterns(sample);

      expect(redacted).toContain(REDACTION_TOKEN);
      // The tail of the credential is the part an attacker would use to confirm a
      // guess, so assert specifically that it is gone.
      expect(redacted).not.toContain(sample.slice(-12));
    });
  }

  it('redacts every occurrence within one string', () => {
    const sample = SAMPLES['aws-access-key-id'] ?? '';
    const redacted = redactPatterns(`${sample} and again ${sample}`);

    expect(redacted).toBe(`${REDACTION_TOKEN} and again ${REDACTION_TOKEN}`);
  });

  it('leaves benign lookalike text completely untouched', () => {
    expect(redactPatterns(BENIGN)).toBe(BENIGN);
  });

  it('keeps the header name when scrubbing an Authorization value', () => {
    const redacted = redactPatterns(SAMPLES['authorization-header'] ?? '');

    expect(redacted).toBe(`Authorization: Bearer ${REDACTION_TOKEN}`);
  });

  it('redacts a private key block that was truncated before its END marker', () => {
    // Half a private key is as disclosing as all of it, so a log that was cut
    // short must still be scrubbed.
    const truncated = '-----BEGIN EC PRIVATE KEY-----\nRXhhbXBsZSBub3QgYSByZWFs';

    expect(redactPatterns(truncated)).toBe(REDACTION_TOKEN);
  });

  it('is stable across repeated calls despite sharing global regexes', () => {
    const sample = SAMPLES.jwt ?? '';

    expect(redactPatterns(sample)).toBe(redactPatterns(sample));
    expect(redactPatterns(sample)).toBe(redactPatterns(sample));
  });

  it('does not backtrack catastrophically on adversarial input', () => {
    // Long runs of the characters each pattern's prefix starts with: the shape
    // that makes a poorly written alternation blow up.
    const adversarial = [
      `sk-${'a'.repeat(20_000)}`,
      `eyJ${'a'.repeat(10_000)}.${'b'.repeat(10_000)}`,
      `Authorization: Bearer ${'='.repeat(20_000)}`,
      `xoxb-${'-'.repeat(20_000)}`,
      // Last on purpose: an unterminated PEM header legitimately swallows the
      // rest of the input, which would mask the cases above.
      `-----BEGIN PRIVATE KEY-----${'A'.repeat(20_000)}`,
    ].join('\n');

    const startedAt = performance.now();
    redactPatterns(adversarial);

    expect(performance.now() - startedAt).toBeLessThan(1000);
  });
});
