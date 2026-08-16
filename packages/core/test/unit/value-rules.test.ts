import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { InvalidInputError } from '../../src/errors.js';
import { SecretValue } from '../../src/secret-value.js';
import { MAX_VALUE_BYTES, validateSecretValue } from '../../src/value-rules.js';

/**
 * Validation is the one place that legitimately calls `expose()`, which makes
 * it the one place a rejection message can accidentally quote a secret. Every
 * rejection path below is therefore checked twice: once for the rule, once for
 * silence.
 */

function canary(): string {
  return `ASECRET_CANARY_${randomBytes(12).toString('hex').toUpperCase()}`;
}

/**
 * Assert that a rendered error says nothing about the value: not the value, not
 * any run of four or more of its characters, and not its length or byte length.
 * Length is included deliberately — it narrows an offline search space enough
 * that docs/logging.md classes it as disclosure.
 */
function assertCarriesNoFragment(rendered: string, raw: string): void {
  // A value made only of whitespace has no distinguishing fragment to look for,
  // and searching for it would just match the indentation of any stack trace.
  if (raw.trim().length === 0) {
    return;
  }
  expect(rendered).not.toContain(raw);
  const window = raw.slice(0, 32);
  for (let start = 0; start < window.length; start += 1) {
    for (let end = start + 4; end <= window.length; end += 1) {
      expect(rendered).not.toContain(window.slice(start, end));
    }
  }
}

function assertSaysNothingAbout(rendered: string, raw: string): void {
  assertCarriesNoFragment(rendered, raw);
  expect(rendered).not.toContain(String(raw.length));
  expect(rendered).not.toContain(String(Buffer.byteLength(raw, 'utf8')));
}

/** Run a rejection and return the error, after proving it disclosed nothing. */
function expectRejection(raw: string, rules?: Parameters<typeof validateSecretValue>[1]) {
  const value = SecretValue.from(raw);
  let thrown: unknown;
  try {
    validateSecretValue(value, rules);
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(InvalidInputError);
  const invalid = thrown as InvalidInputError;
  expect(invalid.field).toBe('value');
  expect(invalid.exitCode).toBe(2);

  assertSaysNothingAbout(invalid.message, raw);
  assertSaysNothingAbout(JSON.stringify(invalid.toSafeJSON()), raw);
  // The stack legitimately carries line numbers, so only the value itself is
  // checked there.
  assertCarriesNoFragment(invalid.stack ?? '', raw);
  // The value must not survive on `cause` either: nothing here should carry it.
  expect(invalid.cause).toBeUndefined();
  return invalid;
}

function expectAccepted(raw: string, rules?: Parameters<typeof validateSecretValue>[1]): void {
  expect(() => validateSecretValue(SecretValue.from(raw), rules)).not.toThrow();
}

describe('emptiness', () => {
  it('rejects an empty value by default', () => {
    const error = expectRejection('');
    expect(error.message).toBe('Secret value is empty.');
    expect(error.hint).toContain('--allow-empty');
  });

  it('accepts an empty value when the caller opts in', () => {
    expectAccepted('', { allowEmpty: true });
  });

  it('accepts a single-character value', () => {
    expectAccepted('x');
  });
});

describe('size', () => {
  it('accepts a value of exactly MAX_VALUE_BYTES', () => {
    // 'é' is two UTF-8 bytes, so String.length is half the byte length here:
    // a limit checked against `.length` would let a value twice the cap through.
    const raw = 'é'.repeat(MAX_VALUE_BYTES / 2);
    expect(Buffer.byteLength(raw, 'utf8')).toBe(MAX_VALUE_BYTES);
    expect(raw.length).toBe(MAX_VALUE_BYTES / 2);
    expectAccepted(raw);
  });

  it('rejects a value one byte over MAX_VALUE_BYTES', () => {
    const raw = `${'é'.repeat(MAX_VALUE_BYTES / 2)}a`;
    expect(Buffer.byteLength(raw, 'utf8')).toBe(MAX_VALUE_BYTES + 1);
    const error = expectRejection(raw);
    expect(error.message).toBe('Secret value exceeds the configured maximum size.');
  });

  it('measures bytes rather than code units for a custom limit', () => {
    // 12 characters, 24 bytes: accepted under a 24-byte cap, rejected under 23.
    const raw = 'é'.repeat(12);
    expect(raw.length).toBe(12);
    expect(Buffer.byteLength(raw, 'utf8')).toBe(24);
    expectAccepted(raw, { maxBytes: 24 });
    expectRejection(raw, { maxBytes: 20 });
  });

  it('measures astral characters correctly', () => {
    // A single emoji is one code point, two UTF-16 code units, four UTF-8 bytes.
    const raw = '🔑';
    expect(raw.length).toBe(2);
    expect(Buffer.byteLength(raw, 'utf8')).toBe(4);
    expectAccepted(raw, { maxBytes: 4 });
    expectRejection(raw, { maxBytes: 3 });
  });

  it('does not name the value length in the oversize error', () => {
    // The hint may state the configured limit — that is a constant the operator
    // chose. It must not state how far over the limit the value was.
    const raw = `${canary()}${'X'.repeat(40)}`;
    const error = expectRejection(raw, { maxBytes: 20 });
    expect(error.hint).toContain('20 bytes');
    expect(error.hint ?? '').not.toContain(String(raw.length));
  });
});

describe('surrounding whitespace', () => {
  const shapes: Array<[label: string, decorate: (raw: string) => string]> = [
    ['a leading space', (raw) => ` ${raw}`],
    ['a trailing space', (raw) => `${raw} `],
    ['a trailing newline', (raw) => `${raw}\n`],
    ['a trailing CRLF', (raw) => `${raw}\r\n`],
    ['a leading tab', (raw) => `\t${raw}`],
    ['surrounding whitespace', (raw) => `  ${raw}  `],
  ];

  for (const [label, decorate] of shapes) {
    it(`rejects ${label}`, () => {
      const error = expectRejection(decorate(canary()));
      expect(error.message).toBe('Secret value has leading or trailing whitespace.');
      expect(error.hint).toContain('--allow-whitespace');
    });

    it(`accepts ${label} when the caller opts in`, () => {
      expectAccepted(decorate(canary()), { allowWhitespace: true });
    });
  }

  it('accepts interior whitespace, which is legitimate in a PEM key', () => {
    expectAccepted(`${canary()}\nsecond line\n${canary()}`.trim());
    expectAccepted('a b');
  });

  it('rejects a whitespace-only value as empty-after-trim rather than accepting it', () => {
    // '   ' is non-empty but trims to nothing, so the whitespace rule fires.
    const error = expectRejection('   ');
    expect(error.message).toBe('Secret value has leading or trailing whitespace.');
  });
});

describe('rejection messages', () => {
  it('never quotes the value for any rejection path', () => {
    const raw = canary();
    const paths: Array<[string, Parameters<typeof validateSecretValue>[1] | undefined]> = [
      ['', undefined],
      [` ${raw}`, undefined],
      [`${raw}\n`, undefined],
      [raw, { maxBytes: 4 }],
      [`  ${raw}  `, { maxBytes: 1024 }],
    ];
    for (const [value, rules] of paths) {
      expectRejection(value, rules);
    }
  });

  it('produces a message that is identical regardless of the value', () => {
    // Two different values that break the same rule must be indistinguishable
    // from the error alone; anything else is an oracle.
    const first = expectRejection(` ${canary()}`);
    const second = expectRejection(`${canary()}${canary()} `);
    expect(first.message).toBe(second.message);
    expect(first.hint).toBe(second.hint);
    expect(JSON.stringify(first.toSafeJSON())).toBe(JSON.stringify(second.toSafeJSON()));
  });
});

describe('rule precedence and interaction', () => {
  it('checks emptiness before size', () => {
    expect(expectRejection('', { maxBytes: 0 }).message).toBe('Secret value is empty.');
  });

  it('checks size before whitespace', () => {
    expect(expectRejection(' x ', { maxBytes: 1 }).message).toBe(
      'Secret value exceeds the configured maximum size.',
    );
  });

  it('accepts a value that satisfies every rule', () => {
    expectAccepted(canary());
    expectAccepted(canary(), { allowEmpty: true, allowWhitespace: true, maxBytes: 128 });
  });

  it('propagates the disclosure error for a disposed value instead of passing', () => {
    const value = SecretValue.from(canary());
    value.dispose();
    expect(() => validateSecretValue(value)).toThrow(/disposed/);
  });

  it('does not dispose or mutate the value it validated', () => {
    const raw = canary();
    const value = SecretValue.from(raw);
    validateSecretValue(value);
    expect(value.disposed).toBe(false);
    // expose: proving validation left the value untouched
    expect(value.expose()).toBe(raw);
  });
});

describe('MAX_VALUE_BYTES', () => {
  it('is 64 KiB', () => {
    expect(MAX_VALUE_BYTES).toBe(65536);
  });
});
