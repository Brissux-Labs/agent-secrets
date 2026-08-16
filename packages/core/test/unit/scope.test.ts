import { describe, expect, it } from 'vitest';
import { InvalidInputError } from '../../src/errors.js';
import {
  DEFAULT_BACKEND,
  ENVIRONMENTS,
  formatRef,
  formatScope,
  isProduction,
  makeRef,
  makeScope,
  parseRef,
  refInScope,
  type SecretRef,
  type SecretScope,
  scopeOf,
} from '../../src/scope.js';

/**
 * The grammar in scope.ts is a security control, not a style preference: the
 * strings that pass through it end up as `bws` arguments, Keychain account
 * identifiers and secure-form HTML. These tests are the specification of what
 * the parser must refuse.
 */

const VALID_REF: SecretRef = {
  backend: 'bitwarden',
  project: 'ezjob',
  environment: 'development',
  name: 'OPENAI_API_KEY',
};

/** Assert a rejection is a field-scoped InvalidInputError that echoes nothing. */
function expectRejected(build: () => unknown, field: string, submitted?: string): void {
  let thrown: unknown;
  let threw = false;
  try {
    build();
  } catch (error) {
    threw = true;
    thrown = error;
  }
  expect(threw, `expected a rejection for field "${field}"`).toBe(true);
  expect(thrown).toBeInstanceOf(InvalidInputError);
  const invalid = thrown as InvalidInputError;
  expect(invalid.code).toBe('INVALID_INPUT');
  expect(invalid.exitCode).toBe(2);
  expect(invalid.field).toBe(field);
  if (submitted !== undefined && submitted.length > 0) {
    // The message is built from the schema; echoing the submitted string back
    // would put attacker-controlled text into a log line or an HTTP body.
    expect(invalid.message).not.toContain(submitted);
    expect(JSON.stringify(invalid.toSafeJSON())).not.toContain(submitted);
  }
}

describe('makeRef', () => {
  it('accepts a valid reference and defaults only the backend', () => {
    const ref = makeRef({ project: 'ezjob', environment: 'development', name: 'OPENAI_API_KEY' });
    expect(ref).toEqual(VALID_REF);
    expect(ref.backend).toBe(DEFAULT_BACKEND);
    expect(DEFAULT_BACKEND).toBe('bitwarden');
  });

  it('accepts an explicit backend and rejects an unknown one', () => {
    expect(makeRef({ ...VALID_REF, backend: 'bitwarden' })).toEqual(VALID_REF);
    expectRejected(
      () => makeRef({ ...VALID_REF, backend: 'vault-canary' }),
      'backend',
      'vault-canary',
    );
  });
});

describe('secret names', () => {
  const accepted = ['A', 'OPENAI_API_KEY', 'A1', 'A_1_B', 'A'.repeat(128)];

  for (const name of accepted) {
    it(`accepts ${name.length > 32 ? `a ${name.length}-character name` : name}`, () => {
      expect(makeRef({ ...VALID_REF, name }).name).toBe(name);
    });
  }

  const rejected: Array<[label: string, name: string]> = [
    ['a lowercase name', 'openai_key'],
    ['a leading digit', '1ABC'],
    ['a 129-character name', 'A'.repeat(129)],
    ['a hyphen', 'A-B'],
    ['a space', 'A B'],
    ['an empty name', ''],
    ['a dot', 'A.B'],
    ['a slash', 'A/B'],
    ['a null byte', 'A\u0000B'],
  ];

  for (const [label, name] of rejected) {
    it(`rejects ${label}`, () => {
      expectRejected(() => makeRef({ ...VALID_REF, name }), 'name', name);
    });
  }

  // Newline injection gets its own block: a name carrying \n or \r would reach a
  // `bws` argument vector and an audit JSONL line, where it can forge a record.
  const newlineShaped: Array<[label: string, name: string]> = [
    ['an embedded LF', 'A\nB'],
    ['an embedded CR', 'A\rB'],
    ['a trailing LF', 'OPENAI_API_KEY\n'],
    ['a trailing CRLF', 'OPENAI_API_KEY\r\n'],
    ['a leading LF', '\nOPENAI_API_KEY'],
    ['an LF followed by a forged argument', 'A\n--access-token'],
    ['a line separator', 'A\u2028B'],
  ];

  for (const [label, name] of newlineShaped) {
    it(`rejects ${label}`, () => {
      // `$` in JavaScript is end-of-input, not end-of-line, so a trailing
      // newline cannot slip past the anchor the way it would in other regex
      // dialects. This test pins that assumption.
      expectRejected(() => makeRef({ ...VALID_REF, name }), 'name', name);
    });
  }
});

describe('project slugs', () => {
  const accepted = ['ezjob', 'a', 'a-b-c', '0', 'a1-b2', 'a'.repeat(63)];

  for (const project of accepted) {
    it(`accepts ${project.length > 32 ? `a ${project.length}-character slug` : project}`, () => {
      expect(makeRef({ ...VALID_REF, project }).project).toBe(project);
    });
  }

  const rejected: Array<[label: string, project: string]> = [
    ['an uppercase slug', 'Ezjob'],
    ['a leading hyphen', '-abc'],
    ['an underscore', 'a_b'],
    ['a 64-character slug', 'a'.repeat(64)],
    ['an empty slug', ''],
    ['a space', 'a b'],
    ['a newline', 'ezjob\nezjob'],
  ];

  for (const [label, project] of rejected) {
    it(`rejects ${label}`, () => {
      expectRejected(() => makeRef({ ...VALID_REF, project }), 'project', project);
    });
  }

  // Path traversal deserves its own block: the slug is used to build Keychain
  // account identifiers and config paths, so `..` must never survive parsing.
  const traversalShaped = ['../etc', 'a/b', '..', '../../root', 'a/../b', './a', '%2e%2e'];

  for (const project of traversalShaped) {
    it(`rejects path-traversal shaped slug ${JSON.stringify(project)}`, () => {
      expectRejected(() => makeRef({ ...VALID_REF, project }), 'project', project);
    });
  }
});

describe('environment', () => {
  for (const environment of ENVIRONMENTS) {
    it(`accepts ${environment}`, () => {
      expect(makeRef({ ...VALID_REF, environment }).environment).toBe(environment);
    });
  }

  it('rejects an omitted environment instead of inferring production', () => {
    // FR-SCOPE-005. Defaulting here would silently point a create at production.
    const input = { project: 'ezjob', name: 'OPENAI_API_KEY' } as unknown as {
      project: string;
      environment: string;
      name: string;
    };
    expectRejected(() => makeRef(input), 'environment');
    expectRejected(() => makeRef({ ...VALID_REF, environment: '' }), 'environment');
  });

  it('rejects an unknown environment instead of falling back', () => {
    expectRejected(
      () => makeRef({ ...VALID_REF, environment: 'staging' }),
      'environment',
      'staging',
    );
    expectRejected(() => makeRef({ ...VALID_REF, environment: 'PRODUCTION' }), 'environment');
    expectRejected(() => makeRef({ ...VALID_REF, environment: 'prod' }), 'environment');
  });

  it('never yields production for anything but the literal string', () => {
    for (const environment of ['staging', 'prod', 'PRODUCTION', 'production ', '']) {
      let result: SecretRef | undefined;
      try {
        result = makeRef({ ...VALID_REF, environment });
      } catch {
        result = undefined;
      }
      expect(result?.environment).not.toBe('production');
    }
  });
});

describe('makeScope', () => {
  it('builds a scope and defaults the backend', () => {
    expect(makeScope({ project: 'ezjob', environment: 'production' })).toEqual({
      backend: 'bitwarden',
      project: 'ezjob',
      environment: 'production',
    });
  });

  it('rejects an invalid project without echoing it', () => {
    expectRejected(
      () => makeScope({ project: 'BAD_SLUG_CANARY', environment: 'development' }),
      'project',
      'BAD_SLUG_CANARY',
    );
  });
});

describe('parseRef', () => {
  it('parses the four-segment canonical form', () => {
    expect(parseRef('bitwarden/ezjob/development/OPENAI_API_KEY')).toEqual(VALID_REF);
  });

  it('parses the three-segment shorthand and defaults the backend', () => {
    expect(parseRef('ezjob/development/OPENAI_API_KEY')).toEqual(VALID_REF);
  });

  const malformed = [
    ['two segments', 'ezjob/OPENAI_API_KEY'],
    ['one segment', 'OPENAI_API_KEY'],
    ['five segments', 'bitwarden/ezjob/development/OPENAI_API_KEY/EXTRA'],
    ['a trailing slash', 'bitwarden/ezjob/development/OPENAI_API_KEY/'],
  ] as const;

  for (const [label, input] of malformed) {
    it(`rejects ${label}`, () => {
      expectRejected(() => parseRef(input), 'reference');
    });
  }

  it('rejects an empty string', () => {
    expectRejected(() => parseRef(''), 'reference');
  });

  it('rejects a leading slash as an empty backend segment', () => {
    // Four segments, so the shape is accepted and the empty backend is what
    // fails; the important part is that it fails at all.
    expectRejected(() => parseRef('/ezjob/development/OPENAI_API_KEY'), 'backend');
  });

  it('rejects a non-string', () => {
    expectRejected(() => parseRef(undefined as unknown as string), 'reference');
    expectRejected(() => parseRef(null as unknown as string), 'reference');
  });

  it('rejects a reference whose name carries a newline', () => {
    expectRejected(
      () => parseRef('bitwarden/ezjob/development/API\nKEY'),
      'name',
      'bitwarden/ezjob/development/API\nKEY',
    );
  });

  it('does not echo the rejected reference back', () => {
    expectRejected(() => parseRef('ezjob/CANARY_BAD_SEGMENT'), 'reference', 'CANARY_BAD_SEGMENT');
  });
});

describe('formatting round-trips', () => {
  it('formatRef round-trips through parseRef', () => {
    for (const environment of ENVIRONMENTS) {
      const ref = makeRef({ ...VALID_REF, environment });
      expect(parseRef(formatRef(ref))).toEqual(ref);
    }
    expect(formatRef(VALID_REF)).toBe('bitwarden/ezjob/development/OPENAI_API_KEY');
  });

  it('formatScope produces the three-segment prefix of formatRef', () => {
    const scope = scopeOf(VALID_REF);
    expect(formatScope(scope)).toBe('bitwarden/ezjob/development');
    expect(formatRef(VALID_REF).startsWith(`${formatScope(scope)}/`)).toBe(true);
  });

  it('formatScope round-trips through makeScope', () => {
    const scope: SecretScope = { backend: 'bitwarden', project: 'a-b-c', environment: 'preview' };
    const [backend, project, environment] = formatScope(scope).split('/') as [
      string,
      string,
      string,
    ];
    expect(makeScope({ backend, project, environment })).toEqual(scope);
  });
});

describe('scope predicates', () => {
  it('refInScope matches only on all three coordinates', () => {
    const scope = scopeOf(VALID_REF);
    expect(refInScope(VALID_REF, scope)).toBe(true);
    expect(refInScope(makeRef({ ...VALID_REF, name: 'OTHER_KEY' }), scope)).toBe(true);
    expect(refInScope(makeRef({ ...VALID_REF, environment: 'production' }), scope)).toBe(false);
    expect(refInScope(makeRef({ ...VALID_REF, project: 'other' }), scope)).toBe(false);
  });

  it('scopeOf drops the name and nothing else', () => {
    expect(scopeOf(VALID_REF)).toEqual({
      backend: 'bitwarden',
      project: 'ezjob',
      environment: 'development',
    });
    expect(Object.keys(scopeOf(VALID_REF)).sort()).toEqual(['backend', 'environment', 'project']);
  });

  it('isProduction is true only for the production environment', () => {
    expect(isProduction(makeRef({ ...VALID_REF, environment: 'production' }))).toBe(true);
    expect(isProduction(makeScope({ project: 'ezjob', environment: 'production' }))).toBe(true);
    expect(isProduction(VALID_REF)).toBe(false);
    expect(isProduction(makeRef({ ...VALID_REF, environment: 'preview' }))).toBe(false);
  });
});
