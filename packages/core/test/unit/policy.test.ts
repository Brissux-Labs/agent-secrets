import { describe, expect, it } from 'vitest';
import { InvalidInputError, PolicyDeniedError } from '../../src/errors.js';
import {
  ACTIONS,
  type Action,
  actionSchema,
  defaultPolicy,
  type PolicyDocument,
  PolicyEngine,
  parsePolicy,
  policyDocumentSchema,
} from '../../src/policy.js';
import type { SecretRef, SecretScope } from '../../src/scope.js';

/**
 * The policy engine is the only thing standing between a talked-into-it agent
 * and a production credential. Every assertion here is a promise that the
 * decision lives in code, not in a system prompt, and that the closed direction
 * is the default in every ambiguous case.
 */

function scope(project: string, environment: string): SecretScope {
  // The engine reads three fields; casting keeps the unknown-environment case
  // testable without loosening the exported types.
  return { backend: 'bitwarden', project, environment } as unknown as SecretScope;
}

function ref(project: string, environment: string, name = 'OPENAI_API_KEY'): SecretRef {
  return { ...scope(project, environment), name } as SecretRef;
}

const MUTATIONS: Action[] = [
  'create',
  'rotate',
  'delete',
  'run',
  'request-create',
  'request-rotate',
];

describe('defaultPolicy', () => {
  it('parses into a complete document', () => {
    const document = defaultPolicy();
    expect(document.version).toBe(1);
    expect(document.projects).toEqual({});
    expect(document.commands.allowExecutables).toEqual([]);
    expect(document.commands.denyExecutables).toContain('sh');
  });

  it('allows the full lifecycle in development', () => {
    const engine = new PolicyEngine();
    for (const action of ACTIONS) {
      const decision = engine.evaluate({
        action,
        target: ref('ezjob', 'development'),
        // `run` is the one action whose decision also depends on what is being
        // run, so the executable is part of asking the question properly.
        ...(action === 'run' ? { executable: 'npm' } : {}),
      });
      expect(decision.allowed, action).toBe(true);
      expect(decision.requiresHumanApproval, action).toBe(false);
    }
  });

  it('refuses a run decision made without an executable', () => {
    // Fail closed. If the deny list applied only when a caller remembered to
    // pass an executable, the list would be opt-in from the call site — a
    // caller that forgets would get a permissive answer, which is exactly
    // backwards.
    const engine = new PolicyEngine();
    const decision = engine.evaluate({ action: 'run', target: ref('ezjob', 'development') });

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/requires the executable/i);
  });

  it.each([
    ['a bare name', 'sh'],
    ['an absolute path', '/bin/sh'],
    ['a relative path', './sh'],
    ['surrounding whitespace', ' sh '],
    ['different case', 'SH'],
    ['a nested path', '/usr/local/bin/sh'],
  ])('blocks a denied executable spelled as %s', (_label, executable) => {
    const engine = new PolicyEngine();
    const decision = engine.evaluate({
      action: 'run',
      target: ref('ezjob', 'development'),
      executable,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/deny list/i);
  });

  it('allows only list and describe in production', () => {
    const engine = new PolicyEngine();
    for (const action of ACTIONS) {
      const expected = action === 'list' || action === 'describe';
      expect(engine.evaluate({ action, target: ref('ezjob', 'production') }).allowed, action).toBe(
        expected,
      );
    }
  });

  for (const action of ['delete', 'rotate', 'run', 'request-create'] as const) {
    it(`denies "${action}" in production`, () => {
      const decision = new PolicyEngine().evaluate({
        action,
        target: ref('ezjob', 'production'),
        ...(action === 'run' ? { executable: 'node' } : {}),
      });
      expect(decision.allowed).toBe(false);
      expect(decision.requiresHumanApproval).toBe(false);
      expect(decision.reason).toContain(action);
      expect(decision.reason).toContain('ezjob/production');
    });
  }

  it('never allows a production mutation for any project name', () => {
    const engine = new PolicyEngine();
    for (const project of ['ezjob', 'other', 'a-b-c', 'never-seen-before']) {
      for (const action of MUTATIONS) {
        expect(
          engine.evaluate({ action, target: ref(project, 'production') }).allowed,
          `${project}/${action}`,
        ).toBe(false);
      }
    }
  });

  it('makes preview read-only plus execution, with approval on the request actions', () => {
    const engine = new PolicyEngine();
    const target = ref('ezjob', 'preview');
    expect(engine.evaluate({ action: 'list', target }).allowed).toBe(true);
    expect(engine.evaluate({ action: 'describe', target }).allowed).toBe(true);
    expect(engine.evaluate({ action: 'create', target }).allowed).toBe(false);
    expect(engine.evaluate({ action: 'delete', target }).allowed).toBe(false);
    expect(engine.evaluate({ action: 'rotate', target }).allowed).toBe(false);
  });
});

describe('unknown targets', () => {
  it('falls back to the built-in environment defaults for an unknown project', () => {
    const engine = new PolicyEngine();
    expect(
      engine.evaluate({ action: 'list', target: ref('never-seen', 'production') }).allowed,
    ).toBe(true);
    expect(
      engine.evaluate({ action: 'delete', target: ref('never-seen', 'production') }).allowed,
    ).toBe(false);
    expect(
      engine.evaluate({ action: 'create', target: ref('never-seen', 'development') }).allowed,
    ).toBe(true);
  });

  it('denies every action in an unknown environment', () => {
    const engine = new PolicyEngine();
    for (const environment of ['staging', 'prod', 'PRODUCTION', '']) {
      for (const action of ACTIONS) {
        const decision = engine.evaluate({ action, target: scope('ezjob', environment) });
        expect(decision.allowed, `${environment}/${action}`).toBe(false);
        expect(decision.reason).toContain('denied by default');
      }
    }
  });
});

describe('a custom policy document', () => {
  const custom: PolicyDocument = parsePolicy({
    version: 1,
    projects: {
      ezjob: {
        environments: {
          production: { allow: ['list', 'describe', 'rotate'], humanApproval: ['rotate'] },
        },
      },
    },
    commands: { denyExecutables: ['sh'], allowExecutables: [] },
  });

  it('overrides the defaults for its own project', () => {
    const engine = new PolicyEngine(custom);
    const decision = engine.evaluate({
      action: 'rotate',
      target: ref('ezjob', 'production'),
      approvalGranted: true,
    });
    expect(decision.allowed).toBe(true);
  });

  it('leaves other projects on the built-in defaults', () => {
    const engine = new PolicyEngine(custom);
    expect(
      engine.evaluate({
        action: 'rotate',
        target: ref('other-project', 'production'),
        approvalGranted: true,
      }).allowed,
    ).toBe(false);
  });

  it('leaves unlisted environments of the same project on the built-in defaults', () => {
    const engine = new PolicyEngine(custom);
    expect(engine.evaluate({ action: 'create', target: ref('ezjob', 'development') }).allowed).toBe(
      true,
    );
    expect(engine.evaluate({ action: 'create', target: ref('ezjob', 'preview') }).allowed).toBe(
      false,
    );
  });

  it('can narrow an environment to nothing at all', () => {
    const locked = new PolicyEngine(
      parsePolicy({
        version: 1,
        projects: { ezjob: { environments: { development: { allow: [] } } } },
      }),
    );
    for (const action of ACTIONS) {
      expect(locked.evaluate({ action, target: ref('ezjob', 'development') }).allowed, action).toBe(
        false,
      );
    }
  });
});

describe('human approval', () => {
  it('denies an allowed action until the approval is granted', () => {
    const engine = new PolicyEngine();
    const target = ref('ezjob', 'preview');

    const withoutApproval = engine.evaluate({ action: 'request-create', target });
    expect(withoutApproval.allowed).toBe(false);
    expect(withoutApproval.requiresHumanApproval).toBe(true);
    expect(withoutApproval.reason).toContain('requires human approval');

    const withApproval = engine.evaluate({
      action: 'request-create',
      target,
      approvalGranted: true,
    });
    expect(withApproval.allowed).toBe(true);
    // The requirement is still reported once satisfied, so a caller can log it.
    expect(withApproval.requiresHumanApproval).toBe(true);
  });

  it('does not treat a falsy approval flag as granted', () => {
    const engine = new PolicyEngine();
    const decision = engine.evaluate({
      action: 'request-rotate',
      target: ref('ezjob', 'preview'),
      approvalGranted: false,
    });
    expect(decision.allowed).toBe(false);
    expect(decision.requiresHumanApproval).toBe(true);
  });

  it('reports no approval requirement for an action that does not need one', () => {
    const decision = new PolicyEngine().evaluate({
      action: 'list',
      target: ref('ezjob', 'preview'),
    });
    expect(decision.allowed).toBe(true);
    expect(decision.requiresHumanApproval).toBe(false);
  });

  it('does not let approval rescue an action that is not allowed at all', () => {
    const decision = new PolicyEngine().evaluate({
      action: 'delete',
      target: ref('ezjob', 'production'),
      approvalGranted: true,
    });
    expect(decision.allowed).toBe(false);
  });
});

describe('executable rules', () => {
  const engine = new PolicyEngine();
  const target = ref('ezjob', 'development');

  for (const executable of ['sh', 'bash', 'zsh', 'env', 'printenv']) {
    it(`denies the bare name "${executable}"`, () => {
      const decision = engine.evaluate({ action: 'run', target, executable });
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('deny list');
    });
  }

  for (const executable of ['/bin/sh', '/usr/bin/env', '/usr/local/bin/bash', './sh']) {
    it(`denies "${executable}" by basename`, () => {
      // A denylist keyed on the literal string would be trivially bypassed by
      // spelling out the absolute path.
      const decision = engine.evaluate({ action: 'run', target, executable });
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toContain('deny list');
    });
  }

  it('allows an executable that is not on the deny list', () => {
    expect(engine.evaluate({ action: 'run', target, executable: 'node' }).allowed).toBe(true);
    expect(engine.evaluate({ action: 'run', target, executable: '/usr/bin/node' }).allowed).toBe(
      true,
    );
  });

  it('blocks anything outside a non-empty allow list', () => {
    const restricted = new PolicyEngine(
      parsePolicy({
        version: 1,
        commands: { denyExecutables: [], allowExecutables: ['node', 'pnpm'] },
      }),
    );
    expect(restricted.evaluate({ action: 'run', target, executable: 'node' }).allowed).toBe(true);

    for (const executable of ['python', 'curl', 'sh', '/bin/sh']) {
      const decision = restricted.evaluate({ action: 'run', target, executable });
      expect(decision.allowed, executable).toBe(false);
      expect(decision.reason).toContain('allow list');
    }
  });

  it('does not let a path satisfy a bare-name allow list entry', () => {
    // The boundary this protects: with basename matching on both sides,
    // `/tmp/evil/node` satisfies an allow list of `["node"]`, and an agent that
    // chooses the path chooses the binary. A bare-name entry therefore matches
    // only a bare-name invocation, which `spawn` resolves through a PATH the
    // caller does not control.
    const restricted = new PolicyEngine(
      parsePolicy({
        version: 1,
        commands: { denyExecutables: [], allowExecutables: ['node'] },
      }),
    );

    for (const executable of ['/usr/bin/node', './node', '/tmp/evil/node', '../node']) {
      const decision = restricted.evaluate({ action: 'run', target, executable });
      expect(decision.allowed, executable).toBe(false);
    }
  });

  it('allows an absolute path when the allow list names that exact path', () => {
    // The escape hatch for someone who genuinely runs a binary from a fixed
    // location: say so, and it is honoured — but only that path.
    const restricted = new PolicyEngine(
      parsePolicy({
        version: 1,
        commands: { denyExecutables: [], allowExecutables: ['/opt/homebrew/bin/node'] },
      }),
    );

    expect(
      restricted.evaluate({ action: 'run', target, executable: '/opt/homebrew/bin/node' }).allowed,
    ).toBe(true);
    expect(
      restricted.evaluate({ action: 'run', target, executable: '/tmp/evil/node' }).allowed,
    ).toBe(false);
    expect(restricted.evaluate({ action: 'run', target, executable: 'node' }).allowed).toBe(false);
  });

  it('applies the deny list before the allow list', () => {
    const contradictory = new PolicyEngine(
      parsePolicy({
        version: 1,
        commands: { denyExecutables: ['sh'], allowExecutables: ['sh', 'node'] },
      }),
    );
    expect(contradictory.evaluate({ action: 'run', target, executable: 'sh' }).allowed).toBe(false);
  });

  it('ignores executable rules for actions other than run', () => {
    expect(engine.evaluate({ action: 'list', target, executable: 'sh' }).allowed).toBe(true);
  });
});

describe('parsePolicy', () => {
  it('accepts a minimal document and fills in the defaults', () => {
    const document = parsePolicy({ version: 1 });
    expect(document.projects).toEqual({});
    expect(document.commands).toEqual({ denyExecutables: [], allowExecutables: [] });
  });

  const malformed: Array<[label: string, raw: unknown]> = [
    ['a missing version', { projects: {} }],
    ['version 0', { version: 0 }],
    ['version 2', { version: 2 }],
    ['a string version', { version: '1' }],
    ['an unknown top-level key', { version: 1, allowEverything: true }],
    ['an unknown commands key', { version: 1, commands: { deny: ['sh'] } }],
    ['an unknown environment key', { version: 1, projects: { a: { environments: { prod: {} } } } }],
    [
      'an unknown project-level key',
      { version: 1, projects: { a: { environments: {}, inherit: 'b' } } },
    ],
    [
      'an unknown action',
      { version: 1, projects: { a: { environments: { production: { allow: ['exfiltrate'] } } } } },
    ],
    ['an invalid project slug', { version: 1, projects: { 'Bad Slug': { environments: {} } } }],
    ['an empty executable name', { version: 1, commands: { denyExecutables: [''] } }],
    ['null', null],
    ['a string', 'version: 1'],
    ['an array', [{ version: 1 }]],
  ];

  for (const [label, raw] of malformed) {
    it(`fails closed on ${label}`, () => {
      let thrown: unknown;
      try {
        parsePolicy(raw);
      } catch (error) {
        thrown = error;
      }
      expect(thrown, label).toBeInstanceOf(InvalidInputError);
      const invalid = thrown as InvalidInputError;
      expect(invalid.field).toBe('policy');
      expect(invalid.exitCode).toBe(2);
      // Fail closed: the caller gets an error, never a permissive document.
      expect(invalid.hint).toBeDefined();
    });
  }

  it('never yields a document that allows more than the defaults when it fails', () => {
    // A caller that swallows the error must not end up with an engine at all;
    // this pins that parsePolicy has no permissive return path.
    expect(() => parsePolicy({ version: 2, projects: {} })).toThrow(InvalidInputError);
  });

  it('round-trips a document through policyDocumentSchema', () => {
    const document = defaultPolicy();
    expect(policyDocumentSchema.parse(document)).toEqual(document);
    expect(parsePolicy(document)).toEqual(document);
  });
});

describe('PolicyEngine.assert', () => {
  it('returns the decision when the action is allowed', () => {
    const decision = new PolicyEngine().assert({
      action: 'list',
      target: ref('ezjob', 'production'),
    });
    expect(decision.allowed).toBe(true);
  });

  it('throws PolicyDeniedError with exit code 4', () => {
    const engine = new PolicyEngine();
    let thrown: unknown;
    try {
      engine.assert({ action: 'delete', target: ref('ezjob', 'production') });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(PolicyDeniedError);
    const denied = thrown as PolicyDeniedError;
    expect(denied.code).toBe('POLICY_DENIED');
    expect(denied.exitCode).toBe(4);
    expect(denied.reference).toBe('ezjob/production');
    expect(denied.hint).toContain('agent-secrets.policy.yaml');
    expect(denied.toSafeJSON().code).toBe('POLICY_DENIED');
  });

  it('points at the out-of-band channel when approval is what is missing', () => {
    const engine = new PolicyEngine();
    try {
      engine.assert({ action: 'request-create', target: ref('ezjob', 'preview') });
      expect.unreachable('assert must throw');
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyDeniedError);
      expect((error as PolicyDeniedError).hint).toContain('the agent does not control');
    }
  });

  it('throws for a denied executable during run', () => {
    expect(() =>
      new PolicyEngine().assert({
        action: 'run',
        target: ref('ezjob', 'development'),
        executable: '/bin/sh',
      }),
    ).toThrow(PolicyDeniedError);
  });
});

describe('actionSchema', () => {
  it('accepts every declared action and rejects anything else', () => {
    for (const action of ACTIONS) {
      expect(actionSchema.safeParse(action).success, action).toBe(true);
    }
    expect(actionSchema.safeParse('reveal').success).toBe(false);
    expect(actionSchema.safeParse('').success).toBe(false);
  });
});
