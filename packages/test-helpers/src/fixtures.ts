import type { PolicyDocument, SecretMetadata } from '@bx-labs/agent-secrets-core';

/**
 * Deterministic fake data.
 *
 * NONE OF THIS IS REAL. There is no organization, no machine account, no vault,
 * and no credential behind any identifier below. The *shapes* imitate what
 * Bitwarden Secrets Manager emits — token layout, UUID formatting, timestamp
 * precision — for exactly one reason: a parser that is only ever fed tidy,
 * hand-written data is a parser that has never been tested. Every generated
 * component carries the literal word `fake`, so a grep for a leaked credential
 * can dismiss these at a glance and a human reading a failure cannot mistake one
 * for a live secret.
 *
 * A test that needs a *value* must not use these. Values are generated at
 * runtime with `makeCanary()` so that each run is unique and traceable.
 */

/**
 * A `bws` machine-account token is `0.<uuid>.<base64ish>:<base64ish>`. This one
 * is assembled from repeated 'fake' rather than written as a single literal, so
 * no credential-shaped blob ever sits in the source tree.
 */
function buildFakeToken(discriminator: string): string {
  return `0.${FAKE_UUIDS.machineAccount}.${'fake'.repeat(8)}${discriminator}:ZmFrZQ==`;
}

/** Deterministic UUID-shaped identifiers. The trailing digits spell nothing. */
export const FAKE_UUIDS = {
  organization: '00000000-0000-4000-8000-0000000000a1',
  project: '00000000-0000-4000-8000-0000000000b2',
  secret: '00000000-0000-4000-8000-0000000000c3',
  secondSecret: '00000000-0000-4000-8000-0000000000c4',
  machineAccount: '00000000-0000-4000-8000-0000000000d5',
  device: '00000000-0000-4000-8000-0000000000e6',
  secondDevice: '00000000-0000-4000-8000-0000000000e7',
} as const;

/** Not a credential. See the module comment. */
export const FAKE_ACCESS_TOKEN = buildFakeToken('01');

/** A second one, for the two-device revocation tests. Also not a credential. */
export const FAKE_ACCESS_TOKEN_SECOND = buildFakeToken('02');

/** Shaped like a token but never accepted by the fake bws, for negative tests. */
export const FAKE_ACCESS_TOKEN_INVALID = buildFakeToken('99');

/** `bws` serialises Rust chrono timestamps with sub-millisecond precision. */
export const FAKE_TIMESTAMP = '2026-01-15T09:30:00.000000Z';
export const FAKE_TIMESTAMP_LATER = '2026-02-20T14:05:00.000000Z';

export const FAKE_PROJECT_SLUG = 'ezjob';

export function sampleSecretMetadata(overrides: Partial<SecretMetadata> = {}): SecretMetadata {
  const base: SecretMetadata = {
    backend: 'bitwarden',
    project: FAKE_PROJECT_SLUG,
    environment: 'development',
    name: 'OPENAI_API_KEY',
    reference: `bitwarden/${FAKE_PROJECT_SLUG}/development/OPENAI_API_KEY`,
    backendId: FAKE_UUIDS.secret,
    description: 'Model provider key used by the job matcher.',
    provider: 'openai',
    tags: ['llm'],
    createdAt: FAKE_TIMESTAMP,
    updatedAt: FAKE_TIMESTAMP_LATER,
  };
  return { ...base, ...overrides };
}

export function sampleSecretMetadataList(): SecretMetadata[] {
  return [
    sampleSecretMetadata(),
    sampleSecretMetadata({
      name: 'STRIPE_SECRET_KEY',
      reference: `bitwarden/${FAKE_PROJECT_SLUG}/development/STRIPE_SECRET_KEY`,
      backendId: FAKE_UUIDS.secondSecret,
      provider: 'stripe',
      tags: ['payments'],
    }),
  ];
}

/**
 * A manifest as a consumer project would write it.
 *
 * The authoritative schema lives with the CLI, which is being written
 * separately; this fixture is intentionally plain data so it can be fed to that
 * schema once it exists rather than encoding a second, drifting definition.
 */
export interface SampleManifestEntry {
  name: string;
  description?: string;
  provider?: string;
  required?: boolean;
}

export interface SampleManifest {
  version: 1;
  project: string;
  secrets: SampleManifestEntry[];
}

export const SAMPLE_MANIFEST: SampleManifest = {
  version: 1,
  project: FAKE_PROJECT_SLUG,
  secrets: [
    {
      name: 'OPENAI_API_KEY',
      description: 'Model provider key used by the job matcher.',
      provider: 'openai',
      required: true,
    },
    {
      name: 'STRIPE_SECRET_KEY',
      description: 'Server-side Stripe key.',
      provider: 'stripe',
      required: true,
    },
    { name: 'SENTRY_DSN', description: 'Error reporting endpoint.', required: false },
  ],
};

export const SAMPLE_MANIFEST_YAML = [
  'version: 1',
  `project: ${FAKE_PROJECT_SLUG}`,
  'secrets:',
  '  - name: OPENAI_API_KEY',
  '    description: Model provider key used by the job matcher.',
  '    provider: openai',
  '    required: true',
  '  - name: STRIPE_SECRET_KEY',
  '    description: Server-side Stripe key.',
  '    provider: stripe',
  '    required: true',
  '  - name: SENTRY_DSN',
  '    description: Error reporting endpoint.',
  '    required: false',
  '',
].join('\n');

/**
 * A policy that is looser than the built-in default in development and stricter
 * in production, so tests can tell "the fixture applied" from "the default
 * applied" without ambiguity.
 */
export const SAMPLE_POLICY: PolicyDocument = {
  version: 1,
  projects: {
    [FAKE_PROJECT_SLUG]: {
      environments: {
        development: {
          allow: ['list', 'describe', 'create', 'rotate', 'delete', 'run'],
          humanApproval: [],
        },
        preview: {
          allow: ['list', 'describe', 'run'],
          humanApproval: ['run'],
        },
        production: {
          allow: [],
          humanApproval: [],
        },
      },
    },
  },
  commands: {
    denyExecutables: ['env', 'printenv', 'sh', 'bash', 'zsh'],
    allowExecutables: [],
  },
};

export const SAMPLE_POLICY_YAML = [
  'version: 1',
  'projects:',
  `  ${FAKE_PROJECT_SLUG}:`,
  '    environments:',
  '      development:',
  '        allow: [list, describe, create, rotate, delete, run]',
  '        humanApproval: []',
  '      preview:',
  '        allow: [list, describe, run]',
  '        humanApproval: [run]',
  '      production:',
  '        allow: []',
  '        humanApproval: []',
  'commands:',
  '  denyExecutables: [env, printenv, sh, bash, zsh]',
  '  allowExecutables: []',
  '',
].join('\n');
