import { z } from 'zod';
import { InvalidInputError } from './errors.js';

/**
 * Canonical addressing: `backend/project/environment/name`.
 *
 * Example: `bitwarden/ezjob/development/OPENAI_API_KEY`
 *
 * The grammar is deliberately narrow. It is the first line of defence against
 * newline injection into `bws` arguments, path traversal in Keychain account
 * identifiers, and HTML injection into the secure form, so it is validated once
 * here and never re-parsed ad hoc elsewhere.
 */

export const BACKENDS = ['bitwarden'] as const;
export type BackendId = (typeof BACKENDS)[number];

/** FR-SCOPE-004: built-in environments. Custom ones are a post-V1 decision. */
export const ENVIRONMENTS = ['development', 'preview', 'production'] as const;
export type Environment = (typeof ENVIRONMENTS)[number];

/** FR-SCOPE-002 */
export const SECRET_NAME_PATTERN = /^[A-Z][A-Z0-9_]{0,127}$/;
/** FR-SCOPE-003 */
export const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;

export const backendIdSchema = z.enum(BACKENDS);
export const environmentSchema = z.enum(ENVIRONMENTS);

export const projectSlugSchema = z
  .string()
  .regex(SLUG_PATTERN, 'project must match ^[a-z0-9][a-z0-9-]{0,62}$');

export const secretNameSchema = z
  .string()
  .regex(SECRET_NAME_PATTERN, 'name must match ^[A-Z][A-Z0-9_]{0,127}$');

export const secretRefSchema = z.object({
  backend: backendIdSchema,
  project: projectSlugSchema,
  environment: environmentSchema,
  name: secretNameSchema,
});

export type SecretRef = z.infer<typeof secretRefSchema>;

export const secretScopeSchema = z.object({
  backend: backendIdSchema,
  project: projectSlugSchema,
  environment: environmentSchema,
});

export type SecretScope = z.infer<typeof secretScopeSchema>;

export const DEFAULT_BACKEND: BackendId = 'bitwarden';

export interface RefInput {
  backend?: string | undefined;
  project: string;
  /**
   * FR-SCOPE-005: never inferred. An absent environment is an error, so this is
   * required even though `production` would be the "safe-looking" default.
   */
  environment: string;
  name: string;
}

/**
 * Build a validated reference from loose input (CLI flags, HTTP body, MCP tool
 * arguments). Throws `InvalidInputError` with a field-scoped message.
 */
export function makeRef(input: RefInput): SecretRef {
  const parsed = secretRefSchema.safeParse({
    backend: input.backend ?? DEFAULT_BACKEND,
    project: input.project,
    environment: input.environment,
    name: input.name,
  });
  if (!parsed.success) {
    throw invalidFrom(parsed.error);
  }
  return parsed.data;
}

export function makeScope(input: Omit<RefInput, 'name'>): SecretScope {
  const parsed = secretScopeSchema.safeParse({
    backend: input.backend ?? DEFAULT_BACKEND,
    project: input.project,
    environment: input.environment,
  });
  if (!parsed.success) {
    throw invalidFrom(parsed.error);
  }
  return parsed.data;
}

/** `bitwarden/ezjob/development/OPENAI_API_KEY` */
export function formatRef(ref: SecretRef): string {
  return `${ref.backend}/${ref.project}/${ref.environment}/${ref.name}`;
}

/** `bitwarden/ezjob/development` */
export function formatScope(scope: SecretScope): string {
  return `${scope.backend}/${scope.project}/${scope.environment}`;
}

/**
 * Parse a canonical reference string. Accepts the three-segment shorthand
 * `project/environment/name`, which defaults the backend but never the
 * environment.
 */
export function parseRef(input: string): SecretRef {
  if (typeof input !== 'string' || input.length === 0) {
    throw new InvalidInputError('reference must be a non-empty string', { field: 'reference' });
  }
  const segments = input.split('/');
  if (segments.length === 3) {
    const [project, environment, name] = segments as [string, string, string];
    return makeRef({ project, environment, name });
  }
  if (segments.length === 4) {
    const [backend, project, environment, name] = segments as [string, string, string, string];
    return makeRef({ backend, project, environment, name });
  }
  throw new InvalidInputError(
    'reference must be "project/environment/name" or "backend/project/environment/name"',
    { field: 'reference' },
  );
}

export function refInScope(ref: SecretRef, scope: SecretScope): boolean {
  return (
    ref.backend === scope.backend &&
    ref.project === scope.project &&
    ref.environment === scope.environment
  );
}

export function scopeOf(ref: SecretRef): SecretScope {
  return { backend: ref.backend, project: ref.project, environment: ref.environment };
}

export function isProduction(target: SecretRef | SecretScope): boolean {
  return target.environment === 'production';
}

function invalidFrom(error: z.ZodError): InvalidInputError {
  const first = error.issues[0];
  const field = first?.path.join('.') || 'reference';
  // The message is built from the schema, never from the submitted value, so it
  // cannot echo user input back into a log or an HTTP response.
  return new InvalidInputError(first?.message ?? 'invalid reference', { field });
}
