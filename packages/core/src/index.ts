export type { AuditEvent, AuditEventInput, AuditOperation, AuditSink } from './audit.js';
export { auditEventSchema, auditOperations, buildAuditEvent, nullAuditSink } from './audit.js';
export type { BackendHealth, ResolvedSecret, SecretBackend } from './backend.js';
export type { ErrorCode, ErrorDetails, ExitCode, SafeErrorShape } from './errors.js';
export {
  AgentSecretsError,
  AuthRequiredError,
  BackendUnavailableError,
  ChildFailedError,
  ConflictError,
  ERROR_CODES,
  EXIT_CODES,
  ExpiredOrConsumedError,
  InternalError,
  InvalidInputError,
  isAgentSecretsError,
  NotFoundError,
  PolicyDeniedError,
  toSafeError,
} from './errors.js';
export type { InputMetadata, SecretMetadata } from './metadata.js';
export {
  assertNoValueFields,
  descriptionSchema,
  FORBIDDEN_METADATA_FIELDS,
  inputMetadataSchema,
  JSON_SCHEMA_VERSION,
  jsonEnvelopeSchema,
  providerSchema,
  secretMetadataSchema,
  tagSchema,
} from './metadata.js';
export type { Action, PolicyContext, PolicyDecision, PolicyDocument } from './policy.js';
export {
  ACTIONS,
  actionSchema,
  defaultPolicy,
  PolicyEngine,
  parsePolicy,
  policyDocumentSchema,
} from './policy.js';
export type { BackendId, Environment, RefInput, SecretRef, SecretScope } from './scope.js';
export {
  BACKENDS,
  backendIdSchema,
  DEFAULT_BACKEND,
  ENVIRONMENTS,
  environmentSchema,
  formatRef,
  formatScope,
  isProduction,
  makeRef,
  makeScope,
  parseRef,
  projectSlugSchema,
  refInScope,
  SECRET_NAME_PATTERN,
  SLUG_PATTERN,
  scopeOf,
  secretNameSchema,
  secretRefSchema,
  secretScopeSchema,
} from './scope.js';
export {
  isSecretValue,
  SecretDisclosureError,
  SecretValue,
  secretValuesEqual,
} from './secret-value.js';

export { MAX_VALUE_BYTES, validateSecretValue } from './value-rules.js';
