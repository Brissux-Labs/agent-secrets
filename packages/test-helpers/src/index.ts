/**
 * Internal test helpers for Agent Secrets.
 *
 * Everything here exists so that the product can be tested end to end without a
 * real credential, without the real `bws` binary, and without touching the
 * developer's home directory or login keychain.
 *
 * This package is `private: true` and must never be a runtime dependency of a
 * published package: it deliberately contains code that reads and writes
 * plaintext values, which is safe only inside a test process.
 */

export type { CanaryHit, CanarySweepResult, CanarySweepRoots } from './canary.js';
export {
  assertNoCanary,
  CANARY_BODY_LENGTH,
  CANARY_PREFIX,
  containsCanary,
  findCanaries,
  isCanary,
  makeCanary,
  sweepForCanary,
} from './canary.js';
export type { CapturedStreams, RunCliOptions, RunOptions, RunResult } from './capture.js';
export { captureStreams, defaultCliEntry, findRepoRoot, runCli, runProcess } from './capture.js';
export type {
  FakeBws,
  FakeBwsFailureMode,
  FakeBwsOperation,
  FakeBwsOptions,
  FakeBwsProject,
  FakeBwsSecret,
  FakeBwsState,
  RecordedCall,
  SeedSecretInput,
} from './fake-bws.js';
export {
  createFakeBws,
  FAKE_BWS_FAILURE_EXIT,
  FAKE_BWS_FAILURE_MESSAGES,
  FAKE_BWS_GARBAGE_OUTPUT,
  FAKE_BWS_VERSION,
} from './fake-bws.js';
export type {
  FakeKeychain,
  FakeKeychainOptions,
  KeychainEntry,
  KeychainOperation,
  StoredKeychainRow,
} from './fake-keychain.js';
export {
  createFakeKeychain,
  isIsolatedKeychainService,
  isolatedKeychainService,
  KEYCHAIN_TEST_SERVICE_PREFIX,
  readPersistedKeychain,
} from './fake-keychain.js';
export type { SampleManifest, SampleManifestEntry } from './fixtures.js';
export {
  FAKE_ACCESS_TOKEN,
  FAKE_ACCESS_TOKEN_INVALID,
  FAKE_ACCESS_TOKEN_SECOND,
  FAKE_PROJECT_SLUG,
  FAKE_TIMESTAMP,
  FAKE_TIMESTAMP_LATER,
  FAKE_UUIDS,
  SAMPLE_MANIFEST,
  SAMPLE_MANIFEST_YAML,
  SAMPLE_POLICY,
  SAMPLE_POLICY_YAML,
  sampleSecretMetadata,
  sampleSecretMetadataList,
} from './fixtures.js';
export type { TempHome, TempHomeOptions } from './temp-home.js';
export { createTempHome, formatMode } from './temp-home.js';
