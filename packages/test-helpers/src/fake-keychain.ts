import { randomBytes } from 'node:crypto';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

/**
 * A stand-in for the macOS Keychain.
 *
 * The real adapter shells out to `/usr/bin/security`, which exists only on
 * macOS and, worse, touches the developer's actual login keychain. Neither is
 * acceptable in a unit test, so keychain-dependent code is written against this
 * interface and gets the real implementation injected in production.
 *
 * The operations log records service and account but never the password: a test
 * helper that keeps a plaintext credential in an assertion-friendly array is
 * exactly the "test artifact" destination CLAUDE.md §1 forbids. The password
 * lives in the store and nowhere else.
 */

export interface KeychainEntry {
  readonly service: string;
  readonly account: string;
}

export interface KeychainOperation {
  readonly op: 'set' | 'get' | 'delete' | 'list';
  readonly service?: string;
  readonly account?: string;
  /** For `get`/`delete`: whether an entry existed. Carries no value content. */
  readonly found?: boolean;
  readonly timestamp: string;
}

export interface StoredKeychainRow {
  service: string;
  account: string;
  password: string;
}

export interface FakeKeychain {
  setPassword(service: string, account: string, password: string): Promise<void>;
  /** Returns `null` when absent, matching the "missing is not an error" rule. */
  getPassword(service: string, account: string): Promise<string | null>;
  /** Returns whether something was actually removed. */
  deletePassword(service: string, account: string): Promise<boolean>;
  list(): Promise<KeychainEntry[]>;
  /** Every operation attempted, in order. Never contains a password. */
  operations(): readonly KeychainOperation[];
  clearOperations(): void;
  /** Drop every stored entry and, if persisting, the backing file. */
  reset(): Promise<void>;
  /** Set when the keychain mirrors itself to disk for a child process. */
  readonly persistPath: string | undefined;
}

export interface FakeKeychainOptions {
  /**
   * Mirror the store to this file (mode 0600) after every mutation, so a child
   * process can read the same keychain. Omit for a purely in-memory keychain.
   */
  persistPath?: string;
  /** Pre-populated entries, e.g. a device token seeded by a fixture. */
  seed?: readonly StoredKeychainRow[];
}

/**
 * A separator no identifier can contain, rather than a space or a colon: real
 * service names contain spaces ("Agent Secrets TEST <hex>") and real account
 * names contain slashes (canonical references), so any printable separator
 * would let two distinct pairs collide on the same map key.
 */
const KEY_SEPARATOR = '\u0000';

function compositeKey(service: string, account: string): string {
  return service + KEY_SEPARATOR + account;
}

function splitKey(key: string): KeychainEntry {
  const [service = '', account = ''] = key.split(KEY_SEPARATOR);
  return { service, account };
}

export function createFakeKeychain(options: FakeKeychainOptions = {}): FakeKeychain {
  const store = new Map<string, string>();
  const log: KeychainOperation[] = [];
  const persistPath = options.persistPath;

  for (const entry of options.seed ?? []) {
    store.set(compositeKey(entry.service, entry.account), entry.password);
  }

  const record = (operation: Omit<KeychainOperation, 'timestamp'>): void => {
    log.push({ ...operation, timestamp: new Date().toISOString() });
  };

  const persist = async (): Promise<void> => {
    if (persistPath === undefined) {
      return;
    }
    await mkdir(dirname(persistPath), { recursive: true });
    const rows: StoredKeychainRow[] = [...store.entries()].map(([key, password]) => ({
      ...splitKey(key),
      password,
    }));
    await writeFile(persistPath, `${JSON.stringify(rows, null, 2)}\n`, { mode: 0o600 });
  };

  return {
    persistPath,

    async setPassword(service: string, account: string, password: string): Promise<void> {
      store.set(compositeKey(service, account), password);
      record({ op: 'set', service, account });
      await persist();
    },

    async getPassword(service: string, account: string): Promise<string | null> {
      const found = store.get(compositeKey(service, account));
      record({ op: 'get', service, account, found: found !== undefined });
      return found ?? null;
    },

    async deletePassword(service: string, account: string): Promise<boolean> {
      const existed = store.delete(compositeKey(service, account));
      record({ op: 'delete', service, account, found: existed });
      await persist();
      return existed;
    },

    async list(): Promise<KeychainEntry[]> {
      record({ op: 'list' });
      return [...store.keys()].map(splitKey);
    },

    operations(): readonly KeychainOperation[] {
      return log;
    },

    clearOperations(): void {
      log.length = 0;
    },

    async reset(): Promise<void> {
      store.clear();
      log.length = 0;
      if (persistPath !== undefined) {
        await rm(persistPath, { force: true });
      }
    },
  };
}

/** Reads a persisted fake keychain back, for assertions from another process. */
export async function readPersistedKeychain(persistPath: string): Promise<StoredKeychainRow[]> {
  return JSON.parse(await readFile(persistPath, 'utf8')) as StoredKeychainRow[];
}

export const KEYCHAIN_TEST_SERVICE_PREFIX = 'Agent Secrets TEST';

/**
 * A unique service name for the integration tests that deliberately do hit the
 * real macOS keychain.
 *
 * Collision with the user's genuine `Agent Secrets` entries would mean a test
 * run deleting a developer's real device token, so the namespace is randomised
 * per call rather than merely suffixed with `-test`.
 */
export function isolatedKeychainService(): string {
  return `${KEYCHAIN_TEST_SERVICE_PREFIX} ${randomBytes(8).toString('hex')}`;
}

/** True for a service name produced by `isolatedKeychainService`. */
export function isIsolatedKeychainService(service: string): boolean {
  return new RegExp(`^${KEYCHAIN_TEST_SERVICE_PREFIX} [0-9a-f]{16}$`).test(service);
}
