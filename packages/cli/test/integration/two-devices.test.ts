import { newCanary } from '@bx-labs/agent-secrets-redaction';
import {
  createFakeBws,
  createTempHome,
  type FakeBws,
  runCli,
  type TempHome,
} from '@bx-labs/agent-secrets-test-helpers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  FileCredentialStore,
  KEYCHAIN_SERVICE,
  keychainAccount,
  newDeviceConfig,
  resolvePaths,
  saveConfig,
} from '../../src/index.js';

/**
 * The two-Mac model, end to end.
 *
 * This is the milestone acceptance criterion stated most plainly in the product
 * requirements: a secret added on Mac A is usable from Mac B, each machine holds
 * its own credential, and revoking one leaves the other working. Two temp homes
 * and two tokens against one fake vault is exactly that scenario — the only
 * thing simulated is the vault itself.
 */

const CLI = new URL('../../dist/bin.js', import.meta.url).pathname;

describe('two devices sharing one vault', () => {
  let bws: FakeBws;
  let macMini: TempHome;
  let macBook: TempHome;
  let envA: Record<string, string>;
  let envB: Record<string, string>;

  const enrol = async (
    env: Record<string, string>,
    deviceName: string,
    token: string,
  ): Promise<void> => {
    const paths = resolvePaths(env as NodeJS.ProcessEnv);
    const config = newDeviceConfig({
      deviceName,
      projectId: bws.projectId,
      executablePath: bws.path,
    });
    await saveConfig(paths, config);
    const store = new FileCredentialStore(paths.home);
    await store.set(KEYCHAIN_SERVICE, keychainAccount(config.deviceId, bws.projectId), token);
  };

  const on = async (
    env: Record<string, string>,
    args: string[],
    options: { stdin?: string } = {},
  ) =>
    await runCli(args, {
      entry: CLI,
      env,
      ...(options.stdin === undefined ? {} : { stdin: options.stdin }),
    });

  beforeEach(async () => {
    // Two independent machine tokens against one Bitwarden project — the exact
    // arrangement docs/device-enrollment.md describes.
    bws = await createFakeBws({ tokens: ['fake-token-mac-mini', 'fake-token-macbook-air'] });

    macMini = await createTempHome();
    macBook = await createTempHome();

    const base = {
      AGENT_SECRETS_CREDENTIAL_STORE: 'file',
      NO_COLOR: '1',
      PATH: process.env['PATH'] ?? '/usr/bin:/bin',
    };
    envA = { ...macMini.env, ...base };
    envB = { ...macBook.env, ...base };

    await enrol(envA, 'Mac-mini', 'fake-token-mac-mini');
    await enrol(envB, 'MacBook-Air', 'fake-token-macbook-air');
  });

  afterEach(async () => {
    await bws.cleanup();
    await macMini.cleanup();
    await macBook.cleanup();
  });

  it('makes a secret added on one Mac visible from the other', async () => {
    const canary = newCanary();

    const added = await on(
      envA,
      ['add', 'OPENAI_API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'],
      { stdin: canary },
    );
    expect(added.code).toBe(0);

    const seen = await on(envB, ['list', '--project', 'ezjob', '--env', 'development']);
    expect(seen.code).toBe(0);
    expect(seen.stdout).toContain('OPENAI_API_KEY');
    expect(seen.stdout).not.toContain(canary);
  });

  it('propagates a rotation from one Mac to the other', async () => {
    await on(envA, ['add', 'API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'], {
      stdin: newCanary(),
    });

    const rotated = newCanary();
    const rotation = await on(
      envB,
      ['rotate', 'API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'],
      { stdin: rotated },
    );
    expect(rotation.code).toBe(0);

    // Mac A now resolves the value Mac B wrote. Checked at the vault, because
    // the CLI has no way to print a value — which is the point.
    const state = await bws.readState();
    const record = state.secrets.find((secret) => secret.key === 'ezjob/development/API_KEY');
    expect(record?.value).toBe(rotated);
  });

  it('keeps each device credential local to its own machine', async () => {
    const filesA = await macMini.readConfigFiles();
    const filesB = await macBook.readConfigFiles();

    const blobA = JSON.stringify(filesA);
    const blobB = JSON.stringify(filesB);

    expect(blobA).toContain('fake-token-mac-mini');
    expect(blobA).not.toContain('fake-token-macbook-air');
    expect(blobB).toContain('fake-token-macbook-air');
    expect(blobB).not.toContain('fake-token-mac-mini');
  });

  it('leaves the other Mac working after one device token is revoked', async () => {
    await on(envA, ['add', 'API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'], {
      stdin: newCanary(),
    });

    // The lost-laptop procedure: revoke that machine's token in Bitwarden.
    await bws.revokeToken('fake-token-mac-mini');

    const lostMac = await on(envA, ['list', '--project', 'ezjob', '--env', 'development']);
    expect(lostMac.code).toBe(3);
    expect(lostMac.stderr).toMatch(/token|enrol/i);

    const survivingMac = await on(envB, ['list', '--project', 'ezjob', '--env', 'development']);
    expect(survivingMac.code).toBe(0);
    expect(survivingMac.stdout).toContain('API_KEY');
  });

  it('reports the revoked device as unhealthy without printing a credential', async () => {
    await bws.revokeToken('fake-token-mac-mini');

    const doctor = await on(envA, ['doctor']);

    expect(doctor.code).not.toBe(0);
    const output = `${doctor.stdout}${doctor.stderr}`;
    expect(output).toContain('Mac-mini');
    expect(output).not.toContain('fake-token-mac-mini');
  });

  it('removes only the local credential on logout, and says the token still works', async () => {
    const logout = await on(envA, ['logout', '--yes']);
    expect(logout.code).toBe(0);
    // The distinction that matters when a laptop is lost.
    expect(logout.stdout).toContain('still valid in Bitwarden');

    const afterLogout = await on(envA, ['list', '--project', 'ezjob', '--env', 'development']);
    expect(afterLogout.code).toBe(3);

    // The other machine is untouched, and the vault kept its contents.
    const other = await on(envB, ['list', '--project', 'ezjob', '--env', 'development']);
    expect(other.code).toBe(0);
  });
});
