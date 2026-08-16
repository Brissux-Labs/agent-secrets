import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  assertNoCanary,
  findCanaries,
  isCanary,
  makeCanary,
  sweepForCanary,
} from '../../src/canary.js';
import { captureStreams, findRepoRoot, runCli, runProcess } from '../../src/capture.js';
import {
  createFakeKeychain,
  isIsolatedKeychainService,
  isolatedKeychainService,
  readPersistedKeychain,
} from '../../src/fake-keychain.js';
import {
  FAKE_ACCESS_TOKEN,
  FAKE_ACCESS_TOKEN_SECOND,
  SAMPLE_MANIFEST,
  SAMPLE_POLICY,
  sampleSecretMetadata,
} from '../../src/fixtures.js';
import { createTempHome, type TempHome } from '../../src/temp-home.js';

const homes: TempHome[] = [];

async function tempHome(...args: Parameters<typeof createTempHome>): Promise<TempHome> {
  const home = await createTempHome(...args);
  homes.push(home);
  return home;
}

afterEach(async () => {
  while (homes.length > 0) {
    await homes.pop()?.cleanup();
  }
});

describe('createFakeKeychain', () => {
  it('stores, reads, lists and deletes without logging the password', async () => {
    const canary = makeCanary();
    const keychain = createFakeKeychain();
    const service = isolatedKeychainService();

    expect(await keychain.getPassword(service, 'device')).toBeNull();
    await keychain.setPassword(service, 'device', canary);
    expect(await keychain.getPassword(service, 'device')).toBe(canary);
    expect(await keychain.list()).toEqual([{ service, account: 'device' }]);
    expect(await keychain.deletePassword(service, 'device')).toBe(true);
    expect(await keychain.deletePassword(service, 'device')).toBe(false);
    expect(await keychain.getPassword(service, 'device')).toBeNull();

    expect(JSON.stringify(keychain.operations())).not.toContain(canary);
    expect(keychain.operations().map((entry) => entry.op)).toEqual([
      'get',
      'set',
      'get',
      'list',
      'delete',
      'delete',
      'get',
    ]);
  });

  it('keeps service/account pairs distinct even when they share characters', async () => {
    const keychain = createFakeKeychain();
    await keychain.setPassword('a', 'b/c', 'first');
    await keychain.setPassword('a/b', 'c', 'second');
    expect(await keychain.getPassword('a', 'b/c')).toBe('first');
    expect(await keychain.getPassword('a/b', 'c')).toBe('second');
  });

  it('mirrors to a 0600 file when asked', async () => {
    const home = await tempHome();
    const persistPath = join(home.path, 'keychain.json');
    const keychain = createFakeKeychain({ persistPath });
    await keychain.setPassword('svc', 'acct', 'value-under-test');

    expect(await readPersistedKeychain(persistPath)).toEqual([
      { service: 'svc', account: 'acct', password: 'value-under-test' },
    ]);
    expect((await home.statPermissions())['keychain.json']).toBe('0600');

    await keychain.reset();
    expect(await keychain.list()).toEqual([]);
  });

  it('produces a collision-proof isolated service name', () => {
    const first = isolatedKeychainService();
    expect(isIsolatedKeychainService(first)).toBe(true);
    expect(first).not.toBe(isolatedKeychainService());
    expect(isIsolatedKeychainService('Agent Secrets')).toBe(false);
  });
});

describe('createTempHome', () => {
  it('builds an environment overlay that stays inside the temp dir', async () => {
    const home = await tempHome();
    for (const key of ['HOME', 'XDG_CONFIG_HOME', 'AGENT_SECRETS_HOME', 'TMPDIR']) {
      expect(home.env[key]?.startsWith(home.path)).toBe(true);
    }
    // The overlay must not leak the developer's PATH, which usually contains a
    // real `bws` pointed at a real vault.
    expect(home.env.PATH).not.toContain('/usr/local');
    expect(home.env.NO_COLOR).toBe('1');
  });

  it('accepts extra environment entries and a custom PATH', async () => {
    const home = await tempHome({ env: { BWS_ACCESS_TOKEN: FAKE_ACCESS_TOKEN }, path: '/bin' });
    expect(home.env.BWS_ACCESS_TOKEN).toBe(FAKE_ACCESS_TOKEN);
    expect(home.env.PATH).toBe('/bin');
  });

  it('reads back every file it contains and reports its mode', async () => {
    const home = await tempHome();
    await writeFile(join(home.path, '.config', 'config.json'), '{"deviceId":"d"}', { mode: 0o600 });

    const files = await home.readConfigFiles();
    expect(files['.config/config.json']).toBe('{"deviceId":"d"}');

    const modes = await home.statPermissions();
    expect(modes['.config/config.json']).toBe('0600');
    expect(modes['.config']).toBe('0700');
  });

  it('cleans up completely', async () => {
    const home = await createTempHome();
    await home.cleanup();
    await expect(readFile(join(home.path, '.config'), 'utf8')).rejects.toThrow();
  });
});

describe('captureStreams', () => {
  it('collects writes and restores idempotently', () => {
    const captured = captureStreams();
    try {
      process.stdout.write('out-one');
      process.stdout.write(Buffer.from('out-two'));
      process.stderr.write('err\n');
      expect(captured.stdout).toBe('out-oneout-two');
      expect(captured.stderr).toBe('err\n');
      captured.clear();
      expect(captured.stdout).toBe('');
    } finally {
      captured.restore();
      captured.restore();
    }
    // After restore the real stream is back, so nothing more is collected.
    expect(captured.stdout).toBe('');
  });
});

describe('runProcess / runCli', () => {
  it('never hands the parent environment to the child', async () => {
    const marker = makeCanary();
    process.env.AGENT_SECRETS_LEAK_PROBE = marker;
    try {
      const result = await runProcess(process.execPath, [
        '-e',
        'process.stdout.write(JSON.stringify(process.env))',
      ]);
      expect(result.code).toBe(0);
      expect(result.stdout).not.toContain(marker);
      expect(JSON.parse(result.stdout)).toMatchObject({ CI: '1', NO_COLOR: '1' });
    } finally {
      delete process.env.AGENT_SECRETS_LEAK_PROBE;
    }
  });

  it('pipes stdin and reports the exit code', async () => {
    const result = await runProcess(
      process.execPath,
      ['-e', 'process.stdin.on("data", (d) => process.stdout.write(d)); process.exitCode = 7;'],
      { stdin: 'from-stdin' },
    );
    expect(result.stdout).toBe('from-stdin');
    expect(result.code).toBe(7);
  });

  it('kills a child that overruns its timeout', async () => {
    const result = await runProcess(process.execPath, ['-e', 'setTimeout(() => {}, 30000)'], {
      timeoutMs: 300,
    });
    expect(result.timedOut).toBe(true);
    expect(result.signal).toBe('SIGKILL');
  });

  it('explains itself when the CLI has not been built', async () => {
    await expect(runCli(['--help'], { entry: '/nonexistent/bin.js' })).rejects.toThrow(
      /Build it first/,
    );
  });

  it('locates the workspace root', () => {
    expect(findRepoRoot()).toMatch(/agent-secrets$/);
  });
});

describe('canary helpers', () => {
  it('generates recognisable, unique canaries', () => {
    const canary = makeCanary();
    expect(isCanary(canary)).toBe(true);
    expect(canary).not.toBe(makeCanary());
    expect(isCanary('ASECRET_CANARY_nothex')).toBe(false);
    expect(findCanaries(`noise ${canary} noise ${canary}`)).toEqual([canary]);
  });

  it('sweeps files, streams and an allow list in one call', async () => {
    const canary = makeCanary();
    const home = await tempHome();
    const vault = join(home.path, 'vault.json');
    await writeFile(vault, canary);
    await writeFile(join(home.path, '.config', 'leaked.log'), `wrote ${canary}`);

    const dirty = await sweepForCanary(canary, {
      home,
      allow: [vault],
      streams: { stdout: 'clean', stderr: `oops ${canary}` },
    });
    expect(dirty.clean).toBe(false);
    expect(dirty.allowed).toEqual([vault]);
    expect(dirty.hits.map((hit) => hit.kind).sort()).toEqual(['file', 'stream']);
    // The report names locations, never the canary itself.
    expect(JSON.stringify(dirty.hits)).not.toContain(canary);

    await expect(assertNoCanary(canary, { home, allow: [vault] })).rejects.toThrow(/leaked into/);
    await expect(assertNoCanary(makeCanary(), { home })).resolves.toBeDefined();
  });

  it('refuses an empty canary rather than matching everything', async () => {
    await expect(sweepForCanary('', {})).rejects.toThrow(/non-empty/);
  });

  it('scans the git working tree without finding a fresh canary', async () => {
    const result = await sweepForCanary(makeCanary(), { repo: true });
    expect(result.clean).toBe(true);
    expect(result.scanned).toBeGreaterThan(10);
  });
});

describe('fixtures', () => {
  it('are obviously fake', () => {
    expect(FAKE_ACCESS_TOKEN).toContain('fake');
    expect(FAKE_ACCESS_TOKEN).not.toBe(FAKE_ACCESS_TOKEN_SECOND);
    // Shaped like a real machine-account token so a parser can be exercised.
    expect(FAKE_ACCESS_TOKEN).toMatch(/^0\.[0-9a-f-]{36}\.[^:]+:.+$/);
  });

  it('provide metadata that carries no value-derived field', () => {
    const metadata = sampleSecretMetadata({ environment: 'production' });
    expect(metadata.environment).toBe('production');
    expect(metadata.reference).toContain('OPENAI_API_KEY');
    expect(Object.keys(metadata)).not.toContain('value');
  });

  it('provide a manifest and a policy usable as-is', () => {
    expect(SAMPLE_MANIFEST.secrets.map((entry) => entry.name)).toContain('OPENAI_API_KEY');
    expect(SAMPLE_POLICY.projects.ezjob?.environments.production?.allow).toEqual([]);
  });
});
