import { chmod, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
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
 * `agent-secrets run` — the one place a value legitimately leaves the process.
 *
 * These are the tests the product's central claim rests on. Each one is written
 * so that a regression produces a failure rather than a subtly weaker guarantee:
 * the child asserts what it received, and the parent's streams are checked for
 * the canary rather than for a redaction marker.
 */

const CLI = new URL('../../dist/bin.js', import.meta.url).pathname;

describe('controlled execution', () => {
  let home: TempHome;
  let bws: FakeBws;
  let env: Record<string, string>;
  let scriptDir: string;

  const enrol = async (): Promise<void> => {
    const paths = resolvePaths(env as NodeJS.ProcessEnv);
    const config = newDeviceConfig({
      deviceName: 'test-device',
      projectId: bws.projectId,
      executablePath: bws.path,
    });
    await saveConfig(paths, config);
    const store = new FileCredentialStore(paths.home);
    await store.set(KEYCHAIN_SERVICE, keychainAccount(config.deviceId, bws.projectId), bws.token);
  };

  const cli = async (args: string[], options: { stdin?: string } = {}) =>
    await runCli(args, {
      entry: CLI,
      env,
      ...(options.stdin === undefined ? {} : { stdin: options.stdin }),
    });

  const addSecret = async (name: string, value: string): Promise<void> => {
    const result = await cli(
      ['add', name, '--project', 'ezjob', '--env', 'development', '--stdin'],
      { stdin: value },
    );
    expect(result.code).toBe(0);
  };

  /** A child that reports what it can see, so the test asserts on reality. */
  const writeProbe = async (filename: string, body: string): Promise<string> => {
    const path = join(scriptDir, filename);
    await writeFile(path, `#!/usr/bin/env node\n${body}\n`, { mode: 0o755 });
    await chmod(path, 0o755);
    return path;
  };

  beforeEach(async () => {
    home = await createTempHome();
    bws = await createFakeBws();
    scriptDir = home.path;
    env = {
      ...home.env,
      AGENT_SECRETS_CREDENTIAL_STORE: 'file',
      NO_COLOR: '1',
      PATH: process.env['PATH'] ?? '/usr/bin:/bin',
    };
    await enrol();
  });

  afterEach(async () => {
    await bws.cleanup();
    await home.cleanup();
  });

  it('gives the child the exact value and shows it to nobody else', async () => {
    const canary = newCanary();
    await addSecret('API_KEY', canary);

    const probe = await writeProbe(
      'probe.mjs',
      `
      const seen = process.env.API_KEY;
      // Written to a file rather than stdout: proving the child got the value
      // must not require the value to travel through a stream the parent reads.
      await import('node:fs/promises').then((fs) =>
        fs.writeFile(process.env.PROBE_OUT, seen ?? '<missing>'),
      );
      `,
    );

    const outPath = join(home.path, 'probe-output.txt');
    env['PROBE_OUT'] = outPath;

    const result = await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--keys',
      'API_KEY',
      '--',
      process.execPath,
      probe,
    ]);

    expect(result.code).toBe(0);

    const received = await import('node:fs/promises').then((fs) => fs.readFile(outPath, 'utf8'));
    expect(received).toBe(canary);

    // The parent leaked nothing, in either stream.
    expect(result.stdout).not.toContain(canary);
    expect(result.stderr).not.toContain(canary);
  });

  it('injects only the named secrets', async () => {
    const wanted = newCanary();
    const unwanted = newCanary();
    await addSecret('WANTED_KEY', wanted);
    await addSecret('UNWANTED_KEY', unwanted);

    const probe = await writeProbe(
      'probe-scope.mjs',
      `
      const fs = await import('node:fs/promises');
      await fs.writeFile(process.env.PROBE_OUT, JSON.stringify({
        wanted: process.env.WANTED_KEY ?? null,
        unwanted: process.env.UNWANTED_KEY ?? null,
      }));
      `,
    );

    const outPath = join(home.path, 'scope-output.json');
    env['PROBE_OUT'] = outPath;

    await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--keys',
      'WANTED_KEY',
      '--',
      process.execPath,
      probe,
    ]);

    const seen = JSON.parse(
      await import('node:fs/promises').then((fs) => fs.readFile(outPath, 'utf8')),
    ) as { wanted: string | null; unwanted: string | null };

    expect(seen.wanted).toBe(wanted);
    // The secret that was not asked for is simply absent — no empty string, no
    // placeholder, nothing the child could mistake for a value.
    expect(seen.unwanted).toBeNull();
  });

  it('propagates a non-zero child exit code', async () => {
    await addSecret('API_KEY', newCanary());
    const probe = await writeProbe('probe-fail.mjs', 'process.exit(42);');

    const result = await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--keys',
      'API_KEY',
      '--',
      process.execPath,
      probe,
    ]);

    expect(result.code).toBe(42);
  });

  it('does not put the value in the child argument vector', async () => {
    const canary = newCanary();
    await addSecret('API_KEY', canary);

    const probe = await writeProbe(
      'probe-argv.mjs',
      `
      const fs = await import('node:fs/promises');
      await fs.writeFile(process.env.PROBE_OUT, process.argv.join(' '));
      `,
    );

    const outPath = join(home.path, 'argv-output.txt');
    env['PROBE_OUT'] = outPath;

    await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--keys',
      'API_KEY',
      '--',
      process.execPath,
      probe,
    ]);

    const argv = await import('node:fs/promises').then((fs) => fs.readFile(outPath, 'utf8'));
    expect(argv).not.toContain(canary);
  });

  it('does not print values in a dry run', async () => {
    const canary = newCanary();
    await addSecret('API_KEY', canary);

    const result = await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--keys',
      'API_KEY',
      '--dry-run',
      '--',
      'echo',
      'hello',
    ]);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain('API_KEY');
    expect(result.stdout).not.toContain(canary);
    // A dry run resolves nothing, so the backend is never asked for a value.
    const calls = await bws.calls();
    expect(calls.filter((call) => call.argv[1] === 'get')).toHaveLength(0);
  });

  it('refuses to run without named secrets rather than injecting everything', async () => {
    await addSecret('API_KEY', newCanary());

    const result = await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--',
      'echo',
      'hello',
    ]);

    expect(result.code).toBe(2);
    expect(result.stderr).toContain('No secrets were named');
  });

  it('refuses an executable on the deny list', async () => {
    await addSecret('API_KEY', newCanary());

    const result = await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--keys',
      'API_KEY',
      '--',
      'sh',
      '-c',
      'echo hello',
    ]);

    expect(result.code).toBe(4);
    expect(result.stderr).toContain('deny list');
  });

  it('fails closed when a requested secret does not exist', async () => {
    await addSecret('API_KEY', newCanary());

    const result = await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--keys',
      'API_KEY,MISSING_KEY',
      '--',
      'echo',
      'hello',
    ]);

    expect(result.code).toBe(5);
    expect(result.stderr).toContain('MISSING_KEY');
  });

  it('records an audit entry with names and the executable, but no arguments', async () => {
    const canary = newCanary();
    await addSecret('API_KEY', canary);

    await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--keys',
      'API_KEY',
      '--',
      'echo',
      'a-sensitive-looking-argument',
    ]);

    const paths = resolvePaths(env as NodeJS.ProcessEnv);
    const audit = await import('node:fs/promises').then((fs) =>
      fs.readFile(paths.auditFile, 'utf8'),
    );

    expect(audit).toContain('"operation":"run"');
    expect(audit).toContain('"commandExecutable":"echo"');
    expect(audit).toContain('API_KEY');
    // FR-RUN-010: arguments are not recorded, because they routinely carry
    // credentials of their own.
    expect(audit).not.toContain('a-sensitive-looking-argument');
    expect(audit).not.toContain(canary);
  });

  it('gives a minimal environment with --isolated-env', async () => {
    const canary = newCanary();
    await addSecret('API_KEY', canary);
    env['UNRELATED_SECRET_FROM_SHELL'] = 'should-not-reach-the-child';

    // The output path travels as an argument, not an environment variable:
    // with --isolated-env the child receives only the minimal block, so
    // PROBE_OUT would not reach it. That is the behaviour under test.
    const probe = await writeProbe(
      'probe-isolated.mjs',
      `
      const fs = await import('node:fs/promises');
      await fs.writeFile(process.argv[2], JSON.stringify({
        injected: process.env.API_KEY ?? null,
        inherited: process.env.UNRELATED_SECRET_FROM_SHELL ?? null,
      }));
      `,
    );

    const outPath = join(home.path, 'isolated-output.json');

    await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--keys',
      'API_KEY',
      '--isolated-env',
      '--',
      process.execPath,
      probe,
      outPath,
    ]);

    const seen = JSON.parse(
      await import('node:fs/promises').then((fs) => fs.readFile(outPath, 'utf8')),
    ) as { injected: string | null; inherited: string | null };

    expect(seen.injected).toBe(canary);
    expect(seen.inherited).toBeNull();
  });

  it('runs a manifest command with exactly the secrets it declares', async () => {
    const wanted = newCanary();
    await addSecret('MANIFEST_KEY', wanted);

    const probe = await writeProbe(
      'probe-manifest.mjs',
      `
      const fs = await import('node:fs/promises');
      await fs.writeFile(process.env.PROBE_OUT, process.env.MANIFEST_KEY ?? '<missing>');
      `,
    );

    const outPath = join(home.path, 'manifest-output.txt');
    env['PROBE_OUT'] = outPath;

    await writeFile(
      join(home.path, 'agent-secrets.yaml'),
      [
        'version: 1',
        'project: ezjob',
        'commands:',
        '  probe:',
        '    environment: development',
        '    secrets:',
        '      - MANIFEST_KEY',
        `    command: ["${process.execPath}", "${probe}"]`,
        '',
      ].join('\n'),
    );

    const result = await cli(['run', '--manifest', 'probe', '--cwd', home.path]);

    expect(result.code).toBe(0);
    const received = await import('node:fs/promises').then((fs) => fs.readFile(outPath, 'utf8'));
    expect(received).toBe(wanted);
  });

  it('rejects a manifest carrying an unknown key', async () => {
    await addSecret('MANIFEST_KEY', newCanary());
    await writeFile(
      join(home.path, 'agent-secrets.yaml'),
      [
        'version: 1',
        'project: ezjob',
        'injectEverything: true',
        'commands:',
        '  probe:',
        '    environment: development',
        '    secrets: [MANIFEST_KEY]',
        '    command: ["echo", "hi"]',
        '',
      ].join('\n'),
    );

    const result = await cli(['run', '--manifest', 'probe', '--cwd', home.path]);

    // Fail closed: a directive this version does not understand is a refusal,
    // not something to ignore.
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('manifest');
  });
});
