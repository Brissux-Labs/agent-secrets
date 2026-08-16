import { createHash } from 'node:crypto';
import { chmod, readFile, realpath, writeFile } from 'node:fs/promises';
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

  it('redacts a value the child prints to stdout', async () => {
    // The regression this pins: the streaming path used to hand the child our
    // own file descriptors, so a child that echoed its environment printed the
    // value straight to the terminal, the CI log, and any agent transcript
    // wrapping the CLI — with the parent never seeing a byte it could filter.
    // The earlier test deliberately wrote to a file instead of stdout, so it
    // could not have caught this.
    const canary = newCanary();
    await addSecret('API_KEY', canary);

    const probe = await writeProbe('probe-echo.mjs', 'console.log("LEAK=" + process.env.API_KEY);');

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
    expect(result.stdout).toContain('LEAK=');
    expect(result.stdout).not.toContain(canary);
    expect(result.stdout).toContain('[REDACTED]');
  });

  it('redacts a value the child prints to stderr', async () => {
    const canary = newCanary();
    await addSecret('API_KEY', canary);

    const probe = await writeProbe(
      'probe-echo-err.mjs',
      'process.stderr.write("boot config: " + process.env.API_KEY + "\\n");',
    );

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

    expect(result.stderr).not.toContain(canary);
    expect(result.stderr).toContain('[REDACTED]');
  });

  it('redacts a value split across two writes', async () => {
    // The chunk-boundary case the redacting transform's overlap buffer exists
    // for. Written as two separate writes with a tick between them so they
    // cannot coalesce into one chunk.
    const canary = newCanary();
    await addSecret('API_KEY', canary);

    const probe = await writeProbe(
      'probe-split.mjs',
      `
      const value = process.env.API_KEY;
      const half = Math.floor(value.length / 2);
      process.stdout.write('prefix ' + value.slice(0, half));
      await new Promise((r) => setTimeout(r, 50));
      process.stdout.write(value.slice(half) + ' suffix\\n');
      `,
    );

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

    expect(result.stdout).not.toContain(canary);
    expect(result.stdout).toContain('prefix');
    expect(result.stdout).toContain('suffix');
  });

  it('warns and stops redacting when --pass-through-output is used', async () => {
    // The escape hatch is deliberate and documented, but it must be loud: the
    // operator is told, in that run, that redaction is off.
    const canary = newCanary();
    await addSecret('API_KEY', canary);

    const probe = await writeProbe(
      'probe-passthrough.mjs',
      'console.log("LEAK=" + process.env.API_KEY);',
    );

    const result = await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--keys',
      'API_KEY',
      '--pass-through-output',
      '--',
      process.execPath,
      probe,
    ]);

    expect(result.stderr).toContain('redaction is off');
    // Honest about the consequence: with the hatch open, the value does reach
    // the terminal. That is what the warning is for.
    expect(result.stdout).toContain(canary);
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

  it('strips our own credentials from the inherited environment', async () => {
    // `run_with_secrets` lets an agent pick the command, so an inherited
    // environment is a read channel: the MCP server's process carries the
    // adapter credential that mints vault-write links, and a deployment may
    // carry the Bitwarden access token itself.
    const canary = newCanary();
    await addSecret('API_KEY', canary);

    const adapterToken = `fake-adapter-${newCanary()}`;
    env['AGENT_SECRETS_ADAPTER_TOKEN'] = adapterToken;
    env['BWS_ACCESS_TOKEN'] = 'fake-bws-token-that-opens-the-vault';

    const probe = await writeProbe(
      'probe-env.mjs',
      `
      const fs = await import('node:fs/promises');
      await fs.writeFile(process.env.PROBE_OUT ?? process.argv[2], JSON.stringify({
        adapter: process.env.AGENT_SECRETS_ADAPTER_TOKEN ?? null,
        bws: process.env.BWS_ACCESS_TOKEN ?? null,
        injected: process.env.API_KEY ?? null,
        path: process.env.PATH ? 'present' : null,
      }));
      `,
    );

    const outPath = join(home.path, 'env-output.json');

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
      outPath,
    ]);

    const seen = JSON.parse(await readFile(outPath, 'utf8')) as Record<string, string | null>;

    expect(seen['adapter']).toBeNull();
    expect(seen['bws']).toBeNull();
    // The secret the caller actually asked for still arrives, and the ordinary
    // environment the command needs is untouched.
    expect(seen['injected']).toBe(canary);
    expect(seen['path']).toBe('present');
  });

  it('reports a failed child as CHILD_FAILED rather than forwarding its status', async () => {
    // Exit codes 2-10 belong to this tool. Forwarding the child's status would
    // make them ambiguous — a caller could not tell "policy denied" (4) from "the
    // child returned 4" — and the caller most likely to get that wrong is an
    // agent making a security decision.
    await addSecret('API_KEY', newCanary());
    const probe = await writeProbe('probe-fail.mjs', 'process.exit(4);');

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

    expect(result.code).toBe(9);
    expect(result.stderr).toContain('failure is in the command');
  });

  it("reports the child's real status in the JSON envelope", async () => {
    await addSecret('API_KEY', newCanary());
    const probe = await writeProbe('probe-fail-json.mjs', 'process.exit(42);');

    const result = await cli([
      '--json',
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

    expect(result.code).toBe(9);
    const payload = JSON.parse(result.stdout) as { data: { childExitCode: number } };
    expect(payload.data.childExitCode).toBe(42);
  });

  it('forwards the child status when --propagate-exit-code is passed', async () => {
    await addSecret('API_KEY', newCanary());
    const probe = await writeProbe('probe-fail-prop.mjs', 'process.exit(42);');

    const result = await cli([
      'run',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--keys',
      'API_KEY',
      '--propagate-exit-code',
      '--',
      process.execPath,
      probe,
    ]);

    expect(result.code).toBe(42);
  });

  it('exits 0 when the child succeeds', async () => {
    await addSecret('API_KEY', newCanary());
    const probe = await writeProbe('probe-ok.mjs', 'process.exit(0);');

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

/**
 * Manifest approval.
 *
 * Split into its own block because these tests care about state that persists
 * between CLI invocations, which the cases above deliberately avoid.
 */
describe('manifest approval', () => {
  let home: TempHome;
  let bws: FakeBws;
  let env: Record<string, string>;

  const cli = async (args: string[], options: { stdin?: string } = {}) =>
    await runCli(args, {
      entry: CLI,
      env,
      ...(options.stdin === undefined ? {} : { stdin: options.stdin }),
    });

  const writeManifest = async (approval: 'required' | 'none'): Promise<void> => {
    await writeFile(
      join(home.path, 'agent-secrets.yaml'),
      [
        'version: 1',
        'project: ezjob',
        'commands:',
        '  deploy:',
        '    environment: development',
        '    secrets:',
        '      - DEPLOY_KEY',
        '    command: ["echo", "deploying"]',
        `    approval: ${approval}`,
        '',
      ].join('\n'),
    );
  };

  beforeEach(async () => {
    home = await createTempHome();
    bws = await createFakeBws();
    env = {
      ...home.env,
      AGENT_SECRETS_CREDENTIAL_STORE: 'file',
      NO_COLOR: '1',
      PATH: process.env['PATH'] ?? '/usr/bin:/bin',
    };

    const paths = resolvePaths(env as NodeJS.ProcessEnv);
    const config = newDeviceConfig({
      deviceName: 'test-device',
      projectId: bws.projectId,
      executablePath: bws.path,
    });
    await saveConfig(paths, config);
    const store = new FileCredentialStore(paths.home);
    await store.set(KEYCHAIN_SERVICE, keychainAccount(config.deviceId, bws.projectId), bws.token);

    await cli(['add', 'DEPLOY_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'], {
      stdin: newCanary(),
    });
  });

  afterEach(async () => {
    await bws.cleanup();
    await home.cleanup();
  });

  it('refuses an unapproved manifest command run non-interactively', async () => {
    await writeManifest('required');

    const result = await cli(['run', '--manifest', 'deploy', '--cwd', home.path]);

    expect(result.code).toBe(4);
    expect(result.stderr).toContain('not approved');
  });

  it('does not let --yes waive manifest approval', async () => {
    await writeManifest('required');

    // The gate exists precisely for the non-interactive caller, so a flag that
    // caller controls must not open it.
    const result = await cli(['run', '--manifest', 'deploy', '--cwd', home.path, '--yes']);

    expect(result.code).toBe(4);
    expect(result.stderr).toContain('cannot be waived');
  });

  it('runs a manifest command that does not require approval', async () => {
    await writeManifest('none');

    const result = await cli(['run', '--manifest', 'deploy', '--cwd', home.path]);

    expect(result.code).toBe(0);
    expect(result.stdout).toContain('deploying');
  });

  it('honours a stored approval and invalidates it when the manifest changes', async () => {
    await writeManifest('required');

    // realpath, because approvals are keyed by the resolved path: on macOS the
    // temp directory is itself a symlink, and an approval recorded under the
    // unresolved name would not match — which is the whole point of resolving.
    const manifestPath = await realpath(join(home.path, 'agent-secrets.yaml'));
    const paths = resolvePaths(env as NodeJS.ProcessEnv);
    const raw = await readFile(manifestPath, 'utf8');
    const digest = createHash('sha256').update(raw, 'utf8').digest('hex');

    // Simulate the approval a human would have given at an interactive prompt.
    await writeFile(
      join(paths.home, 'manifest-approvals.json'),
      JSON.stringify({
        version: 1,
        approvals: [
          {
            manifestPath,
            digest,
            command: 'deploy',
            approvedAt: new Date().toISOString(),
          },
        ],
      }),
      { mode: 0o600 },
    );

    const approved = await cli(['run', '--manifest', 'deploy', '--cwd', home.path]);
    expect(approved.code).toBe(0);

    // Change what the command executes. The approval was for the old content.
    await writeFile(
      manifestPath,
      raw.replace('["echo", "deploying"]', '["echo", "something-else-entirely"]'),
    );

    const afterEdit = await cli(['run', '--manifest', 'deploy', '--cwd', home.path]);
    expect(afterEdit.code).toBe(4);
    expect(afterEdit.stderr).toContain('not approved');
  });

  it('always requires approval for a production manifest command', async () => {
    await writeFile(
      join(home.path, 'agent-secrets.yaml'),
      [
        'version: 1',
        'project: ezjob',
        'commands:',
        '  deploy:',
        '    environment: production',
        '    secrets:',
        '      - DEPLOY_KEY',
        '    command: ["echo", "deploying"]',
        // Note: approval is NOT declared. Production requires it regardless.
        '',
      ].join('\n'),
    );

    const result = await cli(['run', '--manifest', 'deploy', '--cwd', home.path]);

    expect(result.code).toBe(4);
    expect(result.stderr).toContain('not approved');
  });
});
