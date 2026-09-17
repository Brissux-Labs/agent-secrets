import { readFile, writeFile } from 'node:fs/promises';
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
 * The CLI, driven as a real child process against a fake `bws`.
 *
 * Running it as a subprocess rather than calling the functions directly is the
 * point: exit codes, stdout/stderr separation, TTY detection and process
 * lifetime are all part of the contract that agents and scripts depend on, and
 * none of them are exercised by an in-process call.
 */

const CLI = new URL('../../dist/bin.js', import.meta.url).pathname;

describe('CLI lifecycle', () => {
  let home: TempHome;
  let bws: FakeBws;
  let env: Record<string, string>;

  const enrol = async (): Promise<{ deviceId: string }> => {
    const paths = resolvePaths(env as NodeJS.ProcessEnv);
    const config = newDeviceConfig({
      deviceName: 'test-device',
      projectId: bws.projectId,
      executablePath: bws.path,
    });
    await saveConfig(paths, config);

    // Written through the same store the CLI will read from, rather than by
    // hand: if the storage format changes, this test changes with it.
    const store = new FileCredentialStore(paths.home);
    await store.set(KEYCHAIN_SERVICE, keychainAccount(config.deviceId, bws.projectId), bws.token);

    return { deviceId: config.deviceId };
  };

  const cli = async (args: string[], options: { stdin?: string } = {}) =>
    await runCli(args, {
      entry: CLI,
      env,
      ...(options.stdin === undefined ? {} : { stdin: options.stdin }),
    });

  beforeEach(async () => {
    home = await createTempHome();
    bws = await createFakeBws();
    env = {
      ...home.env,
      AGENT_SECRETS_CREDENTIAL_STORE: 'file',
      NO_COLOR: '1',
      PATH: process.env['PATH'] ?? '/usr/bin:/bin',
    };
  });

  afterEach(async () => {
    await bws.cleanup();
    await home.cleanup();
  });

  it('reports exit code 3 and a next step when the device is not enrolled', async () => {
    const result = await cli(['list', '--project', 'ezjob', '--env', 'development']);

    expect(result.code).toBe(3);
    expect(result.stderr).toContain('not enrolled');
    expect(result.stderr).toContain('agent-secrets init');
  });

  it('adds, lists, describes, rotates and deletes a secret', async () => {
    await enrol();
    const canary = newCanary();

    const added = await cli(
      ['add', 'OPENAI_API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'],
      { stdin: canary },
    );
    expect(added.code).toBe(0);
    expect(added.stdout).toContain('bitwarden/ezjob/development/OPENAI_API_KEY');
    expect(added.stdout).not.toContain(canary);
    expect(added.stderr).not.toContain(canary);

    const listed = await cli(['list', '--project', 'ezjob', '--env', 'development']);
    expect(listed.code).toBe(0);
    expect(listed.stdout).toContain('OPENAI_API_KEY');
    expect(listed.stdout).not.toContain(canary);

    const described = await cli([
      'describe',
      'OPENAI_API_KEY',
      '--project',
      'ezjob',
      '--env',
      'development',
    ]);
    expect(described.code).toBe(0);
    expect(described.stdout).not.toContain(canary);

    const rotated = await cli(
      ['rotate', 'OPENAI_API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'],
      { stdin: newCanary() },
    );
    expect(rotated.code).toBe(0);

    const deleted = await cli([
      'delete',
      'OPENAI_API_KEY',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--yes',
      'bitwarden/ezjob/development/OPENAI_API_KEY',
    ]);
    expect(deleted.code).toBe(0);

    const gone = await cli([
      'describe',
      'OPENAI_API_KEY',
      '--project',
      'ezjob',
      '--env',
      'development',
    ]);
    expect(gone.code).toBe(5);
  });

  it('refuses to overwrite an existing secret with add', async () => {
    await enrol();
    await cli(['add', 'API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'], {
      stdin: newCanary(),
    });

    const second = await cli(
      ['add', 'API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'],
      { stdin: newCanary() },
    );

    expect(second.code).toBe(6);
    expect(second.stderr).toContain('already exists');
    expect(second.stderr).toContain('rotate');
  });

  describe('copy', () => {
    const add = async (environment: string, value: string) =>
      await cli(
        [
          'add',
          'OPENAI_API_KEY',
          '--project',
          'ezjob',
          '--env',
          environment,
          '--stdin',
          '--provider',
          'openai',
        ],
        {
          stdin: value,
        },
      );

    const copy = async (from: string, to: string, extra: string[] = []) =>
      await cli([
        'copy',
        'OPENAI_API_KEY',
        '--project',
        'ezjob',
        '--from',
        from,
        '--to',
        to,
        ...extra,
      ]);

    it('promotes a value vault to vault, and prints none of it', async () => {
      await enrol();
      const canary = newCanary();
      await add('development', canary);

      const result = await copy('development', 'preview');

      expect(result.code).toBe(0);
      expect(result.stdout).toContain('bitwarden/ezjob/preview/OPENAI_API_KEY');
      expect(result.stdout).not.toContain(canary);
      expect(result.stderr).not.toContain(canary);

      // The vault is the one place the value belongs, and it must arrive
      // unchanged: a copy that mangles a credential is worse than none.
      const state = await bws.readState();
      const target = state.secrets.find((secret) => secret.key.includes('preview'));
      expect(target?.value).toBe(canary);

      // Metadata rides along, so the promoted record is as documented as the
      // original.
      const described = await cli([
        '--json',
        'describe',
        'OPENAI_API_KEY',
        '--project',
        'ezjob',
        '--env',
        'preview',
      ]);
      expect(described.code).toBe(0);
      expect(JSON.parse(described.stdout).data.provider).toBe('openai');
    });

    it('only goes upward: never from production down, never sideways', async () => {
      await enrol();
      await add('production', newCanary());

      const downward = await copy('production', 'development');
      expect(downward.code).toBe(2);
      expect(downward.stderr).toContain('upward');

      const sideways = await copy('production', 'production');
      expect(sideways.code).toBe(2);
    });

    it('refuses to overwrite an existing target', async () => {
      await enrol();
      await add('development', newCanary());
      expect((await copy('development', 'preview')).code).toBe(0);

      // Second time round the target exists; a copy never becomes a rotate.
      const result = await copy('development', 'preview');
      expect(result.code).toBe(6);
      expect(result.stderr).toContain('rotate');
    });

    it('reports a missing source as not found', async () => {
      await enrol();
      const result = await copy('development', 'preview');
      expect(result.code).toBe(5);
    });

    it('denies a production copy under the default policy, naming the key to add', async () => {
      await enrol();
      const canary = newCanary();
      await add('development', canary);

      const result = await copy('development', 'production');

      expect(result.code).toBe(4);
      expect(result.stderr).toContain('projects.ezjob.environments.production.allow');
      expect(result.stderr).toContain('"copy"');
      expect(result.stderr).not.toContain(canary);

      const state = await bws.readState();
      expect(state.secrets.some((secret) => secret.key.includes('production'))).toBe(false);
    });

    it('honours a policy file that opens production copy, and audits it without the value', async () => {
      await enrol();
      const canary = newCanary();
      await add('development', canary);

      const paths = resolvePaths(env as NodeJS.ProcessEnv);
      await writeFile(
        paths.policyFile,
        [
          'version: 1',
          'projects:',
          '  ezjob:',
          '    environments:',
          '      production:',
          '        allow: [list, describe, create, copy]',
          'commands:',
          '  denyExecutables: [env, printenv, sh, bash, zsh, dash, fish, ksh]',
          '',
        ].join('\n'),
        { mode: 0o600 },
      );

      const result = await copy('development', 'production', ['--json']);
      expect(result.code).toBe(0);
      const envelope = JSON.parse(result.stdout);
      expect(envelope.status).toBe('ok');
      expect(envelope.data.status).toBe('copied');
      expect(envelope.data.from).toBe('bitwarden/ezjob/development/OPENAI_API_KEY');
      expect(envelope.data.reference).toBe('bitwarden/ezjob/production/OPENAI_API_KEY');
      expect(result.stdout).not.toContain(canary);

      const audit = await readFile(paths.auditFile, 'utf8');
      expect(audit).toContain('"operation":"copy"');
      expect(audit).toContain('"reference":"bitwarden/ezjob/production/OPENAI_API_KEY"');
      expect(audit).not.toContain(canary);

      const files = await home.readConfigFiles();
      for (const [path, contents] of Object.entries(files)) {
        expect(contents, `canary leaked into ${path}`).not.toContain(canary);
      }
    });
  });

  it('refuses a delete whose confirmation does not match', async () => {
    await enrol();
    await cli(['add', 'API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'], {
      stdin: newCanary(),
    });

    const wrong = await cli([
      'delete',
      'API_KEY',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--yes',
      'ezjob/development/API_KEY',
    ]);

    expect(wrong.code).toBe(2);
    const still = await cli(['describe', 'API_KEY', '--project', 'ezjob', '--env', 'development']);
    expect(still.code).toBe(0);
  });

  it('requires --env and never defaults it', async () => {
    await enrol();
    const result = await cli(['list', '--project', 'ezjob']);

    expect(result.code).not.toBe(0);
    expect(`${result.stderr}${result.stdout}`).toMatch(/--env/);
  });

  it('rejects an invalid environment rather than guessing', async () => {
    await enrol();
    const result = await cli(['list', '--project', 'ezjob', '--env', 'prod']);

    expect(result.code).not.toBe(0);
    expect(`${result.stderr}${result.stdout}`).toMatch(/development|preview|production/);
  });

  it('denies a production rotation under the default policy', async () => {
    await enrol();
    const result = await cli(
      ['rotate', 'STRIPE_KEY', '--project', 'payments', '--env', 'production', '--stdin'],
      { stdin: newCanary() },
    );

    expect(result.code).toBe(4);
    expect(result.stderr).toContain('production');
  });

  it('allows a production create under the default policy, and still prints no value', async () => {
    // The default used to deny this, which bought no protection — `add` cannot
    // overwrite, and no MCP tool reaches this action — and cost the operator a
    // hand-written policy file for the most ordinary thing the product does.
    await enrol();
    const canary = newCanary();
    const result = await cli(
      ['add', 'STRIPE_KEY', '--project', 'payments', '--env', 'production', '--stdin'],
      { stdin: canary },
    );

    expect(result.code).toBe(0);
    expect(`${result.stdout}${result.stderr}`).not.toContain(canary);
  });

  it('names the policy file and the key to add when it denies', async () => {
    await enrol();
    const result = await cli(
      ['rotate', 'STRIPE_KEY', '--project', 'payments', '--env', 'production', '--stdin'],
      { stdin: newCanary() },
    );

    // The hint has to name the file the CLI actually reads. It used to name a
    // relative `agent-secrets.policy.yaml`, which nothing opens.
    expect(result.stderr).toContain('policy.yaml');
    expect(result.stderr).toContain('projects.payments.environments.production.allow');
  });

  it('emits a stable JSON envelope with no value field', async () => {
    await enrol();
    const canary = newCanary();

    await cli(['add', 'API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'], {
      stdin: canary,
    });

    const listed = await cli(['--json', 'list', '--project', 'ezjob', '--env', 'development']);
    expect(listed.code).toBe(0);

    const payload = JSON.parse(listed.stdout) as {
      schemaVersion: number;
      status: string;
      data: { secrets: Array<Record<string, unknown>> };
    };

    expect(payload.schemaVersion).toBe(1);
    expect(payload.status).toBe('ok');
    expect(payload.data.secrets[0]?.['name']).toBe('API_KEY');
    for (const secret of payload.data.secrets) {
      expect(Object.keys(secret)).not.toContain('value');
      expect(Object.keys(secret)).not.toContain('length');
      expect(Object.keys(secret)).not.toContain('hash');
    }
    expect(listed.stdout).not.toContain(canary);
  });

  it('accepts --json before or after the subcommand', async () => {
    // commander gives the parent precedence in optsWithGlobals(), so the
    // program-level default silently overwrote a --json typed after the
    // subcommand — which is where everyone types it.
    await enrol();

    const trailing = await cli(['list', '--project', 'ezjob', '--env', 'development', '--json']);
    const leading = await cli(['--json', 'list', '--project', 'ezjob', '--env', 'development']);

    for (const result of [trailing, leading]) {
      expect(result.code).toBe(0);
      const payload = JSON.parse(result.stdout) as { schemaVersion: number; status: string };
      expect(payload.schemaVersion).toBe(1);
      expect(payload.status).toBe('ok');
    }
  });

  it('exposes doctor as JSON with a stable envelope', async () => {
    // The command an agent runs to decide whether setup finished.
    const notEnrolled = await cli(['doctor', '--json']);
    expect(notEnrolled.code).toBe(3);
    expect((JSON.parse(notEnrolled.stdout) as { data: { enrolled: boolean } }).data.enrolled).toBe(
      false,
    );

    await enrol();
    const enrolled = await cli(['doctor', '--json']);
    expect(enrolled.code).toBe(0);
    const payload = JSON.parse(enrolled.stdout) as {
      data: { enrolled: boolean; backend: { reachable: boolean } };
    };
    expect(payload.data.enrolled).toBe(true);
    expect(payload.data.backend.reachable).toBe(true);
    // Nothing about the token, in any field.
    expect(enrolled.stdout).not.toContain(bws.token);
  });

  it('reports errors as JSON on stderr in JSON mode', async () => {
    await enrol();
    const result = await cli([
      '--json',
      'describe',
      'MISSING_KEY',
      '--project',
      'ezjob',
      '--env',
      'development',
    ]);

    expect(result.code).toBe(5);
    const payload = JSON.parse(result.stderr) as { status: string; data: { code: string } };
    expect(payload.status).toBe('error');
    expect(payload.data.code).toBe('NOT_FOUND');
    // stdout stays clean so a caller can parse it unconditionally.
    expect(result.stdout.trim()).toBe('');
  });

  it('refuses --stdin when stdin is not piped', async () => {
    await enrol();
    // runCli without stdin content closes stdin immediately, which is an empty
    // pipe rather than a TTY, so this exercises the empty-value rejection.
    const result = await cli([
      'add',
      'API_KEY',
      '--project',
      'ezjob',
      '--env',
      'development',
      '--stdin',
    ]);

    expect(result.code).toBe(2);
    expect(result.stderr).toContain('empty');
  });

  it('rejects a value with surrounding whitespace', async () => {
    await enrol();
    const canary = newCanary();
    const result = await cli(
      ['add', 'API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'],
      { stdin: `  ${canary}  ` },
    );

    expect(result.code).toBe(2);
    expect(result.stderr).toContain('whitespace');
    expect(result.stderr).not.toContain(canary);
  });

  it('writes an audit trail that contains no value', async () => {
    await enrol();
    const canary = newCanary();

    await cli(['add', 'API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'], {
      stdin: canary,
    });
    await cli(['list', '--project', 'ezjob', '--env', 'development']);

    const paths = resolvePaths(env as NodeJS.ProcessEnv);
    const audit = await readFile(paths.auditFile, 'utf8');

    expect(audit).toContain('"operation":"create"');
    expect(audit).toContain('"reference":"bitwarden/ezjob/development/API_KEY"');
    expect(audit).not.toContain(canary);
  });

  it('keeps config and audit files at 0600 and the home at 0700', async () => {
    await enrol();
    await cli(['add', 'API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'], {
      stdin: newCanary(),
    });

    const modes = await home.statPermissions();
    const configMode = Object.entries(modes).find(([path]) => path.endsWith('config.json'))?.[1];
    const auditMode = Object.entries(modes).find(([path]) => path.endsWith('audit.jsonl'))?.[1];

    expect(configMode).toMatch(/^0?600$/);
    expect(auditMode).toMatch(/^0?600$/);
  });

  it('never leaves a canary anywhere under the config home', async () => {
    await enrol();
    const canary = newCanary();

    await cli(['add', 'API_KEY', '--project', 'ezjob', '--env', 'development', '--stdin'], {
      stdin: canary,
    });
    await cli(['list', '--project', 'ezjob', '--env', 'development']);
    await cli(['--json', 'describe', 'API_KEY', '--project', 'ezjob', '--env', 'development']);

    const files = await home.readConfigFiles();
    for (const [path, contents] of Object.entries(files)) {
      expect(contents, `canary leaked into ${path}`).not.toContain(canary);
    }

    // The fake vault is the one place it is supposed to be.
    const state = await bws.readState();
    expect(JSON.stringify(state)).toContain(canary);
  });
});
