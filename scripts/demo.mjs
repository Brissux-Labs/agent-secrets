#!/usr/bin/env node

/**
 * A guided demo, on fake credentials only.
 *
 * It runs the real CLI — the same `dist/bin.js` a user installs — against a fake
 * `bws` executable and a throwaway config directory. Nothing touches your
 * Keychain, your real vault, or your home directory, and no real credential is
 * involved at any point.
 *
 *   node scripts/demo.mjs
 *
 * What it demonstrates, in order:
 *   1. a device that is not enrolled fails with a next step, not a stack trace;
 *   2. enrolment stores the token outside the project;
 *   3. adding a secret prints metadata and never the value;
 *   4. listing and describing expose no value, length, or fingerprint;
 *   5. `run` injects into a child — and redacts what the child prints back;
 *   6. production is refused by the default policy;
 *   7. the value exists in exactly one place: the vault.
 */

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(REPO, 'packages/cli/dist/bin.js');

const { createFakeBws } = await import(join(REPO, 'packages/test-helpers/dist/index.js')).catch(
  () => {
    console.error('The demo needs the workspace built first:\n\n  pnpm install && pnpm build\n');
    process.exit(1);
  },
);

const c = {
  dim: (s) => `[2m${s}[22m`,
  bold: (s) => `[1m${s}[22m`,
  green: (s) => `[32m${s}[39m`,
  red: (s) => `[31m${s}[39m`,
  cyan: (s) => `[36m${s}[39m`,
};

let step = 0;
function heading(title, why) {
  step += 1;
  console.log(`\n${c.bold(`${step}. ${title}`)}`);
  console.log(`   ${c.dim(why)}\n`);
}

function run(args, env, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...env, NO_COLOR: '1' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    if (options.stdin !== undefined) {
      child.stdin.end(options.stdin);
    } else {
      child.stdin.end();
    }
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

function show(label, result) {
  console.log(`   ${c.cyan(`$ agent-secrets ${label}`)}`);
  for (const line of `${result.stdout}${result.stderr}`.trimEnd().split('\n')) {
    if (line.trim()) console.log(`   ${line}`);
  }
  console.log(`   ${c.dim(`exit ${result.code}`)}`);
}

const home = await mkdtemp(join(tmpdir(), 'agent-secrets-demo-'));
const bws = await createFakeBws();

// A canary rather than a plausible-looking key: if it ever shows up somewhere it
// should not, it is unmistakable, and it is not a credential shape any scanner
// will flag.
const SECRET = `ASECRET_${'CANARY'}_${randomBytes(16).toString('hex')}`;

const env = {
  PATH: process.env.PATH,
  HOME: home,
  AGENT_SECRETS_HOME: home,
  // Demo only: keeps the throwaway token out of your real login Keychain.
  AGENT_SECRETS_CREDENTIAL_STORE: 'file',
};

console.log(c.bold('\nAgent Secrets — demo on fake credentials'));
console.log(
  c.dim(
    `\n  fake vault : ${bws.path}\n  config dir : ${home}\n  the "secret": a generated canary, ${SECRET.slice(0, 22)}…\n` +
      '\n  Nothing here touches your Keychain, your vault, or your home directory.',
  ),
);

try {
  heading(
    'A machine that is not enrolled',
    'Exit code 3 means "enrolment required". Agents branch on these codes, so they are a contract.',
  );
  show(
    'list --project demo --env development',
    await run(['list', '--project', 'demo', '--env', 'development'], env),
  );

  heading(
    'Enrol this machine',
    'Written directly rather than through the prompt, because `init` reads the token from a hidden TTY prompt on purpose.',
  );
  const {
    newDeviceConfig,
    saveConfig,
    resolvePaths,
    FileCredentialStore,
    KEYCHAIN_SERVICE,
    keychainAccount,
  } = await import(join(REPO, 'packages/cli/dist/index.js'));
  const paths = resolvePaths(env);
  const config = newDeviceConfig({
    deviceName: 'demo-machine',
    projectId: bws.projectId,
    executablePath: bws.path,
  });
  await saveConfig(paths, config);
  await new FileCredentialStore(paths.home).set(
    KEYCHAIN_SERVICE,
    keychainAccount(config.deviceId, bws.projectId),
    bws.token,
  );
  console.log(`   ${c.green('✓')} device enrolled as ${c.bold('demo-machine')}`);
  console.log(`   ${c.dim(`token stored in ${paths.home}, never in the project`)}`);
  show('doctor', await run(['doctor'], env));

  heading(
    'Add a secret',
    'The value arrives on stdin here; interactively it is a hidden prompt. There is no --value flag, and there never will be — a flag is shell history.',
  );
  show(
    'add OPENAI_API_KEY --project demo --env development --stdin',
    await run(
      [
        'add',
        'OPENAI_API_KEY',
        '--project',
        'demo',
        '--env',
        'development',
        '--stdin',
        '--provider',
        'openai',
      ],
      env,
      { stdin: SECRET },
    ),
  );

  heading(
    'List and describe',
    'Names and metadata. No value, no length, no hash, no preview — by design.',
  );
  show(
    'list --project demo --env development',
    await run(['list', '--project', 'demo', '--env', 'development'], env),
  );
  show(
    'describe OPENAI_API_KEY --project demo --env development',
    await run(['describe', 'OPENAI_API_KEY', '--project', 'demo', '--env', 'development'], env),
  );

  heading(
    'Run a command with the secret',
    'The child gets it in its environment. Watch what happens when the child prints it back.',
  );
  const probe = join(home, 'probe.mjs');
  await writeFile(probe, 'console.log("the child received: " + process.env.OPENAI_API_KEY);\n');
  const ran = await run(
    [
      'run',
      '--project',
      'demo',
      '--env',
      'development',
      '--keys',
      'OPENAI_API_KEY',
      '--',
      process.execPath,
      probe,
    ],
    env,
  );
  show('run … -- node probe.mjs', ran);
  console.log(
    `   ${ran.stdout.includes(SECRET) ? c.red('✗ the value leaked') : c.green('✓ the child got the real value; the terminal got [REDACTED]')}`,
  );

  heading(
    'Ask for production',
    'Denied by the default policy, in code — not in a prompt an agent could argue with.',
  );
  show(
    'add STRIPE_SECRET_KEY --project demo --env production --stdin',
    await run(
      ['add', 'STRIPE_SECRET_KEY', '--project', 'demo', '--env', 'production', '--stdin'],
      env,
      { stdin: SECRET },
    ),
  );

  heading(
    'Where did the value end up?',
    'Exactly one place. Everything else that touched it kept metadata only.',
  );
  const files = { 'audit log': join(home, 'audit.jsonl'), config: join(home, 'config.json') };
  for (const [label, path] of Object.entries(files)) {
    const contents = await readFile(path, 'utf8').catch(() => '');
    const leaked = contents.includes(SECRET);
    console.log(
      `   ${leaked ? c.red('✗') : c.green('✓')} ${label.padEnd(10)} ${leaked ? 'contains the value' : 'no value'}`,
    );
  }
  const vault = JSON.stringify(await bws.readState());
  console.log(
    `   ${vault.includes(SECRET) ? c.green('✓') : c.red('✗')} vault      ${vault.includes(SECRET) ? 'holds the value — as it should' : 'does not hold the value (unexpected)'}`,
  );

  console.log(`\n${c.dim('  Cleaning up. Nothing was left on this machine.')}\n`);
} finally {
  await bws.cleanup();
  await rm(home, { recursive: true, force: true });
}
