#!/usr/bin/env node
/**
 * Setup preflight, written for an agent to run.
 *
 * `agent-secrets doctor` answers "is this installation healthy?" and needs the
 * CLI to already exist. This answers the question before that one: "what is
 * present on this machine, what is missing, and what is the single next action?"
 *
 *   node scripts/preflight.mjs          human-readable
 *   node scripts/preflight.mjs --json   machine-readable
 *
 * The JSON shape is stable and is the contract for `docs/agent-setup.md`:
 *
 *   {
 *     "ready": false,
 *     "checks": [{ "id", "ok", "found", "detail" }, ...],
 *     "nextAction": {
 *       "id": "install-bws",
 *       "actor": "agent" | "human",
 *       "summary": "...",
 *       "command": "..." | null,
 *       "url": "..." | null
 *     }
 *   }
 *
 * `actor` is the field that matters. Some steps cannot be delegated: creating a
 * Bitwarden account and pasting an access token are human work by design, because
 * a token that passes through an agent has passed through a model's context —
 * which is the failure this product exists to prevent. An agent reading this
 * output should stop at the first `"actor": "human"` step and ask.
 */

import { execFile } from 'node:child_process';
import { access, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = fileURLToPath(new URL('..', import.meta.url));
const json = process.argv.includes('--json');

function which(binary) {
  return new Promise((resolve) => {
    execFile('/usr/bin/env', ['sh', '-c', `command -v ${binary} 2>/dev/null`], (error, stdout) => {
      resolve(error ? null : stdout.trim() || null);
    });
  });
}

function versionOf(binary, args = ['--version']) {
  return new Promise((resolve) => {
    execFile(binary, args, { timeout: 10_000 }, (error, stdout) => {
      resolve(error ? null : stdout.trim().split('\n')[0]);
    });
  });
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

const checks = [];
function record(id, ok, found, detail) {
  checks.push({ id, ok, found, detail });
  return ok;
}

// ── environment ────────────────────────────────────────────────────────────
const nodeMajor = Number.parseInt(process.versions.node.split('.')[0], 10);
const nodeMinor = Number.parseInt(process.versions.node.split('.')[1], 10);
const nodeOk = nodeMajor > 22 || (nodeMajor === 22 && nodeMinor >= 11);
record('node', nodeOk, process.versions.node, nodeOk ? null : 'Node 22.11 or later is required.');

const pnpmPath = await which('pnpm');
record(
  'pnpm',
  pnpmPath !== null,
  pnpmPath,
  pnpmPath ? null : 'pnpm is needed to build from source.',
);

record(
  'platform',
  true,
  process.platform,
  process.platform === 'darwin'
    ? null
    : 'Not macOS: the device token goes in a 0600 file rather than an OS credential store. Weaker; see docs/threat-model.md §5.14.',
);

// ── the product itself ─────────────────────────────────────────────────────
const built = await exists(join(REPO, 'packages/cli/dist/bin.js'));
record(
  'build',
  built,
  built ? 'packages/cli/dist/bin.js' : null,
  built ? null : 'Run: pnpm install && pnpm build',
);

const installedCli = await which('agent-secrets');
record(
  'cli-on-path',
  installedCli !== null,
  installedCli,
  installedCli
    ? null
    : 'Optional while testing from a clone; the built entry point works directly.',
);

// ── the backend ────────────────────────────────────────────────────────────
const bwsPath = await which('bws');
const bwsVersion = bwsPath ? await versionOf(bwsPath) : null;
record(
  'bws',
  bwsPath !== null,
  bwsVersion ?? bwsPath,
  bwsPath
    ? null
    : 'The Bitwarden Secrets Manager CLI is not installed. It is only needed to talk to a real vault; `pnpm demo` runs without it.',
);

/**
 * Mirrors SAFE_PATH in packages/backend-bitwarden/src/subprocess.ts.
 *
 * The adapter resolves a bare `bws` against this fixed list rather than the
 * caller's PATH, so that a poisoned PATH entry cannot substitute a program that
 * captures the access token. The consequence is the one this check exists for:
 * `command -v bws` can succeed on an install the tool will never find — a
 * `~/.local/bin` install, for instance — and the failure it produces at
 * enrolment time looks nothing like "the binary is somewhere else".
 */
const SAFE_PATH_DIRS = [
  '/usr/local/bin',
  '/opt/homebrew/bin',
  '/usr/bin',
  '/bin',
  '/usr/sbin',
  '/sbin',
];
const bwsPinned = (process.env.AGENT_SECRETS_BWS_PATH ?? '').trim().length > 0;
const bwsReachable =
  bwsPath === null ||
  bwsPinned ||
  SAFE_PATH_DIRS.includes(bwsPath.slice(0, bwsPath.lastIndexOf('/')));
record(
  'bws-reachable',
  bwsReachable,
  bwsPinned ? 'AGENT_SECRETS_BWS_PATH is set' : (bwsPath ?? null),
  bwsReachable
    ? null
    : `bws is on your PATH but outside the directories Agent Secrets searches (${SAFE_PATH_DIRS.join(', ')}). Set AGENT_SECRETS_BWS_PATH=${bwsPath} or pass --executable-path to init.`,
);

// ── enrolment ──────────────────────────────────────────────────────────────
const configHome =
  process.env.AGENT_SECRETS_HOME ??
  join(
    process.env.XDG_CONFIG_HOME ?? join(process.env.HOME ?? homedir(), '.config'),
    'agent-secrets',
  );
const configPath = join(configHome, 'config.json');

let enrolled = false;
let deviceName = null;
if (await exists(configPath)) {
  try {
    const parsed = JSON.parse(await readFile(configPath, 'utf8'));
    enrolled = typeof parsed.deviceId === 'string';
    deviceName = parsed.deviceName ?? null;
  } catch {
    // A config we cannot parse is not an enrolment.
  }
}
record(
  'enrolled',
  enrolled,
  enrolled ? `${deviceName} (${configHome})` : null,
  enrolled ? null : 'This machine has no device configuration yet.',
);

// ── what to do next ────────────────────────────────────────────────────────
function nextAction() {
  if (!nodeOk) {
    return {
      id: 'install-node',
      actor: 'agent',
      summary: `Node ${process.versions.node} is too old; install Node 22.11 or later.`,
      command: null,
      url: 'https://nodejs.org',
    };
  }
  if (!pnpmPath) {
    return {
      id: 'install-pnpm',
      actor: 'agent',
      summary: 'Install pnpm.',
      command: 'corepack enable && corepack prepare pnpm@latest --activate',
      url: null,
    };
  }
  if (!built) {
    return {
      id: 'build',
      actor: 'agent',
      summary: 'Install dependencies and build the workspace.',
      command: 'pnpm install && pnpm build',
      url: null,
    };
  }
  if (!enrolled && !bwsPath) {
    return {
      id: 'demo-or-install-bws',
      actor: 'agent',
      summary:
        'Everything needed for the offline demo is present. Run it to verify the build, then install bws only if the human wants to connect a real vault.',
      command: 'pnpm demo',
      url: null,
    };
  }
  if (!bwsPath) {
    return {
      id: 'install-bws',
      actor: 'agent',
      summary: 'Install the Bitwarden Secrets Manager CLI.',
      command:
        process.platform === 'darwin'
          ? 'brew install bitwarden/tap/bws'
          : 'See the release page for your platform.',
      url: 'https://github.com/bitwarden/sdk-sm/releases?q=bws',
    };
  }
  if (!bwsReachable) {
    return {
      id: 'point-at-bws',
      actor: 'agent',
      summary: `bws is installed at ${bwsPath}, which is not one of the directories Agent Secrets searches. Export AGENT_SECRETS_BWS_PATH so enrolment can find it, or pass --executable-path to init.`,
      command: `export AGENT_SECRETS_BWS_PATH=${bwsPath}`,
      url: null,
    };
  }
  if (!enrolled) {
    return {
      id: 'enrol',
      actor: 'human',
      summary:
        'A human must create the Bitwarden project and machine account, then run `agent-secrets init` and paste the access token at the hidden prompt. Do not ask them to paste the token into this conversation, and do not offer to run init for them with the token as an argument: there is no such flag, deliberately.',
      command: 'agent-secrets init',
      url: 'https://bitwarden.com/help/secrets-manager-quick-start/',
    };
  }
  return {
    id: 'verify',
    actor: 'agent',
    summary: 'Enrolled. Verify the backend and permissions.',
    command: 'agent-secrets doctor --json',
    url: null,
  };
}

const action = nextAction();
const ready = checks.every((check) => check.ok || check.id === 'cli-on-path');

if (json) {
  console.log(JSON.stringify({ ready, checks, nextAction: action }, null, 2));
  process.exit(0);
}

const mark = (ok) => (ok ? '[32m✓[39m' : '[33m![39m');
console.log('\nAgent Secrets — setup preflight\n');
for (const check of checks) {
  const found = check.found ? ` ${check.found}` : '';
  console.log(`  ${mark(check.ok)} ${check.id.padEnd(12)}${found}`);
  if (check.detail) {
    console.log(`      [2m${check.detail}[22m`);
  }
}
console.log(`\n  Next: ${action.summary}`);
if (action.command) {
  console.log(`        [36m${action.command}[39m`);
}
if (action.url) {
  console.log(`        [2m${action.url}[22m`);
}
if (action.actor === 'human') {
  console.log('\n  [33mThis step is for a human.[39m An agent should stop here and ask.');
}
console.log('');
