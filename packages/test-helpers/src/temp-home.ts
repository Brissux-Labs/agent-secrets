import { mkdir, mkdtemp, readdir, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';

/**
 * An isolated HOME for a CLI process.
 *
 * Two properties matter here, and only the second is obvious:
 *
 *  1. the process must write nothing outside the temp dir, so a test run cannot
 *     clobber the developer's real `~/.config/agent-secrets`;
 *  2. everything it *did* write must be enumerable, because the canary sweep has
 *     to prove a value did not land in a config file, an audit log, or a
 *     half-written temp artefact. A helper that only exposes the path forces
 *     every test to reimplement the walk, and reimplemented walks miss files.
 *
 * `env` is deliberately a complete overlay rather than a patch on `process.env`:
 * a child that inherits the parent environment inherits the developer's real
 * `BWS_ACCESS_TOKEN`, which is how a "local only" test quietly starts talking to
 * a production vault.
 */

export interface TempHome {
  readonly path: string;
  /** Environment overlay confining a child process to this directory. */
  readonly env: Readonly<Record<string, string>>;
  /** `<home>/.config` */
  readonly configHome: string;
  /** `<home>/.agent-secrets` */
  readonly agentSecretsHome: string;
  /** Every file below the home, keyed by POSIX-style relative path. */
  readConfigFiles(): Promise<Record<string, string>>;
  /** Octal modes ('0600', '0700', ...) for every file and directory below. */
  statPermissions(): Promise<Record<string, string>>;
  cleanup(): Promise<void>;
}

export interface TempHomeOptions {
  /** Extra environment entries, applied last so they win. */
  env?: Record<string, string>;
  /**
   * A minimal PATH for the child. Defaults to the system directories only —
   * never the developer's PATH, which typically contains a real `bws`.
   */
  path?: string;
  /** Skip files larger than this when reading contents back. 16 MiB default. */
  maxReadBytes?: number;
}

const DEFAULT_PATH = '/usr/bin:/bin:/usr/sbin:/sbin';
const DEFAULT_MAX_READ_BYTES = 16 * 1024 * 1024;

export async function createTempHome(options: TempHomeOptions = {}): Promise<TempHome> {
  const path = await mkdtemp(join(tmpdir(), 'agent-secrets-home-'));
  const configHome = join(path, '.config');
  const dataHome = join(path, '.local', 'share');
  const stateHome = join(path, '.local', 'state');
  const cacheHome = join(path, '.cache');
  const agentSecretsHome = join(path, '.agent-secrets');
  const childTmp = join(path, 'tmp');

  // Created up front with 0700: if the CLI is supposed to tighten permissions
  // itself, a test asserting 0700 must not pass merely because the umask was
  // strict on the machine that ran it.
  for (const directory of [configHome, dataHome, stateHome, cacheHome, childTmp]) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
  }

  const env: Record<string, string> = {
    HOME: path,
    // Windows-shaped equivalent, so a helper using os.homedir() under a
    // cross-platform shim still lands inside the sandbox.
    USERPROFILE: path,
    XDG_CONFIG_HOME: configHome,
    XDG_DATA_HOME: dataHome,
    XDG_STATE_HOME: stateHome,
    XDG_CACHE_HOME: cacheHome,
    AGENT_SECRETS_HOME: agentSecretsHome,
    TMPDIR: childTmp,
    PATH: options.path ?? DEFAULT_PATH,
    // Deterministic rendering: colour codes and locale-dependent formatting turn
    // a canary assertion into a flaky one.
    NO_COLOR: '1',
    CI: '1',
    TZ: 'UTC',
    LANG: 'C.UTF-8',
    AGENT_SECRETS_TELEMETRY: '0',
    ...options.env,
  };

  const maxReadBytes = options.maxReadBytes ?? DEFAULT_MAX_READ_BYTES;

  return {
    path,
    configHome,
    agentSecretsHome,
    env: Object.freeze(env),

    async readConfigFiles(): Promise<Record<string, string>> {
      const files: Record<string, string> = {};
      for (const absolute of await walk(path)) {
        const info = await stat(absolute);
        if (info.size > maxReadBytes) {
          continue;
        }
        // Read as UTF-8 even for binary artefacts such as the SQLite file: an
        // ASCII canary survives lossy decoding, which is all the sweep needs.
        files[toPosix(relative(path, absolute))] = await readFile(absolute, 'utf8');
      }
      return files;
    },

    async statPermissions(): Promise<Record<string, string>> {
      const modes: Record<string, string> = {};
      for (const absolute of await walk(path, { includeDirectories: true })) {
        const info = await stat(absolute);
        modes[toPosix(relative(path, absolute))] = formatMode(info.mode);
      }
      modes['.'] = formatMode((await stat(path)).mode);
      return modes;
    },

    async cleanup(): Promise<void> {
      await rm(path, { recursive: true, force: true });
    },
  };
}

/** `0600`-style rendering of a stat mode's permission bits. */
export function formatMode(mode: number): string {
  return `0${(mode & 0o777).toString(8).padStart(3, '0')}`;
}

function toPosix(relativePath: string): string {
  return sep === '/' ? relativePath : relativePath.split(sep).join('/');
}

async function walk(
  root: string,
  options: { includeDirectories?: boolean } = {},
): Promise<string[]> {
  const found: string[] = [];
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const absolute = join(root, entry.name);
    if (entry.isDirectory()) {
      if (options.includeDirectories) {
        found.push(absolute);
      }
      found.push(...(await walk(absolute, options)));
      continue;
    }
    if (entry.isSymbolicLink()) {
      // Skipped rather than followed: following a symlink is how a sweep
      // wanders out of the sandbox and into the developer's real home.
      continue;
    }
    found.push(absolute);
  }
  return found;
}
