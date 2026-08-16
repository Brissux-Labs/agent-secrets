import { EXIT_CODES, isAgentSecretsError } from '@bx-labs/agent-secrets-core';
import { Command, Option } from 'commander';
import { runDoctor, runInit, runLogout } from './commands/enrolment.js';
import { runAdd, runDelete, runDescribe, runList } from './commands/lifecycle.js';
import { runRun } from './commands/run.js';
import { type Context, createContext } from './context.js';
import { shouldUseColor, Writer } from './output.js';

/**
 * The command surface.
 *
 * Two things are load-bearing here rather than cosmetic:
 *
 *  1. **No command accepts a value as an argument or a flag.** `add` and
 *     `rotate` take a name and read the value from a hidden prompt or from
 *     stdin. There is no `--value`, and there never will be — a flag is shell
 *     history, `ps` output, and a CI log.
 *  2. **`--env` is required wherever a scope is needed.** Commander would
 *     happily default it; the product forbids inferring an environment, so the
 *     option is declared mandatory and the error is explicit.
 */

export const VERSION = '0.1.0';

export interface BuildProgramOptions {
  readonly stdout?: NodeJS.WritableStream;
  readonly stderr?: NodeJS.WritableStream;
  readonly env?: NodeJS.ProcessEnv;
  /** Injected by tests; production builds the context from disk. */
  readonly contextFactory?: (writer: Writer) => Promise<Context>;
}

export function buildProgram(options: BuildProgramOptions = {}): Command {
  const program = new Command();

  program
    .name('agent-secrets')
    .description(
      'Secure secret handling for AI agents. Values go to your vault and to the processes ' +
        'that need them — never to a log, a transcript, or a model.',
    )
    .version(VERSION)
    .option('--json', 'machine-readable output with a stable schema', false)
    .option('--no-color', 'disable ANSI colour')
    .enablePositionalOptions()
    .showHelpAfterError();

  const contextFor = async (command: Command): Promise<Context> => {
    // Merged by hand rather than with `optsWithGlobals()` alone: commander gives
    // the *parent* precedence, so the program-level `--json` default of `false`
    // silently overwrote a `--json` typed after the subcommand. Both positions
    // mean the same thing to a user, so both have to work.
    const local = command.opts() as { json?: boolean; color?: boolean };
    const inherited = command.optsWithGlobals() as { json?: boolean; color?: boolean };
    const wantsJson = local.json === true || inherited.json === true;
    const wantsColor = local.color !== false && inherited.color !== false;

    const env = options.env ?? process.env;
    const writer = new Writer({
      mode: wantsJson ? 'json' : 'human',
      color: wantsColor && shouldUseColor(process.argv, env),
      ...(options.stdout === undefined ? {} : { stdout: options.stdout }),
      ...(options.stderr === undefined ? {} : { stderr: options.stderr }),
    });
    return options.contextFactory
      ? await options.contextFactory(writer)
      : await createContext({ writer, env });
  };

  /** Wrap a handler so every command shares the same error and exit contract. */
  const handle =
    (run: (context: Context, ...args: never[]) => Promise<number>) =>
    async (...args: unknown[]): Promise<void> => {
      const command = args[args.length - 1] as Command;
      const context = await contextFor(command);
      try {
        const code = await run(context, ...(args.slice(0, -1) as never[]));
        process.exitCode = code;
      } catch (error) {
        context.writer.fail(error);
        process.exitCode = isAgentSecretsError(error) ? error.exitCode : EXIT_CODES.internal;
      } finally {
        context.dispose();
      }
    };

  /**
   * Options every subcommand accepts.
   *
   * Declared per subcommand rather than only on the program, because
   * `enablePositionalOptions()` — which `run` needs so that
   * `run … -- npm test --watch` hands `--watch` to npm — otherwise makes
   * `agent-secrets doctor --json` an error. Trailing flags are how everyone
   * actually types a CLI, so both forms work.
   */
  const commonOptions = (command: Command): Command =>
    command
      .option('--json', 'machine-readable output with a stable schema')
      .option('--no-color', 'disable ANSI colour');

  const scopeOptions = (command: Command): Command =>
    commonOptions(command)
      .requiredOption('-p, --project <slug>', 'project slug, e.g. ezjob')
      .addOption(
        new Option('-e, --env <environment>', 'development | preview | production')
          .makeOptionMandatory(true)
          .choices(['development', 'preview', 'production']),
      );

  // ── device lifecycle ──────────────────────────────────────────────────────

  commonOptions(
    program
      .command('init')
      .description('enrol this device: store its backend access token in the OS credential store'),
  )
    .option('--device-name <name>', 'how this machine appears in audit records')
    .option('--project-id <uuid>', 'Bitwarden project ID')
    .option(
      '--server-url <url>',
      'Bitwarden base URL — required off the US cloud, e.g. https://vault.bitwarden.eu for the EU',
    )
    .option(
      '--executable-path <path>',
      'absolute path to the bws binary, when it is not in a system directory',
    )
    .option('--force', 're-enrol a device that is already enrolled', false)
    .action(handle((context, opts) => runInit(context, opts)));

  commonOptions(
    program
      .command('doctor')
      .description('check enrolment, backend reachability, and file permissions'),
  ).action(handle((context) => runDoctor(context)));

  commonOptions(
    program
      .command('logout')
      .description("remove this device's local token — vault secrets are untouched"),
  )
    .option('-y, --yes', 'skip the confirmation prompt', false)
    .action(handle((context, opts) => runLogout(context, opts)));

  // ── secret lifecycle ──────────────────────────────────────────────────────

  const add = scopeOptions(
    program
      .command('add <NAME>')
      .description('add a secret — the value is read from a hidden prompt, never an argument'),
  )
    .option('--stdin', 'read the value from stdin instead of a prompt (refuses a TTY)', false)
    .option('--description <text>', 'non-secret note about what this credential is for')
    .option('--provider <slug>', 'provider metadata, e.g. openai')
    .option('--tag <tag>', 'repeatable tag', collect, [])
    .option('--max-bytes <n>', 'maximum accepted value size', Number.parseInt)
    .option('--allow-empty', 'accept an empty value', false)
    .option('--allow-whitespace', 'accept leading or trailing whitespace', false);

  add.action(handle((context, name, opts) => runAdd(context, name as string, opts as never)));

  scopeOptions(
    program.command('list').description('list secret names and metadata — never values'),
  ).action(handle((context, opts) => runList(context, opts as never)));

  scopeOptions(
    program
      .command('describe <NAME>')
      .description("show one secret's metadata — no value, length, or fingerprint"),
  ).action(handle((context, name, opts) => runDescribe(context, name as string, opts as never)));

  const rotate = scopeOptions(
    program.command('rotate <NAME>').description("replace an existing secret's value"),
  )
    .option('--stdin', 'read the value from stdin instead of a prompt (refuses a TTY)', false)
    .option('--max-bytes <n>', 'maximum accepted value size', Number.parseInt)
    .option('--allow-empty', 'accept an empty value', false)
    .option('--allow-whitespace', 'accept leading or trailing whitespace', false);

  rotate.action(
    handle((context, name, opts) =>
      runAdd(context, name as string, { ...(opts as object), rotate: true } as never),
    ),
  );

  scopeOptions(
    program
      .command('delete <NAME>')
      .description('delete a secret — requires typing its full canonical reference'),
  )
    .option('--yes <reference>', 'non-interactive confirmation: the exact canonical reference')
    .action(handle((context, name, opts) => runDelete(context, name as string, opts as never)));

  // ── controlled execution ──────────────────────────────────────────────────

  commonOptions(
    program
      .command('run')
      .description('run a command with named secrets injected into its environment'),
  )
    .option('-p, --project <slug>', 'project slug')
    .addOption(
      new Option('-e, --env <environment>', 'development | preview | production').choices([
        'development',
        'preview',
        'production',
      ]),
    )
    .option('-k, --keys <names>', 'comma-separated secret names to inject')
    .option('-m, --manifest <command>', 'run a command defined in agent-secrets.yaml')
    .option('--dry-run', 'report which names would be injected and run nothing', false)
    .option('--isolated-env', 'give the child a minimal environment instead of inheriting', false)
    .option(
      '--pass-through-output',
      'give the child this terminal directly — needed for interactive commands, but turns off output redaction',
      false,
    )
    .option('-y, --yes', 'skip the production confirmation prompt', false)
    .option(
      '--propagate-exit-code',
      "exit with the child's status instead of 9 — convenient for CI, ambiguous for agents",
      false,
    )
    .option('--cwd <path>', 'working directory for the child process')
    // Everything after `--` belongs to the child, including its own flags.
    .argument('[command...]', 'the command to run, after --')
    .passThroughOptions()
    .action(
      handle((context, command, opts) =>
        runRun(context, (command as string[]) ?? [], opts as never),
      ),
    );

  return program;
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}
