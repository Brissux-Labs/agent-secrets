import { BitwardenBackend, BwsClient } from '@bx-labs/agent-secrets-backend-bitwarden';
import {
  AuthRequiredError,
  buildAuditEvent,
  formatScope,
  InvalidInputError,
} from '@bx-labs/agent-secrets-core';
import { confirm, input, password } from '@inquirer/prompts';
import {
  checkPermissions,
  defaultDeviceName,
  deleteConfig,
  newDeviceConfig,
  saveConfig,
} from '../config.js';
import type { Context } from '../context.js';
import { KEYCHAIN_SERVICE, keychainAccount, MacOSKeychainStore } from '../credential-store.js';

/**
 * Device lifecycle: `init`, `doctor`, `logout`.
 *
 * The rule these three share is that the access token has exactly one home —
 * the OS credential store — and never appears in a file this tool writes, in an
 * argument, or in any output. `init` reads it through a hidden prompt and hands
 * it straight to the credential store; nothing in between keeps a copy.
 */

export interface InitOptions {
  readonly deviceName?: string;
  readonly projectId?: string;
  readonly serverUrl?: string;
  readonly executablePath?: string;
  readonly force?: boolean;
}

export async function runInit(context: Context, options: InitOptions): Promise<number> {
  const { writer } = context;

  if (context.config && !options.force) {
    throw new InvalidInputError('This device is already enrolled.', {
      hint: 'Pass --force to re-enrol it, or run `agent-secrets logout` first.',
    });
  }

  if (writer.isJson) {
    // Enrolment needs a hidden prompt for the token, which cannot happen in a
    // machine-driven session. Failing here is better than inventing a way to
    // pass a token non-interactively — that way would be a flag, and a flag is
    // shell history.
    throw new InvalidInputError('`init` cannot run in JSON mode.', {
      hint: 'Run `agent-secrets init` interactively; the access token is entered at a hidden prompt.',
    });
  }

  writer.note((fmt) => `${fmt.bold('Agent Secrets setup')}\n`);
  writer.note(() => '  Backend: Bitwarden Secrets Manager');

  const deviceName =
    options.deviceName ?? (await input({ message: 'Device name:', default: defaultDeviceName() }));

  const projectId = options.projectId ?? (await input({ message: 'Bitwarden project ID (UUID):' }));

  // Hidden, like the value prompts. The token opens the whole vault; it is at
  // least as sensitive as anything it stores.
  const accessToken = await password({ message: 'Access token:', mask: '*' });

  if (accessToken.trim().length === 0) {
    throw new InvalidInputError('No access token was entered.', { field: 'accessToken' });
  }

  const config = newDeviceConfig({
    deviceName,
    projectId,
    ...(options.serverUrl === undefined ? {} : { serverUrl: options.serverUrl }),
    ...(options.executablePath === undefined ? {} : { executablePath: options.executablePath }),
  });

  context.redaction.trackString(accessToken);

  // Verify before persisting anything. A cancelled or failed setup must leave
  // no partial credential behind — that is an explicit acceptance criterion,
  // and the ordering here is what delivers it.
  writer.note(() => '\n  Checking the backend…');

  const probe = new BitwardenBackend({
    client: new BwsClient({
      accessToken,
      projectId: config.bitwarden?.projectId ?? projectId,
      ...(options.executablePath === undefined ? {} : { executable: options.executablePath }),
      ...(options.serverUrl === undefined ? {} : { serverUrl: options.serverUrl }),
      redactionScope: context.redaction,
    }),
  });

  const health = await probe.health();
  if (!health.reachable) {
    throw new AuthRequiredError('The backend rejected this token, or is unreachable.', {
      hint: 'Check the token and the project ID. Nothing was saved.',
    });
  }

  await saveConfig(context.paths, config);

  const store = context.credentials;
  await store.set(KEYCHAIN_SERVICE, keychainAccount(config.deviceId, projectId), accessToken);

  await context.audit.record(
    buildAuditEvent({
      actorType: 'human',
      actorId: config.deviceId,
      deviceId: config.deviceId,
      operation: 'init',
      reference: '',
      outcome: 'success',
    }),
  );

  writer.ok(
    {
      device: { id: config.deviceId, name: config.deviceName },
      backend: 'bitwarden',
      credentialStore: store.id,
      configFile: context.paths.configFile,
    },
    (fmt) =>
      [
        '',
        `${fmt.success('✓')} Backend authenticated`,
        `${fmt.success('✓')} Device registered as ${fmt.bold(config.deviceName)}`,
        `${fmt.success('✓')} Token stored in ${store.description}`,
        `${fmt.success('✓')} No secret written to project files`,
        '',
        `Next: ${fmt.bold('agent-secrets doctor')}`,
      ].join('\n'),
  );

  return 0;
}

export async function runDoctor(context: Context): Promise<number> {
  const { writer } = context;
  const config = context.config;

  const permissions = await checkPermissions(context.paths);
  const permissionProblems = permissions.filter((report) => !report.ok);

  if (!config) {
    writer.ok({ enrolled: false, permissions }, (fmt) =>
      [
        `${fmt.warn('!')} This device is not enrolled.`,
        `  ${fmt.dim('next:')} run \`agent-secrets init\``,
      ].join('\n'),
    );
    return 3;
  }

  let backendReport: Record<string, unknown> = { reachable: false };
  let exitCode = 0;

  try {
    const backend = await context.requireBackend();
    const health = await backend.health();
    backendReport = {
      reachable: health.reachable,
      canRead: health.canRead,
      canWrite: health.canWrite,
      latencyMs: health.latencyMs,
      ...(health.errorCode === undefined ? {} : { errorCode: health.errorCode }),
    };
    if (!health.reachable) {
      exitCode = 7;
    }
  } catch (error) {
    backendReport = {
      reachable: false,
      errorCode: (error as { code?: string }).code ?? 'INTERNAL',
    };
    exitCode = (error as { exitCode?: number }).exitCode ?? 7;
  }

  if (permissionProblems.length > 0 && exitCode === 0) {
    exitCode = 2;
  }

  const isMac = MacOSKeychainStore.isSupported();

  writer.ok(
    {
      enrolled: true,
      device: { id: config.deviceId, name: config.deviceName },
      credentialStore: context.credentials.id,
      backend: backendReport,
      permissions,
      auditEnabled: config.audit.enabled,
    },
    (fmt) => {
      const lines = [
        `${fmt.bold('Device')}      ${config.deviceName} (${config.deviceId})`,
        `${fmt.bold('Credentials')} ${context.credentials.description}`,
      ];

      if (!isMac) {
        lines.push(
          `${fmt.warn('  ! ')}Not macOS: the token is in a 0600 file rather than an OS credential store.`,
        );
      }

      lines.push(
        backendReport['reachable']
          ? `${fmt.success('✓')} Backend reachable (${String(backendReport['latencyMs'])} ms)`
          : `${fmt.error('✗')} Backend unreachable (${String(backendReport['errorCode'] ?? 'unknown')})`,
      );

      if (backendReport['reachable']) {
        lines.push(
          `  read:  ${backendReport['canRead'] ? fmt.success('yes') : fmt.error('no')}`,
          // Stated as "probable" because a non-destructive write probe is not
          // possible; claiming certainty here would be a lie the user would
          // discover at the worst moment.
          `  write: ${backendReport['canWrite'] ? fmt.success('probable') : fmt.error('no')} ${fmt.dim('(not verified — a write probe would create a record)')}`,
        );
      }

      for (const report of permissions) {
        lines.push(
          report.ok
            ? `${fmt.success('✓')} ${report.path} (${report.mode})`
            : `${fmt.error('✗')} ${report.path} is ${report.mode}, expected ${report.expected} or stricter`,
        );
      }

      lines.push(`${fmt.bold('Audit')}       ${config.audit.enabled ? 'enabled' : 'disabled'}`);
      return lines.join('\n');
    },
  );

  return exitCode;
}

export async function runLogout(context: Context, options: { yes?: boolean }): Promise<number> {
  const { writer } = context;
  const config = context.config;

  if (!config) {
    writer.ok({ removed: false }, () => 'This device was not enrolled. Nothing to do.');
    return 0;
  }

  if (!options.yes && !writer.isJson) {
    const confirmed = await confirm({
      message: `Remove this device's access token? Vault secrets are not affected.`,
      default: false,
    });
    if (!confirmed) {
      writer.note(() => 'Cancelled.');
      return 0;
    }
  }

  const removed = config.bitwarden
    ? await context.credentials.delete(
        KEYCHAIN_SERVICE,
        keychainAccount(config.deviceId, config.bitwarden.projectId),
      )
    : false;

  await deleteConfig(context.paths);

  await context.audit.record(
    buildAuditEvent({
      actorType: 'human',
      actorId: config.deviceId,
      deviceId: config.deviceId,
      operation: 'logout',
      reference: '',
      outcome: 'success',
    }),
  );

  writer.ok({ removed, tokenRevoked: false }, (fmt) =>
    [
      `${fmt.success('✓')} Local token removed from ${context.credentials.description}`,
      `${fmt.success('✓')} Local configuration removed`,
      '',
      // The distinction that matters when a laptop is lost: removing the local
      // copy does nothing to the vault's opinion of that token.
      `${fmt.warn('!')} The token is still valid in Bitwarden.`,
      `  ${fmt.dim('next:')} revoke the machine account access token in Bitwarden to complete this.`,
    ].join('\n'),
  );

  return 0;
}

/** Shared by commands that print a scope in human mode. */
export function scopeLabel(project: string, environment: string): string {
  return formatScope({ backend: 'bitwarden', project, environment } as never);
}
