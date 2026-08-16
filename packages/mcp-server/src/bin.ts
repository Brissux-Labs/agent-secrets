#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { loadConfig, resolvePaths } from '@bx-labs/agent-secrets/config';
import {
  defaultCredentialStore,
  KEYCHAIN_SERVICE,
  keychainAccount,
} from '@bx-labs/agent-secrets/credential-store';
import { BitwardenBackend } from '@bx-labs/agent-secrets-backend-bitwarden';
import { defaultPolicy, PolicyEngine, parsePolicy } from '@bx-labs/agent-secrets-core';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { parse as parseYaml } from 'yaml';
import { HttpLinkIssuer } from './link-issuer.js';
import { createMcpServer } from './server.js';

/**
 * stdio entry point (FR-MCP-006).
 *
 * The server reuses the CLI's enrolment: the same device config, the same
 * Keychain entry, the same policy file. An agent therefore gets exactly the
 * access its human already granted this machine — never more, and nothing it
 * had to be given separately.
 *
 * Everything diagnostic goes to stderr. stdout is the MCP transport; a single
 * stray console.log there corrupts the protocol stream.
 */
async function main(): Promise<void> {
  const paths = resolvePaths(process.env);
  const config = await loadConfig(paths);

  if (!config?.bitwarden) {
    console.error(
      'agent-secrets-mcp: this device is not enrolled. Run `agent-secrets init` first.',
    );
    process.exit(3);
  }

  const credentials = defaultCredentialStore(paths.home, process.env);
  const token = await credentials.get(
    KEYCHAIN_SERVICE,
    keychainAccount(config.deviceId, config.bitwarden.projectId),
  );
  if (!token) {
    console.error('agent-secrets-mcp: no access token for this device. Run `agent-secrets init`.');
    process.exit(3);
  }

  const backend = new BitwardenBackend({
    accessToken: token,
    projectId: config.bitwarden.projectId,
    ...(config.bitwarden.executablePath === undefined
      ? {}
      : { executable: config.bitwarden.executablePath }),
    ...(config.bitwarden.serverUrl === undefined ? {} : { serverUrl: config.bitwarden.serverUrl }),
  });

  let policyDocument = defaultPolicy();
  try {
    policyDocument = parsePolicy(parseYaml(await readFile(paths.policyFile, 'utf8')));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      console.error(`agent-secrets-mcp: ${(error as Error).message}`);
      process.exit(2);
    }
  }

  const apiUrl = process.env['AGENT_SECRETS_API_URL'];
  const adapterToken = process.env['AGENT_SECRETS_ADAPTER_TOKEN'];

  const server = createMcpServer({
    backend,
    policy: new PolicyEngine(policyDocument),
    // Read-only mode is opt-in through the environment so a user can wire a
    // deliberately harmless server into an untrusted project.
    readOnly: process.env['AGENT_SECRETS_MCP_READ_ONLY'] === '1',
    ...(apiUrl && adapterToken
      ? { linkIssuer: new HttpLinkIssuer({ baseUrl: apiUrl, adapterToken }) }
      : {}),
  });

  await server.connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
  console.error(`agent-secrets-mcp failed to start: ${(error as Error).message}`);
  process.exit(10);
});
