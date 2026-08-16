import { BitwardenBackend, BwsClient } from '@bx-labs/agent-secrets-backend-bitwarden';
import {
  defaultPolicy,
  makeRef,
  PolicyEngine,
  parsePolicy,
  SecretValue,
} from '@bx-labs/agent-secrets-core';
import { newCanary } from '@bx-labs/agent-secrets-redaction';
import { createFakeBws, type FakeBws } from '@bx-labs/agent-secrets-test-helpers';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createMcpServer, TOOL_DESCRIPTIONS } from '../../src/index.js';
import type { LinkIssuer } from '../../src/link-issuer.js';

/**
 * The MCP server, driven through a real MCP client over an in-memory transport.
 *
 * Going through the client rather than calling the handlers directly is what
 * makes the central assertion meaningful: what is checked is the payload that
 * would actually land in a model's context window, after the SDK has
 * serialized it.
 */

const DEV = { project: 'ezjob', environment: 'development' as const };

describe('MCP server', () => {
  let bws: FakeBws;
  let client: Client;
  let canary: string;

  const stubIssuer: LinkIssuer = {
    async issue({ action, ref }) {
      return {
        id: 'req_test',
        url: `https://secrets.example.test/input/fake-one-time-token-${action}-${ref.name}`,
        expiresAt: new Date(Date.now() + 120_000).toISOString(),
      };
    },
  };

  const connect = async (
    options: {
      policy?: PolicyEngine;
      readOnly?: boolean;
      issuer?: LinkIssuer;
      onLinkIssued?: (issued: { action: string; reference: string; url: string }) => void;
    } = {},
  ): Promise<void> => {
    const backend = new BitwardenBackend({
      client: new BwsClient({
        executable: bws.path,
        accessToken: bws.token,
        projectId: bws.projectId,
        valueTransport: 'argv',
      }),
    });

    const server = createMcpServer({
      backend,
      policy: options.policy ?? new PolicyEngine(defaultPolicy()),
      ...(options.readOnly === undefined ? {} : { readOnly: options.readOnly }),
      ...(options.issuer === undefined ? {} : { linkIssuer: options.issuer }),
      ...(options.onLinkIssued === undefined ? {} : { onLinkIssued: options.onLinkIssued }),
    });

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client({ name: 'test-client', version: '1.0.0' });
    await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  };

  const textOf = (result: unknown): string =>
    ((result as { content: Array<{ text: string }> }).content ?? [])
      .map((part) => part.text)
      .join('\n');

  /**
   * The MCP SDK surfaces a refusal as a result with `isError: true` rather than
   * a rejected promise, so a denial is something the model reads — which is the
   * behaviour we want and therefore the behaviour we assert on.
   */
  const expectRefusal = (result: unknown, pattern: RegExp): void => {
    expect((result as { isError?: boolean }).isError).toBe(true);
    expect(textOf(result)).toMatch(pattern);
  };

  beforeEach(async () => {
    bws = await createFakeBws();
    canary = newCanary();

    // Seed a secret through the backend so the tools have something to see.
    const seeding = new BitwardenBackend({
      client: new BwsClient({
        executable: bws.path,
        accessToken: bws.token,
        projectId: bws.projectId,
        valueTransport: 'argv',
      }),
    });
    await seeding.create(makeRef({ ...DEV, name: 'OPENAI_API_KEY' }), SecretValue.from(canary), {
      provider: 'openai',
      description: 'used by the dev server',
    });
  });

  afterEach(async () => {
    await client?.close();
    await bws.cleanup();
  });

  it('exposes exactly the seven default tools and no raw getter', async () => {
    await connect();
    const { tools } = await client.listTools();
    const names = tools.map((tool) => tool.name).sort();

    expect(names).toEqual([
      'run_with_secrets',
      'secret_add_request',
      'secret_delete_request',
      'secret_describe',
      'secret_health',
      'secret_list',
      'secret_rotate_request',
    ]);

    // No tool name suggests value retrieval. The structural guard in
    // scripts/check-no-raw-getter.mjs covers the source; this covers the wire.
    for (const name of names) {
      expect(name).not.toMatch(/\b(get|read|reveal|show|fetch|value|plaintext)\b/);
    }

    // Every description states the guarantee, because a model reads these
    // before deciding what to try.
    for (const tool of tools) {
      expect(tool.description).toBe(TOOL_DESCRIPTIONS[tool.name as keyof typeof TOOL_DESCRIPTIONS]);
    }
  });

  it('lists names and metadata without the value', async () => {
    await connect();
    const result = await client.callTool({ name: 'secret_list', arguments: DEV });
    const text = textOf(result);

    expect(text).toContain('OPENAI_API_KEY');
    expect(text).toContain('openai');
    expect(text).not.toContain(canary);
  });

  it('describes a secret without any value-derived field', async () => {
    await connect();
    const result = await client.callTool({
      name: 'secret_describe',
      arguments: { ...DEV, name: 'OPENAI_API_KEY' },
    });
    const text = textOf(result);

    expect(text).toContain('"exists": true');
    expect(text).not.toContain(canary);
    for (const forbidden of ['"value"', '"length"', '"hash"', '"preview"', '"entropy"']) {
      expect(text).not.toContain(forbidden);
    }
  });

  it('reports a missing secret as exists:false rather than an error', async () => {
    await connect();
    const result = await client.callTool({
      name: 'secret_describe',
      arguments: { ...DEV, name: 'NOT_THERE' },
    });
    expect(textOf(result)).toContain('"exists": false');
  });

  it('acknowledges an add request without putting the link in the model context', async () => {
    // The link is a two-minute write capability for one named reference. In a
    // tool result it would sit in the model's context, its provider's logs, and
    // any transcript the user pastes elsewhere — reachable by an agent with a
    // browser tool, or one that has been prompt-injected. It goes to the human
    // out of band instead.
    const delivered: string[] = [];

    await connect({
      issuer: stubIssuer,
      onLinkIssued: ({ url }) => delivered.push(url),
    });

    const result = await client.callTool({
      name: 'secret_add_request',
      arguments: { ...DEV, name: 'NEW_KEY' },
    });
    const text = textOf(result);

    expect(text).toContain('NEW_KEY');
    expect(text).toContain('out of band');
    expect(text).not.toContain('https://');
    expect(text).not.toContain('fake-one-time-token');
    expect(text).not.toContain(canary);

    // The host did receive it, so the human can still be given the link.
    expect(delivered).toHaveLength(1);
    expect(delivered[0]).toContain('https://secrets.example.test/input/');
  });

  it('says so plainly when secure links are not configured', async () => {
    await connect();
    const result = await client.callTool({
      name: 'secret_add_request',
      arguments: { ...DEV, name: 'NEW_KEY' },
    });

    expect((result as { isError?: boolean }).isError).toBe(true);
    expect(textOf(result)).toContain('not configured');
  });

  /**
   * Without the link service there is still a way through: the human types the
   * value at the CLI's hidden prompt. The command is built here rather than
   * left to the model to compose, because the human is about to paste it into a
   * shell — see the note in test/unit/handoff-command.test.ts.
   */
  it('hands over the exact command to run when links are not configured', async () => {
    await connect();
    const text = textOf(
      await client.callTool({
        name: 'secret_add_request',
        arguments: { ...DEV, name: 'NEW_KEY' },
      }),
    );

    expect(text).toContain('agent-secrets add NEW_KEY --project ezjob --env development');
    expect(text).toMatch(/exactly as written|verbatim/i);
    // The agent must not "help" by collecting the value first.
    expect(text).toMatch(/never see|do not ask/i);
  });

  it('hands over the rotate command for a rotation, not the add command', async () => {
    await connect();
    const text = textOf(
      await client.callTool({
        name: 'secret_rotate_request',
        arguments: { ...DEV, name: 'OPENAI_API_KEY' },
      }),
    );

    expect(text).toContain('agent-secrets rotate OPENAI_API_KEY --project ezjob --env development');
    expect(text).not.toContain('agent-secrets add');
  });

  /**
   * Read-only is the operator saying "this agent causes no writes". Handing
   * over a command that produces one anyway would route around the setting,
   * so the refusal stays a refusal.
   */
  it('hands over nothing in read-only mode', async () => {
    await connect({ readOnly: true });
    const text = textOf(
      await client.callTool({
        name: 'secret_add_request',
        arguments: { ...DEV, name: 'NEW_KEY' },
      }),
    );

    expect(text).toContain('read-only');
    expect(text).not.toContain('agent-secrets add');
  });

  it('refuses to rotate a secret that does not exist', async () => {
    await connect({ issuer: stubIssuer });
    const result = await client.callTool({
      name: 'secret_rotate_request',
      arguments: { ...DEV, name: 'NEVER_CREATED' },
    });

    expect((result as { isError?: boolean }).isError).toBe(true);
    expect(textOf(result)).toContain('does not exist');
  });

  it('denies every production mutation under the default policy', async () => {
    await connect({ issuer: stubIssuer });
    const production = { project: 'ezjob', environment: 'production' as const };

    expectRefusal(
      await client.callTool({
        name: 'secret_add_request',
        arguments: { ...production, name: 'PROD_KEY' },
      }),
      /not allowed/i,
    );

    expectRefusal(
      await client.callTool({
        name: 'secret_delete_request',
        arguments: {
          ...production,
          name: 'PROD_KEY',
          confirmation: 'bitwarden/ezjob/production/PROD_KEY',
        },
      }),
      /not allowed/i,
    );

    expectRefusal(
      await client.callTool({
        name: 'run_with_secrets',
        arguments: { ...production, secrets: ['PROD_KEY'], command: ['echo', 'hi'] },
      }),
      /not allowed/i,
    );
  });

  it('cannot be talked out of policy by an argument that claims authorisation', async () => {
    await connect({ issuer: stubIssuer });

    // The shape a prompt-injected agent would try: extra arguments asserting
    // permission. They are not in the schema, so they never reach the decision,
    // which was made from the policy document alone.
    expectRefusal(
      await client.callTool({
        name: 'secret_add_request',
        arguments: {
          project: 'ezjob',
          environment: 'production',
          name: 'PROD_KEY',
          approved: true,
          humanApproved: true,
          policyOverride: 'allow',
        },
      }),
      /not allowed/i,
    );
  });

  it('requires an exact confirmation string to delete', async () => {
    await connect();
    const wrong = await client.callTool({
      name: 'secret_delete_request',
      arguments: { ...DEV, name: 'OPENAI_API_KEY', confirmation: 'OPENAI_API_KEY' },
    });

    expect((wrong as { isError?: boolean }).isError).toBe(true);
    expect(textOf(wrong)).toContain('did not match');

    const right = await client.callTool({
      name: 'secret_delete_request',
      arguments: {
        ...DEV,
        name: 'OPENAI_API_KEY',
        confirmation: 'bitwarden/ezjob/development/OPENAI_API_KEY',
      },
    });
    expect(textOf(right)).toContain('"deleted": true');
  });

  it('runs a command with secrets and returns redacted output', async () => {
    await connect();

    // A child that prints its own secret — the case redaction exists for.
    const result = await client.callTool({
      name: 'run_with_secrets',
      arguments: {
        ...DEV,
        secrets: ['OPENAI_API_KEY'],
        command: [process.execPath, '-e', 'console.log(process.env.OPENAI_API_KEY)'],
      },
    });
    const text = textOf(result);

    expect(text).toContain('"exitCode": 0');
    expect(text).toContain('OPENAI_API_KEY');
    // The child printed the value; what reaches the model does not contain it.
    expect(text).not.toContain(canary);
    expect(text).toContain('[REDACTED]');
  });

  /**
   * The naming contract, asserted rather than assumed.
   *
   * An application receives the variable name it expects. Scope lives in the
   * reference — project/environment/name — and never in the variable name, so
   * two projects can both hold an `OPENAI_API_KEY` without either child process
   * learning that the other exists. Any future "helpful" prefixing or aliasing
   * breaks every consumer silently; this test is the thing that would fail.
   */
  it('injects each secret under its own name, unprefixed and unaliased', async () => {
    await connect();
    const probe = [
      'const seen = Object.keys(process.env).filter((k) => k.includes("OPENAI"));',
      'console.log(JSON.stringify(seen));',
    ].join('');

    const text = textOf(
      await client.callTool({
        name: 'run_with_secrets',
        arguments: {
          ...DEV,
          secrets: ['OPENAI_API_KEY'],
          command: [process.execPath, '-e', probe],
        },
      }),
    );

    expect(text).toContain('OPENAI_API_KEY');
    expect(text).not.toMatch(
      /EZJOB_OPENAI_API_KEY|OPENAI_API_KEY_DEVELOPMENT|AGENT_SECRETS_OPENAI/,
    );
    expect(text).not.toContain(canary);
  });

  it('sends its instructions to whatever client connects', async () => {
    await connect();
    const instructions = client.getInstructions() ?? '';

    // The process, not just the inventory: a client that only ever reads tool
    // descriptions never learns when to involve this server in the first place.
    expect(instructions).toContain('run_with_secrets');
    expect(instructions).toMatch(/never[\s\S]{0,80}paste/i);
    expect(instructions).toMatch(/compromised/i);
    expect(instructions).not.toContain(canary);
  });

  it('reports a dry run without touching the vault', async () => {
    await connect();
    const before = (await bws.calls()).length;

    const result = await client.callTool({
      name: 'run_with_secrets',
      arguments: {
        ...DEV,
        secrets: ['OPENAI_API_KEY'],
        command: ['echo', 'hi'],
        dryRun: true,
      },
    });

    expect(textOf(result)).toContain('"dryRun": true');
    expect(textOf(result)).not.toContain(canary);
    expect((await bws.calls()).length).toBe(before);
  });

  it('refuses a shell as the executable', async () => {
    await connect();
    expectRefusal(
      await client.callTool({
        name: 'run_with_secrets',
        arguments: { ...DEV, secrets: ['OPENAI_API_KEY'], command: ['sh', '-c', 'env'] },
      }),
      /deny list/i,
    );
  });

  it('disables mutation and execution in read-only mode', async () => {
    await connect({ readOnly: true, issuer: stubIssuer });

    const deletion = await client.callTool({
      name: 'secret_delete_request',
      arguments: {
        ...DEV,
        name: 'OPENAI_API_KEY',
        confirmation: 'bitwarden/ezjob/development/OPENAI_API_KEY',
      },
    });
    expect((deletion as { isError?: boolean }).isError).toBe(true);
    expect(textOf(deletion)).toContain('read-only');

    const execution = await client.callTool({
      name: 'run_with_secrets',
      arguments: { ...DEV, secrets: ['OPENAI_API_KEY'], command: ['echo', 'hi'] },
    });
    expect((execution as { isError?: boolean }).isError).toBe(true);

    // Reads still work: read-only is a ceiling on mutation, not a shutdown.
    const listed = await client.callTool({ name: 'secret_list', arguments: DEV });
    expect(textOf(listed)).toContain('OPENAI_API_KEY');
  });

  it('reports health without leaking a credential or a project inventory', async () => {
    await connect();
    const text = textOf(await client.callTool({ name: 'secret_health', arguments: {} }));

    expect(text).toContain('"reachable": true');
    expect(text).not.toContain(bws.token);
    expect(text).not.toContain(canary);
    expect(text).not.toContain('OPENAI_API_KEY');
  });

  it('honours a policy document that opens production deliberately', async () => {
    // Proves the denial is policy, not a hard-coded refusal: an operator who
    // writes it down explicitly gets what they asked for.
    const policy = new PolicyEngine(
      parsePolicy({
        version: 1,
        projects: {
          ezjob: {
            environments: {
              production: { allow: ['list', 'describe', 'request-create'], humanApproval: [] },
            },
          },
        },
        commands: { denyExecutables: [], allowExecutables: [] },
      }),
    );

    await connect({ policy, issuer: stubIssuer });
    const result = await client.callTool({
      name: 'secret_add_request',
      arguments: { project: 'ezjob', environment: 'production', name: 'PROD_KEY' },
    });

    expect(textOf(result)).toContain('out of band');
    expect((result as { isError?: boolean }).isError).toBeFalsy();
  });

  it('rejects a malformed reference before reaching the backend', async () => {
    await connect();
    expectRefusal(
      await client.callTool({
        name: 'secret_describe',
        arguments: { project: '../etc', environment: 'development', name: 'OPENAI_API_KEY' },
      }),
      /validation|invalid/i,
    );

    expectRefusal(
      await client.callTool({
        name: 'secret_describe',
        arguments: { ...DEV, name: 'lowercase_name' },
      }),
      /validation|invalid/i,
    );
  });
});
