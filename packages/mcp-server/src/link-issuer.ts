import { BackendUnavailableError, type SecretRef } from '@bx-labs/agent-secrets-core';
import { z } from 'zod';

/**
 * Issues one-time secure input links by calling the Agent Secrets API.
 *
 * The MCP server does not generate links itself, and that separation is
 * deliberate. Link issuance requires the adapter credential and touches the
 * request database; keeping it behind an HTTP call means the MCP server — which
 * runs on a developer's laptop, inside an agent's process tree — never holds
 * the ability to mint links on its own.
 *
 * When no API is configured, the request tools report that plainly instead of
 * degrading into something less safe.
 */

const responseSchema = z
  .object({ id: z.string(), url: z.url(), expiresAt: z.iso.datetime() })
  .strict();

export interface IssuedLink {
  readonly id: string;
  readonly url: string;
  readonly expiresAt: string;
}

export interface LinkIssuer {
  issue(input: { action: 'create' | 'rotate'; ref: SecretRef }): Promise<IssuedLink>;
}

export class HttpLinkIssuer implements LinkIssuer {
  readonly #baseUrl: string;
  readonly #adapterToken: string;
  readonly #timeoutMs: number;

  constructor(options: { baseUrl: string; adapterToken: string; timeoutMs?: number }) {
    this.#baseUrl = options.baseUrl.replace(/\/$/, '');
    this.#adapterToken = options.adapterToken;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
  }

  async issue(input: { action: 'create' | 'rotate'; ref: SecretRef }): Promise<IssuedLink> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);

    try {
      const response = await fetch(`${this.#baseUrl}/v1/requests`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${this.#adapterToken}`,
        },
        body: JSON.stringify({
          action: input.action,
          project: input.ref.project,
          environment: input.ref.environment,
          name: input.ref.name,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        // The status is enough for the agent to relay something useful; the
        // body is a machine interface and may not be written for display.
        throw new BackendUnavailableError(
          `The secure link service refused the request (HTTP ${response.status}).`,
          { hint: 'Check that the API is running and the adapter credential matches.' },
        );
      }
      return responseSchema.parse(await response.json());
    } catch (error) {
      if (error instanceof BackendUnavailableError) {
        throw error;
      }
      throw new BackendUnavailableError('The secure link service is not reachable.', {
        cause: error,
      });
    } finally {
      clearTimeout(timer);
    }
  }
}
