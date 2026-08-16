import { z } from 'zod';

/**
 * The Telegram adapter's view of the API.
 *
 * Note what this client cannot do: there is no method that returns a value,
 * because no such endpoint exists. The adapter's entire vocabulary is "please
 * issue a one-time link" and "what happened to request X".
 */

const createResponseSchema = z
  .object({
    id: z.string(),
    url: z.url(),
    expiresAt: z.iso.datetime(),
  })
  .strict();

export type CreatedRequest = z.infer<typeof createResponseSchema>;

const statusResponseSchema = z
  .object({
    id: z.string(),
    action: z.enum(['create', 'rotate']),
    project: z.string(),
    environment: z.string(),
    name: z.string(),
    status: z.enum(['pending', 'processing', 'succeeded', 'failed', 'expired']),
    createdAt: z.string(),
    expiresAt: z.string(),
    consumedAt: z.string().nullable(),
  })
  .strict();

export type RequestStatus = z.infer<typeof statusResponseSchema>;

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export class ApiClient {
  readonly #baseUrl: string;
  readonly #adapterToken: string;
  readonly #timeoutMs: number;

  constructor(options: { baseUrl: string; adapterToken: string; timeoutMs?: number }) {
    this.#baseUrl = options.baseUrl.replace(/\/$/, '');
    this.#adapterToken = options.adapterToken;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
  }

  async createRequest(input: {
    action: 'create' | 'rotate';
    project: string;
    environment: string;
    name: string;
    telegramUserId: string;
  }): Promise<CreatedRequest> {
    const response = await this.#fetch('/v1/requests', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${this.#adapterToken}`,
      },
      body: JSON.stringify(input),
    });

    if (!response.ok) {
      // The API's body is not surfaced to the user: it is a machine interface
      // and its wording is not written for a chat window.
      throw new ApiError(response.status, `The service refused the request (${response.status}).`);
    }
    return createResponseSchema.parse(await response.json());
  }

  async getStatus(id: string): Promise<RequestStatus> {
    const response = await this.#fetch(`/v1/requests/${encodeURIComponent(id)}/status`, {
      headers: { authorization: `Bearer ${this.#adapterToken}` },
    });
    if (!response.ok) {
      throw new ApiError(
        response.status,
        `Could not read the request status (${response.status}).`,
      );
    }
    return statusResponseSchema.parse(await response.json());
  }

  async health(): Promise<{ ready: boolean; latencyMs: number }> {
    const startedAt = Date.now();
    try {
      const response = await this.#fetch('/health/ready');
      return { ready: response.ok, latencyMs: Date.now() - startedAt };
    } catch {
      return { ready: false, latencyMs: Date.now() - startedAt };
    }
  }

  async #fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      return await fetch(`${this.#baseUrl}${path}`, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }
}
