import { z } from 'zod';

/**
 * Service configuration, validated at startup.
 *
 * The service refuses to boot when a production-relevant setting is missing.
 * That is deliberate and slightly rude: the failure mode it prevents is a
 * single-tenant server quietly coming up over plain HTTP with no adapter
 * credential, handing out one-time links that anyone can intercept. A crash
 * with a clear message at deploy time is cheaper than that.
 */

const nonEmpty = z.string().min(1);

export const apiConfigSchema = z
  .object({
    /** Public origin used to build one-time URLs, e.g. https://secrets.example.com */
    publicUrl: z.url(),
    host: z.string().default('127.0.0.1'),
    port: z.coerce.number().int().min(1).max(65535).default(8787),
    /** 'development' relaxes the HTTPS requirement for localhost only. */
    nodeEnv: z.enum(['development', 'production']).default('production'),

    /** Shared credential the Telegram adapter presents to POST /v1/requests. */
    adapterToken: nonEmpty.min(32, 'the adapter credential must be at least 32 characters'),

    databasePath: nonEmpty.default('./data/agent-secrets.sqlite'),

    bitwarden: z.object({
      accessToken: nonEmpty,
      projectId: z.uuid(),
      executablePath: z.string().optional(),
      serverUrl: z.url().optional(),
    }),

    ttlSeconds: z.coerce.number().int().min(30).max(900).default(120),
    maxValueBytes: z.coerce
      .number()
      .int()
      .min(1)
      .max(256 * 1024)
      .default(64 * 1024),

    rateLimit: z
      .object({
        /** Per source IP, per window. */
        max: z.coerce.number().int().min(1).default(20),
        windowMs: z.coerce.number().int().min(1000).default(60_000),
        /** Submission attempts per request id before it is burned. */
        maxAttemptsPerRequest: z.coerce.number().int().min(1).default(3),
      })
      .default({ max: 20, windowMs: 60_000, maxAttemptsPerRequest: 3 }),

    /**
     * When true, the server trusts `X-Forwarded-For`. Only enable behind a
     * reverse proxy you control: otherwise a client can spoof its own IP and
     * walk straight through the rate limiter.
     */
    trustProxy: z
      .string()
      .transform((v) => v === 'true' || v === '1')
      .default(false),
  })
  .strict();

export type ApiConfig = z.infer<typeof apiConfigSchema>;

export function loadApiConfig(env: NodeJS.ProcessEnv = process.env): ApiConfig {
  const parsed = apiConfigSchema.safeParse({
    publicUrl: env['AGENT_SECRETS_PUBLIC_URL'],
    host: env['AGENT_SECRETS_HOST'],
    port: env['AGENT_SECRETS_PORT'],
    nodeEnv: env['NODE_ENV'] === 'development' ? 'development' : 'production',
    adapterToken: env['AGENT_SECRETS_ADAPTER_TOKEN'],
    databasePath: env['AGENT_SECRETS_DB_PATH'],
    bitwarden: {
      accessToken: env['BWS_ACCESS_TOKEN'],
      projectId: env['BWS_PROJECT_ID'],
      executablePath: env['BWS_EXECUTABLE_PATH'],
      serverUrl: env['BWS_SERVER_URL'],
    },
    ttlSeconds: env['AGENT_SECRETS_TTL_SECONDS'],
    maxValueBytes: env['AGENT_SECRETS_MAX_VALUE_BYTES'],
    rateLimit: {
      max: env['AGENT_SECRETS_RATE_LIMIT_MAX'],
      windowMs: env['AGENT_SECRETS_RATE_LIMIT_WINDOW_MS'],
      maxAttemptsPerRequest: env['AGENT_SECRETS_MAX_ATTEMPTS'],
    },
    trustProxy: env['AGENT_SECRETS_TRUST_PROXY'],
  });

  if (!parsed.success) {
    // Names the missing variables and nothing else. A validation error that
    // echoed the submitted values would print the access token to the logs of
    // whatever supervisor restarted the process.
    const fields = parsed.error.issues.map((issue) => issue.path.join('.')).join(', ');
    throw new Error(
      `Agent Secrets API cannot start: invalid or missing configuration (${fields}). ` +
        'See .env.example for the required variables.',
    );
  }

  const config = parsed.data;

  if (config.nodeEnv === 'production' && !config.publicUrl.startsWith('https://')) {
    throw new Error(
      'Agent Secrets API cannot start: AGENT_SECRETS_PUBLIC_URL must use https in production. ' +
        'The one-time link travels through Telegram and must not be interceptable.',
    );
  }

  return config;
}
