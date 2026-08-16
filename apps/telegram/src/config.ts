import { z } from 'zod';

/**
 * Adapter configuration.
 *
 * The allowlist is required and must be non-empty. There is no "allow everyone"
 * mode and no default: a bot token leaks eventually, and the allowlist is what
 * stands between a leaked token and a stranger issuing write links against your
 * vault.
 */
export const telegramConfigSchema = z
  .object({
    botToken: z.string().min(20),
    allowedUserIds: z
      .string()
      .transform((raw) =>
        raw
          .split(',')
          .map((part) => part.trim())
          .filter(Boolean)
          .map((part) => Number.parseInt(part, 10)),
      )
      .pipe(z.array(z.number().int().positive()).min(1)),
    apiUrl: z.url(),
    adapterToken: z.string().min(32),
    rateLimitMax: z.coerce.number().int().min(1).default(10),
    rateLimitWindowMs: z.coerce.number().int().min(1000).default(60_000),
  })
  .strict();

export type TelegramConfig = z.infer<typeof telegramConfigSchema>;

export function loadTelegramConfig(env: NodeJS.ProcessEnv = process.env): TelegramConfig {
  const parsed = telegramConfigSchema.safeParse({
    botToken: env['TELEGRAM_BOT_TOKEN'],
    allowedUserIds: env['TELEGRAM_ALLOWED_USER_IDS'],
    apiUrl: env['AGENT_SECRETS_API_URL'],
    adapterToken: env['AGENT_SECRETS_ADAPTER_TOKEN'],
    rateLimitMax: env['TELEGRAM_RATE_LIMIT_MAX'],
    rateLimitWindowMs: env['TELEGRAM_RATE_LIMIT_WINDOW_MS'],
  });

  if (!parsed.success) {
    // Field names only. `TELEGRAM_BOT_TOKEN` in a startup log would be a
    // full account takeover.
    const fields = parsed.error.issues.map((issue) => issue.path.join('.')).join(', ');
    throw new Error(
      `Telegram adapter cannot start: invalid or missing configuration (${fields}). ` +
        'See .env.example.',
    );
  }
  return parsed.data;
}
