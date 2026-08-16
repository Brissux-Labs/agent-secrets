import {
  environmentSchema,
  projectSlugSchema,
  secretNameSchema,
} from '@bx-labs/agent-secrets-core';
import { Bot, type Context as GrammyContext } from 'grammy';
import { ApiClient, ApiError } from './api-client.js';
import { isAllowedUser, isPrivateChat, looksLikeValue, RateLimiter } from './guards.js';

/**
 * The Telegram adapter.
 *
 * Its job is small on purpose: parse a metadata-only command, check who sent
 * it, ask the API for a one-time link, and reply with that link. It never sees
 * a value, never stores one, and — stated explicitly because it is the point of
 * the design — never sends anything to a language model. There is no LLM in
 * this file and there is no code path that would let one appear.
 */

export interface BotConfig {
  readonly botToken: string;
  readonly allowedUserIds: readonly number[];
  readonly apiUrl: string;
  readonly adapterToken: string;
  readonly rateLimitMax?: number;
  readonly rateLimitWindowMs?: number;
}

export function createBot(config: BotConfig): Bot {
  const bot = new Bot(config.botToken);
  const api = new ApiClient({ baseUrl: config.apiUrl, adapterToken: config.adapterToken });
  const limiter = new RateLimiter(config.rateLimitMax ?? 10, config.rateLimitWindowMs ?? 60_000);

  setInterval(() => limiter.sweep(), 5 * 60_000).unref();

  /**
   * One gate in front of everything.
   *
   * Ordering matters: chat type and allowlist are checked before the message
   * text is examined at all, so an unauthorized user's content is never parsed,
   * matched against patterns, or echoed anywhere.
   */
  bot.use(async (ctx, next) => {
    if (!isPrivateChat(ctx.chat?.type)) {
      // Silence rather than a reply. Answering in a group would confirm the
      // bot's presence to everyone in it.
      return;
    }
    if (!isAllowedUser(ctx.from?.id, config.allowedUserIds)) {
      await ctx.reply('This bot is private.');
      return;
    }
    const decision = limiter.check(ctx.from?.id ?? 0);
    if (!decision.allowed) {
      await ctx.reply(
        `Too many requests. Try again in ${Math.ceil(decision.retryAfterMs / 1000)} seconds.`,
      );
      return;
    }
    await next();
  });

  /**
   * FR-TG-013 / FR-TG-014.
   *
   * Runs before the command handlers so a value-bearing command is refused
   * rather than partially processed.
   */
  bot.on('message:text', async (ctx, next) => {
    const text = ctx.message.text;
    if (!text.startsWith('/')) {
      await ctx.reply(
        'Send a command. Try /help.\n\nNever paste a secret value here — this chat is not a secure channel.',
      );
      return;
    }

    const suspicion = looksLikeValue(text);
    if (suspicion.suspicious) {
      await ctx.reply(
        [
          '⚠️ Refused: this message may contain a secret value.',
          '',
          `I refused it because ${suspicion.reason}.`,
          '',
          'Values never go through Telegram. Send only the name:',
          '`/add_secret <project> <environment> <NAME>`',
          '',
          'I will try to delete your message, but **Telegram has already received it**.',
          'Deleting does not undo that. If this really was a live credential, rotate it at the provider.',
        ].join('\n'),
        { parse_mode: 'Markdown' },
      );

      try {
        await ctx.deleteMessage();
      } catch {
        // Deletion needs the message to be recent and the bot to have the
        // right. Failure changes nothing about the advice already given.
      }
      return;
    }

    await next();
  });

  bot.command('start', async (ctx) => {
    await ctx.reply(
      [
        'Agent Secrets.',
        '',
        'I create one-time secure links so you can add a secret without ever',
        'typing its value into this chat.',
        '',
        'Try /help.',
      ].join('\n'),
    );
  });

  bot.command('help', async (ctx) => {
    await ctx.reply(
      [
        '*Commands*',
        '',
        '`/add_secret <project> <environment> <NAME>`',
        '`/rotate_secret <project> <environment> <NAME>`',
        '`/list_secrets <project> <environment>`',
        '`/secret_status`',
        '',
        'Environments: `development`, `preview`, `production`.',
        '',
        '*The rule*: never send a value here. I answer with a link that opens a',
        'secure form; the value goes from your browser straight to your vault.',
      ].join('\n'),
      { parse_mode: 'Markdown' },
    );
  });

  bot.command('add_secret', (ctx) => handleRequest(ctx, api, 'create'));
  bot.command('rotate_secret', (ctx) => handleRequest(ctx, api, 'rotate'));

  bot.command('list_secrets', async (ctx) => {
    // Listing requires reading the vault, which the adapter deliberately cannot
    // do: giving the Telegram bot a vault-reading credential would make the bot
    // token as valuable as the vault. Metadata listing belongs to the CLI and
    // the MCP server, which run on a machine the user controls.
    await ctx.reply(
      [
        'Listing is not available from Telegram.',
        '',
        'The bot holds no vault credential on purpose — its token is worth',
        'nothing on its own. Use `agent-secrets list` on your machine, or the',
        '`secret_list` MCP tool from your coding agent.',
      ].join('\n'),
      { parse_mode: 'Markdown' },
    );
  });

  bot.command('secret_status', async (ctx) => {
    const health = await api.health();
    await ctx.reply(
      health.ready
        ? `✅ Service reachable (${health.latencyMs} ms).`
        : '❌ The service is not reachable. Secrets cannot be added right now.',
    );
  });

  bot.catch((error) => {
    // grammY hands us the update alongside the error. Neither is logged: an
    // update object contains the full message text, which is exactly what we
    // refuse to persist when a user pastes a value by accident.
    console.error(
      `telegram adapter error: ${error.error instanceof Error ? error.error.name : 'unknown'}`,
    );
  });

  return bot;
}

async function handleRequest(
  ctx: GrammyContext,
  api: ApiClient,
  action: 'create' | 'rotate',
): Promise<void> {
  const args = (ctx.match ?? '').toString().trim().split(/\s+/).filter(Boolean);

  if (args.length !== 3) {
    await ctx.reply(
      `Usage: \`/${action === 'create' ? 'add' : 'rotate'}_secret <project> <environment> <NAME>\`\n\nThree arguments, and never the value.`,
      { parse_mode: 'Markdown' },
    );
    return;
  }

  const [project, environment, name] = args as [string, string, string];

  // Validated against the same grammar the CLI and API use. An invalid argument
  // is rejected here so nothing malformed reaches the API.
  const projectResult = projectSlugSchema.safeParse(project);
  const environmentResult = environmentSchema.safeParse(environment);
  const nameResult = secretNameSchema.safeParse(name);

  if (!projectResult.success || !environmentResult.success || !nameResult.success) {
    const problems = [
      projectResult.success ? null : 'project must be lowercase letters, digits and hyphens',
      environmentResult.success ? null : 'environment must be development, preview or production',
      nameResult.success ? null : 'name must be UPPER_SNAKE_CASE',
    ].filter(Boolean);
    await ctx.reply(`I could not use that: ${problems.join('; ')}.`);
    return;
  }

  try {
    const created = await api.createRequest({
      action,
      project: projectResult.data,
      environment: environmentResult.data,
      name: nameResult.data,
      telegramUserId: String(ctx.from?.id ?? ''),
    });

    const expiresInSeconds = Math.max(
      0,
      Math.round((new Date(created.expiresAt).getTime() - Date.now()) / 1000),
    );

    await ctx.reply(
      [
        `${action === 'create' ? 'Add' : 'Rotate'} \`${nameResult.data}\` in \`${projectResult.data}/${environmentResult.data}\`.`,
        '',
        `Open the secure form below. It expires in ${expiresInSeconds} seconds and works once.`,
      ].join('\n'),
      {
        parse_mode: 'Markdown',
        reply_markup: {
          inline_keyboard: [[{ text: 'Open secure form', url: created.url }]],
        },
      },
    );
  } catch (error) {
    if (error instanceof ApiError) {
      await ctx.reply(`❌ ${error.message}`);
      return;
    }
    await ctx.reply('❌ The service is not reachable right now. Nothing was changed.');
  }
}
