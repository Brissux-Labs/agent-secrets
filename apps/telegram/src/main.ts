import { createBot } from './bot.js';
import { loadTelegramConfig } from './config.js';

async function main(): Promise<void> {
  const config = loadTelegramConfig();
  const bot = createBot(config);

  const shutdown = async (): Promise<void> => {
    await bot.stop();
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown());
  process.on('SIGINT', () => void shutdown());

  // Long polling rather than webhooks: it needs no inbound port, which keeps
  // the adapter off the public internet entirely. A webhook deployment is a
  // documented alternative, not the default.
  await bot.start({
    allowed_updates: ['message'],
    onStart: (info) => {
      console.error(`agent-secrets telegram adapter running as @${info.username}`);
    },
  });
}

main().catch((error: unknown) => {
  console.error(`agent-secrets telegram adapter failed to start: ${(error as Error).message}`);
  process.exit(1);
});
