import { loadApiConfig } from './config.js';
import { buildServer } from './server.js';
import { RequestStore } from './store.js';

/**
 * Process entry point.
 *
 * Startup order matters: configuration is validated before anything is bound,
 * so a misconfigured deployment fails immediately and visibly rather than
 * serving links over plain HTTP.
 */
async function main(): Promise<void> {
  const config = loadApiConfig();
  const store = new RequestStore(config.databasePath);
  const app = await buildServer({ config, store });

  // Expire stale requests periodically. Without this, a pending row sits at
  // `pending` forever and the status endpoint reports something misleading.
  const sweeper = setInterval(() => {
    try {
      store.sweep();
    } catch (error) {
      app.log.error({ err: (error as Error).name }, 'request sweep failed');
    }
  }, 60_000);
  sweeper.unref();

  const shutdown = async (signal: string): Promise<void> => {
    app.log.info({ signal }, 'shutting down');
    clearInterval(sweeper);
    await app.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));

  await app.listen({ host: config.host, port: config.port });
  app.log.info({ port: config.port, host: config.host }, 'agent-secrets api listening');
}

main().catch((error: unknown) => {
  // The message is the only thing printed. A stack trace from a config error
  // can embed the environment that produced it.
  console.error(`agent-secrets api failed to start: ${(error as Error).message}`);
  process.exit(1);
});
