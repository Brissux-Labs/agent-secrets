import { defineConfig } from 'vitest/config';

/**
 * Two projects, deliberately separated:
 *
 *  - `unit`        : pure, fast, no filesystem beyond temp dirs, no child processes.
 *  - `integration` : spawns the fake `bws` binary, touches temp HOME dirs, boots Fastify.
 *
 * Both run with telemetry disabled and with a per-run canary namespace so that
 * the leak scanner (scripts/scan-secrets.mjs) can prove nothing escaped.
 */
export default defineConfig({
  test: {
    globals: false,
    env: {
      AGENT_SECRETS_TELEMETRY: '0',
      NO_COLOR: '1',
      TZ: 'UTC',
    },
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          include: ['packages/*/test/unit/**/*.test.ts', 'apps/*/test/unit/**/*.test.ts'],
          environment: 'node',
        },
      },
      {
        extends: true,
        test: {
          name: 'integration',
          include: [
            'packages/*/test/integration/**/*.test.ts',
            'apps/*/test/integration/**/*.test.ts',
          ],
          environment: 'node',
          testTimeout: 30_000,
          hookTimeout: 30_000,
          pool: 'forks',
        },
      },
    ],
  },
});
