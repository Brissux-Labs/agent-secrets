# syntax=docker/dockerfile:1

# The Telegram adapter.
#
# Unlike the API, this image needs no `bws` binary and holds no vault
# credential: the adapter's only secrets are its own bot token and the shared
# adapter credential it uses to call the API. That asymmetry is the design —
# compromising this container does not compromise the vault.

ARG NODE_VERSION=22.20.0

FROM node:${NODE_VERSION}-bookworm-slim AS build
WORKDIR /app
RUN corepack enable

COPY pnpm-workspace.yaml pnpm-lock.yaml package.json tsconfig.base.json tsconfig.json ./
COPY packages/core/package.json packages/core/
COPY packages/redaction/package.json packages/redaction/
COPY packages/backend-bitwarden/package.json packages/backend-bitwarden/
COPY packages/cli/package.json packages/cli/
COPY packages/mcp-server/package.json packages/mcp-server/
COPY packages/test-helpers/package.json packages/test-helpers/
COPY apps/api/package.json apps/api/
COPY apps/telegram/package.json apps/telegram/

RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile

COPY . .
RUN pnpm --filter @bx-labs/agent-secrets-telegram... run build
RUN pnpm --filter @bx-labs/agent-secrets-telegram deploy --prod --legacy /out

FROM node:${NODE_VERSION}-bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends dumb-init ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build --chown=node:node /out ./
USER node
ENV NODE_ENV=production
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/main.js"]
