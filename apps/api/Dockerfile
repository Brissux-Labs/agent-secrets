# syntax=docker/dockerfile:1

# Reference deployment for the Agent Secrets API.
#
# Two things drive the shape of this file:
#
#  1. The container needs the `bws` binary, because the API writes to Bitwarden
#     through it. It is fetched at build time with a pinned version and a
#     verified checksum — an unverified download at build time would be exactly
#     the supply-chain shortcut docs/threat-model.md warns against.
#  2. The process must not run as root and must not be able to write anywhere
#     except its data volume. A server that receives plaintext secrets in
#     request bodies is not a place to be relaxed about container hardening.

ARG NODE_VERSION=22.20.0
ARG BWS_VERSION=1.0.0

# ---------------------------------------------------------------- build stage
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
RUN pnpm --filter @bx-labs/agent-secrets-api... run build

# Prune to production dependencies only, so no test helper or linter reaches
# the runtime image.
RUN pnpm --filter @bx-labs/agent-secrets-api deploy --prod --legacy /out

# -------------------------------------------------------------- bws fetch stage
FROM debian:bookworm-slim AS bws
ARG BWS_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /bws
# The checksum must be updated together with BWS_VERSION. The build fails
# closed if it does not match; do not "fix" a mismatch by removing the check.
COPY apps/api/bws-checksums.txt .
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) asset="bws-x86_64-unknown-linux-gnu-${BWS_VERSION}.zip" ;; \
      arm64) asset="bws-aarch64-unknown-linux-gnu-${BWS_VERSION}.zip" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://github.com/bitwarden/sdk-sm/releases/download/bws-v${BWS_VERSION}/${asset}" -o bws.zip; \
    grep " ${asset}\$" bws-checksums.txt | sed "s| ${asset}\$|  bws.zip|" | sha256sum -c -; \
    unzip -q bws.zip; \
    chmod 0755 bws

# ------------------------------------------------------------- runtime stage
FROM node:${NODE_VERSION}-bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends dumb-init \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bws /bws/bws /usr/local/bin/bws

WORKDIR /app
COPY --from=build --chown=node:node /out ./

# The data volume holds the SQLite file: pending one-time requests and the
# metadata audit trail. No secret value is ever written here.
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]

USER node
ENV NODE_ENV=production \
    AGENT_SECRETS_HOST=0.0.0.0 \
    AGENT_SECRETS_PORT=8787 \
    AGENT_SECRETS_DB_PATH=/data/agent-secrets.sqlite \
    BWS_EXECUTABLE_PATH=/usr/local/bin/bws

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.AGENT_SECRETS_PORT||8787)+'/health/live').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/main.js"]
