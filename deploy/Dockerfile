FROM node:24-trixie-slim@sha256:366fdef91728b1b7fa18c84fba63b6e79ed77b7e10cc206878e9705da4d7b169 AS workspace
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10.33.2 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY apps/extension/package.json apps/extension/package.json
COPY apps/recovery-tool/package.json apps/recovery-tool/package.json
COPY packages/client-core/package.json packages/client-core/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/crypto/package.json packages/crypto/package.json
COPY packages/domain/package.json packages/domain/package.json
COPY packages/e2ee/package.json packages/e2ee/package.json
COPY packages/migration-worker-runtime-deps/package.json packages/migration-worker-runtime-deps/package.json
COPY packages/ui-tokens/package.json packages/ui-tokens/package.json
RUN --mount=type=cache,id=mima-pnpm-store,target=/pnpm/store,sharing=locked \
  pnpm install --store-dir /pnpm/store --network-concurrency 8 --frozen-lockfile
COPY . .

FROM workspace AS recovery-tool-build
ENV NODE_ENV=production
RUN pnpm --filter @mima/recovery-tool build

FROM workspace AS web-build
ARG MIMA_EXTENSION_API_BASE=https://mima.example.com
ARG MIMA_EXTENSION_PUBLIC_KEY
ARG MIMA_EXTENSION_ID
ENV NODE_ENV=production
COPY --from=recovery-tool-build /app/apps/recovery-tool/dist/cli.js /tmp/recovery-tool/mima-recovery-tool.mjs
COPY --from=recovery-tool-build /app/apps/recovery-tool/dist/打开企业恢复向导.html /tmp/recovery-tool/打开企业恢复向导.html
COPY apps/recovery-tool/OFFLINE-USAGE.txt /tmp/recovery-tool/OFFLINE-USAGE.txt
RUN test -n "$MIMA_EXTENSION_PUBLIC_KEY" \
  && test -n "$MIMA_EXTENSION_ID" \
  && VITE_MIMA_EXTENSION_ID="$MIMA_EXTENSION_ID" pnpm --filter @mima/web build \
  && VITE_MIMA_API_BASE="$MIMA_EXTENSION_API_BASE" \
    MIMA_EXTENSION_PUBLIC_KEY="$MIMA_EXTENSION_PUBLIC_KEY" \
    pnpm --filter @mima/extension build:production \
  && node scripts/verify-strict-runtime.mjs \
    --web-dir apps/web/dist \
    --extension-dir apps/extension/dist \
    --extension-api-base "$MIMA_EXTENSION_API_BASE" \
  && node scripts/package-release-downloads.mjs \
    --prefix mima \
    --version 0.2.0 \
    --extension-dir apps/extension/dist \
    --recovery-tool-file /tmp/recovery-tool/mima-recovery-tool.mjs \
    --recovery-wizard-file /tmp/recovery-tool/打开企业恢复向导.html \
    --offline-usage-file /tmp/recovery-tool/OFFLINE-USAGE.txt \
    --output-dir apps/web/dist/downloads

FROM workspace AS api-build
ENV NODE_ENV=production
RUN pnpm --filter @mima/api build

FROM workspace AS migration-worker-build
ENV NODE_ENV=production
RUN pnpm --filter @mima/api build:migration-worker

FROM node:24-trixie-slim@sha256:366fdef91728b1b7fa18c84fba63b6e79ed77b7e10cc206878e9705da4d7b169 AS runtime-deps
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10.33.2 --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY apps/extension/package.json apps/extension/package.json
COPY apps/recovery-tool/package.json apps/recovery-tool/package.json
COPY packages/client-core/package.json packages/client-core/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/crypto/package.json packages/crypto/package.json
COPY packages/domain/package.json packages/domain/package.json
COPY packages/e2ee/package.json packages/e2ee/package.json
COPY packages/migration-worker-runtime-deps/package.json packages/migration-worker-runtime-deps/package.json
COPY packages/ui-tokens/package.json packages/ui-tokens/package.json
RUN --mount=type=cache,id=mima-pnpm-store,target=/pnpm/store,sharing=locked \
  pnpm install --store-dir /pnpm/store --network-concurrency 8 --prod --frozen-lockfile --filter @mima/api... \
  && rm -rf /app/apps/api/node_modules/@mima \
  && rm -rf /app/node_modules/.pnpm/node_modules/@mima

FROM runtime-deps AS worker-runtime-deps
RUN --mount=type=cache,id=mima-pnpm-store,target=/pnpm/store,sharing=locked \
  rm -rf /app/node_modules /app/apps/*/node_modules /app/packages/*/node_modules \
  && pnpm install --store-dir /pnpm/store --prod --offline --frozen-lockfile --filter @mima/migration-worker-runtime-deps \
  && rm -rf /app/node_modules/.pnpm/node_modules/@mima

FROM node:24-trixie-slim@sha256:366fdef91728b1b7fa18c84fba63b6e79ed77b7e10cc206878e9705da4d7b169 AS api
ARG MIMA_SOURCE_SNAPSHOT_SHA256
LABEL org.opencontainers.image.version="0.2.0" \
  mima.e2ee-protocol="lm-e2ee-v1" \
  mima.component="api" \
  mima.runtime="strict-api" \
  mima.schema-head="0027_recovery_case_terminal_transitions" \
  mima.source-snapshot-sha256="${MIMA_SOURCE_SNAPSHOT_SHA256}"
ENV NODE_ENV=production
WORKDIR /app
COPY --from=runtime-deps /app/node_modules /app/node_modules
COPY --from=runtime-deps /app/apps/api/node_modules /app/apps/api/node_modules
COPY apps/api/package.runtime.json /app/apps/api/package.json
COPY --from=api-build /app/apps/api/dist /app/apps/api/dist
COPY scripts/init-server-keys.mjs /app/scripts/init-server-keys.mjs
COPY scripts/verify-strict-runtime.mjs /tmp/verify-strict-runtime.mjs
RUN node /tmp/verify-strict-runtime.mjs --api-dir /app/apps/api/dist --runtime-root /app \
  && rm /tmp/verify-strict-runtime.mjs \
  && chown -R node:node /app
USER node
EXPOSE 4174
CMD ["node", "apps/api/dist/server.js"]

FROM node:24-trixie-slim@sha256:366fdef91728b1b7fa18c84fba63b6e79ed77b7e10cc206878e9705da4d7b169 AS recovery-tool
ARG MIMA_SOURCE_SNAPSHOT_SHA256
LABEL org.opencontainers.image.version="0.2.0" \
  mima.e2ee-protocol="lm-e2ee-v1" \
  mima.component="recovery-tool" \
  mima.runtime="offline-recovery-tool" \
  mima.source-snapshot-sha256="${MIMA_SOURCE_SNAPSHOT_SHA256}"
ENV NODE_ENV=production
WORKDIR /app
COPY --from=recovery-tool-build /app/apps/recovery-tool/dist/cli.js /app/cli.mjs
COPY scripts/verify-strict-runtime.mjs /tmp/verify-strict-runtime.mjs
RUN node /tmp/verify-strict-runtime.mjs --recovery-tool-file /app/cli.mjs \
  && rm /tmp/verify-strict-runtime.mjs \
  && chown -R node:node /app
USER node
ENTRYPOINT ["node", "/app/cli.mjs"]

FROM node:24-trixie-slim@sha256:366fdef91728b1b7fa18c84fba63b6e79ed77b7e10cc206878e9705da4d7b169 AS migration-worker
ARG MIMA_SOURCE_SNAPSHOT_SHA256
LABEL org.opencontainers.image.version="0.2.0" \
  mima.e2ee-protocol="lm-e2ee-v1" \
  mima.component="migration-worker" \
  mima.runtime="isolated-migration-worker" \
  mima.schema-head="0027_recovery_case_terminal_transitions" \
  mima.source-snapshot-sha256="${MIMA_SOURCE_SNAPSHOT_SHA256}"
ENV NODE_ENV=production
WORKDIR /app
COPY --from=worker-runtime-deps /app/node_modules /app/node_modules
COPY --from=worker-runtime-deps /app/packages/migration-worker-runtime-deps/node_modules /app/apps/api/node_modules
COPY apps/api/package.runtime.json /app/apps/api/package.json
COPY --from=migration-worker-build /app/apps/api/dist-migration-worker /app/apps/api/dist-migration-worker
COPY scripts/verify-strict-runtime.mjs /tmp/verify-strict-runtime.mjs
RUN node /tmp/verify-strict-runtime.mjs \
    --worker-dir /app/apps/api/dist-migration-worker \
    --worker-runtime-root /app \
  && rm /tmp/verify-strict-runtime.mjs \
  && chown -R node:node /app
USER node
ENTRYPOINT ["node", "apps/api/dist-migration-worker/legacy-migration-worker.js"]

FROM nginx:alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de AS gateway
ARG MIMA_SOURCE_SNAPSHOT_SHA256
LABEL org.opencontainers.image.version="0.2.0" \
  mima.e2ee-protocol="lm-e2ee-v1" \
  mima.component="gateway" \
  mima.runtime="static-web-gateway" \
  mima.source-snapshot-sha256="${MIMA_SOURCE_SNAPSHOT_SHA256}"
COPY --from=web-build /app/apps/web/dist /usr/share/nginx/html
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
