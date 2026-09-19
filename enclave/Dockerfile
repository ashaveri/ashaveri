# syntax=docker/dockerfile:1

# Build the whole workspace, then let pnpm extract a self-contained production copy of
# the gateway. dist/ is gitignored, so the image has to compile from source itself.
FROM node:24-bookworm-slim AS build
RUN corepack enable
WORKDIR /repo
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml tsconfig.base.json ./
COPY packages ./packages
COPY gateway ./gateway
RUN pnpm install --frozen-lockfile
RUN pnpm build
RUN pnpm deploy --filter @ashaveri/signerd --prod /app
COPY enclave/weights.mjs enclave/docker-entrypoint.sh /app/
RUN chmod 755 /app/docker-entrypoint.sh

FROM node:24-bookworm-slim AS runtime
WORKDIR /app
COPY --from=build /app /app
# A named volume mounted at an existing path inherits its ownership, so the log directory has to
# exist and belong to the runtime user before the volume lands on it. Without this the gateway boots
# and serves: opening the log only makes a directory that is already there, and a rejected append is
# caught so it cannot fail a request that admission already decided. What is lost is the access log
# itself, one warning line per request and nothing else, which is the quietest way to break this
# deployment's only retention obligation.
RUN mkdir -p /var/lib/ashaveri/access-log && chown -R node:node /var/lib/ashaveri
USER node
EXPOSE 8081
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["--help"]
