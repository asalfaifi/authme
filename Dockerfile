# syntax=docker/dockerfile:1.7

ARG NODE_VERSION=22-bookworm-slim

FROM node:${NODE_VERSION} AS production-dependencies
WORKDIR /opt/authme

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && npm cache clean --force

FROM node:${NODE_VERSION} AS runtime

# Package managers are build-time tooling. Removing them from the runtime image
# reduces both image size and the vulnerability surface exposed in production.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-v1.22.22 \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/pnpm /usr/local/bin/pnpx /usr/local/bin/yarn /usr/local/bin/yarnpkg

ENV NODE_ENV=production \
    AUTHME_PORT=3000 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /opt/authme

COPY --from=production-dependencies --chown=node:node /opt/authme/node_modules ./node_modules
COPY --chown=node:node package.json package-lock.json ./
COPY --chown=node:node src ./src
COPY --chown=node:node migrations ./migrations
COPY --chown=node:node scripts ./scripts

USER node

EXPOSE 3000
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.AUTHME_PORT || '3000') + '/health/ready').then((response) => { if (!response.ok) process.exitCode = 1; }).catch(() => { process.exitCode = 1; })"]

CMD ["node", "src/index.js"]
