FROM node:26.12.1-trixie-slim@sha256:36793bcbb160a6a16cede1e62b93f84e26b78a972a8a4c0b879c1c12f22761ec AS build
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches ./patches
RUN npm install --global "pnpm@$(node -p "require('./package.json').devEngines.packageManager.version")" \
    && pnpm config set store-dir /pnpm/store
COPY apps/server/package.json ./apps/server/package.json
COPY apps/web/package.json ./apps/web/package.json
COPY packages/admin-api/package.json ./packages/admin-api/package.json
COPY packages/dev/package.json ./packages/dev/package.json
COPY packages/sdk/package.json ./packages/sdk/package.json
RUN --mount=type=cache,target=/pnpm/store VP_GIT_HOOKS=0 pnpm install --frozen-lockfile
COPY . .
RUN pnpm build
RUN --mount=type=cache,target=/pnpm/store pnpm --filter @clankerauth/server deploy --prod /out

FROM node:26.12.1-trixie-slim@sha256:36793bcbb160a6a16cede1e62b93f84e26b78a972a8a4c0b879c1c12f22761ec
ENV NODE_ENV=production CLANKERAUTH_HOST=0.0.0.0 CLANKERAUTH_PORT=3000 CLANKERAUTH_DATABASE=/data/clankerauth.sqlite
WORKDIR /app
COPY --from=build --chown=node:node /out ./
# Build hosts may copy restrictive modes; any runtime user must be able to read the app.
RUN chmod -R a+rX /app
RUN mkdir /data && chown node:node /data && chmod 700 /data
USER node
EXPOSE 3000
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD node -e "fetch('http://127.0.0.1:'+process.env.CLANKERAUTH_PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/main.mjs"]
