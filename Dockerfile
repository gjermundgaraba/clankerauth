FROM node:26.7.0-bookworm-slim AS build
RUN npm install -g pnpm@12.3.4
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/server/package.json ./apps/server/package.json
COPY apps/web/package.json ./apps/web/package.json
COPY packages/api/package.json ./packages/api/package.json
COPY packages/dev/package.json ./packages/dev/package.json
COPY packages/node/package.json ./packages/node/package.json
COPY patches ./patches
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build && pnpm --filter @clankerauth/server deploy --prod /out

FROM node:26.7.0-bookworm-slim
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000 AUTH_DATABASE=/data/auth.sqlite
WORKDIR /app
COPY --from=build --chown=node:node /out ./
RUN mkdir /data && chown node:node /data && chmod 700 /data
USER node
EXPOSE 3000
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/main.mjs"]
