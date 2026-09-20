FROM node:26.8.2-bookworm-slim AS build
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN npm install -g "$(node -p "require('./package.json').packageManager")"
COPY apps/server/package.json ./apps/server/package.json
COPY apps/web/package.json ./apps/web/package.json
COPY packages/admin-api/package.json ./packages/admin-api/package.json
COPY packages/dev/package.json ./packages/dev/package.json
COPY packages/sdk/package.json ./packages/sdk/package.json
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build && pnpm --filter @clankerauth/server deploy --prod /out

FROM node:26.8.2-bookworm-slim
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000 AUTH_DATABASE=/data/auth.sqlite
WORKDIR /app
COPY --from=build --chown=node:node /out ./
# Build hosts may copy restrictive modes; any runtime user must be able to read the app.
RUN chmod -R a+rX /app
RUN mkdir /data && chown node:node /data && chmod 700 /data
USER node
EXPOSE 3000
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/main.mjs"]
