# docs.varlatch.com: the documentation site, static files served by Caddy.
# The pages come from docs/ and the other files listed in
# apps/docs/src/sources.mjs, and links to any file in the repository are
# checked, so the build context is the repository root:
#   docker build -f apps/docs/Dockerfile .
# apps/docs is its own pnpm workspace, with its own lockfile. Only the Caddy
# stage is per-architecture (as in apps/web/Dockerfile).
FROM --platform=$BUILDPLATFORM node:26-slim AS build
RUN npm install -g pnpm@12.3.4
WORKDIR /repo/apps/docs
COPY apps/docs/package.json apps/docs/pnpm-lock.yaml apps/docs/pnpm-workspace.yaml apps/docs/.npmrc ./
RUN pnpm install --frozen-lockfile
WORKDIR /repo
COPY . .
RUN cd apps/docs && pnpm build

FROM caddy:2.10.2
COPY apps/docs/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /repo/apps/docs/dist /srv
EXPOSE 80
