# varlatch-web: the dashboard served same-origin with varlatchd's auth/API
# surface (nginx static + reverse proxy), so session cookies stay first-party.
# Static output: the build stage runs on the build machine's platform, and
# only the nginx stage is per-architecture (ADR-0037 D5).
FROM --platform=$BUILDPLATFORM node:26-slim AS build
RUN npm install -g pnpm@12.3.4
WORKDIR /repo
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml .npmrc .pnpmfile.cjs tsconfig.base.json ./
COPY packages/protocol/package.json packages/protocol/
COPY packages/sdk/package.json packages/sdk/
COPY convex/package.json convex/
COPY apps/web/package.json apps/web/
RUN pnpm install --frozen-lockfile --filter @varlatch/web...
COPY packages/protocol packages/protocol
COPY packages/sdk packages/sdk
COPY apps/web apps/web
# Nothing installation-specific is baked: the browser-facing Convex origin is
# runtime config (CONVEX_URL -> varlatch-config.js via the entrypoint below),
# so one release image serves every installation.
RUN pnpm --filter @varlatch/protocol generate \
 && pnpm --filter @varlatch/protocol build \
 && pnpm --filter @varlatch/sdk build \
 && pnpm --filter @varlatch/web build

FROM nginx:1.29-alpine
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY apps/web/docker-entrypoint.d/10-varlatch-config.sh /docker-entrypoint.d/
RUN chmod +x /docker-entrypoint.d/10-varlatch-config.sh
COPY --from=build /repo/apps/web/dist /usr/share/nginx/html
COPY LICENSE THIRD-PARTY-NOTICES.md /usr/share/doc/varlatch/
COPY LICENSES /usr/share/doc/varlatch/LICENSES
EXPOSE 80
