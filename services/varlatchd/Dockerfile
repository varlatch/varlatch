# varlatchd — the Varlatch Secret Plane daemon (ADR-0009/0019).
# One image, two entrypoints: `serve` (runtime role) and `migrate` (elevated
# role). Compose decides which credentials each container receives.
#
# Built for linux/amd64 and linux/arm64 (ADR-0037 D5). The build stages run on
# the build machine's own platform: their output is JavaScript, and the
# production tree has no native modules (the build stage fails if one
# appears, since it would be compiled for the wrong architecture). Only the
# final stage runs as the target platform.

FROM --platform=$BUILDPLATFORM node:26-slim AS build
WORKDIR /app
# corepack no longer ships with Node images; install the pinned pnpm directly.
RUN npm install -g pnpm@12.3.4
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml .npmrc .pnpmfile.cjs tsconfig.base.json ./
COPY packages/contract/package.json packages/contract/
COPY packages/protocol/package.json packages/protocol/
COPY packages/backup/package.json packages/backup/
COPY packages/sync/package.json packages/sync/
COPY services/varlatchd/package.json services/varlatchd/
RUN pnpm install --frozen-lockfile --filter @varlatch/varlatchd...
COPY packages/contract packages/contract
COPY packages/protocol packages/protocol
COPY packages/backup packages/backup
COPY packages/sync packages/sync
COPY services/varlatchd services/varlatchd
RUN pnpm --filter @varlatch/contract build \
 && pnpm --filter @varlatch/protocol generate \
 && pnpm --filter @varlatch/protocol build \
 && pnpm --filter @varlatch/sync build \
 && pnpm --filter @varlatch/backup build \
 && pnpm --filter @varlatch/varlatchd build \
 && pnpm --filter @varlatch/varlatchd --prod deploy /out \
 && if find /out/node_modules -name '*.node' | grep .; then \
      echo "native module in the production tree: cross-built images would carry the wrong architecture" >&2; exit 1; \
    fi

# The operator CLI bundle (ADR-0033 host backups). Shipped in this image so the
# host backup job can take the CLI from the running release instead of a
# hand-maintained host copy; the daemon never executes it.
FROM --platform=$BUILDPLATFORM node:26-slim AS cli
WORKDIR /app
RUN npm install -g pnpm@12.3.4
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml .npmrc .pnpmfile.cjs tsconfig.base.json ./
COPY packages/contract/package.json packages/contract/
COPY packages/protocol/package.json packages/protocol/
COPY packages/backup/package.json packages/backup/
COPY packages/sync/package.json packages/sync/
COPY packages/context/package.json packages/context/
COPY packages/sdk/package.json packages/sdk/
COPY packages/env-schema/package.json packages/env-schema/
COPY packages/matcher/package.json packages/matcher/
COPY apps/cli/package.json apps/cli/
RUN pnpm install --frozen-lockfile --filter @varlatch/cli...
COPY packages/contract packages/contract
COPY packages/protocol packages/protocol
COPY packages/backup packages/backup
COPY packages/sync packages/sync
COPY packages/context packages/context
COPY packages/sdk packages/sdk
COPY packages/env-schema packages/env-schema
COPY packages/matcher packages/matcher
COPY apps/cli apps/cli
RUN pnpm --filter @varlatch/protocol generate \
 && pnpm --filter "@varlatch/cli..." build \
 && node apps/cli/dist/varlatch.cjs --version

# The Application Plane function fingerprint this release deploys (ADR-0035
# D4); `admin doctor` compares it with what Convex actually serves.
FROM --platform=$BUILDPLATFORM node:26-slim AS convex-fingerprint
WORKDIR /src
COPY convex/package.json convex/package.json
COPY convex/convex convex/convex
COPY convex/scripts/fingerprint.mjs convex/scripts/fingerprint.mjs
RUN node convex/scripts/fingerprint.mjs --root convex > /convex-functions.fingerprint

FROM node:26-slim
RUN groupadd -r varlatch && useradd -r -g varlatch varlatch
WORKDIR /app
COPY --from=build /out /app
# root:root 0644 in 0755 directories: readable for extraction, not writable
# by the daemon user. (--chmod would also apply to a directory COPY creates.)
# The host backup job runs these scripts and CLI from the running release.
RUN install -d -m 755 /opt/varlatch /opt/varlatch/host-backup /usr/share/doc/varlatch /usr/share/doc/varlatch/LICENSES
COPY --from=cli --chmod=644 /app/apps/cli/dist/varlatch.cjs /opt/varlatch/varlatch.cjs
COPY --chmod=644 infra/host-backup/run.sh infra/host-backup/verify-remote.sh /opt/varlatch/host-backup/
COPY --from=convex-fingerprint --chmod=644 /convex-functions.fingerprint /opt/varlatch/convex-functions.fingerprint
COPY --chmod=644 LICENSE THIRD-PARTY-NOTICES.md /usr/share/doc/varlatch/
COPY --chmod=644 LICENSES/AGPL-3.0-or-later.txt LICENSES/Apache-2.0.txt /usr/share/doc/varlatch/LICENSES/
RUN mkdir -p /var/lib/varlatch && chown varlatch:varlatch /var/lib/varlatch
USER varlatch
ENV NODE_ENV=production
EXPOSE 8686
ENTRYPOINT ["node", "dist/cli.js"]
CMD ["serve"]
