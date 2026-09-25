# One-shot Application Plane reconciliation (ADR-0019 §6, ADR-0035 D3/D4):
# the only place Convex deployment authority is used. It compares what the
# backend serves and trusts with this release and deploys or repairs only
# what differs (convex/scripts/reconcile.mjs).
#
# The key tool comes from the same pinned backend image the stack runs — keep
# this digest identical to convex-backend in docker-compose.yml
# (scripts/test-backup-compose.mjs checks it). The digest is a multi-platform
# index, so each architecture's image gets that architecture's binary.
FROM ghcr.io/get-convex/convex-backend@sha256:1f2044e3eac463ac78973b136c0baf72d4ada602611d853d6f99f280e29e0a98 AS convex-backend

FROM node:26-slim
WORKDIR /app
COPY --from=convex-backend --chmod=755 /convex/generate_key /usr/local/bin/convex-generate-key
# The committed lock pins the deploy tooling exactly; THIRD-PARTY-NOTICES.md
# lists this image's packages from it. Runtime dependencies only: CI has
# typechecked the functions, and without TypeScript installed `convex deploy`
# skips its own typecheck.
COPY convex/package.json convex/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
# Only sources — never the host's node_modules (pnpm symlinks would clobber).
COPY convex/convex ./convex
COPY convex/scripts ./scripts
COPY LICENSE THIRD-PARTY-NOTICES.md /usr/share/doc/varlatch/
COPY LICENSES /usr/share/doc/varlatch/LICENSES
# Stamp the bundle with this release's fingerprint; `meta:release` reports it.
RUN node scripts/fingerprint.mjs --root . --stamp && chown -R node:node /app
USER node
CMD ["node", "scripts/reconcile.mjs"]
