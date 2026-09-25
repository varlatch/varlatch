# Varlatch Application Plane (Convex)

Non-authoritative by design: this deployment holds one-way Mirrors
and dashboard product state. Corrupting it breaks UI, never authorization.
Convex verifies varlatchd-issued ES256 JWTs (custom JWT provider against
varlatchd's `/.well-known/jwks.json`) and can never mint anything varlatchd
accepts back.

## Local development

```sh
# 1. Run a local self-hosted Convex backend (SQLite mode is fine for dev):
docker run -d --name convex-dev -p 3210:3210 -p 3211:3211 \
  -e INSTANCE_NAME=varlatch-dev -e INSTANCE_SECRET=$(openssl rand -hex 32) \
  -e CONVEX_CLOUD_ORIGIN=http://127.0.0.1:3210 \
  -e CONVEX_SITE_ORIGIN=http://127.0.0.1:3211 \
  -e DISABLE_BEACON=1 ghcr.io/get-convex/convex-backend:latest
docker exec convex-dev ./generate_admin_key.sh

# 2. Configure and deploy the functions:
export CONVEX_SELF_HOSTED_URL=http://127.0.0.1:3210
export CONVEX_SELF_HOSTED_ADMIN_KEY='<from step 1>'
npx convex env set VARLATCH_ISSUER  http://172.17.0.1:8686      # varlatchd as seen from the container
npx convex env set VARLATCH_JWKS_URL http://172.17.0.1:8686/.well-known/jwks.json
npx convex deploy -y

# 3. Point varlatchd at it (compose .env):
#    VARLATCH_PUBLIC_URL=http://172.17.0.1:8686    (must equal VARLATCH_ISSUER)
#    VARLATCH_CONVEX_URL=http://172.17.0.1:3210
# varlatchd then republishes mirrors every 60s; force one with:
docker compose exec varlatchd node dist/cli.js admin mirror-sync
```

The Convex admin key is Infrastructure Operator authority: it lives only in
deployment tooling, never in runtime varlatchd. Mirror writes
authenticate with varlatchd's dedicated `role: "mirror"` JWT identity.

Canonical-Compose integration of the Convex services (pinned images, own
PostgreSQL database/role, deploy step inside varlatch-migrate) lands with the
web dashboard.
