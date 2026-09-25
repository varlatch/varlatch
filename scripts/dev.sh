#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The contributor setup (ADR-0037 D7): one command builds the canonical
# Compose stack from this checkout and fills it with synthetic data.
#
#   scripts/dev.sh up      build and start; seed on first start; print sign-in
#   scripts/dev.sh link    print a new one-time link to add a passkey
#   scripts/dev.sh down    stop, keeping the data
#   scripts/dev.sh reset   stop and delete everything, data included
#
# State lives in .dev/ (git-ignored; VARLATCH_DEV_DIR overrides): generated
# database passwords, a development Root KEK, and the seeded admin's CLI
# credential. None of it protects real data. Ports are fixed when .dev/ is
# created: VARLATCH_WEB_PORT (8787), VARLATCHD_PORT (8686), and CONVEX_PORT
# (3210), all on 127.0.0.1.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEV_DIR=${VARLATCH_DEV_DIR:-$REPO_ROOT/.dev}
PROJECT=${VARLATCH_DEV_PROJECT:-varlatch-dev}
COMPOSE=(docker compose --project-name "$PROJECT" --project-directory "$DEV_DIR"
  --env-file "$DEV_DIR/.env" -f "$DEV_DIR/docker-compose.yml" -f "$DEV_DIR/build.json")

# The deployment files come from the checkout on every start, so the stack
# follows the branch; the generated state is created once.
prepare() {
  mkdir -p "$DEV_DIR/secrets"
  cp "$REPO_ROOT/infra/compose/docker-compose.yml" "$REPO_ROOT/infra/compose/convex-supervisor.cjs" "$DEV_DIR/"
  rm -rf "$DEV_DIR/postgres-init"
  cp -r "$REPO_ROOT/infra/compose/postgres-init" "$DEV_DIR/postgres-init"
  printf '{"services":{%s}}\n' "$(for s in varlatchd varlatch-migrate varlatch-web convex-deploy; do
    printf '"%s":{"build":{"context":"%s"}},' "$s" "$REPO_ROOT"; done | sed 's/,$//')" > "$DEV_DIR/build.json"
  if [ ! -f "$DEV_DIR/.env" ]; then
    local web=${VARLATCH_WEB_PORT:-8787}
    # The KEK is bind-mounted for varlatchd's unprivileged user, so the file
    # is world-readable; its 0700 directory keeps other host users out.
    chmod 700 "$DEV_DIR/secrets"
    openssl rand -hex 32 > "$DEV_DIR/secrets/varlatch-kek"
    chmod 644 "$DEV_DIR/secrets/varlatch-kek"
    (
      umask 077
      cat > "$DEV_DIR/.env" <<EOF
POSTGRES_SUPERUSER_PASSWORD=$(openssl rand -hex 24)
VARLATCH_MIGRATE_PASSWORD=$(openssl rand -hex 24)
VARLATCH_RUNTIME_PASSWORD=$(openssl rand -hex 24)
CONVEX_DB_PASSWORD=$(openssl rand -hex 24)
CONVEX_INSTANCE_SECRET=$(openssl rand -hex 32)
BIND_ADDRESS=127.0.0.1
VARLATCH_WEB_PORT=$web
VARLATCHD_PORT=${VARLATCHD_PORT:-8686}
CONVEX_PORT=${CONVEX_PORT:-3210}
VARLATCH_PUBLIC_URL=http://localhost:$web
CONVEX_CLOUD_ORIGIN=http://localhost:$web/convex
VARLATCH_JWKS_URL=http://varlatchd:8686/.well-known/jwks.json
VARLATCH_CONVEX_URL=http://convex-backend:3210
EOF
    )
  fi
}

setting() { sed -n "s/^$1=//p" "$DEV_DIR/.env"; }
admin() { "${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin "$@" </dev/null; }

api() {
  local method=$1 path=$2 body=${3:-}
  curl -fsS -X "$method" "$(setting VARLATCH_PUBLIC_URL)/v1$path" \
    -H "Authorization: Bearer $(cat "$DEV_DIR/admin-token")" \
    -H 'Content-Type: application/json' ${body:+-d "$body"}
}

# Synthetic data only: every value is a placeholder, safe to show and share.
seed() {
  if [ -f "$DEV_DIR/admin-token" ]; then
    echo "Seeding was interrupted earlier; start over with: scripts/dev.sh reset" >&2
    exit 1
  fi
  echo "--- seeding synthetic data"
  local out
  out=$(admin bootstrap --cli-credential --name "Dev Admin")
  (umask 077; tail -1 <<< "$out" > "$DEV_DIR/admin-token")
  grep -o 'idn_[a-z0-9]*' <<< "$out" | head -1 > "$DEV_DIR/admin-identity"

  api POST /organizations '{"name":"Acme Example","slug":"acme"}' >/dev/null
  api POST /organizations/acme/projects '{"name":"API","slug":"api","contractAuthority":"git"}' >/dev/null
  for tier in development staging production; do
    api POST /organizations/acme/projects/api/environments "{\"name\":\"$tier\",\"tier\":\"$tier\"}" >/dev/null
  done
  local revision
  revision=$(api POST /organizations/acme/projects/api/contract/revisions '{"contract":{"schemaVersion":1,"items":[
    {"name":"DATABASE_URL","required":{"kind":"always"},"sensitive":true,"type":"url"},
    {"name":"PORT","required":{"kind":"always"},"sensitive":false,"type":"number","defaultValue":"3000"},
    {"name":"API_KEY","required":{"kind":"selector","selector":{"kind":"tier","tier":"production"}},"sensitive":true,"type":"string"},
    {"name":"PUBLIC_URL","required":{"kind":"never"},"sensitive":false,"type":"string"}]}}' |
    node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).id))')
  api POST "/organizations/acme/projects/api/contract/revisions/$revision/activate" '{}' >/dev/null
  value() { api PUT "/organizations/acme/projects/api/environments/$1/values/$2" "{\"value\":\"$3\"}" >/dev/null; }
  value development DATABASE_URL "postgres://localhost:5432/api_development"
  value development PORT 3000
  value staging DATABASE_URL "postgres://db.staging.example.invalid:5432/api"
  value staging PORT 8080
  value staging PUBLIC_URL "https://staging.example.com"
  value production DATABASE_URL "postgres://db.example.invalid:5432/api"
  value production PORT 8080
  value production API_KEY "example-placeholder-not-a-secret"
  value production PUBLIC_URL "https://example.com"

  api POST /organizations/acme/projects '{"name":"Web","slug":"web","contractAuthority":"git"}' >/dev/null
  for tier in development production; do
    api POST /organizations/acme/projects/web/environments "{\"name\":\"$tier\",\"tier\":\"$tier\"}" >/dev/null
  done
  revision=$(api POST /organizations/acme/projects/web/contract/revisions '{"contract":{"schemaVersion":1,"items":[
    {"name":"API_BASE_URL","required":{"kind":"always"},"sensitive":false,"type":"url"}]}}' |
    node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).id))')
  api POST "/organizations/acme/projects/web/contract/revisions/$revision/activate" '{}' >/dev/null
  api PUT /organizations/acme/projects/web/environments/development/values/API_BASE_URL '{"value":"http://localhost:3000"}' >/dev/null
  api PUT /organizations/acme/projects/web/environments/production/values/API_BASE_URL '{"value":"https://api.example.com"}' >/dev/null
  admin mirror-sync >/dev/null
  touch "$DEV_DIR/seeded"
}

link() {
  admin recover --identity "$(cat "$DEV_DIR/admin-identity")" | grep -o 'http://[^ ]*enroll#[^ ]*'
}

up() {
  prepare
  "${COMPOSE[@]}" up -d --build
  local url
  url=$(setting VARLATCH_PUBLIC_URL)
  echo "--- waiting for $url"
  for _ in $(seq 1 60); do
    curl -fsS -o /dev/null "$url/v1/meta" 2>/dev/null && break
    sleep 3
  done
  curl -fsS -o /dev/null "$url/v1/meta"
  echo "--- deploying the Application Plane functions"
  "${COMPOSE[@]}" --profile deploy build convex-deploy
  "${COMPOSE[@]}" --profile deploy run --rm convex-deploy </dev/null
  [ -f "$DEV_DIR/seeded" ] || seed
  cat <<EOF

Varlatch is running at $url with synthetic data: organization "acme",
projects "api" (development, staging, production) and "web".

Sign in: open this one-time link and add a passkey for "Dev Admin"
(\`scripts/dev.sh link\` prints a new one):
  $(link)

CLI (after \`pnpm build\`), without touching your own CLI sessions:
  export VARLATCH_SERVER=$url VARLATCH_TOKEN=\$(cat "$DEV_DIR/admin-token")
  node apps/cli/dist/varlatch.cjs org list
EOF
}

case "${1:-}" in
  up) up ;;
  link) link ;;
  down) [ -f "$DEV_DIR/.env" ] && "${COMPOSE[@]}" down ;;
  reset)
    if [ -f "$DEV_DIR/.env" ]; then "${COMPOSE[@]}" --profile deploy down -v --remove-orphans; fi
    rm -rf "$DEV_DIR"
    ;;
  *)
    echo "Usage: scripts/dev.sh up|link|down|reset" >&2
    exit 2
    ;;
esac
