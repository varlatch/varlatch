#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Clean-room end-to-end: fresh canonical stack -> convex deploy -> passkey
# bootstrap -> seeded data -> dashboard + CLI-login E2Es. Used by CI and
# runnable locally (wrap in `newgrp docker` if your session lacks the group).
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
E2E_DIR=$(mktemp -d)
E2E_PROJECT="varlatch-e2e-$(basename "$E2E_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
cp "$REPO_ROOT/infra/compose/docker-compose.yml" "$E2E_DIR/docker-compose.yml"
cp "$REPO_ROOT/infra/compose/convex-supervisor.cjs" "$E2E_DIR/convex-supervisor.cjs"
cp -r "$REPO_ROOT/infra/compose/postgres-init" "$E2E_DIR/postgres-init"
# Resolve build contexts against the source checkout; every runtime file,
# secret, network, and volume belongs to the disposable project.
python3 - "$REPO_ROOT" "$E2E_DIR/build.json" <<'BUILD'
import json,sys
json.dump({"services": {name: {"build": {"context": sys.argv[1]}} for name in ["varlatchd", "varlatch-migrate", "varlatch-web", "convex-deploy"]}}, open(sys.argv[2], "w"))
BUILD
COMPOSE=(docker compose --project-name "$E2E_PROJECT" --env-file "$E2E_DIR/.env" -f "$E2E_DIR/docker-compose.yml" -f "$E2E_DIR/build.json")
cleanup() {
  result=$?
  if [ "$result" -ne 0 ]; then "${COMPOSE[@]}" logs --tail 50; fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$E2E_DIR"
  exit "$result"
}
trap cleanup EXIT
cd "$E2E_DIR"
# Ask the kernel for three unused loopback ports.
read -r VARLATCH_WEB_PORT VARLATCHD_PORT CONVEX_PORT < <(python3 - <<'PORTS'
import socket
sockets=[socket.socket() for _ in range(3)]
for s in sockets: s.bind(('127.0.0.1',0))
print(*(s.getsockname()[1] for s in sockets))
PORTS
)
export VARLATCH_WEB_PORT VARLATCHD_PORT CONVEX_PORT
export WEB_ORIGIN="http://localhost:${VARLATCH_WEB_PORT}"
# One public origin (ADR-0035 D5): the browser reaches Convex through the
# dashboard at /convex, exercising the same-origin proxy in every suite.
export CONVEX_CLOUD_ORIGIN="${WEB_ORIGIN}/convex"
export BIND_ADDRESS=127.0.0.1
export VARLATCH_KEK_HOST_PATH="$E2E_DIR/secrets/varlatch-kek"

cat > .env <<EOF
POSTGRES_SUPERUSER_PASSWORD=$(openssl rand -hex 24)
VARLATCH_MIGRATE_PASSWORD=$(openssl rand -hex 24)
VARLATCH_RUNTIME_PASSWORD=$(openssl rand -hex 24)
CONVEX_DB_PASSWORD=$(openssl rand -hex 24)
CONVEX_INSTANCE_SECRET=$(openssl rand -hex 32)
VARLATCH_PUBLIC_URL=${WEB_ORIGIN}
VARLATCH_JWKS_URL=http://varlatchd:8686/.well-known/jwks.json
VARLATCH_CONVEX_URL=http://convex-backend:3210
EOF
mkdir -p secrets
openssl rand -hex 32 > secrets/varlatch-kek

"${COMPOSE[@]}" up -d --build

echo "--- waiting for readiness"
for i in $(seq 1 60); do
  curl -fsS -o /dev/null "${WEB_ORIGIN}/v1/meta" && break
  sleep 3
done
curl -fsS "http://localhost:${VARLATCHD_PORT}/readyz" | grep -q '"ready":true'

echo "--- Application Plane reconciliation (ADR-0035 D3/D4; no admin key anywhere)"
# `up --build` skips profiled services, and `run` reuses a cached image — so
# rebuild explicitly or a newly added Convex function ships stale source.
"${COMPOSE[@]}" --profile deploy build convex-deploy
RECONCILE=$("${COMPOSE[@]}" --profile deploy run --rm convex-deploy </dev/null)
echo "$RECONCILE"
grep -q "deployment authority derived" <<< "$RECONCILE" || { echo "FAIL: admin key was not derived inside the job"; exit 1; }
grep -q "reconcile: deployed functions" <<< "$RECONCILE" || { echo "FAIL: first reconcile did not deploy"; exit 1; }
RECONCILE=$("${COMPOSE[@]}" --profile deploy run --rm convex-deploy </dev/null)
grep -q "nothing to change" <<< "$RECONCILE" || { echo "FAIL: reconcile of an unchanged installation changed something"; echo "$RECONCILE"; exit 1; }
echo "PASS  reconcile derives its key, deploys once, and is a no-op on an unchanged installation"

echo "--- passkey bootstrap E2E"
BOOT_URL=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin bootstrap </dev/null | grep -o 'http://[^ ]*enroll#[^ ]*')
E2E_OUT=$(node "$REPO_ROOT"/services/varlatchd/scripts/e2e-passkey.mjs "$BOOT_URL")
echo "$E2E_OUT"
echo "$E2E_OUT" | grep -q "FAIL" && exit 1
ADMIN_ID=$(echo "$E2E_OUT" | grep -o 'idn_[a-z0-9]*' | head -1)

echo "--- seed data as ${ADMIN_ID}"
TOKEN=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin recover --identity "$ADMIN_ID" --cli-credential </dev/null | tail -1)
H="Authorization: Bearer $TOKEN"
curl -fsS -X POST "${WEB_ORIGIN}/v1/organizations" -H "$H" -H 'Content-Type: application/json' -d '{"name":"Acme","slug":"acme"}' >/dev/null
curl -fsS -X POST "${WEB_ORIGIN}/v1/organizations/acme/projects" -H "$H" -H 'Content-Type: application/json' -d '{"name":"API","slug":"api","contractAuthority":"git"}' >/dev/null
curl -fsS -X POST "${WEB_ORIGIN}/v1/organizations/acme/projects/api/environments" -H "$H" -H 'Content-Type: application/json' -d '{"name":"development","tier":"development"}' >/dev/null
curl -fsS -X POST "${WEB_ORIGIN}/v1/organizations/acme/projects/api/environments" -H "$H" -H 'Content-Type: application/json' -d '{"name":"production","tier":"production"}' >/dev/null
REV=$(curl -fsS -X POST "${WEB_ORIGIN}/v1/organizations/acme/projects/api/contract/revisions" -H "$H" -H 'Content-Type: application/json' -d '{"contract":{"schemaVersion":1,"items":[{"name":"DATABASE_URL","required":{"kind":"always"},"sensitive":true,"type":"url"},{"name":"PORT","required":{"kind":"always"},"sensitive":false,"type":"number","defaultValue":"3000"},{"name":"API_KEY","required":{"kind":"selector","selector":{"kind":"tier","tier":"production"}},"sensitive":true,"type":"string"},{"name":"PUBLIC_URL","required":{"kind":"never"},"sensitive":false,"type":"string"}]}}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -fsS -X POST "${WEB_ORIGIN}/v1/organizations/acme/projects/api/contract/revisions/${REV}/activate" -H "$H" -H 'Content-Type: application/json' -d '{}' >/dev/null
curl -fsS -X PUT "${WEB_ORIGIN}/v1/organizations/acme/projects/api/environments/development/values/DATABASE_URL" -H "$H" -H 'Content-Type: application/json' -d '{"value":"postgres://dev-db"}' >/dev/null
curl -fsS -X PUT "${WEB_ORIGIN}/v1/organizations/acme/projects/api/environments/development/values/PORT" -H "$H" -H 'Content-Type: application/json' -d '{"value":"3000"}' >/dev/null
"${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin mirror-sync </dev/null

echo "--- dashboard E2E (production container)"
GRANT1=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin recover --identity "$ADMIN_ID" </dev/null | grep -o 'http://[^ ]*enroll#[^ ]*')
node "$REPO_ROOT"/apps/web/scripts/e2e-web.mjs "$GRANT1"

echo "--- values/matrix E2E (production container)"
GRANT_V=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin recover --identity "$ADMIN_ID" </dev/null | grep -o 'http://[^ ]*enroll#[^ ]*')
node "$REPO_ROOT"/apps/web/scripts/e2e-values.mjs "$GRANT_V" "$TOKEN"

echo "--- access E2E (production container)"
GRANT_A=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin recover --identity "$ADMIN_ID" </dev/null | grep -o 'http://[^ ]*enroll#[^ ]*')
node "$REPO_ROOT"/apps/web/scripts/e2e-access.mjs "$GRANT_A"

echo "--- P4 audit/contract/palette E2E (production container)"
GRANT_P=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin recover --identity "$ADMIN_ID" </dev/null | grep -o 'http://[^ ]*enroll#[^ ]*')
# A disposable same-identity credential the suite revokes live to assert the
# me-scoped identitySignal refreshes /credentials without a reload.
TOKEN_DISPOSABLE=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin recover --identity "$ADMIN_ID" --cli-credential </dev/null | tail -1)
node "$REPO_ROOT"/apps/web/scripts/e2e-p4.mjs "$GRANT_P" "$TOKEN" "$TOKEN_DISPOSABLE"

echo "--- onboarding E2E (production container)"
GRANT_O=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin recover --identity "$ADMIN_ID" </dev/null | grep -o 'http://[^ ]*enroll#[^ ]*')
node "$REPO_ROOT"/apps/web/scripts/e2e-onboarding.mjs "$GRANT_O" "$TOKEN"

echo "--- degraded realtime: Convex down (ADR-0035 D10), incl. the credential broker E2E (ADR-0022)"
GRANT_R=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin recover --identity "$ADMIN_ID" </dev/null | grep -o 'http://[^ ]*enroll#[^ ]*')
node "$REPO_ROOT"/apps/web/scripts/e2e-realtime.mjs "$GRANT_R" "$TOKEN" -- "${COMPOSE[@]}"

echo "--- isolating maintenance: dashboard and CLI ride it out (ADR-0036 D6)"
GRANT_M=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin recover --identity "$ADMIN_ID" </dev/null | grep -o 'http://[^ ]*enroll#[^ ]*')
node "$REPO_ROOT"/apps/web/scripts/e2e-maintenance.mjs "$GRANT_M" "$TOKEN" -- "${COMPOSE[@]}"
# No secret plaintext may reach application logs (design doc Phase 3 §1.18).
if "${COMPOSE[@]}" logs varlatchd 2>/dev/null | grep -q "postgres://dev-db"; then
  echo "FAIL: secret plaintext found in varlatchd logs"; exit 1
fi

echo "--- CLI browser-handoff login E2E"
GRANT2=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin recover --identity "$ADMIN_ID" </dev/null | grep -o 'http://[^ ]*enroll#[^ ]*')
node "$REPO_ROOT"/services/varlatchd/scripts/e2e-cli-login.mjs "$GRANT2"

echo "--- device sign-in E2E (login --start/--wait, dashboard /device approval with a passkey)"
GRANT_D=$("${COMPOSE[@]}" exec -T varlatchd node dist/cli.js admin recover --identity "$ADMIN_ID" </dev/null | grep -o 'http://[^ ]*enroll#[^ ]*')
node "$REPO_ROOT"/apps/web/scripts/e2e-device.mjs "$GRANT_D"

echo "--- client runtime E2E (run --redact, run --export-context, types, scan; bundled CLI)"
node "$REPO_ROOT"/services/varlatchd/scripts/e2e-client-runtime.mjs "$WEB_ORIGIN" "$TOKEN" -- "${COMPOSE[@]}"

echo "--- strict startup E2E (varlatch run --strict, bundled CLI)"
node "$REPO_ROOT"/services/varlatchd/scripts/e2e-strict-run.mjs "$WEB_ORIGIN" "$TOKEN"

echo "--- read-only doctor (ADR-0035 D8)"
# The host CLI resolves the project the way plain `docker compose` does in
# --dir; point it at this disposable project through Compose's own env vars.
AUDIT_BEFORE=$("${COMPOSE[@]}" exec -T postgres psql -U postgres -d varlatch -Atc 'SELECT count(*) FROM audit_events' </dev/null)
set +e
DOCTOR_JSON=$(COMPOSE_PROJECT_NAME="$E2E_PROJECT" COMPOSE_FILE="$E2E_DIR/docker-compose.yml:$E2E_DIR/build.json" \
  COMPOSE_ENV_FILES="$E2E_DIR/.env" node "$REPO_ROOT"/apps/cli/dist/varlatch.cjs doctor --dir "$E2E_DIR" --json --wait 30)
DOCTOR_EXIT=$?
set -e
AUDIT_AFTER=$("${COMPOSE[@]}" exec -T postgres psql -U postgres -d varlatch -Atc 'SELECT count(*) FROM audit_events' </dev/null)
printf '%s' "$DOCTOR_JSON" > "$E2E_DIR/doctor.json"
python3 - "$DOCTOR_EXIT" "$AUDIT_BEFORE" "$AUDIT_AFTER" "$E2E_DIR/doctor.json" <<'PY'
import json, sys
exit_code, before, after, path = sys.argv[1:5]
checks = {c["id"]: c for c in json.load(open(path))["checks"]}
failed = False
def check(name, ok, detail=""):
    global failed
    print(("PASS  " if ok else "FAIL  ") + name + (f" — {detail}" if detail else ""))
    failed |= not ok
check("doctor exits 0 (no mandatory failure)", exit_code == "0", f"exit {exit_code}")
for cid in ["services.running", "secret-plane.ready", "config.public-url", "mirror.catch-up", "application-plane.functions", "release.pending-upgrade"]:
    c = checks.get(cid, {})
    check(f"doctor: {cid} passes", c.get("status") == "pass", c.get("detail", "missing"))
check("doctor: browser reachability is reported unknown", checks.get("realtime.browser", {}).get("status") == "unknown")
check("doctor wrote no audit events", before == after, f"{before} -> {after}")
sys.exit(1 if failed else 0)
PY

echo "--- dashboard keeps serving while Convex is down (ADR-0035 D5/D10)"
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
"${COMPOSE[@]}" stop convex-backend >/dev/null 2>&1
DOWN_WEB=$(code "$WEB_ORIGIN/"); DOWN_API=$(code -H "$H" "$WEB_ORIGIN/v1/organizations")
CVX_START=$(date +%s); DOWN_CVX=$(code "$WEB_ORIGIN/convex/version"); CVX_SECONDS=$(( $(date +%s) - CVX_START ))
"${COMPOSE[@]}" restart varlatch-web >/dev/null 2>&1
for i in $(seq 1 30); do [ "$(code "$WEB_ORIGIN/")" = 200 ] && break; sleep 1; done
RESTARTED_WEB=$(code "$WEB_ORIGIN/")
"${COMPOSE[@]}" start convex-backend >/dev/null 2>&1
for i in $(seq 1 60); do [ "$(code "$WEB_ORIGIN/convex/version")" = 200 ] && break; sleep 2; done
UP_CVX=$(code "$WEB_ORIGIN/convex/version")
echo "web=$DOWN_WEB api=$DOWN_API convex=$DOWN_CVX (${CVX_SECONDS}s) web-after-restart=$RESTARTED_WEB convex-after-start=$UP_CVX"
# /convex answers a gateway error: 502 once Docker DNS has dropped the
# stopped backend, 504 while nginx still holds its cached address.
[ "$DOWN_WEB" = 200 ] && [ "$DOWN_API" = 200 ] && { [ "$DOWN_CVX" = 502 ] || [ "$DOWN_CVX" = 504 ]; } && [ "$RESTARTED_WEB" = 200 ] && [ "$UP_CVX" = 200 ] \
  || { echo "FAIL: dashboard/API must not depend on convex-backend being up"; exit 1; }
[ "$CVX_SECONDS" -le 10 ] || { echo "FAIL: /convex must fail fast while the backend is down (${CVX_SECONDS}s)"; exit 1; }
echo "PASS  dashboard and /v1 serve while Convex is down; /convex recovers when it returns"

echo "ALL E2E SUITES PASSED"
