#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The contributor setup must keep working (ADR-0037 D7): `scripts/dev.sh up`
# on a clean machine yields a running instance with the synthetic data, a
# sign-in link that enrolls a passkey in the dashboard, and a working CLI
# credential; a second `up` changes nothing; `down` keeps the data; `reset`
# removes everything. Runs in a scratch directory and project on free ports,
# so a contributor's own .dev/ is never touched.
# Needs `pnpm build` (the CLI) and Playwright's Chromium (the sign-in check).
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRATCH=$(mktemp -d)
export VARLATCH_DEV_DIR="$SCRATCH/dev"
VARLATCH_DEV_PROJECT="varlatch-devtest-$(basename "$SCRATCH" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
export VARLATCH_DEV_PROJECT
read -r VARLATCH_WEB_PORT VARLATCHD_PORT CONVEX_PORT < <(python3 - <<'PORTS'
import socket
sockets=[socket.socket() for _ in range(3)]
for s in sockets: s.bind(('127.0.0.1',0))
print(*(s.getsockname()[1] for s in sockets))
PORTS
)
export VARLATCH_WEB_PORT VARLATCHD_PORT CONVEX_PORT
DEV="$REPO_ROOT/scripts/dev.sh"
URL="http://localhost:$VARLATCH_WEB_PORT"
cleanup() {
  result=$?
  "$DEV" reset >/dev/null 2>&1 || true
  rm -rf "$SCRATCH"
  exit "$result"
}
trap cleanup EXIT

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1" >&2; exit 1; }
api() { curl -fsS "$URL/v1$1" -H "Authorization: Bearer $(cat "$VARLATCH_DEV_DIR/admin-token")"; }
count() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const d=JSON.parse(s);const a=Array.isArray(d)?d:Object.values(d).find(Array.isArray);console.log(a.length)})'; }

echo "--- first start"
FIRST=$("$DEV" up 2>&1) || { echo "$FIRST"; fail "scripts/dev.sh up"; }
grep -q -- "--- seeding synthetic data" <<< "$FIRST" || fail "first start seeds"
LINK=$(grep -o 'http://[^ ]*enroll#[^ ]*' <<< "$FIRST" | head -1)
[ -n "$LINK" ] || fail "first start prints a sign-in link"
test "$(stat -c %a "$VARLATCH_DEV_DIR/admin-token")" = 600 || fail "the CLI credential is private to its owner"
pass "up builds, starts, deploys, seeds, and prints a sign-in link"

test "$(api /organizations | count)" = 1 || fail "one organization"
test "$(api /organizations/acme/projects | count)" = 2 || fail "two projects"
test "$(api /organizations/acme/projects/api/environments | count)" = 3 || fail "three environments"
for env in development staging production; do
  VALID=$(curl -fsS -X POST "$URL/v1/organizations/acme/projects/api/environments/$env/validate" \
    -H "Authorization: Bearer $(cat "$VARLATCH_DEV_DIR/admin-token")" -H 'Content-Type: application/json' -d '{}' |
    node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).valid))')
  test "$VALID" = true || fail "$env satisfies the contract"
done
pass "synthetic data: organization, two projects, environments satisfying their contracts"

ORGS=$(VARLATCH_SERVER=$URL VARLATCH_TOKEN=$(cat "$VARLATCH_DEV_DIR/admin-token") node "$REPO_ROOT/apps/cli/dist/varlatch.cjs" org list)
grep -q acme <<< "$ORGS" || fail "the CLI reaches the instance with the printed credential"
pass "the printed CLI credential works"

node "$REPO_ROOT/apps/web/scripts/e2e-web.mjs" "$LINK" || fail "the sign-in link enrolls a passkey in the dashboard"
pass "the sign-in link enrolls a passkey and the dashboard shows the data"

echo "--- second start"
SECOND=$("$DEV" up 2>&1) || { echo "$SECOND"; fail "second scripts/dev.sh up"; }
! grep -q -- "--- seeding" <<< "$SECOND" || fail "a second start does not seed again"
test "$(api /organizations | count)" = 1 || fail "still one organization"
grep -q 'enroll#' <<< "$SECOND" || fail "a second start prints a new link"
pass "a second up changes nothing and prints a fresh link"

"$DEV" down >/dev/null 2>&1
"$DEV" up >/dev/null 2>&1
test "$(api /organizations/acme/projects/api/environments | count)" = 3 || fail "data survives down"
pass "down keeps the data"

"$DEV" reset >/dev/null 2>&1
[ ! -e "$VARLATCH_DEV_DIR" ] || fail "reset removes the state directory"
[ -z "$(docker volume ls -q --filter "label=com.docker.compose.project=$VARLATCH_DEV_PROJECT")" ] || fail "reset removes the volumes"
pass "reset removes the state and the volumes"

echo "PASS: contributor setup (ADR-0037 D7)"
