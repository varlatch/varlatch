#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# G6, the upgrade gate (ADR-0059 Decision 8; internal docs/design/
# go-step6.md decision 5, slice 6.6a): the previous release's varlatchd
# runs on a database the new release upgraded, then the new one runs on
# what the previous one wrote.
#
#   g6.sh <previous-varlatchd> <new-varlatchd> <out-dir> [<suite>...]
#
# Both binaries are conformance builds (go build -tags conformance); the
# conformance runner (run from the repository root, with the workspace
# built) serves them through the go-binary target. With no suite named,
# each run takes every suite. G6_ROLLBACK_SAFE is the new release's
# declaration (go/release/release.json's rollbackSafe): true or false.
# G6_CONFORMANCE=off leaves the conformance runs out (the steps around them
# still run): go.yml's cheap checks that a release declared not
# rollback-safe passes G6 only when the previous release refuses its
# database, and one declared rollback-safe fails when it does.
#
# 1. The previous release creates an installation (`admin backup run`,
#    offline, which also takes an archive of it).
# 2. The new release upgrades its schema (`admin schema upgrade`); its
#    steps write a row of every new kind they bring.
# 3. Declared rollback-safe: the previous release opens the upgraded
#    database (`admin schema status`), and the conformance suites pass
#    against it there; what that run wrote is kept. Not rollback-safe: the
#    previous release must refuse it, and steps 3 and 4 end there.
# 4. The new release upgrades again (nothing to do: the previous release
#    leaves the schema as it found it), takes an archive (reading every
#    table the previous release wrote to) and checks the Root KEK.
# 5. The conformance suites pass against the new release on the upgraded
#    installation of step 2.
#
# Docker is not needed; nothing here needs privileges. Exit 0 when every
# step holds, 1 otherwise.
set -eu

[ $# -ge 3 ] || { echo "usage: g6.sh <previous-varlatchd> <new-varlatchd> <out-dir> [<suite>...]" >&2; exit 2; }
previous=$1 new=$2 out=$3
shift 3
for b in "$previous" "$new"; do
  [ -x "$b" ] || { echo "g6: $b is not executable" >&2; exit 2; }
done
[ ! -e "$out" ] || { echo "g6: $out exists; give a new directory" >&2; exit 2; }
case "${G6_ROLLBACK_SAFE:-}" in
  true | false) ;;
  *) echo "g6: G6_ROLLBACK_SAFE must be true or false" >&2; exit 2 ;;
esac
case "${G6_CONFORMANCE:-on}" in
  on | off) conformance=${G6_CONFORMANCE:-on} ;;
  *) echo "g6: G6_CONFORMANCE must be on or off" >&2; exit 2 ;;
esac
command -v jq > /dev/null || { echo "g6: jq is needed" >&2; exit 2; }
suites=''
for s in "$@"; do suites="$suites --suite $s"; done

step() { printf '\n=== G6: %s\n' "$*"; }
fail() { printf 'G6 FAILED: %s\n' "$*" >&2; exit 1; }

umask 077
mkdir -p "$out/upgraded/data" "$out/keys"
key() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; echo; }
key > "$out/keys/backup-key"
key > "$out/upgraded/root-kek"
conf() { # conf <installation directory>
  cat > "$1/varlatchd.conf" <<EOF
listen = 127.0.0.1:0
data_dir = $1/data
root_kek_file = $1/root-kek
backup_key_file = $out/keys/backup-key
backup_interval = off
EOF
}
conf "$out/upgraded"

# previous_status <config> <out.json> [<previous schema>]: the previous
# release's `admin schema status --json` on the installation. A previous
# release without the command (`admin schema` came with slice 6.6b, #330;
# v0.50.0-rc.1 has none) answers "unknown command schema", and only then:
# the database is read by the new release's status, which reads it
# read-only, and whether the previous release opens it is the previous
# release's own rule (db.Init, unchanged since rc.1): the same schema
# version, or a newer one whose compatible_from is at most the previous
# release's. Its schema version is the one it created the installation
# with (the third argument, from the first call). Once `previous` is a
# release with `admin schema`, every call takes the direct path, and any
# other failure fails G6 as before.
previous_status() {
  if "$previous" admin schema status --json --config "$1" > "$2" 2> "$2.err"; then
    cat "$2.err" >&2
    return 0
  fi
  cat "$2.err" >&2
  grep -q "unknown command schema" "$2.err" || fail "the previous release's admin schema status failed (its message is above)"
  echo "the previous release has no admin schema status: the database read by the new release's (read-only), opens by the previous release's rule"
  "$new" admin schema status --json --config "$1" > "$2.new" || fail "the new release's admin schema status failed (its message is above)"
  db=$(jq -er '.database.schemaVersion' "$2.new")
  compat=$(jq -er '.database.compatibleFrom' "$2.new")
  prev=${3:-$db}
  jq -n --argjson db "$db" --argjson compat "$compat" --argjson prev "$prev" \
    '{binary: {schemaVersion: $prev}, database: {schemaVersion: $db, compatibleFrom: $compat},
      opens: (($db == $prev) or ($db > $prev and $compat <= $prev)), derived: true}' > "$2"
}

step "the previous release creates the installation"
"$previous" admin backup run --config "$out/upgraded/varlatchd.conf"
previous_status "$out/upgraded/varlatchd.conf" "$out/previous-status.json"
before=$(jq -er '.database.schemaVersion' "$out/previous-status.json")
previous_schema=$(jq -er '.binary.schemaVersion' "$out/previous-status.json")

step "the new release upgrades it"
# The upgrade's own message and status, not a pipe's.
"$new" admin schema upgrade --json --config "$out/upgraded/varlatchd.conf" > "$out/upgrade.json" \
  || fail "the new release's schema upgrade failed (its message is above)"
cat "$out/upgrade.json"
after=$(jq -er '.to' "$out/upgrade.json")
new_schema=$(jq -er '.binary.schemaVersion' "$out/upgrade.json")
[ "$after" = "$new_schema" ] || fail "the database's schema is $after after the upgrade, not the new release's $new_schema"
echo "schema $before -> $after (the previous release knows $previous_schema)"

step "the previous release on the upgraded database"
previous_status "$out/upgraded/varlatchd.conf" "$out/rollback-status.json" "$previous_schema"
# -r, not -e: false is an answer here (the not-rollback-safe case).
opens=$(jq -r '.opens' "$out/rollback-status.json")
case "$opens" in
  true | false) ;;
  *) fail "admin schema status gave no opens: $opens" ;;
esac
if [ "$G6_ROLLBACK_SAFE" = false ]; then
  [ "$opens" = false ] || [ "$after" = "$before" ] \
    || fail "declared not rollback-safe, but the previous release opens the upgraded database: raise compatibleFrom"
  echo "not rollback-safe: the previous release refuses the upgraded database, as declared"
else
  [ "$opens" = true ] || fail "declared rollback-safe, but the previous release cannot open the upgraded database"
  if [ "$conformance" = off ]; then
    echo "the conformance runs are left out (G6_CONFORMANCE=off): the previous release opens the upgraded database"
    echo
    echo "G6 passed without the conformance runs: schema $before -> $after, rollback-safe $G6_ROLLBACK_SAFE"
    exit 0
  fi
  # shellcheck disable=SC2086 # one word per --suite and suite name
  VARLATCH_GO_BINARY_FROM="$out/upgraded" VARLATCH_GO_BINARY_KEEP="$out/after-previous" \
    node scripts/conformance/run.mjs --target "go-binary:$previous" --cli source $suites --report "$out/previous-report.json" \
    || fail "the conformance suites fail with the previous release on the upgraded database"

  step "the new release on what the previous release wrote"
  [ -d "$out/after-previous/data" ] || fail "the previous release's run kept no data"
  conf "$out/after-previous"
  "$new" admin schema upgrade --json --config "$out/after-previous/varlatchd.conf" > "$out/upgrade-again.json" \
    || fail "the new release's second upgrade failed (its message is above)"
  cat "$out/upgrade-again.json"
  [ "$(jq -er '.changed' "$out/upgrade-again.json")" = false ] \
    || fail "the previous release changed the schema it was given"
  "$new" admin kek verify --config "$out/after-previous/varlatchd.conf" \
    || fail "the Root KEK no longer opens the installation the previous release wrote"
  "$new" admin backup run --config "$out/after-previous/varlatchd.conf" \
    || fail "the new release cannot archive what the previous release wrote"
fi

if [ "$conformance" = off ]; then
  echo
  echo "G6 passed without the conformance runs: schema $before -> $after, rollback-safe $G6_ROLLBACK_SAFE"
  exit 0
fi

step "the conformance suites with the new release on the upgraded database"
# shellcheck disable=SC2086 # one word per --suite and suite name
VARLATCH_GO_BINARY_FROM="$out/upgraded" \
  node scripts/conformance/run.mjs --target "go-binary:$new" --cli source $suites --report "$out/new-report.json" \
  || fail "the conformance suites fail with the new release on the upgraded database"

echo
echo "G6 passed: schema $before -> $after, rollback-safe $G6_ROLLBACK_SAFE"
