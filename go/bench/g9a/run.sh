#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Runs ADR-0059's storage benchmark (G9a) once and judges it:
#
#   bench/g9a/run.sh OUT [plan.json]
#
# OUT must not exist yet. Without a plan file the G9a profile runs (36
# minutes of load). Exit status: the report's (0 pass, 1 fail,
# 2 inconclusive), or 3 when the harness itself failed.
#
# Environment:
#   G9A_BIN     a built g9a (default: go build, which needs Go)
#   G9A_DATA    the data directory to measure (default OUT/data); its disk
#               is the one the verdict holds for
#   G9A_LISTEN  the server's address (default 127.0.0.1:8080)
#   G9A_SCOPE   a command the server runs under for G9's memory limits, as
#               root on the benchmark host:
#               systemd-run --scope --quiet -p MemoryMax=1G -p MemorySwapMax=0
#   K6          a k6 binary (default: k6 on PATH, else the pinned image in
#               Docker, which needs host networking)
set -eu

die() { echo "run.sh: $*" >&2; exit 3; }
[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: run.sh OUT [plan.json]"
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$1
[ -e "$OUT" ] && die "$OUT exists: every run gets a new directory"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
DATA=${G9A_DATA:-$OUT/data}
LISTEN=${G9A_LISTEN:-127.0.0.1:8080}
K6IMG='grafana/k6:2.3.0@sha256:2dd4756ec6e14e62778916e1eb850108e4b499304c02df56760fa0bdb0fba0b8'

BIN=${G9A_BIN:-}
if [ -z "$BIN" ]; then
  BIN=$OUT/g9a
  (cd "$HERE/../.." && go build -o "$BIN" ./bench/g9a/cmd/g9a) || die "go build failed"
fi
if [ $# -eq 2 ]; then
  cp "$2" "$OUT/plan.in.json"
else
  "$BIN" plan > "$OUT/plan.in.json"
fi

# The server: seeds, probes the idle disk, then waits for the load.
# shellcheck disable=SC2086 # G9A_SCOPE is a command line
${G9A_SCOPE:-} "$BIN" serve -plan "$OUT/plan.in.json" -data "$DATA" -out "$OUT" -listen "$LISTEN" 2> "$OUT/server.log" &
SERVER=$!
# shellcheck disable=SC2329 # called by the trap
stop_server() { kill "$SERVER" 2>/dev/null || true; }
trap stop_server EXIT INT TERM

i=0
until curl -fsS "http://$LISTEN/healthz" > /dev/null 2>&1; do
  kill -0 "$SERVER" 2>/dev/null || { cat "$OUT/server.log" >&2; die "the server stopped before it was ready"; }
  i=$((i + 1)); [ $i -le 1200 ] || die "the server was not ready after 10 minutes"
  sleep 0.5
done

# The load. k6 prints one line per request on its console.
set -- run -q --no-color --log-format raw --console-output "$OUT/requests.log" \
  -e "BASE=http://$LISTEN" -e "PLAN=$OUT/plan.json" -e "MANIFEST=$OUT/manifest.json" \
  -e "SUMMARY=$OUT/k6-summary.json"
k6_status=0
if [ -n "${K6:-}" ] || command -v k6 > /dev/null 2>&1; then
  "${K6:-k6}" "$@" "$HERE/k6/g9a.js" > "$OUT/k6.log" 2>&1 || k6_status=$?
else
  docker run --rm --network host -u "$(id -u):$(id -g)" -v "$OUT:$OUT" -v "$HERE/k6:$HERE/k6:ro" \
    "$K6IMG" "$@" "$HERE/k6/g9a.js" > "$OUT/k6.log" 2>&1 || k6_status=$?
fi
[ "$k6_status" -eq 0 ] || echo "run.sh: k6 exited $k6_status (see $OUT/k6.log)" >&2

curl -fsS -X POST "http://$LISTEN/run/stop" > /dev/null || true
wait "$SERVER" || { trap - EXIT; cat "$OUT/server.log" >&2; die "the server failed"; }
trap - EXIT
[ -s "$OUT/k6-summary.json" ] || die "k6 wrote no summary (see $OUT/k6.log)"

status=0
"$BIN" report "$OUT" || status=$?
[ "$status" -le 2 ] || die "the report failed"
exit "$status"
