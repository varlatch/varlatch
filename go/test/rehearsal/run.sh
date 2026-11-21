#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the real-source rehearsal (step 7.8b) on this host:
#
#   run.sh <typescript-checkout> <run> [<release-dir>]
#
# Builds varlatch (-tags rehearsal), varlatchd and this package's test
# binary in golang:1.27.4 (Go caches under ~/.cache), the TypeScript images
# with images.sh unless <release-dir> holds them already, then runs the
# test binary as root in a runner container (runner.Dockerfile), with the
# host's Docker. Its files, and its report, go under
# $VL_RH_ROOT/<run> (default: ./rehearsal-runs). One run at a time; every
# container, network and volume is named vl-rh-<run>-... and removed by
# that name when the run ends (VL_RH_KEEP=1 keeps the installations).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd) gomod=$(cd "$here/../.." && pwd)
ts=$(cd "$1" && pwd) run=$2
root=${VL_RH_ROOT:-$PWD/rehearsal-runs}/$run
mkdir -p "$root"/{bin,work,report}
release=${3:-$root/release}
[ -f "$release/images.json" ] || "$here/images.sh" "$ts" "$run" "$release"
docker run --rm --name "vl-rh-$run-build" -u "$(id -u):$(id -g)" -e HOME=/tmp -e CGO_ENABLED=0 \
  -e GOCACHE=/gocache -e GOMODCACHE=/gomod -v "$HOME/.cache/varlatch-go-nr:/gocache" -v "$HOME/.cache/varlatch-gomod:/gomod:ro" \
  -v "$gomod/..:/src" -v "$root/bin:/out" -w /src/go golang:1.27.4 sh -c '
    go build -tags rehearsal -o /out/varlatch ./cmd/varlatch &&
    go build -o /out/varlatchd ./cmd/varlatchd &&
    go test -c -tags rehearsal -o /out/rehearsal.test ./test/rehearsal/'
release=$(cd "$release" && pwd)
# The test binary runs as root, as varlatch migrate does on a real host
# (it reads the bundle the TypeScript container writes, mode 0600, as uid
# 999): in a runner of this run's own, on the host's network (the
# installations' ports are on loopback), driving the host's Docker through
# its socket, every path mounted where it is on the host.
runner=vl-rh-$run-runner
docker build -q -t "$runner" -f "$here/runner.Dockerfile" "$here" >/dev/null
cleanup() {
  docker run --rm --name "vl-rh-$run-chown" -u 0 -v "$root:$root" "$runner" chown -R "$(id -u):$(id -g)" "$root" || true
  docker image rm "$runner" >/dev/null || true
}
trap cleanup EXIT
docker run --rm --name "vl-rh-$run-test" --network host -u 0 -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$root:$root" -v "$release:$release:ro" -v "$ts:$ts:ro" -w "$root/work" \
  -e VL_RH_RUN="$run" -e VL_RH_RELEASE_DIR="$release" -e VL_RH_BIN="$root/bin" -e VL_RH_WORK="$root/work" \
  -e VL_RH_REPORT="$root/report" -e VL_RH_TS="$ts" -e VL_RH_BACKUPS_WORKAROUND -e VL_RH_KEEP -e VL_RH_ONLY \
  -e VL_RH_TARGET_ROOT=/var/lib/vl-rh \
  "$runner" "$root/bin/rehearsal.test" -test.v -test.timeout 90m -test.run '^TestRehearsal$' 2>&1 | tee "$root/report/test.log"
