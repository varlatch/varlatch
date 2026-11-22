#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs the real-source rehearsal (step 7.8b) on this host:
#
#   run.sh <typescript-checkout> <run> [<release-dir>]
#
# Builds varlatch (-tags rehearsal,crashpoint; the crash points do nothing
# unless VL_RH_KILL asks), varlatchd and this package's test
# binary in golang:1.27.4 (Go caches under ~/.cache), the TypeScript images
# with images.sh unless <release-dir> holds them already, then runs the
# test binary as root in a runner container (runner.Dockerfile), with the
# host's Docker. Its files, and its report, go under
# $VL_RH_ROOT/<run> (default: ./rehearsal-runs). One run at a time; every
# container, network and volume is named vl-rh-<run>-... and removed by
# that name when the run ends (VL_RH_KEEP=1 keeps the installations).
#
# VL_RH_PROFILE=box (the experiments server; internal
# docs/design/go-step8-rehearsals.md): run by the owner as root on the
# host (sudo -i first), the test binary directly on the host, with real
# systemd and the box's cases (VL_RH_INGRESS=public|coolify, ...). It never
# stops, removes or rebinds anything that is not this run's; the run's
# files are handed back to the user who ran sudo.
#
# VL_RH_SYNC=fakes (a workstation): the sync case, Sync Targets to the
# conformance suites' platform stand-ins, migrated and then pushed from Go
# (VL_RH_ONLY=sync runs it alone).
set -euo pipefail
[ $# -ge 2 ] || { echo "usage: run.sh <typescript-checkout> <run> [<release-dir>]" >&2; exit 64; }
profile=${VL_RH_PROFILE:-workstation}
if [ "$profile" = box ] && [ "$(id -u)" != 0 ]; then
  echo "the box profile runs as root: sudo -i, then run this again" >&2
  exit 64
fi
# The box's test timeout: the run's own work (6 h at most) plus every pause
# for the owner at its longest (VL_RH_PAUSE_TIMEOUT, default 2h, in h, m and
# s), so a slow owner never trips the timeout's panic, which skips the
# cleanups. The Coolify case pauses at most pause_budget times (the source
# and target apps, each exit 75 of the migration and the rollback, the
# cleanup), which the test holds it to; the other cases never pause.
duration_seconds() {
  [[ $1 =~ ^(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?$ ]] && [ -n "$1" ] || return 1
  echo $(( ${BASH_REMATCH[2]:-0} * 3600 + ${BASH_REMATCH[4]:-0} * 60 + ${BASH_REMATCH[6]:-0} ))
}
pause_budget=0
[ "${VL_RH_INGRESS:-proxy}" != coolify ] || pause_budget=8
pause_seconds=$(duration_seconds "${VL_RH_PAUSE_TIMEOUT:-2h}") || {
  echo "VL_RH_PAUSE_TIMEOUT is hours, minutes and seconds (2h, 90m, 1h30m), not ${VL_RH_PAUSE_TIMEOUT}" >&2
  exit 64
}
# Refused here, before anything starts, as each pause would refuse it
# later (after the owner made the Coolify apps).
if [ "$pause_seconds" -le 0 ]; then
  echo "VL_RH_PAUSE_TIMEOUT must be longer than zero, not ${VL_RH_PAUSE_TIMEOUT}" >&2
  exit 64
fi
test_timeout=$(( 6 * 3600 + pause_budget * pause_seconds ))s
if [ "$profile" = box ] && [ -z "${SUDO_UID:-}" ]; then
  echo "warning: SUDO_UID is not set (a root shell from su, not sudo -i): the run's files, its report" >&2
  echo "  included, stay root-owned under ${VL_RH_ROOT:-$PWD/rehearsal-runs}/$2; before fetch-report.sh can" >&2
  echo "  read them, chown -R <your user> that directory as root (or use sudo -i next time)" >&2
fi
here=$(cd "$(dirname "$0")" && pwd) gomod=$(cd "$here/../.." && pwd)
ts=$(cd "$1" && pwd) run=$2
[[ $run =~ ^[a-z0-9-]+$ ]] || { echo "run is lowercase letters, digits and dashes" >&2; exit 64; }
root=${VL_RH_ROOT:-$PWD/rehearsal-runs}/$run
target_root=${VL_RH_TARGET_ROOT:-/var/lib/vl-rh}
check_capacity() {
  local min_mem_mib=${VL_RH_MIN_MEM_MIB:-2048}
  local min_disk_mib=${VL_RH_MIN_DISK_MIB:-6144}
  local mem_avail_mib=""
  if [ -r /proc/meminfo ]; then
    mem_avail_mib=$(awk '/^MemAvailable:/ { printf "%d", $2 / 1024 }' /proc/meminfo)
  elif command -v free >/dev/null 2>&1; then
    mem_avail_mib=$(free -m | awk '/^Mem:/ { print $7 }')
  fi
  if [ -n "$mem_avail_mib" ] && [ "$mem_avail_mib" -lt "$min_mem_mib" ]; then
    echo "preflight: only ${mem_avail_mib} MiB memory available (need at least ${min_mem_mib} MiB; set VL_RH_MIN_MEM_MIB to override)" >&2
    exit 1
  fi
  local path check_path avail_mib
  for path in "$root" /var/lib/docker /var/lib; do
    check_path=$path
    while [ ! -e "$check_path" ] && [ "$check_path" != / ]; do
      check_path=$(dirname "$check_path")
    done
    [ -r "$check_path" ] || continue
    avail_mib=$(df -Pm "$check_path" | awk 'NR==2 { print $4 }')
    if [ -n "$avail_mib" ] && [ "$avail_mib" -lt "$min_disk_mib" ]; then
      echo "preflight: only ${avail_mib} MiB free on $path (need at least ${min_disk_mib} MiB; set VL_RH_MIN_DISK_MIB to override)" >&2
      exit 1
    fi
  done
}
check_capacity
mkdir -p "$root"/{bin,work,report}
release=${3:-$root/release}
runner=vl-rh-$run-runner
created_release=0
runner_built=0
cleanup_release() {
  docker rm -fv "vl-rh-$run-registry" >/dev/null 2>&1 || true
  if [ -f "$release/images.json" ]; then
    local ref tag_ref digest_ref
    while IFS= read -r ref; do
      [ -n "$ref" ] || continue
      tag_ref=${ref%%@*}
      digest_ref="${tag_ref%:*}@${ref#*@}"
      docker image rm "$tag_ref" >/dev/null 2>&1 || true
      docker image rm "$digest_ref" >/dev/null 2>&1 || true
    done < <(node -e 'const d = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); for (const r of Object.values(d.images || {})) console.log(r);' "$release/images.json" 2>/dev/null || true)
  fi
}
cleanup() {
  if [ "$runner_built" = 1 ]; then
    docker run --rm --name "vl-rh-$run-chown" -u 0 -v "$root:$root" "$runner" chown -R "$(id -u):$(id -g)" "$root" || true
    docker image rm "$runner" >/dev/null 2>&1 || true
  fi
  # The stand-ins' key goes whatever VL_RH_KEEP says.
  rm -f "$root/work/sync-fakes/key.pem" 2>/dev/null || true
  if [ "${VL_RH_KEEP:-}" != 1 ]; then
    # The sync case's (VL_RH_SYNC=fakes), when an interrupt left them (the
    # test binary has no signal handler): its Compose stack, the
    # stand-ins' container and network, and their directory, by their
    # exact names. After a clean run there is nothing left to remove.
    docker compose -p "vl-rh-$run-sync" --profile deploy down -v --remove-orphans --timeout 20 >/dev/null 2>&1 || true
    docker rm -fv "vl-rh-$run-sync-fakes" >/dev/null 2>&1 || true
    docker network rm "vl-rh-$run-sync" >/dev/null 2>&1 || true
    rm -rf "$root/work/sync-fakes" 2>/dev/null || true
    if [ "$created_release" = 1 ]; then
      cleanup_release
    fi
    if [ -d "$target_root/$run" ]; then
      rm -rf "$target_root/$run" 2>/dev/null || true
    fi
    if [ "$profile" = box ] && [ -d "/srv/vl-rh/$run" ]; then
      rm -rf "/srv/vl-rh/$run" 2>/dev/null || true
    fi
  fi
  if [ "$profile" = box ] && [ -n "${SUDO_UID:-}" ]; then
    chown -R "$SUDO_UID:$SUDO_GID" "$root" || true
  elif [ "$profile" = box ]; then
    echo "warning: SUDO_UID is not set: $root stays root-owned; chown -R <your user> it as root before fetch-report.sh" >&2
  fi
}
trap cleanup EXIT
if [ ! -f "$release/images.json" ]; then
  created_release=1
  "$here/images.sh" "$ts" "$run" "$release"
fi
# The Go caches: the workstation's (the module cache read-only, as the
# repository's other builds use it), or on the box (or when absent), the
# run's own writable cache.
if [ "$profile" = box ] || [ ! -d "$HOME/.cache/varlatch-gomod" ]; then
  mkdir -p "$root/cache/go" "$root/cache/mod"
  gocache=$root/cache/go gomodcache=$root/cache/mod:/gomod
else
  mkdir -p "$HOME/.cache/varlatch-go-nr"
  gocache=$HOME/.cache/varlatch-go-nr gomodcache=$HOME/.cache/varlatch-gomod:/gomod:ro
fi
docker run --rm --name "vl-rh-$run-build" -u "$(id -u):$(id -g)" -e HOME=/tmp -e CGO_ENABLED=0 \
  -e GOCACHE=/gocache -e GOMODCACHE=/gomod -v "$gocache:/gocache" -v "$gomodcache" \
  -v "$gomod/..:/src" -v "$root/bin:/out" -w /src/go golang:1.27.4 sh -c '
    go build -tags rehearsal,crashpoint -o /out/varlatch ./cmd/varlatch &&
    go build -o /out/varlatchd ./cmd/varlatchd &&
    go test -c -tags rehearsal -o /out/rehearsal.test ./test/rehearsal/'
# The sync case's platform stand-ins (VL_RH_SYNC=fakes), beside the
# binaries: the runner sees the run's directory, not this checkout.
cp "$gomod/../scripts/conformance/lib/platform-fakes.cjs" "$root/bin/platform-fakes.cjs"
release=$(cd "$release" && pwd)
pass=(VL_RH_PROFILE VL_RH_TARGET VL_RH_INGRESS VL_RH_PUBLIC_NAME VL_RH_PUBLIC_BIND VL_RH_SOURCE VL_RH_KILL VL_RH_SYNC
  VL_RH_CONTINUE_DIR VL_RH_GO_IMAGE VL_RH_COOLIFY_SOURCE_DIR VL_RH_PAUSE_TIMEOUT VL_RH_SEED VL_RH_SEED_VALUES
  VL_RH_KEEP VL_RH_ONLY)
if [ "$profile" = box ]; then
  # On the box: as root on the host, real systemd, the target under a
  # root-owned path; the run's files handed back to the sudo user after.
  cd "$root/work"
  VL_RH_RUN=$run VL_RH_RELEASE_DIR=$release VL_RH_BIN=$root/bin VL_RH_WORK=$root/work VL_RH_REPORT=$root/report VL_RH_TS=$ts \
    VL_RH_TARGET_ROOT="$target_root" VL_RH_PAUSE_BUDGET=$pause_budget \
    "$root/bin/rehearsal.test" -test.v -test.timeout "$test_timeout" -test.run '^TestRehearsal$' 2>&1 | tee "$root/report/test.log"
  exit "${PIPESTATUS[0]}"
fi
# On a workstation the test binary runs as root, as varlatch migrate does
# on a real host (it reads the bundle the TypeScript container writes, mode
# 0600, as uid 999): in a runner of this run's own, on the host's network
# (the installations' ports are on loopback), driving the host's Docker
# through its socket, every path mounted where it is on the host.
docker build -q -t "$runner" -f "$here/runner.Dockerfile" "$here" >/dev/null
runner_built=1
envs=()
for v in "${pass[@]}"; do envs+=(-e "$v"); done
docker run --rm --name "vl-rh-$run-test" --network host -u 0 -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$root:$root" -v "$release:$release:ro" -v "$ts:$ts:ro" -w "$root/work" \
  -e VL_RH_RUN="$run" -e VL_RH_RELEASE_DIR="$release" -e VL_RH_BIN="$root/bin" -e VL_RH_WORK="$root/work" \
  -e VL_RH_REPORT="$root/report" -e VL_RH_TS="$ts" -e VL_RH_TARGET_ROOT="$target_root" "${envs[@]}" \
  "$runner" "$root/bin/rehearsal.test" -test.v -test.timeout 90m -test.run '^TestRehearsal$' 2>&1 | tee "$root/report/test.log"
