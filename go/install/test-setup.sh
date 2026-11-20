#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# `varlatch setup` end to end on a disposable machine with systemd (CI's
# runner VM; ADR-0059 step 6, slice 6.4a): the setup suite's replacement.
#
#   sudo VARLATCH_TEST_DISPOSABLE_ROOT=1 [VARLATCH_TEST_PEBBLE=<dir url> VARLATCH_TEST_PEBBLE_ROOT=<pem>] \
#     go/install/test-setup.sh <directory holding varlatch and varlatchd>
#
# For each ingress mode (localhost, own proxy, and public against Pebble
# when it is given), from an empty host: the binaries and the unit
# installed as install.sh --server installs them, then one non-interactive
# `varlatch setup`, which must leave the unit running and ready, the keys
# root's (0600) and their copies (0600) holding them, and no key in its
# output, its journal, the configuration, the unit's journal or a backup;
# a rerun must change nothing and restart nothing. Then setup stopped
# after each step and run again ends as a run in one go.
#
# It touches only a disposable machine: it refuses to start unless
# VARLATCH_TEST_DISPOSABLE_ROOT=1, as root, with nothing of a Varlatch
# installation present, and removes all it made.
set -eu

[ "${VARLATCH_TEST_DISPOSABLE_ROOT:-}" = 1 ] || {
  echo "refusing: set VARLATCH_TEST_DISPOSABLE_ROOT=1, on a disposable machine only" >&2
  exit 2
}
[ "$(id -u)" = 0 ] || { echo "refusing: needs root" >&2; exit 2; }
bin=${1:-}
[ -x "$bin/varlatch" ] && [ -x "$bin/varlatchd" ] || { echo "refusing: no varlatch and varlatchd in '$bin'" >&2; exit 2; }
unit=$(cd "$(dirname "$0")" && pwd)/varlatchd.service
[ -f "$unit" ] || { echo "refusing: no $unit" >&2; exit 2; }

for p in /etc/varlatch /var/lib/varlatch /var/lib/private/varlatch /etc/systemd/system/varlatchd.service \
         /usr/local/bin/varlatchd /usr/local/bin/varlatch /usr/local/share/varlatch-setup-test; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    echo "refusing: $p exists" >&2
    exit 2
  fi
done
if id varlatch >/dev/null 2>&1; then
  echo "refusing: user varlatch exists" >&2
  exit 2
fi

work=$(mktemp -d)
chmod 700 "$work"
SHARE=/usr/local/share/varlatch-setup-test

teardown() {
  systemctl disable --now varlatchd.service >/dev/null 2>&1 || true
  systemctl reset-failed varlatchd.service >/dev/null 2>&1 || true
  rm -rf /etc/varlatch /var/lib/varlatch /var/lib/private/varlatch
  userdel varlatch >/dev/null 2>&1 || true
  groupdel varlatch >/dev/null 2>&1 || true
}
cleanup() {
  trap '' HUP INT TERM
  teardown
  rm -f /etc/systemd/system/varlatchd.service /usr/local/bin/varlatchd /usr/local/bin/varlatch
  rm -rf "$SHARE" "$work"
  systemctl daemon-reload || true
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# Installed as install.sh --server installs them.
install -m 755 "$bin/varlatch" /usr/local/bin/varlatch
install -m 755 "$bin/varlatchd" /usr/local/bin/varlatchd
install -m 644 "$unit" /etc/systemd/system/varlatchd.service
systemctl daemon-reload

failures=0
fail() { echo "FAIL  $*" >&2; failures=$((failures + 1)); }
pass() { echo "PASS  $*"; }

# The key files' hex, for the checks that no key leaks (never printed).
keys_leak_into() {
  for k in /etc/varlatch/root-kek /etc/varlatch/backup-key; do
    key=$(tr -d '\n' <"$k")
    if grep -qF -- "$key" "$@" 2>/dev/null; then
      return 0
    fi
  done
  return 1
}

mode_of() { stat -c '%a %U:%G' "$1"; }

# setup_once <name> <flags...>: one non-interactive setup, its output in
# $work/<name>.out, its status in $status.
setup_once() {
  name=$1
  shift
  set +e
  /usr/local/bin/varlatch setup "$@" --backups host --accept-slow-disk \
    --root-kek-out "$work/$name-root-kek" --backup-key-out "$work/$name-backup-key" \
    </dev/null >"$work/$name.out" 2>&1
  status=$?
  set -e
}

# check_installation <name> <flags...>: the run's results, then a rerun.
check_installation() {
  name=$1
  shift
  if [ "$status" = 0 ]; then pass "$name: setup exits 0"; else fail "$name: setup exited $status: $(tail -n 5 "$work/$name.out")"; return; fi
  if [ "$(systemctl is-active varlatchd.service)" = active ]; then pass "$name: the unit is active"; else fail "$name: the unit is not active"; fi
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8686/readyz || true)
  if [ "$code" = 200 ]; then pass "$name: /readyz answers 200"; else fail "$name: /readyz answered $code"; fi
  for f in root-kek backup-key setup.json; do
    if [ "$(mode_of /etc/varlatch/$f)" = "600 root:root" ]; then pass "$name: /etc/varlatch/$f is 600 root"; else fail "$name: /etc/varlatch/$f is $(mode_of /etc/varlatch/$f)"; fi
  done
  if ! [ "$(mode_of /etc/varlatch/varlatchd.conf)" = "640 root:varlatch" ]; then fail "$name: varlatchd.conf is $(mode_of /etc/varlatch/varlatchd.conf)"; fi
  if ! [ "$(mode_of /etc/varlatch)" = "750 root:varlatch" ]; then fail "$name: /etc/varlatch is $(mode_of /etc/varlatch)"; fi
  if ! [ "$(mode_of /var/lib/varlatch)" = "700 varlatch:varlatch" ]; then fail "$name: /var/lib/varlatch is $(mode_of /var/lib/varlatch)"; fi
  for k in root-kek backup-key; do
    if [ "$(stat -c %a "$work/$name-$k")" = 600 ] && cmp -s "$work/$name-$k" /etc/varlatch/$k; then
      pass "$name: the $k copy is the key, 600"
    else
      fail "$name: the $k copy is not the key, or not 600"
    fi
  done
  journalctl -u varlatchd.service --no-pager >"$work/$name.journal" 2>&1 || true
  if keys_leak_into "$work/$name.out" /etc/varlatch/setup.json /etc/varlatch/varlatchd.conf "$work/$name.journal"; then
    fail "$name: a key in setup's output, its journal, the configuration or the unit's journal"
  else
    pass "$name: no key in setup's output, its journal, the configuration or the unit's journal"
  fi
  # A backup: the archive holds no key.
  if /usr/local/bin/varlatch admin backup run --json >"$work/$name.backup" 2>&1; then
    if keys_leak_into /var/lib/varlatch/backups/*.vltbak "$work/$name.backup"; then
      fail "$name: a key in the backup archive or its output"
    else
      pass "$name: no key in the backup archive"
    fi
  else
    fail "$name: varlatch admin backup run: $(tail -n 3 "$work/$name.backup")"
  fi
  # A rerun: nothing changes, nothing restarts.
  before=$(cd /etc/varlatch && sha256sum root-kek backup-key varlatchd.conf setup.json)
  started=$(systemctl show -p ActiveEnterTimestampMonotonic --value varlatchd.service)
  setup_once "$name-again" "$@"
  # The rerun's copies are the first run's own files.
  if [ "$status" = 0 ] && [ "$before" = "$(cd /etc/varlatch && sha256sum root-kek backup-key varlatchd.conf setup.json)" ] &&
     [ "$started" = "$(systemctl show -p ActiveEnterTimestampMonotonic --value varlatchd.service)" ]; then
    pass "$name: a rerun changes nothing and restarts nothing"
  else
    fail "$name: the rerun exited $status or changed something: $(tail -n 3 "$work/$name-again.out")"
  fi
}

# The ingress modes, each from an empty host.
setup_once localhost --ingress localhost
check_installation localhost --ingress localhost
teardown

setup_once proxy --ingress proxy --public-url https://vault.varlatch.test
check_installation proxy --ingress proxy --public-url https://vault.varlatch.test
if grep -q '^trusted_proxies = 127.0.0.1,::1$' /etc/varlatch/varlatchd.conf; then pass "proxy: the configuration trusts the proxy on this host"; else fail "proxy: no trusted_proxies"; fi
teardown

if [ -n "${VARLATCH_TEST_PEBBLE:-}" ]; then
  # The unit reads the CA's root from a place its sandbox lets it.
  install -d -m 755 "$SHARE"
  install -m 644 "$VARLATCH_TEST_PEBBLE_ROOT" "$SHARE/pebble-api-root.pem"
  set -- --ingress public --public-url https://setup.varlatch.test:5001 --listen-https 127.0.0.1:5001 \
    --listen-http-redirect 127.0.0.1:5002 --acme-ca "$VARLATCH_TEST_PEBBLE" --acme-ca-root "$SHARE/pebble-api-root.pem"
  setup_once public "$@"
  check_installation public "$@"
  got=""
  for _ in $(seq 1 60); do
    got=$(curl -s -o /dev/null -w '%{http_code}' -k --resolve setup.varlatch.test:5001:127.0.0.1 https://setup.varlatch.test:5001/readyz || true)
    [ "$got" = 200 ] && break
    sleep 1
  done
  if [ "$got" = 200 ]; then pass "public: HTTPS answers with Pebble's certificate"; else fail "public: HTTPS answered $got"; fi
  teardown
else
  echo "SKIP  public: no Pebble (VARLATCH_TEST_PEBBLE)"
fi

# Interrupted after each step, then run again: as a run in one go.
for step in answers user data-dir probe keys key-copies config unit; do
  set +e
  VARLATCH_SETUP_STOP_AFTER=$step /usr/local/bin/varlatch setup --ingress localhost --backups host --accept-slow-disk \
    --root-kek-out "$work/stop-$step-root-kek" --backup-key-out "$work/stop-$step-backup-key" </dev/null >"$work/stop-$step.out" 2>&1
  stopped=$?
  set -e
  if ! [ "$stopped" = 75 ]; then fail "stopped after $step: exited $stopped: $(tail -n 3 "$work/stop-$step.out")"; fi
  setup_once "resume-$step" --ingress localhost
  # The copies of a resumed run are its first part's.
  if [ "$status" = 0 ] && [ "$(systemctl is-active varlatchd.service)" = active ] && [ -s /etc/varlatch/root-kek ] &&
     [ "$(grep -c '"' /etc/varlatch/setup.json)" -gt 0 ]; then
    pass "stopped after $step, then resumed: ready"
  else
    fail "stopped after $step, then resumed: exited $status: $(tail -n 3 "$work/resume-$step.out")"
  fi
  teardown
done

if [ "$failures" -gt 0 ]; then
  echo "$failures checks failed" >&2
  exit 1
fi
echo "every check passed"
