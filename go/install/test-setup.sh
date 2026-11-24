#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# `varlatch setup` end to end on a disposable machine with systemd (CI's
# runner VM; ADR-0059 step 6, slice 6.4a): the setup suite's replacement.
#
#   sudo VARLATCH_TEST_DISPOSABLE_ROOT=1 [VARLATCH_TEST_PEBBLE=<dir url> VARLATCH_TEST_PEBBLE_ROOT=<pem>] \
#     go/install/test-setup.sh <directory holding varlatch, varlatchd, enrollpasskey and setupterminal>
#
# For each ingress mode (localhost, own proxy, and public against Pebble
# when it is given), from an empty host: the binaries and the unit
# installed as install.sh --server installs them, then a non-interactive
# `varlatch setup`: it writes the first administrator's enrollment link to
# its file and stops (75); enrollpasskey (authtest's software
# authenticator, as a browser) enrolls a passkey from it; setup run again
# with --attest finishes. It must leave the unit running and ready, the
# keys root's (0600) and their copies (0600) holding them, the custody
# attested for both keys, the first backup verified, and no key in its
# output, its journal, the configuration, the unit's journal or a backup;
# a rerun must change nothing and restart nothing. G13 through setup: the
# localhost installation's latest archive and its two keys' copies, on the
# host emptied again, restored by `setup --restore` (the administrator and
# their passkey back, no link issued, a backup verified). Then setup on a
# terminal (setupterminal, a pseudo-terminal), which acts only on what the
# terminal shows: the passkey enrolled from the link shown, the two keys
# pasted back as shown; and the links `varlatch admin reenroll` and
# `varlatchd admin recover` print enroll one too. Then setup stopped after
# each step and run again ends as a run in one go.
#
# It touches only a disposable machine: it refuses to start unless
# VARLATCH_TEST_DISPOSABLE_ROOT=1, as root, with nothing of a Varlatch
# installation present, and removes all it made. go.yml runs it on
# GitHub-hosted runners only, never on a self-hosted varlatch-ci VM.
set -eu

[ "${VARLATCH_TEST_DISPOSABLE_ROOT:-}" = 1 ] || {
  echo "refusing: set VARLATCH_TEST_DISPOSABLE_ROOT=1, on a disposable machine only" >&2
  exit 2
}
[ "$(id -u)" = 0 ] || { echo "refusing: needs root" >&2; exit 2; }
bin=${1:-}
[ -x "$bin/varlatch" ] && [ -x "$bin/varlatchd" ] && [ -x "$bin/enrollpasskey" ] && [ -x "$bin/setupterminal" ] || { echo "refusing: no varlatch, varlatchd, enrollpasskey and setupterminal in '$bin'" >&2; exit 2; }
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

# setup_once <name> <flags...>: a non-interactive setup to its end: each
# run's output in $work/<name>.out (appended), its status in $status. A run
# that stops for the passkey (75, the link in $work/<name>-link) is
# followed by enrollpasskey and another run; one stopped by
# VARLATCH_SETUP_STOP_AFTER ends it. Every run attests (--attest): the
# copies are this test's. It keeps <name> in run, not name: sh has no
# locals, and check_installation's name is its caller's.
setup_once() {
  run=$1
  shift
  : >"$work/$run.out"
  rounds=0
  while :; do
    rounds=$((rounds + 1))
    set +e
    /usr/local/bin/varlatch setup "$@" --backups host --accept-slow-disk --attest --admin-wait 0s \
      --admin-link-out "$work/$run-link" --root-kek-out "$work/$run-root-kek" --backup-key-out "$work/$run-backup-key" \
      </dev/null >>"$work/$run.out" 2>&1
    status=$?
    set -e
    if [ "$status" != 75 ] || grep -q 'VARLATCH_SETUP_STOP_AFTER' "$work/$run.out" || [ "$rounds" -ge 3 ]; then
      return
    fi
    enroll "$run"
  done
}

# enroll <name>: a passkey from the link setup wrote, as a browser would,
# sent to $enroll_via: the plain listener (localhost, and own proxy as the
# proxy would, with X-Forwarded-Proto), or the public HTTPS listener
# reached by address with the link's name for SNI (public, against
# Pebble's certificate). The link's file must be 600.
enroll_via=http://127.0.0.1:8686
enroll() {
  set -- "$work/$1-link" "$1"
  if [ "$(stat -c %a "$1")" = 600 ]; then pass "$2: the enrollment link's file is 600"; else fail "$2: the link's file is $(stat -c %a "$1")"; fi
  case "$enroll_via" in
    https://*)
      # The first certificate may still be on its way.
      name_port=$(sed -n 's#^https://\([^/]*\)/.*#\1#p' "$1")
      for _ in $(seq 1 60); do
        curl -fsk -o /dev/null --resolve "$name_port:127.0.0.1" "https://$name_port/readyz" && break
        sleep 1
      done
      "$bin/enrollpasskey" -link-file "$1" -connect "$enroll_via" -insecure >/dev/null
      ;;
    *)
      "$bin/enrollpasskey" -link-file "$1" -connect "$enroll_via" >/dev/null
      ;;
  esac
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
  if [ -e "$work/$name-link" ]; then fail "$name: the used link's file is still there"; else pass "$name: the used link's file is removed"; fi
  if grep -q '/enroll#' "$work/$name.out"; then fail "$name: the enrollment link in setup's output"; fi
  custody=$(/usr/local/bin/varlatchd admin custody status --config /etc/varlatch/varlatchd.conf 2>&1 || true)
  if printf '%s' "$custody" | grep -q '"root-kek":{"key":"root-kek","method":"copy"' && printf '%s' "$custody" | grep -q '"backup-key":{"key":"backup-key","method":"copy"'; then
    pass "$name: both keys' custody is attested"
  else
    fail "$name: custody status $custody"
  fi
  if grep -q '"firstBackup": "[0-9a-f]' /etc/varlatch/setup.json && grep -q 'is made and verified' "$work/$name.out"; then pass "$name: the first backup is verified"; else fail "$name: no verified first backup"; fi
  if grep -q 'varlatch doctor:' "$work/$name.out"; then pass "$name: setup ran doctor"; else fail "$name: setup ran no doctor"; fi
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
  if [ "$status" = 0 ] && ! grep -q 'enrollment link' "$work/$name-again.out" && [ "$before" = "$(cd /etc/varlatch && sha256sum root-kek backup-key varlatchd.conf setup.json)" ] &&
     [ "$started" = "$(systemctl show -p ActiveEnterTimestampMonotonic --value varlatchd.service)" ]; then
    pass "$name: a rerun changes nothing and restarts nothing"
  else
    fail "$name: the rerun exited $status or changed something: $(tail -n 3 "$work/$name-again.out")"
  fi
}

# The ingress modes, each from an empty host.
setup_once localhost --ingress localhost
check_installation localhost --ingress localhost
# What a restore starts from (G13): the latest archive and the two keys'
# copies, kept off the host; nothing else survives the teardown.
mkdir -m 700 "$work/g13"
# The archive check_installation's backup run made, by the path it gave.
archive=$(sed -n 's/.*"path": *"\([^"]*\.vltbak\)".*/\1/p' "$work/localhost.backup" | head -n 1)
cp "$archive" "$work/g13/archive.vltbak"
cp "$work/localhost-root-kek" "$work/g13/root-kek"
cp "$work/localhost-backup-key" "$work/g13/backup-key"
admin_before=$(/usr/local/bin/varlatchd admin bootstrap-status --config /etc/varlatch/varlatchd.conf | grep -o '"id":"[^"]*"')
teardown

# G13 through setup: a fresh host, only the archive and the two keys.
set +e
/usr/local/bin/varlatch setup --ingress localhost --backups host --accept-slow-disk --attest --admin-wait 0s \
  --admin-link-out "$work/g13-link" --restore "$work/g13/archive.vltbak" \
  --root-kek-file "$work/g13/root-kek" --backup-key-file "$work/g13/backup-key" </dev/null >"$work/g13.out" 2>&1
status=$?
set -e
if [ "$status" = 0 ]; then pass "g13: setup --restore exits 0"; else fail "g13: setup --restore exited $status: $(tail -n 5 "$work/g13.out")"; fi
if [ "$(systemctl is-active varlatchd.service)" = active ] && [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8686/readyz || true)" = 200 ]; then
  pass "g13: the restored installation is ready"
else
  fail "g13: the restored installation is not ready"
fi
status_after=$(/usr/local/bin/varlatchd admin bootstrap-status --config /etc/varlatch/varlatchd.conf 2>&1 || true)
if [ -n "$admin_before" ] && printf '%s' "$status_after" | grep -q "$admin_before,\"enabled\":true,\"hasPasskey\":true"; then
  pass "g13: the administrator and their passkey are restored"
else
  fail "g13: bootstrap-status after the restore: $status_after"
fi
if [ -e "$work/g13-link" ] || grep -q 'enrollment link' "$work/g13.out"; then fail "g13: a restore issued an enrollment link"; else pass "g13: no enrollment link"; fi
for k in root-kek backup-key; do
  if cmp -s "$work/g13/$k" /etc/varlatch/$k && [ "$(mode_of /etc/varlatch/$k)" = "600 root:root" ]; then pass "g13: /etc/varlatch/$k is your key, 600 root"; else fail "g13: /etc/varlatch/$k"; fi
done
if grep -q '"firstBackup": "[0-9a-f]' /etc/varlatch/setup.json && grep -q 'is made and verified' "$work/g13.out"; then pass "g13: a backup of the restored installation is verified"; else fail "g13: no verified backup after the restore"; fi
journalctl -u varlatchd.service --no-pager >"$work/g13.journal" 2>&1 || true
if keys_leak_into "$work/g13.out" /etc/varlatch/setup.json /etc/varlatch/varlatchd.conf "$work/g13.journal"; then fail "g13: a key in setup's output, its journal, the configuration or the unit's journal"; else pass "g13: no key in setup's output or any journal"; fi
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
  enroll_via=https://127.0.0.1:5001
  setup_once public "$@"
  check_installation public "$@"
  enroll_via=http://127.0.0.1:8686
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

# On a terminal: what a person sees is enough to finish, and the links
# shown later work too.
set +e
"$bin/setupterminal" -enrollpasskey "$bin/enrollpasskey" -connect http://127.0.0.1:8686 -link-file "$work/terminal-link" \
  -public-url https://vault.varlatch.test /usr/local/bin/varlatch >"$work/terminal.out" 2>&1
status=$?
set -e
if [ "$status" = 0 ] && grep -q '^Setup is done' "$work/terminal.out"; then
  pass "terminal: the link shown enrolls the passkey, the keys shown are the keys, setup exits 0"
else
  fail "terminal: setup ended with $status: $(tail -n 8 "$work/terminal.out")"
fi
admin=$(/usr/local/bin/varlatchd admin bootstrap-status --config /etc/varlatch/varlatchd.conf | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
# link_works <name> <command...>: the link the command prints enrolls.
link_works() {
  what=$1
  shift
  (umask 077; "$@" 2>/dev/null | grep -o 'https://[^ ]*/enroll#[^ ]*' >"$work/shown-link" || true)
  if [ "$(wc -l <"$work/shown-link")" = 1 ] && "$bin/enrollpasskey" -link-file "$work/shown-link" -connect http://127.0.0.1:8686 >/dev/null; then
    pass "terminal: the link $what prints enrolls a passkey"
  else
    fail "terminal: the link $what prints does not work"
  fi
  rm -f "$work/shown-link"
}
link_works "varlatch admin reenroll" /usr/local/bin/varlatch admin reenroll --all
link_works "varlatchd admin recover" /usr/local/bin/varlatchd admin recover --identity "$admin" --config /etc/varlatch/varlatchd.conf
teardown

# Interrupted after each step, then run again: as a run in one go.
for step in answers user data-dir probe keys config unit ready admin key-copies custody backup; do
  export VARLATCH_SETUP_STOP_AFTER="$step"
  setup_once "stop-$step" --ingress localhost
  unset VARLATCH_SETUP_STOP_AFTER
  if ! [ "$status" = 75 ] || ! grep -q "stopped after $step" "$work/stop-$step.out"; then fail "stopped after $step: exited $status: $(tail -n 3 "$work/stop-$step.out")"; fi
  setup_once "resume-$step" --ingress localhost
  if [ "$status" = 0 ] && [ "$(systemctl is-active varlatchd.service)" = active ] && [ -s /etc/varlatch/root-kek ] &&
     grep -q '"firstBackup"' /etc/varlatch/setup.json; then
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
