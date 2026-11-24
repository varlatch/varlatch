#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# `varlatch upgrade` on a disposable machine with systemd (CI's runner VM;
# ADR-0059 step 6, slices 6.6b and 6.6c), with the unit, the users and the
# paths a host has:
#
#   sudo VARLATCH_TEST_DISPOSABLE_ROOT=1 go/install/test-upgrade.sh <build-upgrade.sh's directory>
#
# 1. The last published prerelease, installed by its own install.sh, its
#    release checked as install.sh checks it; set up, with data.
# 2. It is upgraded to the candidate (this checkout) by its own varlatch, as
#    people do it: that release's engine, its journal and its health checks.
#    First killed on the way, then restarted as by a reboot and finished by
#    the varlatch that is installed then, as an operator would.
#    Where the candidate has upgrade --rollback, a rollback to a release that
#    cannot read one's journal is refused with the steps by hand, which are
#    then taken, and it is upgraded again, by the candidate's varlatch.
# 3. The candidate to a release that never serves: undone.
# 4. The candidate to the next release, killed at each step, then a restart
#    as a reboot makes it, then upgrade run again: the previous release
#    serves, or the next one, with the data, and nothing of root's is in the
#    data directory. A write between the kill and the rerun that is accepted
#    must be there after it. Where varlatchd reads the upgrade's journal at its
#    start (GATE below), it serves nothing in between; without that, a lost
#    write is said (KNOWN) and is no failure.
# 5. Where there is upgrade --rollback: the binaries alone (a change made since
#    stays), then the snapshot (a change made since is lost, and only with
#    --accept-data-loss).
# 6. Uninstalled as docs/reference/uninstall.md says: nothing is left.
# 7. The candidate on the emptied host: set up on a terminal (setupterminal,
#    which acts only on what it shows), a backup, the host emptied, setup
#    --restore, doctor; where a restored installation is held, an upgrade is
#    refused until it is resumed. Uninstalled again.
#
# It touches only a disposable machine: it refuses to start unless
# VARLATCH_TEST_DISPOSABLE_ROOT=1, as root, with nothing of a Varlatch
# installation present, and removes all it made. upgrade-systemd.yml runs it on
# GitHub-hosted runners only. It downloads the published prerelease from
# GitHub, and nothing else leaves the machine.
#
# shellcheck disable=SC2329,SC2016 # what check and must call; what another sh expands
set -eu

[ "${VARLATCH_TEST_DISPOSABLE_ROOT:-}" = 1 ] || {
  echo "refusing: set VARLATCH_TEST_DISPOSABLE_ROOT=1, on a disposable machine only" >&2
  exit 2
}
[ "$(id -u)" = 0 ] || { echo "refusing: needs root" >&2; exit 2; }
built=${1:-}
for f in bin/fakegithub bin/enrollpasskey bin/setupterminal from/varlatch versions; do
  [ -f "$built/$f" ] || { echo "refusing: no $f in '$built' (build-upgrade.sh makes it)" >&2; exit 2; }
done
built=$(cd "$built" && pwd)
unit=$(cd "$(dirname "$0")" && pwd)/varlatchd.service
[ -f "$unit" ] || { echo "refusing: no $unit" >&2; exit 2; }
FROM='' CANDIDATE='' NEXT='' UNSAFE='' BROKEN=''
# shellcheck source=/dev/null
. "$built/versions"

# The published prerelease to start from: its install.sh's hash, which is in
# its signed SHA256SUMS. install.sh checks the rest itself.
case "$FROM" in
  0.50.0-rc.2) FROM_INSTALL=82ca234af771ada287d7074077afc759d3204180665edb6765ed087dd6068ed7 ;;
  *) echo "refusing: this script has no hash of $FROM's install.sh" >&2; exit 2 ;;
esac
# Whether the candidate's varlatchd refuses to serve while an upgrade is not
# over (its journal says it may be half done).
GATE=${VARLATCH_TEST_UPGRADE_GATE:-1}
# The steps at which an upgrade is killed, in order (upgrade.go's crash points);
# from the last on it is finished, before it undone.
KILLS="verified snapshot stopping stop:done stopped prepared data:keep-original:link:varlatch.db kept install:$NEXT:varlatchd install:$NEXT:varlatch installed data:swap:rename:varlatch.db swapped start:$NEXT started checked"
# And in an undo, of a release that never serves; from the second on it may
# have put the files back, which is not done twice.
UNDOS="undo:stopped data:put-back:rename:varlatch.db undo:files-back install:$NEXT:varlatchd undo:binaries-back start:$NEXT undo:checked undone"

LEFT='/etc/varlatch /var/lib/varlatch /var/lib/private/varlatch /etc/systemd/system/varlatchd.service /usr/local/bin/varlatchd /usr/local/bin/varlatch /usr/local/lib/varlatch'
# Nothing of it is there (what is is in $there).
host_is_empty() {
  there=''
  for p in $LEFT; do
    if [ -e "$p" ] || [ -L "$p" ]; then there="$there $p"; fi
  done
  if id varlatch >/dev/null 2>&1; then there="$there user:varlatch"; fi
  if getent group varlatch >/dev/null 2>&1; then there="$there group:varlatch"; fi
  [ -z "$there" ]
}
if ! host_is_empty; then
  echo "refusing: this machine has$there" >&2
  exit 2
fi

work=$(mktemp -d)
chmod 700 "$work"
mkdir -m 700 "$work/home" "$work/repo" "$work/source" "$work/saved"
github=''

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
  if [ -n "$github" ]; then kill "$github" 2>/dev/null || true; fi
  rm -f /etc/systemd/system/varlatchd.service /usr/local/bin/varlatchd /usr/local/bin/varlatch
  rm -rf /usr/local/lib/varlatch "$work"
  systemctl daemon-reload || true
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

failures=0
fail() { echo "FAIL  $*" >&2; failures=$((failures + 1)); }
pass() { echo "PASS  $*"; }
check() { # <what> <command...>: it holds
  what=$1
  shift
  if "$@"; then pass "$what"; else fail "$what"; fi
}
finish() {
  if [ "$failures" -gt 0 ]; then
    echo "$failures checks failed" >&2
    exit 1
  fi
  echo "every check passed"
  exit 0
}
# must <what> <command...>: the rest needs it.
must() {
  check "$@"
  if [ "$failures" -gt 0 ]; then finish; fi
}

CONF=/etc/varlatch/varlatchd.conf URL=http://127.0.0.1:8686
VARLATCH=/usr/local/bin/varlatch VARLATCHD=/usr/local/bin/varlatchd
# The client is the candidate's, whatever the host runs, with its own home.
client_bin=$built/releases/$CANDIDATE/$(cd "$built/releases/$CANDIDATE" && echo varlatch-*)
chmod 755 "$client_bin"
# It waits out a 503 by itself, for longer than a check here.
client() { (cd "$work/repo" && HOME="$work/home" VARLATCH_TOKEN="$(cat "$work/token")" timeout 10 "$client_bin" "$@"); }

# --- what must hold of the host ---

ready() {
  for _ in $(seq 1 60); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "$URL/readyz" || true)" = 200 ]; then return 0; fi
    sleep 1
  done
  return 1
}
not_answering() { [ "$(curl -s -o /dev/null -m 5 -w '%{http_code}' "$URL/readyz" || true)" != 200 ]; }
# The release installed, and the one that answers.
serves() {
  ready && [ "$("$VARLATCHD" --version)" = "varlatchd $1" ] && [ "$("$VARLATCH" --version)" = "varlatch $1" ] &&
    curl -s "$URL/v1/meta" | grep -qF "\"serverVersion\":\"$1\"" && [ "$(systemctl is-active varlatchd.service)" = active ]
}
# What a run gives a command for an item: its value, or absent. Nothing when
# the run itself fails.
value() { client run -e development -- sh -c 'printenv "$1" || echo absent' sh "$1" 2>/dev/null || true; }
has() { [ "$(value "$1")" = "value-of-$1" ]; }
has_not() { [ "$(value "$1")" = absent ]; }
put() { printf 'value-of-%s' "$1" | client values set "$1" --stdin -e development >/dev/null 2>&1; }
journal_says() { grep -q "\"state\": *\"$1\"" /etc/varlatch/upgrade.json 2>/dev/null; }
# varlatchd runs as varlatch: a file of root's in its directory is one it may
# not be able to open.
data_is_varlatchs() { [ -z "$(find /var/lib/varlatch ! -user varlatch -print -quit)" ]; }
keys_are_roots() { [ "$(stat -c '%a %U:%G' /etc/varlatch/root-kek /etc/varlatch/backup-key | sort -u)" = '600 root:root' ]; }
says() { grep -qF -- "$2" "$work/$1.out" && return 0; tail -n 8 "$work/$1.out" >&2; return 1; }
no_key_in() {
  for k in /etc/varlatch/root-kek /etc/varlatch/backup-key; do
    if grep -qF -- "$(tr -d '\n' <"$k")" "$@" 2>/dev/null; then return 1; fi
  done
}
doctor() { "$VARLATCH" doctor --config "$CONF" >"$work/doctor.txt" 2>&1 || { cat "$work/doctor.txt" >&2; return 1; }; }
has_hold() { "$client_bin" admin --help 2>/dev/null | grep -q 'restore resume'; }
held() { curl -s "$URL/readyz" | grep -q '"held": *true' && "$VARLATCHD" admin restore status --config "$CONF" >"$work/hold.txt" 2>&1; }
not_held() { ready && ! curl -s "$URL/readyz" | grep -q '"held": *true'; }
has_rollback() { "$client_bin" upgrade --help 2>/dev/null | grep -q -- --rollback; }

# upgrade <name> <binary> <arguments...>: its output in $work/<name>.out, its
# status in $status.
upgrade() {
  into=$1 binary=$2
  shift 2
  set +e
  HOME="$work/home" VARLATCH_TEST_SELFUPDATE_SOURCE="$work/source/source.json" "$binary" upgrade "$@" </dev/null >"$work/$into.out" 2>&1
  status=$?
  set -e
}
upgraded() { # <name> <release>: the last upgrade ended so
  if [ "$status" != 0 ]; then tail -n 8 "$work/$1.out" >&2; fi
  check "$1: exits 0" [ "$status" = 0 ]
  check "$1: $2 serves" serves "$2"
  check "$1: the journal says done" journal_says "done"
  check "$1: the data directory is varlatch's" data_is_varlatchs
  check "$1: the keys are root's" keys_are_roots
}

# As a reboot finds the host: varlatchd killed, then started by its unit.
restarted() {
  systemctl kill -s KILL varlatchd.service >/dev/null 2>&1 || true
  systemctl stop varlatchd.service >/dev/null 2>&1 || true
  systemctl reset-failed varlatchd.service >/dev/null 2>&1 || true
  systemctl start varlatchd.service >/dev/null 2>&1 || true
}

# --- installing and setting up ---

setup_flags="--backups host --accept-slow-disk --attest --admin-wait 0s --admin-link-out $work/link --root-kek-out $work/root-kek --backup-key-out $work/backup-key"
# set_up <command...>: run until it is done, the passkey enrolled when it asks.
set_up() {
  for _ in 1 2 3; do
    set +e
    # shellcheck disable=SC2086 # flags, split on purpose
    "$@" --ingress localhost $setup_flags </dev/null >>"$work/setup.out" 2>&1
    status=$?
    set -e
    [ "$status" = 75 ] && [ -f "$work/link" ] || break
    "$built/bin/enrollpasskey" -link-file "$work/link" -connect "$URL" >/dev/null || return 1
    # A rerun is setup's own, not install.sh's.
    set -- "$VARLATCH" setup
  done
  if [ "$status" != 0 ]; then tail -n 8 "$work/setup.out" >&2; return 1; fi
}
# A CLI credential of the administrator's, and the project the data is in.
sign_in() {
  admin=$("$VARLATCHD" admin bootstrap-status --config "$CONF" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
  (umask 077; "$VARLATCHD" admin recover --identity "$admin" --cli-credential --config "$CONF" 2>/dev/null | tail -n 1 >"$work/token")
  grep -q '^vlt_' "$work/token"
}
make_data() {
  printf 'organization = "acme"\nproject = "web"\nserver = "%s"\ndefault_environment = "development"\n' "$URL" >"$work/repo/varlatch.toml"
  client org create acme --server "$URL" >/dev/null && client project create web --org acme --server "$URL" >/dev/null &&
    client env-create development --tier development >/dev/null && put FIRST
}
# As docs/reference/uninstall.md says.
uninstall() {
  systemctl disable --now varlatchd >/dev/null 2>&1
  rm /etc/systemd/system/varlatchd.service
  systemctl daemon-reload
  rm -r /etc/varlatch /var/lib/varlatch
  rm -rf /usr/local/lib/varlatch
  rm /usr/local/bin/varlatch /usr/local/bin/varlatchd
  userdel varlatch
}

"$built/bin/fakegithub" -releases "$built/releases" -source "$work/source" >"$work/github.out" 2>"$work/github.err" &
github=$!
for _ in $(seq 1 50); do grep -q serving "$work/github.out" && break; sleep 0.1; done
must "the releases are served" [ -s "$work/source/source.json" ]

# --- 1. the published prerelease ---

curl -fsSL --retry 5 -o "$work/install.sh" "https://github.com/varlatch/varlatch/releases/download/v$FROM/install.sh"
must "$FROM's install.sh is the published one" [ "$(sha256sum "$work/install.sh" | cut -d' ' -f1)" = "$FROM_INSTALL" ]
must "$FROM: installed by its install.sh and set up" set_up sh "$work/install.sh" --server --
must "$FROM serves" serves "$FROM"
must "$FROM: a CLI credential" sign_in
must "$FROM: data" make_data
must "$FROM: the data is read back" has FIRST

# --- 2. to the candidate ---

# past <step>: an upgrade is under way, its journal at that step or further
# (the step is in $at).
past() {
  journal_says in-progress || return 1
  at=$(sed -n 's/.*"step": *"\([^"]*\)".*/\1/p' /etc/varlatch/upgrade.json 2>/dev/null || true)
  seen=no
  for s in verified snapshot stopping stopped prepared swapped started checked; do
    if [ "$s" = "$1" ]; then seen=yes; fi
    if [ "$seen $s" = "yes $at" ]; then return 0; fi
  done
  return 1
}
# Beside the installed varlatchd. $FROM's own engine, and not the candidate's.
tool=/usr/local/bin/varlatch-upgrade-test
trap 'rm -f "$tool"; cleanup' EXIT
install -m 755 "$built/from/varlatch" "$tool"
must "to-candidate: upgraded by $FROM's varlatch" [ "$("$tool" --version)" = "varlatch $FROM" ]
# It has no crash points: it is killed once its journal is at a step, which
# it may have gone on from meanwhile.
for step in stopped swapped started; do
  name=from-kill-$step
  HOME="$work/home" VARLATCH_TEST_SELFUPDATE_SOURCE="$work/source/source.json" "$tool" upgrade "$CANDIDATE" --yes --accept-not-rollback-safe </dev/null >"$work/$name.out" 2>&1 &
  engine=$!
  for _ in $(seq 1 6000); do
    if past "$step" || ! kill -0 "$engine" 2>/dev/null; then break; fi
    sleep 0.01
  done
  kill -KILL "$engine" 2>/dev/null || true
  wait "$engine" 2>/dev/null || true
  check "$name: killed on the way" journal_says in-progress
  echo "      at $at, $("$VARLATCH" --version) installed"
  restarted
  upgrade "$name-again" "$VARLATCH"
  if [ "$status" != 0 ]; then tail -n 8 "$work/$name-again.out" >&2; fi
  check "$name: finished by the installed varlatch: it exits 0" [ "$status" = 0 ]
  if journal_says undone; then
    check "$name: undone: $FROM serves" serves "$FROM"
  else
    # It got through its checks before the kill.
    check "$name: finished: $CANDIDATE serves" serves "$CANDIDATE"
  fi
  check "$name: the data is there" has FIRST
  check "$name: the data directory is varlatch's" data_is_varlatchs
  if [ "$failures" -gt 0 ] || ! journal_says undone; then break; fi
done
if [ "$failures" -gt 0 ]; then finish; fi
must "from-kill: $FROM serves, to go on from" serves "$FROM"
upgrade to-candidate "$tool" "$CANDIDATE" --yes --accept-not-rollback-safe
upgraded to-candidate "$CANDIDATE"
must "to-candidate: the data is there" has FIRST
put SECOND
check "to-candidate: the snapshot is kept" test -n "$(find /var/lib/varlatch/upgrades -name 'snapshot*' -print -quit)"

install -m 755 "$client_bin" "$tool"
if has_rollback; then
  before=$(sha256sum /etc/varlatch/upgrade.json "$VARLATCH" "$VARLATCHD")
  upgrade by-hand "$tool" --rollback --yes --accept-data-loss
  check "by-hand: a rollback to $FROM is refused" [ "$status" != 0 ]
  check "by-hand: it gives the steps" says by-hand "By hand, losing every change made since the upgrade:"
  check "by-hand: nothing changed" [ "$before" = "$(sha256sum /etc/varlatch/upgrade.json "$VARLATCH" "$VARLATCHD")" ]
  check "by-hand: $CANDIDATE still serves" serves "$CANDIDATE"
  # The steps as printed, one command each, and nothing else.
  sed -n 's/^  sudo //p' "$work/by-hand.out" >"$work/by-hand.sh"
  check "by-hand: the steps stop varlatchd first and start it last" [ "$(sed -n '1p;$p' "$work/by-hand.sh" | tr '\n' ' ')" = 'systemctl stop varlatchd systemctl start varlatchd ' ]
  if sh -e "$work/by-hand.sh" >"$work/by-hand-steps.out" 2>&1; then
    check "by-hand: $FROM serves again" serves "$FROM"
    check "by-hand: the data from before the upgrade is there" has FIRST
    check "by-hand: what changed since is lost, as it says" has_not SECOND
    check "by-hand: the data directory is varlatch's" data_is_varlatchs
    check "by-hand: varlatch doctor passes" doctor
  else
    fail "by-hand: a step: $(tail -n 4 "$work/by-hand-steps.out")"
  fi
  if [ "$failures" -gt 0 ]; then finish; fi
  touch "$work/now"
  upgrade to-candidate-again "$tool" "$CANDIDATE" --yes
  upgraded to-candidate-again "$CANDIDATE"
  # The new engine's snapshot is root's, out of varlatchd's reach.
  check "snapshot: root's, in a directory of its own" [ "$(find /usr/local/lib/varlatch/snapshots -name snapshot.vltbak -newer "$work/now" -exec stat -c '%a %U' {} +)" = '600 root' ]
  check "snapshot: the directories are root's alone" [ "$(find /usr/local/lib/varlatch/snapshots -type d -exec stat -c '%a %U' {} + | sort -u)" = '700 root' ]
  check "snapshot: none in the data directory" [ -z "$(find /var/lib/varlatch/upgrades -name 'snapshot*' -newer "$work/now" -print -quit)" ]
  put SECOND
else
  echo "SKIP  by-hand: this candidate has no upgrade --rollback"
fi
must "the candidate has the data" has SECOND

# --- 3. to a release that never serves ---

upgrade broken "$VARLATCH" "$BROKEN" --yes
check "broken: exits with a failure" [ "$status" != 0 ]
check "broken: it says that it was undone" says broken "it was undone: $CANDIDATE serves"
check "broken: $CANDIDATE serves" serves "$CANDIDATE"
check "broken: the journal says undone" journal_says undone
check "broken: the data is there" has SECOND
check "broken: the data directory is varlatch's" data_is_varlatchs
if [ "$failures" -gt 0 ]; then finish; fi

# --- 4. killed at each step ---

for point in $KILLS; do
  name=$(echo "kill-$point" | tr ':' '-')
  export VARLATCH_TEST_UPGRADE_KILL="$point"
  upgrade "$name" "$VARLATCH" "$NEXT" --yes
  unset VARLATCH_TEST_UPGRADE_KILL
  # A kill in the child that works in the data directory ends its parent.
  case "$point" in
    data:*) check "$name: killed there" [ "$status" = 1 ] ;;
    *) check "$name: killed there" [ "$status" = 137 ] ;;
  esac
  check "$name: the journal says in progress" journal_says in-progress
  restarted
  step=$(sed -n 's/.*"step": *"\([^"]*\)".*/\1/p' /etc/varlatch/upgrade.json)
  case "$GATE $step" in
    '1 stopping' | '1 stopped' | '1 prepared' | '1 kept' | '1 installed' | '1 swapped' | '1 started')
      check "$name: varlatchd serves nothing until the upgrade is over" not_answering
      ;;
  esac
  # A client's write, if it is taken. The release that takes it may not be
  # ready at once: it is tried for a few seconds.
  item=MEANWHILE_$(echo "$point" | tr -c 'A-Za-z0-9\n' _ | tr '[:lower:]' '[:upper:]')
  written=no
  for _ in 1 2; do
    if put "$item"; then written=yes; break; fi
    sleep 1
  done
  upgrade "$name-again" "$VARLATCH"
  if [ "$status" != 0 ]; then tail -n 8 "$work/$name-again.out" >&2; fi
  check "$name: run again, it exits 0" [ "$status" = 0 ]
  if [ "$point" = checked ]; then
    check "$name: finished: $NEXT serves" serves "$NEXT"
    check "$name: the journal says done" journal_says "done"
  else
    check "$name: undone: $CANDIDATE serves" serves "$CANDIDATE"
    check "$name: the journal says undone" journal_says undone
  fi
  check "$name: the data is there" has SECOND
  check "$name: the data directory is varlatch's" data_is_varlatchs
  check "$name: varlatch doctor passes" doctor
  if [ "$written" = no ]; then
    pass "$name: no write was taken in between"
  else
    # Undone, the previous database is as it was: a write the next release's
    # copy took is in it only when that copy's write-ahead log was read into
    # it. Before the copy is in its place, and once finished, it must be there.
    case "$point" in
      swap:database-in | install:* | installed | data:swap:* | swapped | start:* | started)
        if has "$item"; then wrong='is in the previous database, from the other one'; else wrong='is lost'; fi
        ;;
      *) if has "$item"; then wrong=''; else wrong='is lost'; fi ;;
    esac
    if [ -z "$wrong" ]; then
      pass "$name: a write taken in between is there"
    elif [ "$GATE" = 1 ]; then
      fail "$name: a write taken in between $wrong"
    else
      echo "KNOWN $name: a write taken in between $wrong (varlatchd serves while the upgrade is not over)"
    fi
  fi
  if [ "$failures" -gt 0 ]; then finish; fi
done

# --- 4b. killed in an undo ---

for point in $UNDOS; do
  name=$(echo "undo-$point" | tr ':' '-')
  export VARLATCH_TEST_UPGRADE_KILL="$point"
  upgrade "$name" "$VARLATCH" "$BROKEN" --yes
  unset VARLATCH_TEST_UPGRADE_KILL
  case "$point" in
    data:*) check "$name: killed there" [ "$status" = 1 ] ;;
    *) check "$name: killed there" [ "$status" = 137 ] ;;
  esac
  restarted
  item=UNDO_$(echo "$point" | tr -c 'A-Za-z0-9\n' _ | tr '[:lower:]' '[:upper:]')
  written=no
  for _ in 1 2; do
    if put "$item"; then written=yes; break; fi
    sleep 1
  done
  over=no
  if journal_says undone; then over=yes; fi
  if [ "$over" = no ]; then
    check "$name: varlatchd serves nothing until the upgrade is over" [ "$written" = no ]
    upgrade "$name-again" "$VARLATCH"
    if [ "$status" != 0 ]; then tail -n 8 "$work/$name-again.out" >&2; fi
    check "$name: run again, it exits 0" [ "$status" = 0 ]
  fi
  check "$name: undone: $NEXT serves" serves "$NEXT"
  check "$name: the journal says undone" journal_says undone
  check "$name: the data is there" has SECOND
  check "$name: the data directory is varlatch's" data_is_varlatchs
  if [ "$written" = yes ]; then check "$name: a write taken in between is there" has "$item"; fi
  if [ "$failures" -gt 0 ]; then finish; fi
done

# --- 5. the rollback ---

# killed_rollback <name> <point> <arguments...>: a rollback killed there, then
# a restart; what it left, and what it goes to, in $left and $to. Run again,
# it is undone, or finished once it is checked.
killed_rollback() {
  name=$1 point=$2
  shift 2
  export VARLATCH_TEST_UPGRADE_KILL="$point"
  upgrade "$name" "$VARLATCH" --rollback "$@"
  unset VARLATCH_TEST_UPGRADE_KILL
  case "$point" in
    data:*) check "$name: killed there" [ "$status" = 1 ] ;;
    *) check "$name: killed there" [ "$status" = 137 ] ;;
  esac
  check "$name: the journal says in progress" journal_says in-progress
  restarted
  step=$(sed -n 's/.*"step": *"\([^"]*\)".*/\1/p' /etc/varlatch/upgrade.json | head -n 1)
  if [ "$step" != checked ]; then
    check "$name: varlatchd serves nothing until the rollback is over" not_answering
  fi
  upgrade "$name-again" "$VARLATCH"
  if [ "$status" != 0 ]; then tail -n 8 "$work/$name-again.out" >&2; fi
  check "$name: run again, it exits 0" [ "$status" = 0 ]
  if [ "$step" = checked ]; then
    check "$name: finished: $to serves" serves "$to"
    check "$name: the journal is the rollback's" grep -q '"kind": *"rollback"' /etc/varlatch/upgrade.json
  else
    check "$name: undone: $left serves" serves "$left"
    check "$name: the journal is the upgrade's again" sh -c '! grep -q "^  \"kind\": *\"rollback\"" "$1" && grep -q "\"lastRollback\"" "$1"' sh /etc/varlatch/upgrade.json
  fi
  check "$name: the journal says done" journal_says "done"
  check "$name: the data is there" has THIRD
  check "$name: the data directory is varlatch's" data_is_varlatchs
  check "$name: the keys are root's" keys_are_roots
  check "$name: varlatch doctor passes" doctor
  if [ "$failures" -gt 0 ]; then finish; fi
}

if has_rollback; then
  put THIRD
  left=$NEXT to=$CANDIDATE
  for at_point in stopping stop:done stopped prepared "install:$CANDIDATE:varlatchd" "install:$CANDIDATE:varlatch" installed swapped "start:$CANDIDATE" started checked; do
    killed_rollback "$(echo "rollback-$at_point" | tr ':' '-')" "$at_point" --yes
  done
  check "rollback: the binaries alone: a change made since is kept" has THIRD
  upgrade to-next-again "$VARLATCH" "$NEXT" --yes
  upgraded to-next-again "$NEXT"
  upgrade rollback "$VARLATCH" --rollback --yes
  upgraded rollback "$CANDIDATE"
  check "rollback: not killed: a change made since is kept" has THIRD
  upgrade unsafe-refused "$VARLATCH" "$UNSAFE" --yes
  check "unsafe: refused unless accepted" [ "$status" != 0 ]
  upgrade unsafe "$VARLATCH" "$UNSAFE" --yes --accept-not-rollback-safe
  upgraded unsafe "$UNSAFE"
  put FOURTH
  upgrade loss-refused "$VARLATCH" --rollback --yes
  check "snapshot: refused without --accept-data-loss" [ "$status" != 0 ]
  check "snapshot: $UNSAFE still serves" serves "$UNSAFE"
  check "snapshot: the change is still there" has FOURTH
  left=$UNSAFE
  for at_point in stopping stop:done stopped prepared data:keep-original:link:varlatch.db kept "install:$CANDIDATE:varlatchd" "install:$CANDIDATE:varlatch" installed rollback:restored swapped "start:$CANDIDATE" started checked; do
    # Off a terminal --accept-data-loss is enough.
    killed_rollback "$(echo "loss-$at_point" | tr ':' '-')" "$at_point" --accept-data-loss
    if [ "$at_point" != checked ]; then check "loss-$at_point: the change is still there" has FOURTH; fi
  done
  check "snapshot: what was there before the upgrade is there" has THIRD
  check "snapshot: what changed since is lost, as it says" has_not FOURTH
  if has_hold; then
    # It is a restore too.
    check "snapshot: held until it is resumed" held
    check "snapshot: resumed" "$VARLATCH" admin restore resume --config "$CONF"
  fi
  upgrade after-loss "$VARLATCH" "$NEXT" --yes
  upgraded after-loss "$NEXT"
else
  echo "SKIP  rollback: this candidate has no upgrade --rollback"
fi
journalctl -u varlatchd.service --no-pager >"$work/journal.txt" 2>&1 || true
check "no key in an upgrade's output, its journal or the unit's" no_key_in "$work"/*.out "$work/journal.txt" /etc/varlatch/upgrade.json
check "varlatch doctor passes" doctor

# --- 6. uninstalled ---

rm -f "$tool"
uninstall
if host_is_empty; then pass "uninstalled: nothing is left"; else fail "uninstalled: left:$there"; fi
if [ "$failures" -gt 0 ]; then finish; fi

# --- 7. the candidate on an empty host ---

install -m 755 "$client_bin" "$VARLATCH"
install -m 755 "$built/releases/$CANDIDATE"/varlatchd-* "$VARLATCHD"
install -m 644 "$unit" /etc/systemd/system/varlatchd.service
systemctl daemon-reload
set +e
"$built/bin/setupterminal" -enrollpasskey "$built/bin/enrollpasskey" -connect "$URL" -link-file "$work/terminal-link" \
  -public-url https://vault.varlatch.test "$VARLATCH" >"$work/terminal.out" 2>&1
status=$?
set -e
check "terminal: setup ends well, the link and both keys as it showed them" [ "$status" = 0 ]
must "terminal: $CANDIDATE serves" serves "$CANDIDATE"
check "terminal: a backup" sh -c '"$1" admin backup run --json >"$2"' sh "$VARLATCH" "$work/backup.json"
archive=$(sed -n 's/.*"path": *"\([^"]*\.vltbak\)".*/\1/p' "$work/backup.json" | head -n 1)
cp "$archive" "$work/saved/archive.vltbak"
cp /etc/varlatch/root-kek /etc/varlatch/backup-key "$work/saved/"
admin=$("$VARLATCHD" admin bootstrap-status --config "$CONF" | grep -o '"id":"[^"]*"')
teardown
set +e
"$VARLATCH" setup --ingress proxy --public-url https://vault.varlatch.test --backups host --accept-slow-disk --attest --admin-wait 0s \
  --admin-link-out "$work/restore-link" --restore "$work/saved/archive.vltbak" \
  --root-kek-file "$work/saved/root-kek" --backup-key-file "$work/saved/backup-key" </dev/null >"$work/restore.out" 2>&1
status=$?
set -e
if [ "$status" != 0 ]; then tail -n 8 "$work/restore.out" >&2; fi
must "restore: setup --restore onto the emptied host exits 0" [ "$status" = 0 ]
check "restore: $CANDIDATE serves" serves "$CANDIDATE"
check "restore: the administrator is back" sh -c '"$1" admin bootstrap-status --config "$2" | grep -qF "$3,\"enabled\":true,\"hasPasskey\":true"' sh "$VARLATCHD" "$CONF" "$admin"
check "restore: varlatch doctor passes" doctor
if has_hold; then
  # What the archive holds may be undone since: the work waits for the
  # operator, and so does an upgrade.
  check "hold: a restored installation is held" held
  install -m 755 "$client_bin" "$tool"
  upgrade held "$tool" "$NEXT" --yes
  check "hold: an upgrade is refused" [ "$status" != 0 ]
  check "hold: it says what to run" says held "restore resume"
  check "hold: $CANDIDATE still serves, held" held
  check "hold: resumed" "$VARLATCH" admin restore resume --config "$CONF"
  check "hold: it is held no more" not_held
  upgrade resumed "$tool" "$NEXT" --yes
  upgraded resumed "$NEXT"
  check "hold: not held after the upgrade" not_held
  rm -f "$tool"
else
  echo "SKIP  hold: this candidate holds no restored installation"
fi
check "restore: no key in an output" no_key_in "$work/terminal.out" "$work/restore.out" "$work/backup.json"
uninstall
if host_is_empty; then pass "uninstalled again: nothing is left"; else fail "uninstalled again: left:$there"; fi
finish
