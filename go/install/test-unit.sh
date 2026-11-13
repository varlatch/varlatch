#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Checks varlatchd.service on a disposable machine (CI): systemd-analyze
# verify and security (exposure at most 2.0), then go/install/unitprobe run
# as its ExecStart, which must pass every check.
#
#   sudo VARLATCH_TEST_DISPOSABLE_ROOT=1 go/install/test-unit.sh <unitprobe>
#
# It never touches a Varlatch installation: it refuses to start if any
# Varlatch configuration, key, data, unit, binary or user exists, and works
# on a copy of the unit renamed to varlatchd-unittest (its own unit name,
# state directory, /etc directory, user and binaries; nothing else in the
# unit changes, which the script checks). It removes what it created.
set -eu

[ "${VARLATCH_TEST_DISPOSABLE_ROOT:-}" = 1 ] || {
  echo "refusing: set VARLATCH_TEST_DISPOSABLE_ROOT=1, on a disposable machine only" >&2
  exit 2
}
[ "$(id -u)" = 0 ] || { echo "refusing: needs root" >&2; exit 2; }
probe=${1:-}
[ -f "$probe" ] && [ -x "$probe" ] || { echo "refusing: no executable probe at '$probe'" >&2; exit 2; }
unit=$(dirname "$0")/varlatchd.service
[ -f "$unit" ] || { echo "refusing: no $unit" >&2; exit 2; }

T=varlatch-unittest
UNIT=varlatchd-unittest.service
ETC=/etc/$T
STATE=/var/lib/$T
BIN=/usr/local/bin/varlatchd-unittest
LIBDIR=/usr/local/lib/$T
HOMEDIR=/home/$T-fixture

# Nothing of a real installation, nor of an earlier run, may be present.
for p in /etc/varlatch /var/lib/varlatch /var/lib/private/varlatch \
         /etc/systemd/system/varlatchd.service /usr/local/bin/varlatchd /usr/local/bin/varlatch \
         "$ETC" "$STATE" "/var/lib/private/$T" "/etc/systemd/system/$UNIT" "$BIN" "$BIN-probe" "$LIBDIR" "$HOMEDIR"; do
  if [ -e "$p" ] || [ -L "$p" ]; then
    echo "refusing: $p exists" >&2
    exit 2
  fi
done
for u in varlatch "$T"; do
  if id "$u" >/dev/null 2>&1; then
    echo "refusing: user $u exists" >&2
    exit 2
  fi
done

cleanup() {
  systemctl stop "$UNIT" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$UNIT"
  systemctl daemon-reload || true
  rm -rf "$ETC" "$STATE" "/var/lib/private/$T" "$LIBDIR" "$HOMEDIR"
  rm -f "$BIN" "$BIN-probe"
  userdel "$T" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The renamed copy: these substitutions and no other change.
rename() {
  sed -e "s|/etc/varlatch/|$ETC/|g" \
      -e "s|^StateDirectory=varlatch\$|StateDirectory=$T|" \
      -e "s|^User=varlatch\$|User=$T|" \
      -e "s|^Group=varlatch\$|Group=$T|" \
      -e "s|^ExecStart=/usr/local/bin/varlatchd |ExecStart=$BIN |" "$unit"
}
renamed=$(rename)
changed=$(printf '%s\n' "$renamed" | diff "$unit" - | grep -c '^>' || true)
[ "$changed" = 10 ] || { echo "the renamed unit changes $changed lines, not the expected 10" >&2; exit 1; }
if printf '%s\n' "$renamed" | grep -q '/etc/varlatch/\|=varlatch$\|/usr/local/bin/varlatchd '; then
  echo "the renamed unit still names the real installation" >&2
  exit 1
fi

useradd --system --no-create-home --shell /usr/sbin/nologin "$T"
install -d -m 755 "$ETC"
: > "$ETC/varlatchd.conf"
for key in root-kek backup-key; do
  ( umask 077; od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$ETC/$key" )
done

# The unit as shipped (renamed), with a stand-in binary.
printf '%s\n' "$renamed" > "/etc/systemd/system/$UNIT"
printf '#!/bin/sh\nexit 0\n' > "$BIN"
chmod 755 "$BIN"
systemd-analyze verify "/etc/systemd/system/$UNIT"
# The threshold is on a scale of 100: at most 2.0 (1.6 when written).
systemd-analyze security --offline=true --threshold=20 "/etc/systemd/system/$UNIT"

# Fixtures the service user could change or read without the sandbox: its
# own files under /etc and /usr/local, and a world-readable file in /home.
ro="$ETC/owned-by-service"
install -d -m 755 "$LIBDIR"
for f in "$ro" "$LIBDIR/owned-by-service"; do
  : > "$f"
  chown "$T:$T" "$f"
  chmod 600 "$f"
done
install -d -m 755 "$HOMEDIR"
echo readable > "$HOMEDIR/readable"
chmod 644 "$HOMEDIR/readable"

# The same unit starting the probe, without restarts.
install -m 755 "$probe" "$BIN-probe"
printf '%s\n' "$renamed" | sed \
  -e "s|^ExecStart=.*|ExecStart=$BIN-probe -state-dir $STATE -key-file $ETC/root-kek -ro-files $ro,$LIBDIR/owned-by-service -home-file $HOMEDIR/readable|" \
  -e 's|^Restart=on-failure$|Restart=no|' > "/etc/systemd/system/$UNIT"
systemctl daemon-reload
systemctl start "$UNIT"
i=0
while state=$(systemctl show -p ActiveState --value "$UNIT") && { [ "$state" = active ] || [ "$state" = activating ]; }; do
  i=$((i + 1))
  [ $i -lt 120 ] || { echo "the probe did not finish" >&2; exit 1; }
  sleep 1
done
journalctl -u "$UNIT" --no-pager -o cat
result=$(systemctl show -p Result --value "$UNIT")
status=$(systemctl show -p ExecMainStatus --value "$UNIT")
echo "result=$result status=$status"
[ "$result" = success ] && [ "$status" = 0 ]
