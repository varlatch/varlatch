#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Checks the shipped varlatchd.service with systemd-analyze (verify, and
# security with a threshold), then runs go/install/unitprobe under it,
# changed only in what it starts (the probe) and in not restarting, and
# fails unless the probe passes every check. It installs a unit, a system user
# and files under /etc: run it as root on a disposable machine only (CI).
#
#   sudo go/install/test-unit.sh <path to the built unitprobe>
set -eu
probe=$1
unit=$(dirname "$0")/varlatchd.service
[ "$(id -u)" = 0 ] || { echo "needs root" >&2; exit 1; }

id varlatch >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin varlatch
install -d -m 755 /etc/varlatch
: > /etc/varlatch/varlatchd.conf
for key in root-kek backup-key; do
  ( umask 077; od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "/etc/varlatch/$key" )
done

# First the shipped unit as it is, with a stand-in for the binary: systemd
# must accept it, and its exposure score must stay at or under 2.0 (1.6
# when written; the threshold is on a scale of 100).
install -m 644 "$unit" /etc/systemd/system/varlatchd.service
[ -e /usr/local/bin/varlatchd ] || printf '#!/bin/sh\nexit 0\n' | install -m 755 /dev/stdin /usr/local/bin/varlatchd
systemd-analyze verify /etc/systemd/system/varlatchd.service
systemd-analyze security --offline=true --threshold=20 /etc/systemd/system/varlatchd.service

# Then the same unit starting the probe.
sed -e 's|^ExecStart=.*|ExecStart=/usr/local/bin/varlatchd-unitprobe|' \
    -e 's|^Restart=on-failure$|Restart=no|' "$unit" > /etc/systemd/system/varlatchd.service
grep -q '^ExecStart=/usr/local/bin/varlatchd-unitprobe$' /etc/systemd/system/varlatchd.service
grep -q '^Restart=no$' /etc/systemd/system/varlatchd.service
install -m 755 "$probe" /usr/local/bin/varlatchd-unitprobe

systemctl daemon-reload
systemctl start varlatchd.service
i=0
while [ "$(systemctl show -p ActiveState --value varlatchd.service)" = active ] || \
      [ "$(systemctl show -p ActiveState --value varlatchd.service)" = activating ]; do
  i=$((i + 1))
  [ $i -lt 120 ] || { echo "the probe did not finish" >&2; exit 1; }
  sleep 1
done
journalctl -u varlatchd.service --no-pager -o cat
result=$(systemctl show -p Result --value varlatchd.service)
status=$(systemctl show -p ExecMainStatus --value varlatchd.service)
echo "result=$result status=$status"
[ "$result" = success ] && [ "$status" = 0 ]
