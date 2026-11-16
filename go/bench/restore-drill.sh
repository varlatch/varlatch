#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The restore drill (ADR-0059 step 4.14, gate G13): a Go archive restored
# into a fresh container that holds only the archive and the two keys.
#
#   restore-drill.sh <varlatchd> <out-dir>
#
# 1. A source installation: a fresh data directory, a Root KEK and a Backup
#    Encryption Key; `varlatchd admin backup run` (offline) creates the
#    installation and takes an archive of it.
# 2. A container from scratch holding varlatchd and nothing else (it is
#    static), with no network, the archive and the two keys mounted
#    read-only and an empty data directory: `varlatchd admin backup
#    restore` restores the archive there.
# 3. Outside, the source's Root KEK opens the restored installation's
#    canary (`admin kek verify`).
#
# It leaves <out-dir>/restored/data and <out-dir>/restored/root-kek, which
# the conformance runner serves with VARLATCH_GO_BINARY_FROM for a full
# run. The image is built here and removed by its name. Docker only; no
# privileges.
set -eu

binary=$1
out=$2
[ -x "$binary" ] || { echo "restore-drill: $binary is not executable" >&2; exit 2; }
[ ! -e "$out" ] || { echo "restore-drill: $out exists; give a new directory" >&2; exit 2; }
umask 077
mkdir -p "$out/source/data" "$out/keys" "$out/restored/data" "$out/context" "$out/in"
key() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; echo; }
key > "$out/keys/root-kek"
key > "$out/keys/backup-key"

cat > "$out/source/varlatchd.conf" <<EOF
listen = 127.0.0.1:0
data_dir = $out/source/data
root_kek_file = $out/keys/root-kek
backup_key_file = $out/keys/backup-key
backup_interval = off
EOF
"$binary" admin backup run --config "$out/source/varlatchd.conf"
set -- "$out"/source/data/backups/*.vltbak
[ "$#" -eq 1 ] && [ -f "$1" ] || { echo "restore-drill: the source made no archive" >&2; exit 1; }
cp "$1" "$out/in/archive.vltbak"

# The container: varlatchd from scratch, no network, the archive and the
# keys read-only, an empty data directory, as this user.
cp "$binary" "$out/context/varlatchd"
printf 'FROM scratch\nCOPY varlatchd /varlatchd\nENTRYPOINT ["/varlatchd"]\n' > "$out/context/Dockerfile"
image="varlatchd-restore-drill:$(od -An -tx1 -N6 /dev/urandom | tr -d ' \n')"
docker build --quiet --tag "$image" "$out/context" > /dev/null
trap 'docker image rm "$image" > /dev/null 2>&1 || true' EXIT
cat > "$out/restored/varlatchd.conf" <<EOF
listen = 127.0.0.1:8686
data_dir = /data
root_kek_file = /keys/root-kek
backup_key_file = /keys/backup-key
backup_interval = off
EOF
docker run --rm --network none --read-only --user "$(id -u):$(id -g)" \
  --volume "$out/in/archive.vltbak:/in/archive.vltbak:ro" \
  --volume "$out/keys:/keys:ro" \
  --volume "$out/restored/varlatchd.conf:/varlatchd.conf:ro" \
  --volume "$out/restored/data:/data" \
  "$image" admin backup restore --in /in/archive.vltbak --config /varlatchd.conf

cp "$out/keys/root-kek" "$out/restored/root-kek"
cat > "$out/restored/check.conf" <<EOF
listen = 127.0.0.1:0
data_dir = $out/restored/data
root_kek_file = $out/restored/root-kek
EOF
"$binary" admin kek verify --config "$out/restored/check.conf"
echo "restore-drill: restored in a fresh container into $out/restored/data"
