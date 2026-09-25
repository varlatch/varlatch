#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# One-time interactive install of the Varlatch root backup timer on the
# installation host. Read it, then run it from this directory WITH SUDO:
#
#   sudo ./install.sh <compose-dir> [<compose-file-name>]
#
# <compose-dir> is the running installation's Compose directory, the one
# holding its compose file and .env (e.g. /srv/varlatch; on Coolify
# /data/coolify/applications/<uuid>). `docker compose ls` shows the directory
# and the file(s) each running project was started with.
#
# This script deliberately does NOT create key material. After it runs, you
# place these files yourself (see README.md), all root:root mode 0600:
#   /etc/varlatch-backup/bek            32-byte hex/base64 Backup Encryption Key
#   /etc/varlatch-backup/root-kek       copy of the Root KEK
#   /etc/varlatch-backup/s3-write.json  {"accessKeyId":"...","secretAccessKey":"..."}
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
COMPOSE_DIR="${1:?usage: sudo ./install.sh <compose-dir> [<compose-file-name>]}"
COMPOSE_DIR=$(cd "$COMPOSE_DIR" && pwd)

# --- Compose file ---
# docker compose auto-discovers only the default names; a directory holding
# several compose files (variants, generated copies) is ambiguous, so the
# running file must then be named explicitly. It is recorded as COMPOSE_FILE
# for every later call. Override files are merged by compose itself.
COMPOSE_FILE_NAME="${2:-}"
if [ -n "$COMPOSE_FILE_NAME" ]; then
  [ -f "$COMPOSE_DIR/$COMPOSE_FILE_NAME" ] || { echo "$COMPOSE_DIR has no $COMPOSE_FILE_NAME" >&2; exit 1; }
else
  mapfile -t CANDIDATES < <(find "$COMPOSE_DIR" -maxdepth 1 -type f \( -name '*compose*.yml' -o -name '*compose*.yaml' \) ! -name '*.override.*' -printf '%f\n' | sort)
  case "${#CANDIDATES[@]}" in
    0) echo "$COMPOSE_DIR has no compose file" >&2; exit 1 ;;
    1) case "${CANDIDATES[0]}" in
         compose.yaml|compose.yml|docker-compose.yaml|docker-compose.yml) ;;  # auto-discovered
         *) COMPOSE_FILE_NAME="${CANDIDATES[0]}" ;;
       esac ;;
    *) echo "Several compose files in $COMPOSE_DIR (${CANDIDATES[*]}); name the running one, e.g.:" >&2
       echo "  sudo ./install.sh $COMPOSE_DIR ${CANDIDATES[0]}" >&2; exit 1 ;;
  esac
fi
if [ -n "$COMPOSE_FILE_NAME" ]; then export COMPOSE_FILE="$COMPOSE_DIR/$COMPOSE_FILE_NAME"; fi

# --- Prerequisites ---
docker compose version >/dev/null 2>&1 || { echo "Docker with the compose plugin (v2) is required" >&2; exit 1; }
(cd "$COMPOSE_DIR" && docker compose config --services 2>/dev/null | grep -qx varlatchd) \
  || { echo "No varlatchd service in the compose project at $COMPOSE_DIR${COMPOSE_FILE:+ ($COMPOSE_FILE)}" >&2; exit 1; }
if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 22 ]; then
  echo "Node.js 22 or newer is required on the host (it runs the operator CLI)." >&2
  echo "Install it from your distribution or https://nodejs.org/en/download (package managers)." >&2
  exit 1
fi
# Current images ship the scripts and CLI, which run.sh takes from the running
# container on every run. Older images need a host copy of the release CLI.
# (Into a temp dir: docker compose cp refuses device targets like /dev/null.)
PROBE=$(mktemp -d)
if (cd "$COMPOSE_DIR" && docker compose cp varlatchd:/opt/varlatch/varlatch.cjs "$PROBE/") >/dev/null 2>&1; then IMAGE_CLI=1; else IMAGE_CLI=""; fi
rm -rf "$PROBE"
if [ -z "$IMAGE_CLI" ] && [ ! -f /usr/local/bin/varlatch ] && [ ! -f /opt/varlatch/cli/apps/cli/dist/main.js ]; then
  echo "varlatchd is not running, or its image predates the shipped CLI. For older" >&2
  echo "releases install the release CLI first (docs/operations/backup.md):" >&2
  echo "  sudo install -m 755 varlatch-cli-<version>.cjs /usr/local/bin/varlatch" >&2
  exit 1
fi

# --- Config directory (keys are placed manually afterwards) ---
install -d -m 700 /etc/varlatch-backup
[ -f /etc/varlatch-backup/config.env ] || cat > /etc/varlatch-backup/config.env <<EOF
COMPOSE_DIR=$COMPOSE_DIR
${COMPOSE_FILE:+COMPOSE_FILE=$COMPOSE_FILE}
DESTINATION=offsite
LOCAL_KEEP=7
EOF
if [ ! -f /etc/varlatch-backup/destinations.json ]; then
  cat > /etc/varlatch-backup/destinations.json <<'EOF'
{
  "offsite": {
    "endpoint": "https://YOUR-S3-ENDPOINT",
    "region": "YOUR-REGION",
    "bucket": "YOUR-BUCKET",
    "prefix": "production/",
    "forcePathStyle": true,
    "writeCredentialsFile": "s3-write.json"
  }
}
EOF
  echo "EDIT /etc/varlatch-backup/destinations.json with your destination (omit \"endpoint\" for AWS S3)."
fi
chmod 600 /etc/varlatch-backup/destinations.json /etc/varlatch-backup/config.env

# --- Scripts and units ---
install -d /usr/local/lib/varlatch-backup
install -m 755 run.sh verify-remote.sh /usr/local/lib/varlatch-backup/
install -m 644 varlatch-backup.service varlatch-backup.timer /etc/systemd/system/
systemctl daemon-reload

cat <<'EOF'

Installed. Remaining manual steps, in order (details in README.md):
 1. Place bek, root-kek, s3-write.json in /etc/varlatch-backup (root:root 0600).
    s3-write.json is the destination's write-only upload key.
 2. Edit /etc/varlatch-backup/destinations.json.
 3. First run, watched:  sudo systemctl start varlatch-backup.service
    then:                sudo journalctl -u varlatch-backup.service -n 50
 4. Remote-verify that archive with the READ key (never stored on this host):
    sudo /usr/local/lib/varlatch-backup/verify-remote.sh
 5. Rehearse a restore on a disposable host (docs/operations/backup.md).
 6. Only after the rehearsal:  sudo systemctl enable --now varlatch-backup.timer
EOF
