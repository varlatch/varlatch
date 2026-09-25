#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Periodic remote verification (ADR-0033 Decision 8): download an archive from
# the off-host destination with a READ key, run the full checks, and record
# the result. The status warns when no remote check passed within 30 days.
#
#   sudo /usr/local/lib/varlatch-backup/verify-remote.sh [--archive <id>] [--read-credentials-file <path>]
#
# Defaults to the newest archive delivered to $DESTINATION. Without
# --read-credentials-file it prompts for the read key; the key only ever lives
# in a root-only file under /dev/shm for the duration of this command, never
# on disk or in process arguments.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }

CONF=/etc/varlatch-backup
# shellcheck source=/dev/null  # operator config, root-only on the host
source "$CONF/config.env"
[ -n "${COMPOSE_FILE:-}" ] && export COMPOSE_FILE
FROM_IMAGE=/var/lib/varlatch-backup/from-image
install -d -m 700 "$FROM_IMAGE"
from_image() {
  (cd "$COMPOSE_DIR" && docker compose cp "varlatchd:$1" "$2.new") 2>/dev/null && mv "$2.new" "$2"
}
# Same as run.sh: prefer the copy shipped with the deployed release.
if [ -z "${VARLATCH_BACKUP_FROM_IMAGE:-}" ] && from_image /opt/varlatch/host-backup/verify-remote.sh "$FROM_IMAGE/verify-remote.sh"; then
  VARLATCH_BACKUP_FROM_IMAGE=1 exec bash "$FROM_IMAGE/verify-remote.sh" "$@"
fi
if [ -z "${CLI:-}" ]; then
  if from_image /opt/varlatch/varlatch.cjs "$FROM_IMAGE/varlatch.cjs"; then CLI="$FROM_IMAGE/varlatch.cjs"
  elif [ -f /usr/local/bin/varlatch ]; then CLI=/usr/local/bin/varlatch
  else CLI=/opt/varlatch/cli/apps/cli/dist/main.js; fi
fi
DESTINATION="${DESTINATION:-offsite}"
STATUS_FILE="${STATUS_FILE:-/var/lib/varlatch-backup/status.json}"

ARCHIVE_ID="" CREDENTIALS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --archive) ARCHIVE_ID="${2:?--archive needs an ID}"; shift 2 ;;
    --read-credentials-file) CREDENTIALS="${2:?--read-credentials-file needs a path}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$ARCHIVE_ID" ]; then
  ARCHIVE_ID=$(node "$CLI" admin backup status --dir "$COMPOSE_DIR" | DESTINATION="$DESTINATION" node -e '
    let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
      const a = JSON.parse(s).archives.find(a => a.delivery?.destination === process.env.DESTINATION);
      if (a) console.log(a.archiveId);
    });')
  [ -n "$ARCHIVE_ID" ] || { echo "no archive delivered to $DESTINATION yet" >&2; exit 1; }
fi
echo "verifying remote copy of $ARCHIVE_ID on $DESTINATION"

if [ -z "$CREDENTIALS" ]; then
  CREDENTIALS=$(umask 077; mktemp /dev/shm/varlatch-read.XXXXXX)
  trap 'rm -f "$CREDENTIALS"' EXIT
  read -rp "Read key ID: " KEY_ID
  read -rsp "Read key secret (hidden): " KEY_SECRET; echo
  # Environment, not argv: argv is world-readable in /proc.
  KEY_ID="$KEY_ID" KEY_SECRET="$KEY_SECRET" node -e \
    'process.stdout.write(JSON.stringify({ accessKeyId: process.env.KEY_ID, secretAccessKey: process.env.KEY_SECRET }))' > "$CREDENTIALS"
  unset KEY_SECRET
fi

node "$CLI" admin backup verify \
  --dir "$COMPOSE_DIR" \
  --destination "$DESTINATION" \
  --destinations-file "$CONF/destinations.json" \
  --archive "$ARCHIVE_ID" \
  --read-credentials-file "$CREDENTIALS" \
  --bek-file "$CONF/bek" \
  --kek-file "$CONF/root-kek" \
  --record

node "$CLI" admin backup status --dir "$COMPOSE_DIR" > "$STATUS_FILE.tmp"
chmod 644 "$STATUS_FILE.tmp"
mv "$STATUS_FILE.tmp" "$STATUS_FILE"
echo "remote verification recorded; status published to $STATUS_FILE"
