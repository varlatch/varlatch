#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Varlatch nightly backup (ADR-0033). Runs as root from varlatch-backup.service.
# Success requires capture, off-host delivery, AND a passing local verification;
# any failure fails the unit.
set -euo pipefail

CONF=/etc/varlatch-backup
# config.env defines: COMPOSE_DIR (the running installation's Compose directory)
# and optionally COMPOSE_FILE, CLI (path to the CLI), DESTINATION, LOCAL_KEEP,
# STATUS_FILE.
# shellcheck source=/dev/null  # operator config, root-only on the host
source "$CONF/config.env"
# Non-default compose file name (e.g. a Tailscale variant): docker compose,
# here and inside the CLI, honors this from the environment.
[ -n "${COMPOSE_FILE:-}" ] && export COMPOSE_FILE
FROM_IMAGE=/var/lib/varlatch-backup/from-image
install -d -m 700 "$FROM_IMAGE"
# Copy a file out of the RUNNING varlatchd container. It is root-owned in the
# digest-pinned image this job already drives as root: no added trust.
from_image() {
  (cd "$COMPOSE_DIR" && docker compose cp "varlatchd:$1" "$2.new") 2>/dev/null && mv "$2.new" "$2"
}

# Run the run.sh shipped with the deployed release, so script changes arrive
# with deploys. The installed copy is only the bootstrap, and the fallback for
# images that predate the shipped scripts.
if [ -z "${VARLATCH_BACKUP_FROM_IMAGE:-}" ] && from_image /opt/varlatch/host-backup/run.sh "$FROM_IMAGE/run.sh"; then
  echo "using run.sh from the running image"
  VARLATCH_BACKUP_FROM_IMAGE=1 exec bash "$FROM_IMAGE/run.sh" "$@"
fi

# Default: the CLI shipped in the running image, refreshed every run, so it
# always matches the deployed release (a stale CLI fails compatibility
# checks). Images that predate it fall back to a host copy: the release file
# at /usr/local/bin/varlatch, then a source build under /opt/varlatch/cli.
if [ -z "${CLI:-}" ]; then
  if from_image /opt/varlatch/varlatch.cjs "$FROM_IMAGE/varlatch.cjs"; then CLI="$FROM_IMAGE/varlatch.cjs"
  elif [ -f /usr/local/bin/varlatch ]; then CLI=/usr/local/bin/varlatch
  else CLI=/opt/varlatch/cli/apps/cli/dist/main.js; fi
fi
CLI_VERSION=$(node "$CLI" --version 2>/dev/null) || CLI_VERSION="version unknown (predates --version)"
echo "using CLI $CLI: $CLI_VERSION"
DESTINATION="${DESTINATION:-offsite}"
LOCAL_KEEP="${LOCAL_KEEP:-7}"
STATUS_FILE="${STATUS_FILE:-/var/lib/varlatch-backup/status.json}"

CREATED=$(node "$CLI" admin backup create \
  --dir "$COMPOSE_DIR" \
  --destination "$DESTINATION" \
  --destinations-file "$CONF/destinations.json" \
  --bek-file "$CONF/bek" \
  --kek-file "$CONF/root-kek")
# Not `tee /dev/stderr`: under systemd stderr is a journal socket, which
# cannot be opened by path, and pipefail would abort after a good capture.
printf '%s\n' "$CREATED"
ARCHIVE=$(sed -n 's/^Archive created: \(.*\) ([0-9a-f-]*)$/\1/p' <<< "$CREATED")
[ -n "$ARCHIVE" ] || { echo "could not determine the created archive path" >&2; exit 1; }

# Verify the local archive (integrity, compatibility, Root KEK match) and
# record it; this also keeps the 30-day Root KEK check current. A failed check
# fails the unit. Remote retrieval stays a periodic operator ritual with read
# credentials this host never stores (verify-remote.sh, ADR-0033 Decision 8).
node "$CLI" admin backup verify \
  --dir "$COMPOSE_DIR" \
  --in "$ARCHIVE" \
  --bek-file "$CONF/bek" \
  --kek-file "$CONF/root-kek" \
  --record

# Local prune: keep the newest $LOCAL_KEEP archives on disk. Remote retention
# is governed by the bucket's lifecycle rules, never by this script.
# shellcheck disable=SC2012  # archive names are UUIDs
ls -1t "$COMPOSE_DIR"/backups/*.vltbak 2>/dev/null | tail -n +$((LOCAL_KEEP + 1)) | xargs -r rm -f --

# Publish read-only status for agents/monitoring (agents cannot reach the
# operator socket; this file and /v1/installation/backups are their view).
install -d -m 755 "$(dirname "$STATUS_FILE")"
node "$CLI" admin backup status --dir "$COMPOSE_DIR" > "$STATUS_FILE.tmp"
chmod 644 "$STATUS_FILE.tmp"
mv "$STATUS_FILE.tmp" "$STATUS_FILE"
echo "backup run complete; status published to $STATUS_FILE"
