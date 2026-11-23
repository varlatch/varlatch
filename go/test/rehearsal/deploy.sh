#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The agent's part of a box run (internal docs/design/go-step8-rehearsals.md):
# copies this harness's checkout and the TypeScript checkout to the
# experiments server over ssh, as the ssh user, into ~/vl-rh/<run>/, then
# prints what the owner runs there as root. It runs nothing as root and
# nothing on the box but the copy.
#
#   deploy.sh <ssh-host> <typescript-checkout> <run> [VAR=value ...]
#
# The VAR=value pairs are the run's profile (VL_RH_INGRESS=public, ...),
# printed into the owner's command; no secret belongs in them.
set -euo pipefail
[ $# -ge 3 ] || { echo "usage: deploy.sh <ssh-host> <typescript-checkout> <run> [VAR=value ...]" >&2; exit 64; }
host=$1 ts=$(cd "$2" && pwd) run=$3
shift 3
[[ $run =~ ^[a-z0-9-]+$ ]] || { echo "run is lowercase letters, digits and dashes" >&2; exit 64; }
here=$(cd "$(dirname "$0")" && pwd) repo=$(cd "$here/../../.." && pwd)
dest=vl-rh/$run
ssh "$host" "mkdir -p ~/$dest"
rsync -a --delete --exclude .git --exclude node_modules --exclude rehearsal-runs "$repo/" "$host:$dest/varlatch/"
# The TypeScript checkout with its dependencies and build (the release
# files and the S3 client come from it).
rsync -a --delete --exclude .git "$ts/" "$host:$dest/ts/"
home=$(ssh "$host" 'printf %s "$HOME"')
extra=""
if [ $# -gt 0 ]; then
  extra=" $*"
fi
cat <<OWNER

On $host, as root (sudo -i first, alone), then:

  cd $home/$dest/varlatch/go && VL_RH_PROFILE=box${extra} VL_RH_ROOT=$home/$dest/runs \\
    ./test/rehearsal/run.sh $home/$dest/ts $run

It pauses for your steps (it prints each, and the file to touch). When it
ends, the agent fetches the report with fetch-report.sh $host $run.
With VL_RH_TARGET=image (B3), use VL_RH_ROOT=/srv/vl-rh-runs instead: the
image's user (uid 65532) must reach the run's varlatchd, which a home of mode
0750 refuses; the agent then fetches with fetch-report.sh $host $run /srv/vl-rh-runs.
OWNER
