#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fetches a box run's report (report.json, report.md, test.log) to
# ./rehearsal-runs/<run>/report, as the ssh user. The run's files were
# handed back to that user when the run ended (run.sh).
#
#   fetch-report.sh <ssh-host> <run>
set -euo pipefail
[ $# -ge 2 ] || { echo "usage: fetch-report.sh <ssh-host> <run>" >&2; exit 64; }
host=$1 run=$2
[[ $run =~ ^[a-z0-9-]+$ ]] || { echo "run is lowercase letters, digits and dashes" >&2; exit 64; }
mkdir -p "rehearsal-runs/$run/report"
rsync -a "$host:vl-rh/$run/runs/$run/report/" "rehearsal-runs/$run/report/"
echo "rehearsal-runs/$run/report: $(ls "rehearsal-runs/$run/report" | tr '\n' ' ')"
