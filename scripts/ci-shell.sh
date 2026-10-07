#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The shell for workflow jobs that run the end-to-end suites, whose output
# can carry the disposable stack's credentials while CI logs are public:
#
#   defaults:
#     run:
#       shell: bash scripts/ci-shell.sh {0}
#
# Runs the step's script as GitHub's bash shell does (-eo pipefail), with
# stderr merged into stdout and every line passed through
# redact-output.mjs, which masks Varlatch tokens. That covers bash output
# and child processes too, which redact-tokens.mjs alone cannot reach.
# Exits with the script's status, or with the filter's if only it failed.
set -uo pipefail
bash --noprofile --norc -eo pipefail "$1" 2>&1 | node "$(dirname "$0")/redact-output.mjs"
status=("${PIPESTATUS[@]}")
[ "${status[0]}" -ne 0 ] && exit "${status[0]}"
exit "${status[1]}"
