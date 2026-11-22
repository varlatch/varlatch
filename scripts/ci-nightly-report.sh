#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The nightly Go run's issue (.github/workflows/go.yml, job nightly-report).
# Nobody is notified of a scheduled run, so a red nightly could stay red for
# days unseen (the go-container job did, 2026-11-20 to 21). This keeps one
# open issue while the nightly is red:
#   - go-ok failed or was cancelled: open the issue, or comment on the open
#     one, with the run's link, its commit and its failed jobs;
#   - go-ok passed: comment on the open issue and close it.
# One issue at a time: the open one titled exactly so and opened by this
# job (app/github-actions), so an issue anyone else opens with the title is
# never commented on or closed. Only GITHUB_TOKEN, with issues: write;
# nothing else is read or written.
#
# The report never changes the run's result (the job is also
# continue-on-error): a failed call to GitHub is a warning, and the script
# exits 0.
#
# Environment: RESULT (needs.go-ok.result), RUN_ID, RUN_URL, SHA, and gh's
# GH_TOKEN and GH_REPO.
set -euo pipefail

title="Nightly go.yml is red"
: "${RESULT:?}" "${RUN_ID:?}" "${RUN_URL:?}" "${SHA:?}"

# gave_up <what>: the warning for a failed call to GitHub, then exit 0.
gave_up() {
  echo "::warning::The nightly report could not $1 (GitHub's API failed); the run's result stands."
  exit 0
}

open=$(gh issue list --state open --author app/github-actions --search "\"$title\" in:title" \
  --json number,title --jq "[.[] | select(.title == \"$title\")][0].number // empty") ||
  gave_up "look up its issue"

case "$RESULT" in
  failure | cancelled)
    # shellcheck disable=SC2016 # the backquotes are Markdown, for jq, not the shell
    failed=$(gh run view "$RUN_ID" --json jobs \
      --jq '[.jobs[] | select(.conclusion == "failure" or .conclusion == "cancelled") | "- `" + .name + "`: " + .conclusion] | join("\n")') ||
      failed=''
    body="The nightly run of go.yml at ${SHA} is ${RESULT}: ${RUN_URL}

${failed:-"(no failed job listed: see the run)"}"
    if [ -n "$open" ]; then
      gh issue comment "$open" --body "$body" || gave_up "comment on #$open"
      echo "Commented on #$open."
    else
      gh issue create --title "$title" --body "$body

This issue is opened by the nightly-report job of go.yml and closed by it on the next green nightly run." ||
        gave_up "open its issue"
    fi
    ;;
  success)
    if [ -n "$open" ]; then
      gh issue comment "$open" --body "The nightly run of go.yml at ${SHA} is green again: ${RUN_URL}" ||
        gave_up "comment on #$open"
      gh issue close "$open" || gave_up "close #$open"
      echo "Closed #$open."
    else
      echo "Green, and no open issue."
    fi
    ;;
  *)
    echo "go-ok is $RESULT: nothing to report."
    ;;
esac
