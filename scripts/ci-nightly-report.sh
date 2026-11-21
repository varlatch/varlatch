#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The nightly Go run's issue (.github/workflows/go.yml, job nightly-report).
# Nobody is notified of a scheduled run, so a red nightly could stay red for
# days unseen (the go-container job did, 2026-11-20 to 21). This keeps one
# open issue while the nightly is red:
#   - go-ok failed or was cancelled: open the issue, or comment on the open
#     one, with the run's link, its commit and its failed jobs;
#   - go-ok passed: comment on the open issue and close it.
# One issue at a time, found by its exact title. Only GITHUB_TOKEN, with
# issues: write; nothing else is read or written.
#
# Environment: RESULT (needs.go-ok.result), RUN_ID, RUN_URL, SHA, and gh's
# GH_TOKEN and GH_REPO.
set -euo pipefail

title="Nightly go.yml is red"
: "${RESULT:?}" "${RUN_ID:?}" "${RUN_URL:?}" "${SHA:?}"

open=$(gh issue list --state open --search "\"$title\" in:title" --json number,title \
  --jq "[.[] | select(.title == \"$title\")][0].number // empty")

case "$RESULT" in
  failure | cancelled)
    # shellcheck disable=SC2016 # the backquotes are Markdown, for jq, not the shell
    failed=$(gh run view "$RUN_ID" --json jobs \
      --jq '[.jobs[] | select(.conclusion == "failure" or .conclusion == "cancelled") | "- `" + .name + "`: " + .conclusion] | join("\n")')
    body="The nightly run of go.yml at ${SHA} is ${RESULT}: ${RUN_URL}

${failed:-"(no failed job listed: see the run)"}"
    if [ -n "$open" ]; then
      gh issue comment "$open" --body "$body"
      echo "Commented on #$open."
    else
      gh issue create --title "$title" --body "$body

This issue is opened by the nightly-report job of go.yml and closed by it on the next green nightly run."
    fi
    ;;
  success)
    if [ -n "$open" ]; then
      gh issue comment "$open" --body "The nightly run of go.yml at ${SHA} is green again: ${RUN_URL}"
      gh issue close "$open"
      echo "Closed #$open."
    else
      echo "Green, and no open issue."
    fi
    ;;
  *)
    echo "go-ok is $RESULT: nothing to report."
    ;;
esac
