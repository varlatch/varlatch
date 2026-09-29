#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# `pnpm ready`: marks this branch's pull request ready for review, which starts
# its CI (CI does not run on drafts), once `pnpm verify` passes on the pushed
# commit. Needs the GitHub CLI (gh), signed in.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

die() {
  echo "pnpm ready: $*" >&2
  exit 1
}

branch=$(git symbolic-ref --quiet --short HEAD) || die "HEAD is detached; check out the pull request's branch."
[ "$branch" != main ] || die "on main; check out the pull request's branch."
[ -z "$(git status --porcelain)" ] || die "the working tree has uncommitted or untracked files; commit and push them, or stash them, first."

head=$(git rev-parse HEAD)
pushed=$(git ls-remote origin "refs/heads/$branch" | cut -f1)
[ -n "$pushed" ] || die "origin has no branch $branch; push it first: git push -u origin $branch"
[ "$pushed" = "$head" ] || die "origin's $branch is at ${pushed:0:12}, HEAD is at ${head:0:12}; push (or pull) first, so CI tests what is verified here."

if ! pr=$(gh pr view "$branch" --json number,isDraft,state,baseRefName,url --jq '[.number, .isDraft, .state, .baseRefName, .url] | @tsv' 2>&1); then
  echo "$pr" >&2
  die "no pull request found for $branch; open one as a draft: gh pr create --draft"
fi
IFS=$'\t' read -r number draft state base url <<< "$pr"
[ "$state" = OPEN ] || die "pull request #$number is ${state,,}: $url"

echo "Pull request #$number ($url), based on $base."
VERIFY_BASE=$base scripts/verify.sh

if [ "$draft" != true ]; then
  echo "#$number is already ready for review; CI already runs on every push to it."
  exit 0
fi
gh pr ready "$number"
