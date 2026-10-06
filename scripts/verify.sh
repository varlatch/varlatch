#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# `pnpm verify`: the cheap checks of CI's fast tier, run locally so that a
# pull request passes on its first CI run. Stops at the first failure.
#
#   pnpm verify                     tests of the changed packages and their
#                                   dependents, chosen as CI chooses them
#   VERIFY_ALL_TESTS=1 pnpm verify  every package's tests
#
# Changes are measured from where the branch left origin's main
# (VERIFY_BASE names another base branch, as `pnpm ready` does for a pull
# request based on one). It checks the working tree, not what is pushed.
# Tests run one package at a time with at most two workers each, so the
# daemon's suite fits in a desktop's memory; its real-Postgres tests run only
# when VARLATCH_TEST_DATABASE_URL is set, as CI sets it. Needs Docker.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

# The secret-scan job's image.
GITLEAKS=ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
BASE_BRANCH=${VERIFY_BASE:-main}

current="starting"
step() {
  current=$1
  printf '\n==> %s\n' "$1"
}
finish() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    printf '\npnpm verify failed: %s (exit %s)\n' "$current" "$status" >&2
  fi
}
trap finish EXIT

uncommitted=""
if [ -n "$(git status --porcelain)" ]; then
  uncommitted="Uncommitted changes: pnpm verify checks the working tree, not what is pushed."
  printf 'warning: %s\n' "$uncommitted" >&2
fi

step "Fetch origin/$BASE_BRANCH"
if ! git fetch -q origin "$BASE_BRANCH"; then
  git rev-parse -q --verify "origin/$BASE_BRANCH" >/dev/null
  echo "warning: could not fetch; using the local origin/$BASE_BRANCH" >&2
fi
base=$(git merge-base "origin/$BASE_BRANCH" HEAD)
echo "Base: $base"

step "Install (frozen lockfile)"
pnpm install --frozen-lockfile --prefer-offline

step "Protocol types are generated and committed"
pnpm --filter @varlatch/protocol generate
git diff --exit-code packages/protocol/src/generated

step "Coolify Compose file is generated and current"
pnpm compose:check

step "Third-party notices are generated and current"
pnpm notices:check

step "Every file and package matches the license map"
pnpm license:check

step "The changelog has a section for the current version"
VERSION=$(node -p "require('./packages/backup/src/release.json').version")
grep -q "^## ${VERSION} (" CHANGELOG.md || { echo "CHANGELOG.md has no section for ${VERSION}" >&2; exit 1; }

step "Build"
pnpm build

step "Typecheck"
pnpm typecheck

# Its own pnpm workspace, so `pnpm build` above leaves it out.
step "Documentation site builds, and its links resolve"
(cd apps/docs && pnpm install --frozen-lockfile --prefer-offline && pnpm test && pnpm build)

# CI scans every ref, so a credential-shaped fixture on any pushed branch
# fails everyone's CI; scan this branch's commits before they are pushed.
# The Git directory is mounted at its own path too, because a worktree's
# .git file points there.
step "Secret scan of the commits since $base"
if [ "$(git rev-list --count "$base..HEAD")" -eq 0 ]; then
  echo "No commits since the base."
else
  git_dir=$(git rev-parse --path-format=absolute --git-common-dir)
  docker run --rm -v "$PWD:/repo:ro" -v "$git_dir:$git_dir:ro" \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
    "$GITLEAKS" git /repo --log-opts="$base..HEAD" --redact=100 --no-banner
fi

tests=all
if [ "${VERIFY_ALL_TESTS:-}" = 1 ]; then
  step "Tests of every package (VERIFY_ALL_TESTS=1)"
else
  step "Tests of the changed packages and their dependents"
  # As CI classifies a pull request: committed and uncommitted changes of
  # tracked files, moves counted at both paths.
  tests=$(git diff --no-renames --name-only "$base" | scripts/ci-changes.sh classify | sed -n 's/^tests=//p')
fi
if [ -z "${VARLATCH_TEST_DATABASE_URL:-}" ]; then
  echo "VARLATCH_TEST_DATABASE_URL is not set: the daemon's real-Postgres tests are skipped (CI runs them)."
fi
if [ "$tests" = affected ]; then
  packages=$(scripts/ci-changes.sh affected "$base")
  if [ -z "$packages" ]; then
    echo "No package changed: no package tests to run."
  else
    filters=()
    while read -r name; do filters+=(--filter "$name"); done <<< "$packages"
    pnpm --workspace-concurrency=1 "${filters[@]}" test --maxWorkers=2
  fi
else
  pnpm -r --workspace-concurrency=1 test --maxWorkers=2
fi

current="done"
printf '\npnpm verify passed.\n'
if [ -n "$uncommitted" ]; then
  printf 'warning: %s\n' "$uncommitted" >&2
fi
