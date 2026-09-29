#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# What a change needs tested, shared by the changes job in
# .github/workflows/ci.yml and by scripts/verify.sh.
#
#   scripts/ci-changes.sh classify < paths
#       Reads the changed paths, one per line, and prints two lines:
#       code=false when every path is documentation that no check reads
#       (*.md and docs/; CHANGELOG.md and THIRD-PARTY-NOTICES.md are checked,
#       so they count as code), else code=true; tests=all when a path outside
#       the workspace packages is not documentation (the lockfile, the root
#       manifests, tsconfig.base.json, scripts/, infra/, CI itself), else
#       tests=affected. Here every *.md and docs/ path is documentation,
#       CHANGELOG.md included: no package's tests read one, and the checks
#       that do read them run on every pull request. The paths behind each
#       answer go to stderr.
#
#   scripts/ci-changes.sh affected <base>
#       Prints the names of the packages to test when tests=affected: those
#       with a changed file since <base> (committed or not), and every package
#       that depends on them. Documentation inside a package selects nothing.
#
# pnpm's own selector (`--filter "...[<base>]"`) maps a changed file outside
# every package to the workspace root project, which no package depends on
# and whose test script is `pnpm -r test`. Selecting the root would run every
# package's tests with no say over how; leaving it out would test nothing for
# a lockfile or shared tsconfig change. So `classify` decides "all" for those
# files, and `affected` never selects the root.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd -P)

# Documentation, and the documentation that CI checks or ships in images.
DOCS='\.md$|^docs/'
CHECKED_DOCS='^(CHANGELOG|THIRD-PARTY-NOTICES)\.md$'

# True when a path lies inside a workspace package (pnpm-workspace.yaml).
in_package() {
  local top name rest
  IFS=/ read -r top name rest <<< "$1"
  case $top in
    convex) [ -n "$name" ] ;;
    packages | services | apps) [ -n "$rest" ] && [ -f "$REPO_ROOT/$top/$name/package.json" ] ;;
    *) return 1 ;;
  esac
}

classify() {
  local path total=0 code=0 global=()
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    total=$((total + 1))
    if [[ $path =~ $CHECKED_DOCS ]] || ! [[ $path =~ $DOCS ]]; then code=$((code + 1)); fi
    if ! [[ $path =~ $DOCS ]] && ! in_package "$path"; then global+=("$path"); fi
  done
  if [ "$code" -eq 0 ]; then
    echo "code=false"
    echo "code: false, all $total changed file(s) are documentation that no check reads." >&2
  else
    echo "code=true"
    echo "code: true, $code of $total changed file(s) are code or checked documentation." >&2
  fi
  if [ "${#global[@]}" -gt 0 ]; then
    echo "tests=all"
    printf 'tests: all, because of files outside the workspace packages:\n' >&2
    printf '  %s\n' "${global[@]}" >&2
  else
    echo "tests=affected"
    echo "tests: affected, only the changed packages and their dependents." >&2
  fi
}

affected() {
  local base=$1 line rest names=()
  # pnpm diffs with git's rename detection, so a file moved from one package
  # to another would select only the package it moved to. Without it, a move
  # is a deletion in one package and an addition in the other.
  local n=${GIT_CONFIG_COUNT:-0}
  local listing
  listing=$(cd "$REPO_ROOT" && env "GIT_CONFIG_COUNT=$((n + 1))" "GIT_CONFIG_KEY_$n=diff.renames" "GIT_CONFIG_VALUE_$n=false" \
    pnpm --filter "...[$base]" --filter '!{.}' --changed-files-ignore-pattern '**/*.md' ls --depth -1 --parseable --long)
  # Package lines read <directory>:<name>@<version>[:PRIVATE].
  while IFS= read -r line; do
    [[ $line == "$REPO_ROOT"/*:* ]] || continue
    rest=${line#*:}
    rest=${rest%%:*}
    names+=("${rest%@*}")
  done <<< "$listing"
  # The Python accessor's tests read the contract and accessor vectors and
  # run the CLI's generator without depending on those packages; each of them
  # selects the CLI, so the CLI stands in for all three.
  if [[ " ${names[*]} " == *" @varlatch/cli "* ]] && [[ " ${names[*]} " != *" @varlatch/accessor-python "* ]]; then
    names+=("@varlatch/accessor-python")
  fi
  if [ "${#names[@]}" -eq 0 ]; then
    echo "No package changed since ${base}." >&2
    return 0
  fi
  echo "Packages changed since ${base}, and their dependents:" >&2
  printf '  %s\n' "${names[@]}" >&2
  printf '%s\n' "${names[@]}"
}

case ${1:-} in
  classify) classify ;;
  affected)
    [ -n "${2:-}" ] || { echo "usage: $0 affected <base>" >&2; exit 2; }
    affected "$2"
    ;;
  *)
    echo "usage: $0 classify < paths | $0 affected <base>" >&2
    exit 2
    ;;
esac
