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
#       that do read them run on every pull request. The Go rewrite (go/ and
#       .github/workflows/go.yml, ADR-0059) counts as neither: go.yml checks
#       it, and the TypeScript jobs have nothing to test there. A pull
#       request that changes only Go files and documentation answers
#       code=false and tests=affected (no package), so it runs the test job's
#       repository-wide checks (licenses, notices, the changelog section,
#       the build) and the secret scan, and skips every TypeScript test. A
#       mixed change answers for its other paths. The exception is the Go
#       test data that a package's tests produce, read, or compare with (the
#       *_SHARED patterns below: the parity fixtures and vectors, the CLI
#       transcripts and inventory, the Node.js IDNA table, the enrollment
#       page): it counts as code in that package, so a change to it runs the
#       tests that check it against the TypeScript code. The paths behind
#       each answer go to stderr.
#
#   scripts/ci-changes.sh affected <base>
#       Prints the names of the packages to test when tests=affected: those
#       with a changed file since <base> (committed or not), and every package
#       that depends on them, and the package whose tests read a changed
#       *_SHARED file. Documentation inside a package selects nothing.
#
#   scripts/ci-changes.sh check-shared
#       Fails when a package's tests name a Go data file (one under a
#       testdata/ directory, or a .json, .html or .mjs file) that the
#       *_SHARED patterns do not give to that package, so the patterns
#       cannot fall behind the tests.
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
# The Go rewrite, which go.yml checks.
GO='^go/|^\.github/workflows/go\.yml$'
# Go files that a package's tests produce, read, or compare with, by package.
# pnpm sees them as the workspace root's, so `affected` adds the package for
# them. `check-shared` keeps these complete.
# services/varlatchd: the parity fixtures and vectors (go-*-fixture.test.ts,
# go-*-vectors.test.ts), the HTTP known differences, the enrollment page, the
# column mapping, the Node.js IDNA table.
SERVER_SHARED='^go/server/[a-z0-9]+/testdata/ts-vectors\.json$|^go/lib/(contract|backup)/testdata/ts-vectors\.json$|^go/server/(paritytest|values|pgtime)/testdata/|^go/server/environments/testdata/pg-timestamps\.json$|^go/server/security/testdata/approval-vectors\.json$|^go/server/auth/testdata/passkeys-v[0-9.]+\.json$|^go/server/httpserver/testdata/known-differences\.json$|^go/server/httpserver/enroll/enroll\.html$|^go/server/db/mapping\.json$|^go/lib/envelope/testdata/tsfixtures\.mjs$|^go/lib/whatwg/(nodeidna_table\.go|testdata/node-idna\.json|testdata/nodeidna\.mjs)$'
# apps/cli: the Go CLI's transcripts, vectors and inventory (go-*.test.ts,
# cli-inventory.test.ts), and the JSON writer's vectors.
CLI_SHARED='^go/cmd/varlatch/testdata/(cli-inventory\.json$|transcripts/|vectors/)|^go/lib/jsjson/testdata/ts-vectors\.json$'
# packages/sync: the exchanges its tests produce and replay
# (go-vectors.test.ts, go-compose-fuzz.test.ts).
SYNC_SHARED='^go/lib/sync/testdata/ts-exchanges\.json$'

# Prints the packages whose tests read the Go file $1, if any.
shared_owners() {
  if [[ $1 =~ $SERVER_SHARED ]]; then echo "@varlatch/varlatchd"; fi
  if [[ $1 =~ $CLI_SHARED ]]; then echo "@varlatch/cli"; fi
  if [[ $1 =~ $SYNC_SHARED ]]; then echo "@varlatch/sync"; fi
  return 0
}

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
  local path total=0 code=0 go=0 global=()
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    total=$((total + 1))
    if [ -n "$(shared_owners "$path")" ]; then code=$((code + 1)); continue; fi
    if [[ $path =~ $GO ]]; then go=$((go + 1)); continue; fi
    if [[ $path =~ $CHECKED_DOCS ]] || ! [[ $path =~ $DOCS ]]; then code=$((code + 1)); fi
    if ! [[ $path =~ $DOCS ]] && ! in_package "$path"; then global+=("$path"); fi
  done
  if [ "$code" -eq 0 ]; then
    echo "code=false"
    if [ "$go" -eq 0 ]; then
      echo "code: false, all $total changed file(s) are documentation that no check reads." >&2
    elif [ "$go" -eq "$total" ]; then
      echo "code: false, all $total changed file(s) are Go files, which go.yml checks." >&2
    else
      echo "code: false, $go of $total changed file(s) are Go files, which go.yml checks; the rest are documentation that no check reads." >&2
    fi
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
  # A package's tests that read changed Go test data (*_SHARED); pnpm sees
  # those files as the workspace root's.
  local path owner changed
  changed=$(cd "$REPO_ROOT" && { git diff --no-renames --name-only "$base"; git ls-files --others --exclude-standard; })
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    while IFS= read -r owner; do
      [ -n "$owner" ] || continue
      [[ " ${names[*]} " == *" $owner "* ]] || names+=("$owner")
    done < <(shared_owners "$path")
  done <<< "$changed"
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

check_shared() {
  local dir name ref probe missing=0
  for dir in "$REPO_ROOT"/apps/*/ "$REPO_ROOT"/packages/*/ "$REPO_ROOT"/services/*/ "$REPO_ROOT"/convex/; do
    [ -f "$dir/package.json" ] && [ -d "$dir/test" ] || continue
    name=$(node -p "require(process.argv[1]).name" "$dir/package.json")
    # shellcheck disable=SC2016 # the pattern matches a literal ${ in tests
    while IFS= read -r ref; do
      [ -n "$ref" ] || continue
      # A path built from a template (<area>, ${name}) stops before it, and
      # a sentence's full stop is not part of the path.
      ref=${ref%%[<\$]*}
      ref=${ref%%.}
      [[ $ref == */testdata/* || $ref =~ \.(json|html|mjs)$ ]] || continue
      probe=$ref
      if [[ $ref == */ ]]; then probe="${ref}x.json"; fi
      if ! shared_owners "$probe" | grep -qx "$name"; then
        echo "${dir#"$REPO_ROOT"/}test names ${ref}, which no *_SHARED pattern in scripts/ci-changes.sh gives to ${name}." >&2
        missing=1
      fi
    done < <(cd "$dir" && grep -rohE 'go/(cmd|lib|server|internal)/[A-Za-z0-9_./<>${}-]*' test | sort -u)
  done
  if [ "$missing" -ne 0 ]; then
    echo "A change to such a file would skip the tests that read it; add it to the package's pattern." >&2
    return 1
  fi
  echo "Every Go data file that a package's tests name selects that package." >&2
}

case ${1:-} in
  classify) classify ;;
  check-shared) check_shared ;;
  affected)
    [ -n "${2:-}" ] || { echo "usage: $0 affected <base>" >&2; exit 2; }
    affected "$2"
    ;;
  *)
    echo "usage: $0 classify < paths | $0 affected <base> | $0 check-shared" >&2
    exit 2
    ;;
esac
