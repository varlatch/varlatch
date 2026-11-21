#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Checks that a release build of varlatchd keeps no per-stage timing in its
# request path or its storage engine (step 4 decision 7), and none of the
# conformance build's host override. Run from go/ by
# go.yml; needs only the Go toolchain.
#
# For each function that holds marks, the release build must make exactly
# its own clock reads (the baseline: the storage engine's metrics read the
# clock in runBatch, before and without any stage timing) and no call into
# server/stages or the storage engine's job timing; the g9a build must make
# more, so the check sees the marks. A function the release build inlines
# away is checked through the callers listed after it; a listed function
# missing from either build fails the check, naming it, so that this list
# is updated with the code. And the release binary must hold no symbol of
# the timing code at all.
set -eu
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
go build -o "$dir/release" ./cmd/varlatchd
go build -tags g9a -o "$dir/g9a" ./cmd/varlatchd
status=0
fail() {
  echo "check-release.sh: $*" >&2
  status=1
}

# dump <binary> <symbol regexp>: the function's disassembly in $dir/dump;
# an objdump failure stops the check.
dump() {
  if ! go tool objdump -s "$2" "$1" > "$dir/dump"; then
    echo "check-release.sh: go tool objdump failed on $1" >&2
    exit 2
  fi
}
present() { awk '/^TEXT /{n++} END{exit n ? 0 : 1}' "$dir/dump"; }
calls() { awk '/CALL (time\.Now|time\.Since|[^ ]*\/server\/stages\.|[^ ]*\/lib\/storage\.\(\*jobTiming\))/{n++} END{print n+0}' "$dir/dump"; }

# check <symbol> <release baseline> [<caller symbol>...]
check() {
  sym=$1
  base=$2
  shift 2
  dump "$dir/g9a" "$sym"
  if ! present; then
    fail "$sym is not in the g9a build: update the list in this script"
    return
  fi
  g9a=$(calls)
  [ "$g9a" -gt "$base" ] || fail "$sym makes $g9a timing calls in the g9a build, not more than its release baseline $base: the check would not see its marks"
  dump "$dir/release" "$sym"
  if present; then
    release=$(calls)
    echo "$sym: release $release (baseline $base), g9a $g9a"
    [ "$release" -eq "$base" ] || fail "$sym makes $release clock or timing calls in a release build, its baseline is $base"
    return
  fi
  if [ $# -eq 0 ]; then
    fail "$sym is not in the release build (inlined or renamed) and has no callers listed: update the list in this script"
    return
  fi
  for caller in "$@"; do
    dump "$dir/release" "$caller"
    if ! present; then
      fail "$caller, a caller of the inlined $sym, is not in the release build either: update the list in this script"
      continue
    fi
    release=$(calls)
    echo "$sym (inlined), in $caller: release $release, g9a $g9a"
    [ "$release" -eq 0 ] || fail "$caller makes $release clock or timing calls in a release build"
  done
}

check 'values\.\(\*tracker\)\.decide$' 0
check 'values\.\(\*Service\)\.auditThenDecrypt$' 0
check 'values\.\(\*Service\)\.snapshot$' 0 'values\.\(\*Service\)\.Disclose$' 'values\.\(\*Service\)\.EffectiveConfiguration$'
check 'httpserver\.\(\*operations\)\.DiscloseSecrets$' 0
check 'httpserver\.\(\*Server\)\.builtOperation\.func1$' 0
check 'storage\.\(\*DB\)\.Write$' 0
check 'storage\.\(\*DB\)\.runBatch$' 5

if ! go tool nm "$dir/release" > "$dir/nm.release" || ! go tool nm "$dir/g9a" > "$dir/nm.g9a"; then
  echo "check-release.sh: go tool nm failed" >&2
  exit 2
fi
timing='lib/storage\.(\(\*jobTiming\)|timingKey)|server/stages\.(With|Flush|Since|Start|Admitted)'
if grep -E "$timing" "$dir/nm.release" > "$dir/found"; then
  fail "the release binary holds timing code: $(tr '\n' ' ' < "$dir/found")"
fi
grep -qE "$timing" "$dir/nm.g9a" || fail "the g9a binary holds no timing symbol: the symbol check would not see them"

# The conformance build's host override (server/outbound/redirect_conformance.go,
# which redirects api.github.com and the like to the harness's fake
# services): a release binary must hold none of it, neither its code nor
# the name of the variable that turns it on. The conformance build must
# hold both, so this check sees them.
go build -tags conformance -o "$dir/conformance" ./cmd/varlatchd
go tool nm "$dir/conformance" > "$dir/nm.conformance" || { echo "check-release.sh: go tool nm failed" >&2; exit 2; }
override='server/outbound\.(parseConformanceHosts|ConformanceRedirects|conformanceHosts)'
if grep -E "$override" "$dir/nm.release" > "$dir/found"; then
  fail "the release binary holds the conformance host override: $(tr '\n' ' ' < "$dir/found")"
fi
if grep -q VARLATCH_CONFORMANCE_OUTBOUND_HOSTS "$dir/release"; then
  fail "the release binary names VARLATCH_CONFORMANCE_OUTBOUND_HOSTS: the conformance host override is in it"
fi
grep -qE "$override" "$dir/nm.conformance" || fail "the conformance binary holds no host override symbol: the check would not see it"
grep -q VARLATCH_CONFORMANCE_OUTBOUND_HOSTS "$dir/conformance" || fail "the conformance binary does not name VARLATCH_CONFORMANCE_OUTBOUND_HOSTS: the check would not see it"

# serve_cli's conformance release (server/daemon/servecli_conformance.go:
# the harness's directory instead of github.com, and the command that signs
# it with a test Sigstore): none of it in a release binary, all of it in the
# conformance build. The same for the CLIs: the test trusted root the
# conformance CLI links in (main.conformanceTrustedRoot, a constant "" in a
# release), and self-update's test source (-tags selfupdatetest).
servecli='server/daemon\.(signRelease|dirSource)|lib/release/releasetest\.'
if grep -E "$servecli" "$dir/nm.release" > "$dir/found"; then
  fail "the release binary holds serve_cli's conformance release: $(tr '\n' ' ' < "$dir/found")"
fi
grep -qE "$servecli" "$dir/nm.conformance" || fail "the conformance binary holds no serve_cli conformance symbol: the check would not see it"
for name in conformance-sign-release VARLATCH_CONFORMANCE_CLI_RELEASE; do
  if grep -q "$name" "$dir/release"; then
    fail "the release binary names $name: serve_cli's conformance release is in it"
  fi
  grep -q "$name" "$dir/conformance" || fail "the conformance binary does not name $name: the check would not see it"
done
go build -o "$dir/cli-release" ./cmd/varlatch
go build -tags conformance -o "$dir/cli-conformance" ./cmd/varlatch
go build -tags selfupdatetest -o "$dir/cli-selfupdatetest" ./cmd/varlatch
for b in cli-release cli-conformance; do
  go tool nm "$dir/$b" > "$dir/nm.$b" || { echo "check-release.sh: go tool nm failed" >&2; exit 2; }
done
if grep -E ' main\.conformanceTrustedRoot$' "$dir/nm.cli-release" > "$dir/found"; then
  fail "the release CLI holds a settable trusted root: $(tr '\n' ' ' < "$dir/found")"
fi
grep -qE ' main\.conformanceTrustedRoot$' "$dir/nm.cli-conformance" || fail "the conformance CLI holds no main.conformanceTrustedRoot: the check would not see it"
if grep -q VARLATCH_TEST_SELFUPDATE_SOURCE "$dir/cli-release"; then
  fail "the release CLI names VARLATCH_TEST_SELFUPDATE_SOURCE: self-update's test source is in it"
fi
grep -q VARLATCH_TEST_SELFUPDATE_SOURCE "$dir/cli-selfupdatetest" || fail "the selfupdatetest CLI does not name VARLATCH_TEST_SELFUPDATE_SOURCE: the check would not see it"
exit "$status"
