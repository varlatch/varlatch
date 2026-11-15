#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Checks that a release build of varlatchd keeps no per-stage timing in its
# request path (step 4 decision 7): in the functions that hold the marks,
# a build without the g9a tag calls neither the clock nor the stages
# package (a function the release build inlines away counts none: its
# marks are empty there), and the g9a build does (so the check sees the
# marks). Run from go/ by go.yml; needs only the Go toolchain.
set -eu
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
go build -o "$dir/release" ./cmd/varlatchd
go build -tags g9a -o "$dir/g9a" ./cmd/varlatchd
calls() { go tool objdump -s "$1" "$2" | grep -cE 'CALL (time\.Now|time\.Since|[^ ]*/server/stages\.)' || true; }
status=0
for f in 'values\.\(\*tracker\)\.decide$' 'values\.\(\*Service\)\.auditThenDecrypt$' 'values\.\(\*Service\)\.snapshot$' \
  'httpserver\.\(\*operations\)\.DiscloseSecrets$' 'httpserver\.\(\*Server\)\.builtOperation\.func1$' 'storage\.\(\*DB\)\.Write$'; do
  release=$(calls "$f" "$dir/release")
  g9a=$(calls "$f" "$dir/g9a")
  echo "$f: release $release, g9a $g9a"
  [ "$release" -eq 0 ] || { echo "check-release.sh: $f reads the clock or calls stages in a release build" >&2; status=1; }
  [ "$g9a" -gt 0 ] || { echo "check-release.sh: $f has no marks in the g9a build: the check would not see them" >&2; status=1; }
done
exit "$status"
