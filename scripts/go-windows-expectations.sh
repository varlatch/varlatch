#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Puts the Go CLI kit's Windows expectations from a run of the
# windows-expectations workflow into this checkout
# (apps/cli/test/goWindows.ts):
#
#   scripts/go-windows-expectations.sh <run id>
#
# It downloads the run's `windows-expectations` artifact with gh and
# replaces go/cmd/varlatch/testdata/transcripts/windows/ and
# go/cmd/varlatch/testdata/vectors/windows/ with what it holds, then shows
# what changed. Review and commit the result. The recordings hold only the
# fake server's tokens and the kit's fixtures, as the Linux ones do.
set -euo pipefail

run=${1:?usage: scripts/go-windows-expectations.sh <run id>}
[[ $run =~ ^[0-9]+$ ]] || { echo "go-windows-expectations: not a run id: $run" >&2; exit 64; }
cd "$(git rev-parse --show-toplevel)"
testdata=go/cmd/varlatch/testdata

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gh run download "$run" --name windows-expectations --dir "$tmp"
for kind in transcripts vectors; do
  [ -d "$tmp/$kind/windows" ] || continue
  rm -rf "${testdata:?}/$kind/windows"
  mkdir -p "$testdata/$kind"
  cp -R "$tmp/$kind/windows" "$testdata/$kind/windows"
done
git add -N "$testdata/transcripts/windows" "$testdata/vectors/windows" 2>/dev/null || true
git status --short -- "$testdata/transcripts/windows" "$testdata/vectors/windows"
