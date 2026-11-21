#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Every timing test runs alone in CI. A test that calls growsLinearly judges
# how its time grows with its input, so it is named in go.yml's TIMING_TESTS:
# the test steps skip it and a step of its own runs it alone. This fails when
# a test calls growsLinearly and TIMING_TESTS misses it, and when
# TIMING_TESTS names a test that no longer calls it.
#
#   TIMING_TESTS=<regex> scripts/check-timing-tests.sh   (from the repository root)
set -euo pipefail

: "${TIMING_TESTS:?set TIMING_TESTS to the regular expression in go.yml}"

# The list is read back by its shape below, so it must stay a flat list of
# test names.
if ! printf '%s\n' "$TIMING_TESTS" | grep -qE '^\^\((Test[A-Za-z0-9_]+\|)*Test[A-Za-z0-9_]+\)\$$'; then
  echo "TIMING_TESTS (go.yml) must be a flat list of test names, ^(TestA|TestB|...)\$; it is: $TIMING_TESTS" >&2
  exit 1
fi

# file:test for every top-level Test function that calls growsLinearly (the
# helper's own definition is not a call).
# shellcheck disable=SC2016 # the single quotes hold an awk program
found=$(git ls-files -z -- 'go/*_test.go' | xargs -0 -r awk '
  FNR == 1 { fn = "" }
  /^func / {
    fn = ""
    if (match($0, /^func Test[A-Za-z0-9_]*\(/)) fn = substr($0, 6, RLENGTH - 6)
  }
  /growsLinearly\(/ && !/^func growsLinearly/ && fn != "" { print FILENAME ":" fn }
' | sort -u)

status=0
names=""
while IFS= read -r line; do
  [ -n "$line" ] || continue
  name=${line##*:}
  names="$names $name"
  if ! printf '%s\n' "$name" | grep -qE -- "$TIMING_TESTS"; then
    echo "${line%%:*}: $name calls growsLinearly but TIMING_TESTS (go.yml) does not name it, so it would run beside other test binaries" >&2
    status=1
  fi
done <<< "$found"

# Each name TIMING_TESTS lists is a test that still calls growsLinearly.
listed=$(printf '%s\n' "$TIMING_TESTS" | sed -E 's/^\^\(//; s/\)\$$//' | tr '|' '\n')
while IFS= read -r name; do
  case " $names " in
    *" $name "*) ;;
    *) echo "TIMING_TESTS names $name, which no test calling growsLinearly is" >&2; status=1 ;;
  esac
done <<< "$listed"

if [ "$status" -eq 0 ]; then
  echo "Every test that calls growsLinearly runs alone: $(printf '%s\n' "$found" | grep -c .) tests."
fi
exit "$status"
