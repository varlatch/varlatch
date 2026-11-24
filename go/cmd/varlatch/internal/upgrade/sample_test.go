// SPDX-License-Identifier: Apache-2.0

//go:build linux

package upgrade

import "os"

// everything is whether each interruption is tried. By default a fixed part
// of them is, so that the package takes a minute or two: a pull request's
// run. All of them are
//
//	VARLATCH_UPGRADE_TESTS=all go test -timeout 60m ./cmd/varlatch/internal/upgrade
//
// which the Go workflow runs at night and when started by hand, and the
// release workflow for the commit it releases.
func everything() bool { return os.Getenv("VARLATCH_UPGRADE_TESTS") == "all" }

// oneIn is how many interruptions there are to each one tried: 1 when each
// is, n otherwise.
func oneIn(n int) int {
	if everything() {
		return 1
	}
	return n
}

// of is the cases to run: all of them, or the first n, which are the ones
// that stand for the rest.
func of[T any](n int, cases []T) []T {
	if everything() || n >= len(cases) {
		return cases
	}
	return cases[:n]
}
