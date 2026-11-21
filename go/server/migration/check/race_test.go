// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build race

package check_test

// raceDetector is on: the decision table is cut to every fourth pair, so
// the race run stays within its time.
const raceDetector = true
