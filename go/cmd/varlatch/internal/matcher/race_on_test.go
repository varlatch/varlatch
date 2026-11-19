// SPDX-License-Identifier: Apache-2.0

//go:build race

package matcher

// raceSlowdown scales the timing tests' bounds under the race detector.
const raceSlowdown = 10
