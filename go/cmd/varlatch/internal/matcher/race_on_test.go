// SPDX-License-Identifier: Apache-2.0

//go:build race

package matcher

// raceSlowdown is how much slower the race detector makes the timing
// tests' work: their inputs are smaller under it.
const raceSlowdown = 10
