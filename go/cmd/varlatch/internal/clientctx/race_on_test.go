// SPDX-License-Identifier: Apache-2.0

//go:build race

package clientctx

// raceSlowdown is how much slower the race detector makes the timing
// tests' work: their inputs are smaller under it (as in internal/matcher).
const raceSlowdown = 10
