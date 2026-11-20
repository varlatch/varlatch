// SPDX-License-Identifier: Apache-2.0

//go:build !race

package agents

// raceSlowdown is how much slower the race detector makes the timing
// tests' work: their sizing starts that much smaller under it (as in
// internal/matcher).
const raceSlowdown = 1
