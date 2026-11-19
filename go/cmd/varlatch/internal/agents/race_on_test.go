// SPDX-License-Identifier: Apache-2.0

//go:build race

package agents

// raceSlowdown scales time budgets under the race detector, whose
// instrumented code runs several times slower.
const raceSlowdown = 10
