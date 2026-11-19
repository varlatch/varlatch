// SPDX-License-Identifier: Apache-2.0

//go:build !race

package jsjson

// raceSlowdown scales time budgets under the race detector.
const raceSlowdown = 1
