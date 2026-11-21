// SPDX-License-Identifier: Apache-2.0

//go:build race

package broker

// raceSlowdown scales the scenarios' waits under the race detector, which
// makes decompressing a bomb several times slower.
const raceSlowdown = 6
