// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build race

package syncs_test

// sampleEvery: under the race detector, the crash and fence tests take one
// point in seven, one at a time (every point runs, in parallel, in the
// ordinary test run).
const sampleEvery = 7
