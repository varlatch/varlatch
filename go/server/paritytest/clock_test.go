// SPDX-License-Identifier: AGPL-3.0-or-later

package paritytest

import (
	"testing"
	"time"
)

// A replay that starts a second before an hour ends and runs on for two
// minutes keeps every time in the one hour, as far apart as on the real
// clock: its report counts are never split between two buckets.
func TestHourClockKeepsAReplayInOneHour(t *testing.T) {
	real := time.Date(2026, 11, 15, 22, 59, 59, 500_000_000, time.UTC)
	clock := hourClock(func() time.Time { return real })
	first := clock()
	if want := time.Date(2026, 11, 15, 22, 0, 0, 0, time.UTC); !first.Equal(want) {
		t.Fatalf("the replay starts at %v, want %v", first, want)
	}
	real = real.Add(2 * time.Minute)
	later := clock()
	if later.Truncate(time.Hour) != first.Truncate(time.Hour) {
		t.Errorf("%v left the hour %v began in", later, first)
	}
	if d := later.Sub(first); d != 2*time.Minute {
		t.Errorf("%v elapsed, want 2m0s", d)
	}
}
