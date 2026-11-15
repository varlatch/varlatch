// SPDX-License-Identifier: AGPL-3.0-or-later

package stages

import (
	"testing"
	"time"
)

// The buckets hold every time from under 100 ns to beyond 100 s, within 2 %.
func TestBuckets(t *testing.T) {
	for _, d := range []time.Duration{0, 50, 100, 101, time.Microsecond, 7 * time.Millisecond, time.Second, 99 * time.Second, time.Hour} {
		i := bucketOf(d)
		if i < 0 || i >= bucketCount {
			t.Fatalf("%v: bucket %d", d, i)
		}
		if d > bucketBase && d < 100*time.Second {
			if up := upper(i); up < d || float64(up) > float64(d)*1.0201 {
				t.Errorf("%v: bucket %d up to %v", d, i, up)
			}
		}
	}
}

// Summaries come in the stages' order, then others by name.
func TestSummaries(t *testing.T) {
	h := NewHistogram()
	for _, s := range []string{"zeta", "commit", "admission", "commit"} {
		h.Add(s, 2*time.Millisecond)
	}
	got := h.Summaries()
	if len(got) != 3 || got[0].Stage != "admission" || got[1].Stage != "commit" || got[1].Count != 2 || got[2].Stage != "zeta" || got[1].P50Ms < 2 || got[1].P50Ms > 2.05 {
		t.Errorf("%+v", got)
	}
}
