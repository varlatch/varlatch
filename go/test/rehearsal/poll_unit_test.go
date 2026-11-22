// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"testing"
	"time"
)

// Item 6's poll: a source that answers late is waited for and its time to
// the first answer recorded; one that never answers fails at the deadline,
// with its last answer; one that answers at once takes one request.
func TestAnswersWithin(t *testing.T) {
	pass := func(code int, _ string) bool { return code == 200 }
	answersAfter := func(n int) func() (int, string) {
		calls := 0
		return func() (int, string) {
			calls++
			if calls <= n {
				return 502, "bad gateway"
			}
			return 200, `{"serverVersion":"0.23.0"}`
		}
	}
	if a := answersWithin(answersAfter(0), pass, time.Second, 10*time.Millisecond); !a.ok || a.tries != 1 || a.code != 200 {
		t.Errorf("at once: %+v", a)
	}
	a := answersWithin(answersAfter(3), pass, time.Second, 10*time.Millisecond)
	if !a.ok || a.tries != 4 || a.took < 30*time.Millisecond || a.took > 900*time.Millisecond {
		t.Errorf("late: %+v", a)
	}
	never := answersWithin(func() (int, string) { return 0, "connection refused" }, pass, 100*time.Millisecond, 10*time.Millisecond)
	if never.ok || never.code != 0 || never.body != "connection refused" || never.tries < 2 || never.took > time.Second {
		t.Errorf("never: %+v", never)
	}
}
