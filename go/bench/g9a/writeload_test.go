// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A bound run's plan: the write scale is validated, does not make the plan
// a diagnostic one, and sets the added writes per second in W1's mix.
func TestPlanWriteScale(t *testing.T) {
	p := DefaultPlan()
	if p.BoundRun() || len(p.NotGate()) != 0 {
		t.Fatal("the profile is a bound run, or not the gate")
	}
	if d, v := p.WriteRates(p.Phases[3]); d != 0 || v != 0 {
		t.Fatalf("the profile adds writes: %g %g", d, v)
	}
	p.WriteScale = 1.7
	if err := p.Validate(); err != nil || !p.BoundRun() || len(p.NotGate()) != 0 {
		t.Fatalf("a bound run: %v, bound %v, not gate %v", err, p.BoundRun(), p.NotGate())
	}
	// 50/s: 0.7 × 50 disclosures, 0.7 × 5 × 20 / 60 value writes a second.
	d, v := p.WriteRates(p.Phases[3])
	if d < 34.999 || d > 35.001 || v < 1.1666 || v > 1.1667 {
		t.Fatalf("rates %g %g", d, v)
	}
	for _, s := range []float64{0.5, -1, MaxWriteScale + 0.1} {
		q := DefaultPlan()
		q.WriteScale = s
		if err := q.Validate(); err == nil || !strings.Contains(err.Error(), "writeScale") {
			t.Errorf("writeScale %g: %v", s, err)
		}
	}
	if PlannedWrites(35, 900) != 31500 || PlannedWrites(7.0/6, 900) != 1050 || PlannedWrites(0.5, 3) != 2 || PlannedWrites(0, 10) != 0 {
		t.Error("PlannedWrites")
	}
}

type fakeWriter struct {
	mu    sync.Mutex
	seen  map[WriteKind][]int
	fail  func(WriteKind, int) (bool, error)
	block chan struct{}
	calls atomic.Int64
}

func (f *fakeWriter) Write(ctx context.Context, k WriteKind, n int) (bool, error) {
	f.calls.Add(1)
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	f.seen[k] = append(f.seen[k], n)
	f.mu.Unlock()
	if f.fail != nil {
		return f.fail(k, n)
	}
	return false, nil
}

// runWriteLoad runs only the write load of p (its phases from now) and
// returns its events.
func runWriteLoad(t *testing.T, p Plan, w Writer, release func()) []Event {
	t.Helper()
	dir := t.TempDir()
	ev, err := newEventLog(filepath.Join(dir, FileEvents))
	if err != nil {
		t.Fatal(err)
	}
	r := &Runner{opts: RunnerOptions{Plan: p}, ev: ev}
	ctx, cancel := context.WithCancel(context.Background())
	r.writeLoad(ctx, context.Background(), time.Now(), w)
	time.Sleep(p.Duration() + 1500*time.Millisecond)
	if release != nil {
		release()
	}
	cancel()
	r.bg.Wait()
	r.writeLoadEnd()
	if err := ev.close(); err != nil {
		t.Fatal(err)
	}
	events, err := ReadEvents(filepath.Join(dir, FileEvents))
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func writePlan(rate int, seconds float64) Plan {
	p := DefaultPlan()
	p.Phases = []Phase{{Name: "w", Rate: rate, Seconds: seconds, Warmup: true}, {Name: "p", Rate: rate, Seconds: seconds}}
	p.Backups = nil
	p.ConvergeEverySeconds = 10 // 1 × 5 × 20 / 10: 10 value writes a second
	p.WriteScale = 2
	return p
}

func totals(events []Event) map[string]Event {
	out := map[string]Event{}
	for _, e := range events {
		if e.Ev == EvWriteLoadEnd {
			out[e.Kind] = e
		}
	}
	return out
}

// Every planned write is made once, numbered per kind; failures, busy
// writes and the first error are counted; the per-second events add up
// to the totals.
func TestWriteLoad(t *testing.T) {
	p := writePlan(20, 1) // 20 disclosures and 10 value writes in each of 2 phases
	w := &fakeWriter{seen: map[WriteKind][]int{}, fail: func(k WriteKind, n int) (bool, error) {
		if k == WriteDisclose && n == 3 {
			return true, errors.New("database is locked (SQLITE_BUSY)")
		}
		if k == WriteValue && n == 5 {
			return false, errors.New("refused")
		}
		return false, nil
	}}
	events := runWriteLoad(t, p, w, nil)
	tot := totals(events)
	d, v := tot[string(WriteDisclose)], tot[string(WriteValue)]
	if d.Planned != 40 || d.Writes != 40 || d.WritesFailed != 1 || d.WritesBusy != 1 || d.WritesLate != 0 || !strings.Contains(d.Err, "SQLITE_BUSY") {
		t.Errorf("disclosures: %+v", d)
	}
	if v.Planned != 20 || v.Writes != 20 || v.WritesFailed != 1 || v.WritesBusy != 0 || v.Err != "refused" {
		t.Errorf("value writes: %+v", v)
	}
	for _, k := range WriteKinds {
		seen := map[int]bool{}
		for _, n := range w.seen[k] {
			seen[n] = true
		}
		if len(seen) != len(w.seen[k]) || !seen[0] || !seen[len(w.seen[k])-1] {
			t.Errorf("%s numbered %v", k, w.seen[k])
		}
	}
	sum := map[string]int64{}
	for _, e := range events {
		if e.Ev == EvWriteLoad {
			sum[e.Kind] += e.Writes
			if e.Phase != "w" && e.Phase != "p" && e.Phase != "" {
				t.Errorf("phase %q", e.Phase)
			}
		}
	}
	if sum[string(WriteDisclose)] != 40 || sum[string(WriteValue)] != 20 {
		t.Errorf("per-second events add up to %v", sum)
	}
}

// Open loop: a write that comes due while WriteInFlight are running is
// not sent, and counted late.
func TestWriteLoadLate(t *testing.T) {
	p := writePlan(100, 1) // 200 disclosures due in 2 s
	block := make(chan struct{})
	w := &fakeWriter{seen: map[WriteKind][]int{}, block: block}
	events := runWriteLoad(t, p, w, func() { close(block) })
	d := totals(events)[string(WriteDisclose)]
	if d.WritesLate == 0 || d.Writes+d.WritesLate != d.Planned || d.Writes > WriteInFlight {
		t.Errorf("disclosures: %+v", d)
	}
}
