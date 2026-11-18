// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// A bound run's write load (Plan.WriteScale above 1): ADR-0059 G9 says
// that when the WAL never reaches the shipped bound under the profile,
// "a separate run at the same bound raises the write rate until the
// trigger fires and passes the same criteria". The load adds, in every
// phase, the writes of Plan.WriteRates: disclosures and value writes in
// W1's mix, open loop, each made by the server in-process through the
// production write paths (so they are not requests of the load, and the
// load's accounting is unchanged). Everything else in the profile stays.

// WriteKind is one kind of a bound run's added writes.
type WriteKind string

const (
	// WriteDisclose is a disclosure of one Secret through the read path
	// of values, its audit event committed before the value is decrypted.
	WriteDisclose WriteKind = "disclose"
	// WriteValue is a value write: a new version and its audit event.
	WriteValue WriteKind = "value"
)

// WriteKinds are the kinds, in the order the report shows them.
var WriteKinds = []WriteKind{WriteDisclose, WriteValue}

// Writer is a Target that can make a bound run's added writes
// (varlatchd's g9a build).
type Writer interface {
	// Write makes added write n of its kind (from 0); busy is SQLITE_BUSY
	// reaching one of its writes.
	Write(ctx context.Context, kind WriteKind, n int) (busy bool, err error)
}

// WriteInFlight bounds the added writes in flight: one that comes due
// while this many are still running is not sent (skipped).
const WriteInFlight = 64

// WriteLateTolerance is how long after its scheduled time a write may be
// dispatched and still count as on time: a write dispatched later (a
// stalled scheduler, its timers firing at once) is made, and counted late.
// It guards the write load's arrival pattern only. ADR-0059's 100 ms p95
// applies to retrievals and sets no limit on these writes. At G9's 35
// added disclosures a second in the 50/s phase, 250 ms bounds any bunching
// to about 9 writes.
const WriteLateTolerance = 250 * time.Millisecond

// EvWriteLoad is one kind's added writes scheduled in one phase that ended
// since the previous such event (their counts: made, failed, met
// SQLITE_BUSY, dispatched late, skipped), logged every second and once
// more after the last write has ended; EvWriteLoadEnd is one kind's totals
// and the writes the server planned, after that.
const (
	EvWriteLoad    = "write_load"
	EvWriteLoadEnd = "write_load_end"
)

// writeTally counts writes: made, failed, busy, late (dispatched after
// WriteLateTolerance) and skipped (not sent: WriteInFlight running).
type writeTally struct{ done, failed, busy, late, skipped atomic.Int64 }

func (t *writeTally) load() [5]int64 {
	return [5]int64{t.done.Load(), t.failed.Load(), t.busy.Load(), t.late.Load(), t.skipped.Load()}
}

// writeCounts are one kind's tallies, by the phase that scheduled each
// write, and its first error and largest dispatch lag.
type writeCounts struct {
	phases   []writeTally
	firstErr atomic.Pointer[string]
	maxLagUs atomic.Int64
}

func (c *writeCounts) total() [5]int64 {
	var t [5]int64
	for i := range c.phases {
		for j, v := range c.phases[i].load() {
			t[j] += v
		}
	}
	return t
}

// PlannedWrites is how many added writes of each kind a phase schedules:
// one at each i/rate seconds from its start that falls before its end, so
// any positive rate schedules at least the one at its start. A product
// within a millionth of a positive whole number counts as that number.
func PlannedWrites(rate, phaseSeconds float64) int {
	x := rate * phaseSeconds
	if !(x > 0) {
		return 0
	}
	if n := math.Round(x); n >= 1 && math.Abs(x-n) < 1e-6 {
		return int(n)
	}
	return int(math.Ceil(x))
}

// rateOf is a kind's added writes per second in a phase.
func (p Plan) rateOf(k WriteKind, ph Phase) float64 {
	d, v := p.WriteRates(ph)
	if k == WriteDisclose {
		return d
	}
	return v
}

// PlannedWriteTotal is how many added writes of kind k the plan schedules
// over all its phases.
func (p Plan) PlannedWriteTotal(k WriteKind) int {
	n := 0
	for _, ph := range p.Phases {
		n += PlannedWrites(p.rateOf(k, ph), ph.Seconds)
	}
	return n
}

// writeDispatchHook, when set (tests), runs before the scheduler waits for
// write n of kind: a test stalls the scheduler with it.
var writeDispatchHook func(kind WriteKind, n int)

// writeLoad runs the plan's added writes from t0 until the load ends or
// ctx does; each write runs under work, so one that started finishes.
// writeLoadEnd drains them and logs the last counts and the totals.
func (r *Runner) writeLoad(ctx, work context.Context, t0 time.Time, w Writer) {
	p := r.opts.Plan
	counts := map[WriteKind]*writeCounts{}
	for _, k := range WriteKinds {
		counts[k] = &writeCounts{phases: make([]writeTally, len(p.Phases))}
	}
	r.writes = counts
	sem := make(chan struct{}, WriteInFlight)
	var inflight sync.WaitGroup
	for _, kind := range WriteKinds {
		r.bg.Add(1)
		go func() {
			defer r.bg.Done()
			c, n, at := counts[kind], 0, t0
			for pi, ph := range p.Phases {
				rate := p.rateOf(kind, ph)
				tally := &c.phases[pi]
				for i := range PlannedWrites(rate, ph.Seconds) {
					due := at.Add(time.Duration(float64(i) / rate * float64(time.Second)))
					if writeDispatchHook != nil {
						writeDispatchHook(kind, n)
					}
					select {
					case <-time.After(time.Until(due)):
					case <-ctx.Done():
						return
					}
					select {
					case sem <- struct{}{}:
					default:
						tally.skipped.Add(1)
						n++
						continue
					}
					// Open loop: a write is on time if it is dispatched
					// within the tolerance of when it was scheduled.
					lag := time.Since(due)
					for {
						m := c.maxLagUs.Load()
						if lag.Microseconds() <= m || c.maxLagUs.CompareAndSwap(m, lag.Microseconds()) {
							break
						}
					}
					late := lag > WriteLateTolerance
					inflight.Add(1)
					go func(n int) {
						defer func() { <-sem; inflight.Done() }()
						busy, err := w.Write(work, kind, n)
						if busy {
							tally.busy.Add(1)
						}
						if err != nil {
							tally.failed.Add(1)
							msg := err.Error()
							c.firstErr.CompareAndSwap(nil, &msg)
						}
						if late {
							tally.late.Add(1)
						}
						tally.done.Add(1)
					}(n)
					n++
				}
				at = at.Add(seconds(ph.Seconds))
			}
		}()
	}
	r.writesDone = inflight.Wait
	r.writeLast = map[[2]int][5]int64{}
	r.every(ctx, t0.Add(time.Second), time.Second, r.flushWriteLoad)
}

// flushWriteLoad logs, for each kind and phase, what ended since the last
// flush. The per-second sampler calls it, and writeLoadEnd once more after
// the last write, so the events add up to the totals.
func (r *Runner) flushWriteLoad() {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	for ki, k := range WriteKinds {
		c := r.writes[k]
		for pi := range c.phases {
			now := c.phases[pi].load()
			key := [2]int{ki, pi}
			prev := r.writeLast[key]
			if now == prev {
				continue
			}
			r.writeLast[key] = now
			r.ev.emit(Event{Ev: EvWriteLoad, Kind: string(k), Phase: r.opts.Plan.Phases[pi].Name,
				Writes: now[0] - prev[0], WritesFailed: now[1] - prev[1], WritesBusy: now[2] - prev[2], WritesLate: now[3] - prev[3], WritesSkipped: now[4] - prev[4]})
		}
	}
}

// writeLoadEnd waits for the writes in flight, logs what ended since the
// last flush, and each kind's totals with the writes the server planned
// and the largest dispatch lag.
func (r *Runner) writeLoadEnd() {
	if r.writes == nil {
		return
	}
	if r.writesDone != nil {
		r.writesDone()
	}
	r.flushWriteLoad()
	for _, k := range WriteKinds {
		c := r.writes[k]
		t := c.total()
		e := Event{Ev: EvWriteLoadEnd, Kind: string(k), Planned: int64(r.opts.Plan.PlannedWriteTotal(k)),
			Writes: t[0], WritesFailed: t[1], WritesBusy: t[2], WritesLate: t[3], WritesSkipped: t[4], DurUs: c.maxLagUs.Load()}
		if m := c.firstErr.Load(); m != nil {
			e.Err = *m
		}
		r.ev.emit(e)
	}
}

// phaseAt is the name of the phase running at offset d from the run's
// start ("" after the last).
func (p Plan) phaseAt(d time.Duration) string {
	var at time.Duration
	for _, ph := range p.Phases {
		at += seconds(ph.Seconds)
		if d < at {
			return ph.Name
		}
	}
	return ""
}
