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
// while this many are still running is not sent, and counted late.
const WriteInFlight = 64

// EvWriteLoad is a second of a bound run's write load for one kind (its
// phase, the writes that ended in it, failed, met SQLITE_BUSY or were not
// sent on time); EvWriteLoadEnd is the totals and the writes planned, once
// the run's work has finished.
const (
	EvWriteLoad    = "write_load"
	EvWriteLoadEnd = "write_load_end"
)

// writeCounts are one kind's counters.
type writeCounts struct {
	done, failed, busy, late atomic.Int64
	firstErr                 atomic.Pointer[string]
}

// PlannedWrites is how many added writes of each kind a phase schedules:
// one every 1/rate seconds from its start, the last before its end.
func PlannedWrites(rate, phaseSeconds float64) int {
	if rate <= 0 {
		return 0
	}
	return int(math.Ceil(rate*phaseSeconds - 1e-9))
}

// writeLoad runs the plan's added writes from t0 until the load ends or
// ctx does; each write runs under work, so one that started finishes.
func (r *Runner) writeLoad(ctx, work context.Context, t0 time.Time, w Writer) {
	p := r.opts.Plan
	counts := map[WriteKind]*writeCounts{}
	for _, k := range WriteKinds {
		counts[k] = &writeCounts{}
	}
	r.writes = counts
	sem := make(chan struct{}, WriteInFlight)
	var inflight sync.WaitGroup
	for _, kind := range WriteKinds {
		r.bg.Add(1)
		go func() {
			defer r.bg.Done()
			c, n, at := counts[kind], 0, t0
			for _, ph := range p.Phases {
				d, v := p.WriteRates(ph)
				rate := map[WriteKind]float64{WriteDisclose: d, WriteValue: v}[kind]
				planned := PlannedWrites(rate, ph.Seconds)
				for i := range planned {
					due := at.Add(time.Duration(float64(i) / rate * float64(time.Second)))
					select {
					case <-time.After(time.Until(due)):
					case <-ctx.Done():
						return
					}
					select {
					case sem <- struct{}{}:
					default:
						c.late.Add(1)
						n++
						continue
					}
					inflight.Add(1)
					go func(n int) {
						defer func() { <-sem; inflight.Done() }()
						busy, err := w.Write(work, kind, n)
						if busy {
							c.busy.Add(1)
						}
						if err != nil {
							c.failed.Add(1)
							msg := err.Error()
							c.firstErr.CompareAndSwap(nil, &msg)
						}
						c.done.Add(1)
					}(n)
					n++
				}
				at = at.Add(seconds(ph.Seconds))
			}
		}()
	}
	// One event a second for each kind: what ended in that second.
	var last = map[WriteKind][4]int64{}
	r.every(ctx, t0.Add(time.Second), time.Second, func() {
		phase := p.phaseAt(time.Since(t0))
		for _, k := range WriteKinds {
			c := counts[k]
			now := [4]int64{c.done.Load(), c.failed.Load(), c.busy.Load(), c.late.Load()}
			prev := last[k]
			last[k] = now
			if now == prev {
				continue
			}
			r.ev.emit(Event{Ev: EvWriteLoad, Kind: string(k), Phase: phase,
				Writes: now[0] - prev[0], WritesFailed: now[1] - prev[1], WritesBusy: now[2] - prev[2], WritesLate: now[3] - prev[3]})
		}
	})
	r.writesDone = inflight.Wait
}

// writeLoadEnd logs each kind's totals and the writes the plan scheduled.
func (r *Runner) writeLoadEnd() {
	if r.writes == nil {
		return
	}
	if r.writesDone != nil {
		r.writesDone()
	}
	p := r.opts.Plan
	for _, k := range WriteKinds {
		planned := 0
		for _, ph := range p.Phases {
			d, v := p.WriteRates(ph)
			planned += PlannedWrites(map[WriteKind]float64{WriteDisclose: d, WriteValue: v}[k], ph.Seconds)
		}
		c := r.writes[k]
		e := Event{Ev: EvWriteLoadEnd, Kind: string(k), Planned: int64(planned),
			Writes: c.done.Load(), WritesFailed: c.failed.Load(), WritesBusy: c.busy.Load(), WritesLate: c.late.Load()}
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
