// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"math"
	"slices"
	"time"
)

// A request's latency is counted from its scheduled start (G9a: open
// loop). k6's constant-arrival-rate executor starts iteration slot j at
// the scenario's start + j / rate, and drops a slot when no VU is free, so
// a slot it starts is never delayed by a dropped one. The script knows a
// request's iteration (iterationInTest), but that counts only the
// iterations k6 started: after d drops it is d slots behind the request's
// slot, and a schedule computed from it is d intervals too early. In G9's
// bound run of 2026-11-18, 29 drops added 580 ms to every later request.
//
// dropSafe fixes that: when k6 dropped iterations, a request's slot is its
// iteration i plus the drops before it, d(i), and its latency is the
// dispatch's lateness from that slot plus its service time. The wall clock
// gives o(i) = round((dispatch - start) * rate) - i for each request: d(i)
// for one sent on time, more for one sent late (a stalled k6). Drops only
// accumulate, so d(i) is taken as the smallest o over the request and every
// later one in its phase: a request sent late keeps its lateness unless
// drops came before the next request sent on time. Without drops the
// iteration's slot is exact and kept, so a run with no drops is judged
// exactly as before. The drops the slots imply are reported beside k6's
// count, and the dropped iterations still fail the run.

// ScheduleBasis says how the requests' scheduled starts were found.
type ScheduleBasis struct {
	// K6Dropped is k6's dropped_iterations; WallClock is true when the
	// requests were placed on their wall-clock slots (K6Dropped > 0).
	K6Dropped float64 `json:"k6Dropped"`
	WallClock bool    `json:"wallClockSlots"`
	// InferredDrops is the slots skipped before each phase's last request,
	// summed over the phases; Moved the requests whose slot moved, and
	// MaxShiftMs the largest move.
	InferredDrops int64   `json:"inferredDrops"`
	Moved         int     `json:"moved"`
	MaxShiftMs    float64 `json:"maxShiftMs"`
	// Reconstructed is true when the log had no dispatch times (older
	// logs) and they were taken from its own columns.
	Reconstructed bool `json:"reconstructed,omitempty"`
}

// LatencyParts are one phase's latency in its two parts: the dispatch's
// lateness from the request's scheduled start, and the service time.
type LatencyParts struct {
	Phase         string  `json:"phase"`
	LatenessP99Ms float64 `json:"latenessP99Ms"`
	LatenessMaxMs float64 `json:"latenessMaxMs"`
	ServiceP95Ms  float64 `json:"serviceP95Ms"`
	ServiceMaxMs  float64 `json:"serviceMaxMs"`
}

// dropSafe places the requests on their slots when k6 dropped iterations
// (see above), in place, and reports how.
func dropSafe(reqs []Request, p Plan, dropped float64) ScheduleBasis {
	b := ScheduleBasis{K6Dropped: dropped, WallClock: dropped > 0}
	if !b.WallClock {
		return b
	}
	rates := map[string]float64{}
	for _, ph := range p.Phases {
		rates[ph.Name] = float64(ph.Rate)
	}
	// Older logs: the dispatch is the schedule plus the latency's
	// lateness, the scenario's start its first request's schedule (slot 0
	// is never dropped: every VU is free then), the iteration from the
	// schedule.
	starts := map[string]int64{}
	for _, q := range reqs {
		if q.DispatchUs != 0 {
			continue
		}
		b.Reconstructed = true
		if s, ok := starts[q.Phase]; !ok || q.SchedUs < s {
			starts[q.Phase] = q.SchedUs
		}
	}
	// Each phase's requests in iteration order, with their wall-clock
	// offsets o; d is the suffix minimum of o.
	type slot struct {
		k                 int // index in reqs
		iter, o, dispatch int64
		start             int64
		interval          float64
	}
	byPhase := map[string][]slot{}
	for k := range reqs {
		q := &reqs[k]
		rate := rates[q.Phase]
		if rate <= 0 {
			continue
		}
		interval := 1e6 / rate // µs
		dispatch, start, iter := q.DispatchUs, q.StartUs, q.Iter
		if dispatch == 0 {
			start = starts[q.Phase]
			dispatch = q.SchedUs + (q.Lat - q.Service).Microseconds()
			iter = int64(math.Round(float64(q.SchedUs-start) / interval))
		}
		o := max(0, int64(math.Round(float64(dispatch-start)/interval))-iter)
		byPhase[q.Phase] = append(byPhase[q.Phase], slot{k, iter, o, dispatch, start, interval})
	}
	for _, ss := range byPhase {
		slices.SortFunc(ss, func(a, b slot) int { return int(a.iter - b.iter) })
		d := int64(math.MaxInt64)
		for n := len(ss) - 1; n >= 0; n-- {
			s := ss[n]
			d = min(d, s.o)
			if n == len(ss)-1 {
				b.InferredDrops += d
			}
			q := &reqs[s.k]
			if d > 0 {
				b.Moved++
				b.MaxShiftMs = max(b.MaxShiftMs, float64(d)*s.interval/1e3)
			}
			sched := s.start + int64(math.Round(float64(s.iter+d)*s.interval))
			q.SchedUs = sched
			q.Lat = time.Duration(max(0, s.dispatch-sched))*time.Microsecond + q.Service
		}
	}
	return b
}

// latencyParts is each phase's dispatch lateness and service time.
func latencyParts(reqs []Request, p Plan) []LatencyParts {
	late, svc := map[string][]float64{}, map[string][]float64{}
	for _, q := range reqs {
		if q.Status == 0 {
			continue
		}
		late[q.Phase] = append(late[q.Phase], float64((q.Lat-q.Service).Microseconds())/1e3)
		svc[q.Phase] = append(svc[q.Phase], float64(q.Service.Microseconds())/1e3)
	}
	var out []LatencyParts
	for _, ph := range p.Phases {
		l, s := late[ph.Name], svc[ph.Name]
		if len(l) == 0 {
			continue
		}
		slices.Sort(l)
		slices.Sort(s)
		out = append(out, LatencyParts{Phase: ph.Name, LatenessP99Ms: rank(l, 99), LatenessMaxMs: l[len(l)-1], ServiceP95Ms: rank(s, 95), ServiceMaxMs: s[len(s)-1]})
	}
	return out
}
