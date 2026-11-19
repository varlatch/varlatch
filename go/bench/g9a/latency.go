// SPDX-License-Identifier: Apache-2.0

package g9a

import "slices"

// G9a's measure (ADR-0059, Acceptance, G9a's Load; G9 takes it over):
// "latency counted from each request's scheduled start; a request not sent
// on time counts as failed". The script's scheduled start is its scenario's
// start plus its iteration (k6's iterationInTest) over the rate.
//
//   - Without drops that is each request's slot, and the report judges
//     latency from it as it always has. One limit remains: k6 assigns
//     iterationInTest after it hands the iteration to a VU, so a stall can
//     reorder a few requests by a few slots (20 ms each at 50/s).
//   - With drops, iterationInTest leaves the dropped iterations out, so the
//     script's schedule is one interval early per earlier drop (in G9's
//     bound run of 2026-11-18, 29 drops at 50/s added 580 ms to every later
//     request), and the real slot is not known: no request's
//     scheduled-start latency can be measured. The run fails on the drops
//     (a request not sent on time), and the report judges no phase or
//     window p95. It shows, reported only and not the G9 measure, each
//     request's HTTP time from its send (k6's blocked + duration), with the
//     windows taken by send time, and the dispatch lateness against the
//     iteration slot: an upper bound, since it includes one interval per
//     earlier drop. Nothing is inferred.

// ScheduleBasis says what the requests' latency is counted from.
type ScheduleBasis struct {
	// K6Dropped is k6's dropped_iterations. Judged is true when latency is
	// counted from each request's scheduled start (no drops), the G9
	// measure; false when it is HTTP time from the send, reported only.
	K6Dropped float64 `json:"k6Dropped"`
	Judged    bool    `json:"scheduledStartJudged"`
	// Reconstructed is true when the log had no dispatch times (older
	// logs) and the sends were taken from its own columns.
	Reconstructed bool `json:"reconstructed,omitempty"`
}

// LatencyParts are one phase's latency in its two parts, over all its
// requests (transport failures included): the dispatch's lateness against
// the iteration slot, and the HTTP time from the send.
type LatencyParts struct {
	Phase         string  `json:"phase"`
	LatenessP99Ms float64 `json:"latenessP99Ms"`
	LatenessMaxMs float64 `json:"latenessMaxMs"`
	HTTPP95Ms     float64 `json:"httpTimeP95Ms"`
	HTTPMaxMs     float64 `json:"httpTimeMaxMs"`
}

// latencyBasis decides what latency is counted from. With drops it puts
// each request at its send, with its HTTP time as its latency (reported
// only); without, it changes nothing.
func latencyBasis(reqs []Request, dropped float64) ScheduleBasis {
	b := ScheduleBasis{K6Dropped: dropped, Judged: dropped == 0}
	if b.Judged {
		return b
	}
	for k := range reqs {
		q := &reqs[k]
		send := q.DispatchUs
		if send == 0 {
			b.Reconstructed = true
			send = q.SchedUs + (q.Lat - q.Service).Microseconds()
		}
		q.SchedUs, q.Lat = send, q.Service
	}
	return b
}

// latencyParts is each phase's dispatch lateness and HTTP time, over every
// request of the phase, as its phase and windows count them. Call it before
// latencyBasis.
func latencyParts(reqs []Request, p Plan) []LatencyParts {
	late, http := map[string][]float64{}, map[string][]float64{}
	for _, q := range reqs {
		late[q.Phase] = append(late[q.Phase], float64((q.Lat-q.Service).Microseconds())/1e3)
		http[q.Phase] = append(http[q.Phase], float64(q.Service.Microseconds())/1e3)
	}
	var out []LatencyParts
	for _, ph := range p.Phases {
		l, h := late[ph.Name], http[ph.Name]
		if len(l) == 0 {
			continue
		}
		slices.Sort(l)
		slices.Sort(h)
		out = append(out, LatencyParts{Phase: ph.Name, LatenessP99Ms: rank(l, 99), LatenessMaxMs: l[len(l)-1], HTTPP95Ms: rank(h, 95), HTTPMaxMs: h[len(h)-1]})
	}
	return out
}
