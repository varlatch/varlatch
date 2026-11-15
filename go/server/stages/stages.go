// SPDX-License-Identifier: AGPL-3.0-or-later

// Package stages times the stages of a request (step 4 decision 7: G9a's
// slower baseline is diagnosed with per-stage timings for a disclosure).
// A request carries a Recorder only in the g9a build, which attaches one
// to the disclosures it serves (server/daemon/bench_g9a.go); everywhere
// else the marks cost a context lookup and record nothing.
//
// The stages, in a request's order:
//
//	admission       arrival to the operation's handler: the body limit, the
//	                request window, routing
//	authentication  the bearer credential resolved
//	snapshot        the read snapshot (authorization's reads included)
//	authorization   each authorization decision, summed
//	queue           the write job's wait for the single writer
//	commit          the COMMIT of the batch that held the job
//	decryption      the values opened, after the audit job committed
//	encoding        the response body written as JSON
package stages

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
)

// Names are the stages, in a request's order.
var Names = []string{"admission", "authentication", "snapshot", "authorization", "queue", "commit", "decryption", "encoding"}

// Recorder receives each stage's time.
type Recorder interface {
	Add(stage string, d time.Duration)
}

type key struct{}

type request struct {
	r       Recorder
	arrived time.Time
}

// With attaches r to a request that arrived at arrived; the storage
// engine's job timings (queue wait and commit) of writes made with ctx go
// to it too.
func With(ctx context.Context, r Recorder, arrived time.Time) context.Context {
	ctx = context.WithValue(ctx, key{}, &request{r: r, arrived: arrived})
	return storage.WithTiming(ctx, func(t storage.JobTiming) {
		r.Add("queue", t.QueueWait)
		r.Add("commit", t.Commit)
	})
}

// Since records the time since start as stage, if ctx has a Recorder.
func Since(ctx context.Context, stage string, start time.Time) {
	if q, _ := ctx.Value(key{}).(*request); q != nil {
		q.r.Add(stage, time.Since(start))
	}
}

// Admitted records admission: from the request's arrival to now, when its
// operation's handler starts.
func Admitted(ctx context.Context) {
	if q, _ := ctx.Value(key{}).(*request); q != nil {
		q.r.Add("admission", time.Since(q.arrived))
	}
}

// Histogram is a Recorder that keeps each stage's times in logarithmic
// buckets (2 % wide, from 100 ns to 100 s), so its memory stays bounded
// however long the run.
type Histogram struct {
	mu      sync.Mutex
	buckets map[string][]uint64
	sums    map[string]time.Duration
}

const (
	bucketRatio = 1.02
	bucketBase  = 100 * time.Nanosecond
	bucketCount = 1100 // 100 ns * 1.02^1100 > 100 s
)

// NewHistogram returns an empty Histogram.
func NewHistogram() *Histogram {
	return &Histogram{buckets: map[string][]uint64{}, sums: map[string]time.Duration{}}
}

func bucketOf(d time.Duration) int {
	if d <= bucketBase {
		return 0
	}
	i := int(math.Log(float64(d)/float64(bucketBase))/math.Log(bucketRatio)) + 1
	return min(i, bucketCount-1)
}

// upper is a bucket's upper bound.
func upper(i int) time.Duration {
	return time.Duration(float64(bucketBase) * math.Pow(bucketRatio, float64(i)))
}

// Add records one time.
func (h *Histogram) Add(stage string, d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.buckets[stage]
	if b == nil {
		b = make([]uint64, bucketCount)
		h.buckets[stage] = b
	}
	b[bucketOf(d)]++
	h.sums[stage] += d
}

// Summary is one stage's times, in milliseconds (percentiles are bucket
// upper bounds: within 2 % above the true value).
type Summary struct {
	Stage  string  `json:"stage"`
	Count  uint64  `json:"count"`
	MeanMs float64 `json:"meanMs"`
	P50Ms  float64 `json:"p50Ms"`
	P95Ms  float64 `json:"p95Ms"`
	P99Ms  float64 `json:"p99Ms"`
	MaxMs  float64 `json:"maxMs"`
}

// Summaries are every stage recorded, in Names' order, others after by name.
func (h *Histogram) Summaries() []Summary {
	h.mu.Lock()
	defer h.mu.Unlock()
	order := map[string]int{}
	for i, n := range Names {
		order[n] = i
	}
	var stages []string
	for s := range h.buckets {
		stages = append(stages, s)
	}
	sort.Slice(stages, func(i, j int) bool {
		oi, iok := order[stages[i]]
		oj, jok := order[stages[j]]
		switch {
		case iok && jok:
			return oi < oj
		case iok != jok:
			return iok
		}
		return stages[i] < stages[j]
	})
	ms := func(d time.Duration) float64 { return math.Round(float64(d)/1e3) / 1e3 }
	out := make([]Summary, 0, len(stages))
	for _, s := range stages {
		b := h.buckets[s]
		var n uint64
		last := 0
		for i, c := range b {
			n += c
			if c > 0 {
				last = i
			}
		}
		at := func(p float64) time.Duration {
			want := uint64(math.Ceil(p * float64(n)))
			var seen uint64
			for i, c := range b {
				seen += c
				if seen >= want {
					return upper(i)
				}
			}
			return upper(last)
		}
		out = append(out, Summary{Stage: s, Count: n, MeanMs: ms(h.sums[s] / time.Duration(n)),
			P50Ms: ms(at(0.5)), P95Ms: ms(at(0.95)), P99Ms: ms(at(0.99)), MaxMs: ms(upper(last))})
	}
	return out
}
