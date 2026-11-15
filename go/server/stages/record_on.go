// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g9a

package stages

import (
	"context"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
)

// Mark is a stage's start.
type Mark struct{ t time.Time }

// Start takes a stage's start.
func Start() Mark { return Mark{time.Now()} }

type key struct{}

// request is one request's stages, summed until Flush.
type request struct {
	r       Recorder
	arrived time.Time
	mu      sync.Mutex
	sums    map[string]time.Duration
	order   []string
}

func (q *request) add(stage string, d time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.sums[stage]; !ok {
		q.order = append(q.order, stage)
	}
	q.sums[stage] += d
}

// With attaches r to a request that arrived at arrived; the storage
// engine's job timings (queue wait and commit) of writes made with ctx
// count too. Flush hands the request's stages to r.
func With(ctx context.Context, r Recorder, arrived time.Time) context.Context {
	q := &request{r: r, arrived: arrived, sums: map[string]time.Duration{}}
	ctx = context.WithValue(ctx, key{}, q)
	return storage.WithTiming(ctx, func(t storage.JobTiming) {
		q.add("queue", t.QueueWait)
		q.add("commit", t.Commit)
	})
}

// Since adds the time since m to stage, if ctx has a Recorder.
func Since(ctx context.Context, stage string, m Mark) {
	if q, _ := ctx.Value(key{}).(*request); q != nil {
		q.add(stage, time.Since(m.t))
	}
}

// Admitted records admission: from the request's arrival to now, when its
// operation's handler starts.
func Admitted(ctx context.Context) {
	if q, _ := ctx.Value(key{}).(*request); q != nil {
		q.add("admission", time.Since(q.arrived))
	}
}

// Flush hands the request's stages to its Recorder, one time per stage it
// met, and forgets them.
func Flush(ctx context.Context) {
	q, _ := ctx.Value(key{}).(*request)
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, s := range q.order {
		q.r.Add(s, q.sums[s])
	}
	q.sums, q.order = map[string]time.Duration{}, nil
}
