// SPDX-License-Identifier: Apache-2.0

//go:build g9a

package storage

import (
	"context"
	"time"
)

type timingKey struct{}

// WithTiming returns a context whose Write calls report each job's timing
// to fn once the job has its outcome (the g9a build's per-stage timings).
// Without it Write reports nothing; outside the g9a build it is never
// reported (timing_off.go).
func WithTiming(ctx context.Context, fn func(JobTiming)) context.Context {
	return context.WithValue(ctx, timingKey{}, fn)
}

// jobTiming is a job's timing: when it was queued and started, and its
// batch's COMMIT time. The writer writes started and commit before done;
// report reads them after it.
type jobTiming struct {
	fn              func(JobTiming)
	queued, started time.Time
	commit          time.Duration
}

func (t *jobTiming) queue(ctx context.Context) {
	if fn, _ := ctx.Value(timingKey{}).(func(JobTiming)); fn != nil {
		t.fn, t.queued = fn, time.Now()
	}
}

func (t *jobTiming) begin() {
	if t.fn != nil {
		t.started = time.Now()
	}
}

func (t *jobTiming) committed(d time.Duration) { t.commit = d }

func (t *jobTiming) report() {
	if t.fn != nil && !t.started.IsZero() {
		t.fn(JobTiming{QueueWait: t.started.Sub(t.queued), Commit: t.commit})
	}
}
