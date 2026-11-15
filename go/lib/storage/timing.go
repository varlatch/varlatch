// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"time"
)

// JobTiming is how one write job spent its time outside its own code: the
// wait for the writer, and the COMMIT of the batch that held it (which
// holds the fsync).
type JobTiming struct {
	QueueWait time.Duration
	Commit    time.Duration
}

type timingKey struct{}

// WithTiming returns a context whose Write calls report each job's timing
// to fn once the job has its outcome (the g9a build's per-stage timings).
// Without it Write reports nothing.
func WithTiming(ctx context.Context, fn func(JobTiming)) context.Context {
	return context.WithValue(ctx, timingKey{}, fn)
}

func timingOf(ctx context.Context) func(JobTiming) {
	fn, _ := ctx.Value(timingKey{}).(func(JobTiming))
	return fn
}
