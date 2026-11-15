// SPDX-License-Identifier: Apache-2.0

//go:build g9a

package storage

import "context"

type timingKey struct{}

// WithTiming returns a context whose Write calls report each job's timing
// to fn once the job has its outcome (the g9a build's per-stage timings).
// Without it Write reports nothing; outside the g9a build it is never
// reported (timing_off.go).
func WithTiming(ctx context.Context, fn func(JobTiming)) context.Context {
	return context.WithValue(ctx, timingKey{}, fn)
}

func timingOf(ctx context.Context) func(JobTiming) {
	fn, _ := ctx.Value(timingKey{}).(func(JobTiming))
	return fn
}
