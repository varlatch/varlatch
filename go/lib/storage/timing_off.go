// SPDX-License-Identifier: Apache-2.0

//go:build !g9a

package storage

import "context"

// WithTiming reports nothing outside the g9a build: ctx is returned as it
// is, and Write reads no clock for timings.
func WithTiming(ctx context.Context, _ func(JobTiming)) context.Context { return ctx }

func timingOf(context.Context) func(JobTiming) { return nil }
