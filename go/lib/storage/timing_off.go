// SPDX-License-Identifier: Apache-2.0

//go:build !g9a

package storage

import (
	"context"
	"time"
)

// WithTiming reports nothing outside the g9a build: ctx is returned as it
// is.
func WithTiming(ctx context.Context, _ func(JobTiming)) context.Context { return ctx }

// jobTiming is empty outside the g9a build, and its methods do nothing: a
// release job carries no timing state and the writer reads no clock for it.
type jobTiming struct{}

func (*jobTiming) queue(context.Context)   {}
func (*jobTiming) begin()                  {}
func (*jobTiming) committed(time.Duration) {}
func (*jobTiming) report()                 {}
