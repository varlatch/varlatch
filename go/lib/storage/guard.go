// SPDX-License-Identifier: Apache-2.0

package storage

import "context"

// CommitGuard lets the caller of a write refuse it at the last moment: on
// the writer, once the job's function returned nil and before its
// savepoint is released. The tailnet listener's admission uses it, so that
// a write admitted while tailnet access was open never commits after
// access closed (the closing waits for a held guard to be released, so
// every job is either released before the closing or checked after it).
type CommitGuard interface {
	// Hold runs just before the job's savepoint is released. An error
	// rolls the job back to its savepoint, as the job's own error, and
	// Write returns it. On nil, Release runs exactly once, after the
	// release (or once the batch failed), and nothing else of the batch
	// runs in between.
	Hold() error
	Release()
}

type guardKey struct{}

// WithCommitGuard is ctx with g: every Write under it is guarded.
func WithCommitGuard(ctx context.Context, g CommitGuard) context.Context {
	return context.WithValue(ctx, guardKey{}, g)
}

func guardOf(ctx context.Context) CommitGuard {
	g, _ := ctx.Value(guardKey{}).(CommitGuard)
	return g
}
