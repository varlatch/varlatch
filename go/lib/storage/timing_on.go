// SPDX-License-Identifier: Apache-2.0

//go:build g9a

package storage

import (
	"context"
	"fmt"
	"time"

	"modernc.org/sqlite"
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
	walBytes        int64
	batchJobs       int
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

func (t *jobTiming) committed(d time.Duration, walBytes int64, jobs int) {
	t.commit, t.walBytes, t.batchJobs = d, walBytes, jobs
}

func (t *jobTiming) report() {
	if t.fn != nil && !t.started.IsZero() {
		t.fn(JobTiming{QueueWait: t.started.Sub(t.queued), Commit: t.commit, WALBytes: t.walBytes, BatchJobs: t.batchJobs})
	}
}

// statusConn is the driver connection's sqlite3_db_status.
type statusConn interface {
	Status(op sqlite.DBStatusOp, reset bool) (current, high int, err error)
}

// walWritten is what the writer's connection wrote to the WAL since the
// last call, in bytes (pages times a frame's size), and resets the count:
// a batch's WAL bytes when read after its COMMIT, having been read before
// its BEGIN. 0 if it cannot be read.
func (db *DB) walWritten() int64 {
	if db.wconn == nil {
		return 0
	}
	if db.pageSize == 0 {
		var size int64
		if err := db.wconn.QueryRowContext(bg, "PRAGMA page_size").Scan(&size); err != nil {
			return 0
		}
		db.pageSize = size
	}
	var pages int
	err := db.wconn.Raw(func(dc any) error {
		c, ok := unwrapConn(dc).(statusConn)
		if !ok {
			return fmt.Errorf("storage: the driver connection has no db_status (%T)", dc)
		}
		var err error
		pages, _, err = c.Status(sqlite.DBStatusCacheWrite, true)
		return err
	})
	if err != nil {
		return 0
	}
	return int64(pages) * (db.pageSize + walFrameHeader)
}

// walFrameHeader is the header of each WAL frame, before its page.
const walFrameHeader = 24
