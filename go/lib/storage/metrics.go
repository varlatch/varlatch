// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"sync"
	"time"
)

// Metrics is a snapshot of the engine's counters (ADR-0059 Decision 2: the
// WAL size and every non-passive checkpoint's duration are metrics, and
// varlatch doctor reports them).
type Metrics struct {
	WALBytes int64

	Batches       uint64 // committed or failed write transactions
	Jobs          uint64 // jobs the writer ran
	JobErrors     uint64 // jobs that failed alone (their own error)
	FailedBatches uint64 // batches that failed as a whole
	MaxBatch      int
	LastBatch     time.Duration // from BEGIN to the end of COMMIT
	MaxBatchTime  time.Duration
	LastCommit    time.Duration // the COMMIT alone, which holds the fsync
	MaxCommit     time.Duration

	PassiveCheckpoints uint64
	MaxPassive         time.Duration
	// Non-passive checkpoints (TRUNCATE by size, after a snapshot, at close).
	Truncates         uint64
	TruncatesBusy     uint64 // returned busy: the WAL was not reset
	TruncatesDelayed  uint64 // over the bound while a snapshot held TRUNCATE off
	LastTruncate      CheckpointResult
	MaxTruncate       time.Duration
	CheckpointErrors  uint64
	LastCheckpointErr string

	Snapshots    uint64
	LastSnapshot time.Duration
}

type metrics struct {
	mu sync.Mutex
	m  Metrics
}

// Metrics returns the current counters.
func (db *DB) Metrics() Metrics {
	db.m.mu.Lock()
	m := db.m.m
	db.m.mu.Unlock()
	m.WALBytes = db.walSize()
	return m
}

func (x *metrics) batch(jobs, ownErrors int, failed bool, total, commit time.Duration) {
	x.mu.Lock()
	defer x.mu.Unlock()
	m := &x.m
	m.Batches++
	m.Jobs += uint64(jobs)
	m.JobErrors += uint64(ownErrors)
	if failed {
		m.FailedBatches++
	}
	m.MaxBatch = max(m.MaxBatch, jobs)
	m.LastBatch, m.MaxBatchTime = total, max(m.MaxBatchTime, total)
	if !failed {
		m.LastCommit, m.MaxCommit = commit, max(m.MaxCommit, commit)
	}
}

func (x *metrics) checkpoint(r CheckpointResult, err error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	m := &x.m
	if err != nil {
		m.CheckpointErrors++
		m.LastCheckpointErr = err.Error()
		return
	}
	if r.Mode == "PASSIVE" {
		m.PassiveCheckpoints++
		m.MaxPassive = max(m.MaxPassive, r.Duration)
		return
	}
	m.Truncates++
	if r.Busy {
		m.TruncatesBusy++
	}
	m.LastTruncate = r
	m.MaxTruncate = max(m.MaxTruncate, r.Duration)
}

func (x *metrics) truncateDeferred() {
	x.mu.Lock()
	x.m.TruncatesDelayed++
	x.mu.Unlock()
}

func (x *metrics) snapshot(d time.Duration) {
	x.mu.Lock()
	x.m.Snapshots++
	x.m.LastSnapshot = d
	x.mu.Unlock()
}
