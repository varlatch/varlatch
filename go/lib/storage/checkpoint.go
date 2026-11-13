// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"time"
)

// Why a checkpoint ran (CheckpointResult.Trigger).
const (
	TriggerInterval = "interval" // the periodic PASSIVE checkpoint
	TriggerSize     = "size"     // the WAL was over WALBound
	TriggerSnapshot = "snapshot" // a snapshot finished
	TriggerClose    = "close"    // Close
)

// CheckpointResult is what one PRAGMA wal_checkpoint returned.
type CheckpointResult struct {
	Mode    string
	Trigger string
	Start   time.Time
	// Deferred means the size trigger found a snapshot holding TRUNCATE off:
	// no checkpoint ran, and the snapshot truncates the WAL when it ends.
	// Only Options.OnCheckpoint sees such a result.
	Deferred bool
	// Busy is SQLite's first result column: the checkpoint could not finish
	// (a TRUNCATE could not reset the WAL).
	Busy bool
	// LogFrames and Checkpointed are the WAL's frames and how many of them
	// were copied into the database (-1 if not in WAL mode).
	LogFrames, Checkpointed int64
	WALBefore, WALAfter     int64
	Duration                time.Duration
}

// checkpointLoop runs PASSIVE every PassiveEvery and TRUNCATE whenever the
// WAL is over WALBound (ADR-0059 Decision 2). Automatic checkpoints are off
// on every connection. A snapshot holds TRUNCATE off while it runs; the WAL
// may then pass the bound, and the snapshot truncates it when done.
func (db *DB) checkpointLoop() {
	defer db.loops.Done()
	t := time.NewTicker(db.opts.PassiveEvery)
	defer t.Stop()
	for {
		select {
		case <-db.stop:
			return
		case <-t.C:
		}
		_, _ = db.checkpointLocked(bg, "PASSIVE", TriggerInterval)
		if wal := db.walSize(); wal > db.opts.WALBound {
			if db.ckptMu.TryLock() {
				_, _ = db.checkpointLocked(bg, "TRUNCATE", TriggerSize)
				db.ckptMu.Unlock()
			} else {
				db.m.truncateDeferred()
				db.notify(CheckpointResult{Mode: "TRUNCATE", Trigger: TriggerSize, Start: time.Now(), Deferred: true,
					LogFrames: -1, Checkpointed: -1, WALBefore: wal, WALAfter: wal}, nil)
			}
		}
	}
}

// checkpointLocked runs one checkpoint on the checkpointer's connection.
// Any mode but PASSIVE needs ckptMu held.
func (db *DB) checkpointLocked(ctx context.Context, mode, trigger string) (CheckpointResult, error) {
	r := CheckpointResult{Mode: mode, Trigger: trigger, WALBefore: db.walSize()}
	r.Start = time.Now()
	var busy int
	err := db.cconn.QueryRowContext(ctx, "PRAGMA wal_checkpoint("+mode+")").Scan(&busy, &r.LogFrames, &r.Checkpointed)
	r.Duration = time.Since(r.Start)
	r.Busy = busy != 0
	r.WALAfter = db.walSize()
	db.m.checkpoint(r, err)
	db.notify(r, err)
	return r, err
}

// notify hands a checkpoint to Options.OnCheckpoint, if set.
func (db *DB) notify(r CheckpointResult, err error) {
	if db.opts.OnCheckpoint != nil {
		db.opts.OnCheckpoint(r, err)
	}
}
