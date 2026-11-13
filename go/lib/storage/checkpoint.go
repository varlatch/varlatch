// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"time"
)

// CheckpointResult is what one PRAGMA wal_checkpoint returned.
type CheckpointResult struct {
	Mode string
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
		_, _ = db.checkpoint(bg, "PASSIVE")
		if db.walSize() > db.opts.WALBound {
			if db.ckptMu.TryLock() {
				_, _ = db.checkpointLocked(bg, "TRUNCATE")
				db.ckptMu.Unlock()
			} else {
				db.m.truncateDeferred()
			}
		}
	}
}

// checkpoint runs a PASSIVE checkpoint (which needs no lock) or takes the
// checkpoint lock for any other mode.
func (db *DB) checkpoint(ctx context.Context, mode string) (CheckpointResult, error) {
	if mode != "PASSIVE" {
		db.ckptMu.Lock()
		defer db.ckptMu.Unlock()
	}
	return db.checkpointLocked(ctx, mode)
}

func (db *DB) checkpointLocked(ctx context.Context, mode string) (CheckpointResult, error) {
	r := CheckpointResult{Mode: mode, WALBefore: db.walSize()}
	t0 := time.Now()
	var busy int
	err := db.cconn.QueryRowContext(ctx, "PRAGMA wal_checkpoint("+mode+")").Scan(&busy, &r.LogFrames, &r.Checkpointed)
	r.Duration = time.Since(t0)
	r.Busy = busy != 0
	r.WALAfter = db.walSize()
	db.m.checkpoint(r, err)
	return r, err
}
