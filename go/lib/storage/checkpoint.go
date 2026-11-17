// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
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
//
// The loop only decides. PASSIVE runs on the checkpointer's connection: it
// never takes SQLite's write lock, so it blocks nobody. TRUNCATE takes the
// write lock, and holds it while it copies frames, syncs the database file
// and waits for readers on older snapshots (up to the busy timeout), so the
// writer runs it between batches (checkpointLocked): jobs queue behind it
// as behind a batch, and no BEGIN IMMEDIATE can find the lock taken by a
// checkpoint and fail with SQLITE_BUSY.
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

// checkpointLocked runs one checkpoint. Any mode but PASSIVE needs ckptMu
// held. PASSIVE runs on the checkpointer's connection, and is skipped (a
// zero result) if a TRUNCATE is running: the next tick runs it. Any other
// mode runs on the writer's connection, on the writer goroutine between
// batches, or on the checkpointer's once the writer has stopped (Close).
// It must not be called from the writer goroutine.
func (db *DB) checkpointLocked(ctx context.Context, mode, trigger string) (CheckpointResult, error) {
	if mode == "PASSIVE" {
		if !db.ckptRun.TryLock() {
			return CheckpointResult{}, nil
		}
		defer db.ckptRun.Unlock()
		return db.checkpointOn(ctx, db.cconn, mode, trigger)
	}
	var r CheckpointResult
	var err error
	ran, werr := db.onWriterConn(func(c *sql.Conn) error {
		db.ckptRun.Lock()
		defer db.ckptRun.Unlock()
		r, err = db.checkpointOn(bg, c, mode, trigger)
		return nil
	})
	if werr != nil {
		// The writer had no connection and could not open one.
		db.m.checkpoint(CheckpointResult{}, werr)
		db.notify(CheckpointResult{Mode: mode, Trigger: trigger, Start: time.Now()}, werr)
		return CheckpointResult{}, werr
	}
	if !ran {
		db.ckptRun.Lock()
		defer db.ckptRun.Unlock()
		return db.checkpointOn(ctx, db.cconn, mode, trigger)
	}
	return r, err
}

// checkpointOn runs PRAGMA wal_checkpoint(mode) on c and reports it.
func (db *DB) checkpointOn(ctx context.Context, c *sql.Conn, mode, trigger string) (CheckpointResult, error) {
	r := CheckpointResult{Mode: mode, Trigger: trigger, WALBefore: db.walSize()}
	crashPoint(db, "checkpoint")
	r.Start = time.Now()
	var busy int
	err := c.QueryRowContext(ctx, "PRAGMA wal_checkpoint("+mode+")").Scan(&busy, &r.LogFrames, &r.Checkpointed)
	r.Duration = time.Since(r.Start)
	r.Busy = busy != 0
	r.WALAfter = db.walSize()
	db.m.checkpoint(r, err)
	db.notify(r, err)
	// A direct call, not a defer: without the crashpoint tag it compiles away.
	crashPoint(db, "checkpointed")
	return r, err
}

// notify hands a checkpoint to Options.OnCheckpoint, if set.
func (db *DB) notify(r CheckpointResult, err error) {
	if db.opts.OnCheckpoint != nil {
		db.opts.OnCheckpoint(r, err)
	}
}
