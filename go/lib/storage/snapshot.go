// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"modernc.org/sqlite"
)

// SnapshotOptions paces a snapshot. Zero values take the defaults (1,024
// pages every 400 ms, as measured in the ADR-0059 benchmark).
type SnapshotOptions struct {
	StepPages int
	Pause     time.Duration
}

// SnapshotStats describes a finished snapshot.
type SnapshotStats struct {
	Pages    int
	Steps    int
	Restarts int // steps after which more pages remained than before
	Duration time.Duration
	// Truncate is the TRUNCATE checkpoint run after the snapshot.
	Truncate CheckpointResult
}

type backuper interface {
	NewBackup(dstURI string) (*sqlite.Backup, error)
}

// Snapshot writes a consistent copy of the database to dest, a new file
// (mode 0600) that must not exist yet (ADR-0059 Decision 7). It uses
// SQLite's online backup API stepped on the writer's own connection, in
// paced steps between write batches: writes made between steps go into the
// copy instead of restarting it, and no step holds the writer for long.
// TRUNCATE checkpoints wait while it runs, and one runs when it finishes.
// The copy is fsynced before Snapshot returns. On error or cancellation,
// dest is removed.
func (db *DB) Snapshot(ctx context.Context, dest string, o SnapshotOptions) (SnapshotStats, error) {
	if o.StepPages <= 0 {
		o.StepPages = 1024
	}
	if o.Pause <= 0 {
		o.Pause = 400 * time.Millisecond
	}
	if strings.ContainsAny(dest, "?#") {
		return SnapshotStats{}, fmt.Errorf("storage: snapshot path %q: '?' and '#' are not allowed", dest)
	}
	db.mu.RLock()
	if db.closed {
		db.mu.RUnlock()
		return SnapshotStats{}, ErrClosed
	}
	db.snapshots.Add(1)
	db.mu.RUnlock()
	defer db.snapshots.Done()

	// Create the file ourselves: exclusive, and private from the start.
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return SnapshotStats{}, fmt.Errorf("storage: snapshot: %w", err)
	}
	_ = f.Close()

	db.ckptMu.Lock()
	defer db.ckptMu.Unlock()

	st, err := db.snapshot(ctx, dest, o)
	if err != nil {
		_ = os.Remove(dest)
		return st, err
	}
	st.Truncate, _ = db.checkpointLocked(bg, "TRUNCATE")
	db.m.snapshot(st.Duration)
	return st, nil
}

func (db *DB) snapshot(ctx context.Context, dest string, o SnapshotOptions) (SnapshotStats, error) {
	var st SnapshotStats
	t0 := time.Now()
	var b *sqlite.Backup
	// The copy is a temporary file: no journal, and one fsync at the end
	// instead of one per step.
	err := db.onWriter(ctx, func(dc any) error {
		bk, ok := dc.(backuper)
		if !ok {
			return fmt.Errorf("storage: driver connection %T has no backup API", dc)
		}
		var err error
		b, err = bk.NewBackup("file:" + dest + "?_pragma=synchronous(OFF)&_pragma=journal_mode(OFF)")
		return err
	})
	if err != nil {
		return st, fmt.Errorf("storage: snapshot: %w", err)
	}
	finish := func() error { return db.onWriter(bg, func(any) error { return b.Finish() }) }

	last := -1
	for {
		var more bool
		var remaining, pages int
		err = db.onWriter(bg, func(any) error {
			var err error
			more, err = b.Step(int32(o.StepPages))
			remaining, pages = b.Remaining(), b.PageCount()
			return err
		})
		st.Steps++
		st.Pages = pages
		if err != nil {
			_ = finish()
			return st, fmt.Errorf("storage: snapshot step: %w", err)
		}
		if last >= 0 && more && remaining > last {
			st.Restarts++
		}
		last = remaining
		if !more {
			break
		}
		if db.isClosed() {
			_ = finish()
			return st, ErrClosed
		}
		select {
		case <-ctx.Done():
			_ = finish()
			return st, ctx.Err()
		case <-time.After(o.Pause):
		}
	}
	if err := finish(); err != nil {
		return st, fmt.Errorf("storage: snapshot finish: %w", err)
	}
	if err := syncFile(dest); err != nil {
		return st, fmt.Errorf("storage: snapshot sync: %w", err)
	}
	st.Duration = time.Since(t0)
	return st, nil
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
