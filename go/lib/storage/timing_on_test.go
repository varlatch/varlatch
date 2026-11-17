// SPDX-License-Identifier: Apache-2.0

//go:build g9a

package storage

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// The g9a build reports what a job's batch wrote to the WAL: whole frames
// (a page and its 24-byte header), at least the job's own rows, and as
// much as the WAL file grew for a job alone in its batch; jobs that share a
// batch report the same bytes and the batch's size.
func TestJobTimingWALBytes(t *testing.T) {
	db, err := Open(context.Background(), Options{Path: filepath.Join(t.TempDir(), "wal.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Write(context.Background(), func(tx *Tx) error {
		_, err := tx.ExecContext(context.Background(), "CREATE TABLE t (v BLOB)")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	frame := int64(4096 + walFrameHeader)
	for i := range 3 {
		var got JobTiming
		ctx := WithTiming(context.Background(), func(j JobTiming) { got = j })
		before := db.walSize()
		if err := db.Write(ctx, func(tx *Tx) error {
			_, err := tx.ExecContext(ctx, "INSERT INTO t VALUES (randomblob(30000))")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		grew := db.walSize() - before
		if got.BatchJobs != 1 || got.WALBytes < 30000 || got.WALBytes%frame != 0 {
			t.Fatalf("job %d: %+v", i, got)
		}
		// The file grows by what the batch wrote, unless a checkpoint let
		// the WAL start over in between.
		if grew > 0 && grew != got.WALBytes {
			t.Fatalf("job %d: the WAL grew %d bytes, the job reports %d", i, grew, got.WALBytes)
		}
	}

	// Jobs queued together share a batch, and its bytes.
	release := make(chan struct{})
	held := make(chan struct{})
	go func() {
		_ = db.Write(context.Background(), func(*Tx) error { close(held); <-release; return nil })
	}()
	<-held
	var mu sync.Mutex
	var reports []JobTiming
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		ctx := WithTiming(context.Background(), func(j JobTiming) { mu.Lock(); reports = append(reports, j); mu.Unlock() })
		go func() {
			defer wg.Done()
			_ = db.Write(ctx, func(tx *Tx) error {
				_, err := tx.ExecContext(ctx, "INSERT INTO t VALUES (randomblob(9000))")
				return err
			})
		}()
	}
	for db.Metrics().Queued < 3 {
		runtime.Gosched()
	}
	close(release)
	wg.Wait()
	if len(reports) != 3 || reports[0].BatchJobs != 3 || reports[0].WALBytes <= 0 {
		t.Fatalf("shared batch: %+v", reports)
	}
	for _, r := range reports[1:] {
		if r.BatchJobs != reports[0].BatchJobs || r.WALBytes != reports[0].WALBytes {
			t.Fatalf("shared batch: %+v", reports)
		}
	}
}
