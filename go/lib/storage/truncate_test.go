// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// heldTruncate sets up a TRUNCATE that holds SQLite's write lock for its
// whole busy timeout: a reader keeps a snapshot older than the WAL's end,
// and a TRUNCATE waits for it (with the write lock taken) until it gives
// up. It returns the reader's transaction; rolling it back lets a
// TRUNCATE finish.
func heldTruncate(t *testing.T, db *DB) *sql.Tx {
	t.Helper()
	for i := range 20 {
		mustWrite(t, db, insert(fmt.Sprint("before-", i)))
	}
	reader, err := db.Reader().BeginTx(bg, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := reader.QueryRowContext(bg, `SELECT count(*) FROM item`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		mustWrite(t, db, insert(fmt.Sprint("after-", i)))
	}
	return reader
}

// The failure ADR-0059 Decision 2 rules out, and the counters that see
// it: a checkpoint on a connection of its own, as the checkpointer ran
// TRUNCATE before, holds the write lock longer than the writer's busy
// timeout, and the writer's BEGIN IMMEDIATE fails with SQLITE_BUSY.
// Here the foreign connection waits 6 s for a reader; the writer gives up
// after its 5 s.
func TestForeignCheckpointFailsTheWriterAndIsCounted(t *testing.T) {
	t.Parallel()
	db := open(t, Options{ReadConns: 2, PassiveEvery: time.Hour})
	reader := heldTruncate(t, db)
	defer reader.Rollback()
	foreign, err := sql.Open("sqlite", fileURI(db.Path(), "_pragma=busy_timeout(6000)"))
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	foreign.SetMaxOpenConns(1)
	if err := foreign.PingContext(bg); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		var busy, log, ckpt int
		done <- foreign.QueryRowContext(bg, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &log, &ckpt)
	}()
	time.Sleep(200 * time.Millisecond) // it takes the write lock, then waits for the reader

	ctx, busy := WithBusyNote(bg)
	err = db.Write(ctx, insert("blocked"))
	var be *BatchError
	if !errors.As(err, &be) || be.Op != "begin" || !IsBusy(err) || !busy() {
		t.Fatalf("a write while a foreign TRUNCATE held the lock: %v (noted busy: %v)", err, busy())
	}
	if m := db.Metrics(); m.FailedBegins != 1 || m.BusyBatches != 1 || m.FailedBatches != 1 {
		t.Errorf("metrics: %d failed begins, %d busy batches, %d failed batches; want 1 each", m.FailedBegins, m.BusyBatches, m.FailedBatches)
	}
	_ = reader.Rollback()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// The writer recovers: the next batch opens a new connection.
	mustWrite(t, db, insert("after the checkpoint"))
}

// The checkpointer's TRUNCATE runs on the writer, between batches: while
// it holds the write lock waiting for a reader (here its whole 5 s busy
// timeout), jobs queue behind it as behind a batch, and every one commits
// once it returns. No BEGIN fails, and none is answered SQLITE_BUSY.
func TestTruncateOnTheWriterMakesJobsWait(t *testing.T) {
	t.Parallel()
	log := &checkpointLog{}
	db := open(t, Options{ReadConns: 2, PassiveEvery: time.Hour, OnCheckpoint: log.add})
	reader := heldTruncate(t, db)
	defer reader.Rollback()

	type result struct {
		r   CheckpointResult
		err error
	}
	truncated := make(chan result, 1)
	go func() {
		db.ckptMu.Lock()
		defer db.ckptMu.Unlock()
		r, err := db.checkpointLocked(bg, "TRUNCATE", TriggerSize)
		truncated <- result{r, err}
	}()
	time.Sleep(200 * time.Millisecond) // the writer runs it, waiting for the reader

	const jobs = 8
	var wg sync.WaitGroup
	errs := make([]error, jobs)
	ended := make([]time.Time, jobs)
	noted := make([]bool, jobs)
	for i := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, busy := WithBusyNote(bg)
			errs[i] = db.Write(ctx, insert(fmt.Sprint("queued-", i)))
			ended[i], noted[i] = time.Now(), busy()
		}()
	}
	res := <-truncated
	wg.Wait()
	if res.err != nil {
		t.Fatal(res.err)
	}
	// It waited for the reader for its busy timeout, holding the writer.
	if !res.r.Busy || res.r.Duration < busyTimeout-500*time.Millisecond {
		t.Errorf("the TRUNCATE did not wait for the reader: %+v", res.r)
	}
	end := res.r.Start.Add(res.r.Duration)
	for i := range jobs {
		if errs[i] != nil || noted[i] {
			t.Errorf("job %d: %v (noted busy: %v)", i, errs[i], noted[i])
		}
		if ended[i].Before(end) {
			t.Errorf("job %d returned at %s, before the TRUNCATE ended at %s", i, ended[i].Format(time.StampMicro), end.Format(time.StampMicro))
		}
	}
	if m := db.Metrics(); m.FailedBegins != 0 || m.BusyBatches != 0 || m.FailedBatches != 0 {
		t.Errorf("metrics: %d failed begins, %d busy batches, %d failed batches", m.FailedBegins, m.BusyBatches, m.FailedBatches)
	}
	if n := count(t, db, "WHERE name LIKE 'queued-%'"); n != jobs {
		t.Errorf("%d queued jobs committed, want %d", n, jobs)
	}
	// Once the reader is gone, the next TRUNCATE resets the WAL.
	_ = reader.Rollback()
	db.ckptMu.Lock()
	r, err := db.checkpointLocked(bg, "TRUNCATE", TriggerSize)
	db.ckptMu.Unlock()
	if err != nil || r.Busy || db.walSize() != 0 {
		t.Errorf("TRUNCATE after the reader: %+v %v, WAL %d bytes", r, err, db.walSize())
	}
}

// A slow TRUNCATE, however long, only delays jobs: OnCheckpoint here
// blocks the writer goroutine after the checkpoint for twice the busy
// timeout, and the jobs queued meanwhile all commit.
func TestSlowTruncateOnlyDelaysJobs(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var once sync.Once
	entered := make(chan struct{})
	db := open(t, Options{PassiveEvery: time.Hour, OnCheckpoint: func(r CheckpointResult, _ error) {
		if r.Mode == "TRUNCATE" && r.Trigger == TriggerSize {
			once.Do(func() {
				close(entered)
				select {
				case <-release:
				case <-time.After(2 * busyTimeout):
				}
			})
		}
	}})
	mustWrite(t, db, insert("a"))
	go func() {
		db.ckptMu.Lock()
		defer db.ckptMu.Unlock()
		_, _ = db.checkpointLocked(bg, "TRUNCATE", TriggerSize)
	}()
	<-entered
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = db.Write(bg, insert(fmt.Sprint("slow-", i))) }()
	}
	time.Sleep(busyTimeout + 500*time.Millisecond) // past the busy timeout: still queued
	if q := db.Metrics().Queued; q == 0 {
		t.Error("no job waits behind the slow TRUNCATE")
	}
	close(release)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("job %d: %v", i, err)
		}
	}
	if m := db.Metrics(); m.FailedBegins != 0 || m.BusyBatches != 0 {
		t.Errorf("metrics: %+v", m)
	}
}

// Close never hangs on a TRUNCATE the checkpointer queued for a writer
// that is stopping: with checkpoints on every tick and the WAL always over
// its bound, Close returns, and its own TRUNCATE empties the WAL.
func TestCloseWithTruncatesInFlight(t *testing.T) {
	for i := range 20 {
		db := open(t, Options{PassiveEvery: time.Millisecond, WALBound: 4096})
		var wg sync.WaitGroup
		for g := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := range 20 {
					_ = db.Write(bg, insert(fmt.Sprint(i, "-", g, "-", k)))
				}
			}()
		}
		wg.Wait()
		closed := make(chan error, 1)
		go func() { closed <- db.Close() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("round %d: Close did not return", i)
		}
		if db.walSize() != 0 {
			t.Errorf("round %d: WAL %d bytes after Close", i, db.walSize())
		}
	}
}
