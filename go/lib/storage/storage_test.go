// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func open(t *testing.T, opts Options) *DB {
	t.Helper()
	if opts.Path == "" {
		opts.Path = filepath.Join(t.TempDir(), "varlatch.db")
	}
	db, err := Open(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	mustWrite(t, db, func(tx *Tx) error {
		_, err := tx.ExecContext(bg, `CREATE TABLE IF NOT EXISTS item (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, body BLOB) STRICT`)
		return err
	})
	return db
}

func mustWrite(t *testing.T, db *DB, fn func(*Tx) error) {
	t.Helper()
	if err := db.Write(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func insert(name string) func(*Tx) error {
	return func(tx *Tx) error {
		_, err := tx.ExecContext(bg, `INSERT INTO item (name) VALUES (?)`, name)
		return err
	}
}

func count(t *testing.T, db *DB, where string, args ...any) int {
	t.Helper()
	var n int
	if err := db.Reader().QueryRowContext(bg, `SELECT count(*) FROM item `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// queueBatch holds the writer with a gate job, queues fns in order, then
// releases it, so that fns run as one batch. It returns their results.
func queueBatch(t *testing.T, db *DB, fns ...func(*Tx) error) []error {
	t.Helper()
	release := make(chan struct{})
	gateDone := make(chan error, 1)
	entered := make(chan struct{})
	go func() {
		gateDone <- db.Write(context.Background(), func(*Tx) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	results := make([]error, len(fns))
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = db.Write(context.Background(), fn)
		}()
		waitFor(t, func() bool { return len(db.jobs) == i+1 })
	}
	close(release)
	if err := <-gateDone; err != nil {
		t.Fatalf("gate job: %v", err)
	}
	wg.Wait()
	return results
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSettingsOnEveryConnection(t *testing.T) {
	db := open(t, Options{})
	// Open already checked them; check the read pool refuses writes.
	if _, err := db.Reader().ExecContext(bg, `INSERT INTO item (name) VALUES ('x')`); err == nil {
		t.Fatal("the read pool accepted a write")
	}
	var mode string
	if err := db.Reader().QueryRowContext(bg, `PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode %q, %v", mode, err)
	}
}

func TestPathWithSpace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db := open(t, Options{Path: filepath.Join(dir, "var latch.db")})
	mustWrite(t, db, insert("a"))
	if _, err := os.Stat(filepath.Join(dir, "var latch.db")); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRefusesBadPaths(t *testing.T) {
	for _, p := range []string{"", "/tmp/a?b.db", filepath.Join(t.TempDir(), "missing", "x.db")} {
		if db, err := Open(context.Background(), Options{Path: p}); err == nil {
			_ = db.Close()
			t.Errorf("%q: opened", p)
		}
	}
}

func TestGroupCommit(t *testing.T) {
	db := open(t, Options{})
	var fns []func(*Tx) error
	for i := range 20 {
		fns = append(fns, insert(fmt.Sprint("n", i)))
	}
	for i, err := range queueBatch(t, db, fns...) {
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}
	}
	if n := count(t, db, ""); n != 20 {
		t.Fatalf("%d rows", n)
	}
	if m := db.Metrics(); m.MaxBatch != 20 {
		t.Fatalf("max batch %d, want 20", m.MaxBatch)
	}
}

func TestMaxBatch(t *testing.T) {
	db := open(t, Options{MaxBatch: 3})
	var fns []func(*Tx) error
	for i := range 7 {
		fns = append(fns, insert(fmt.Sprint("n", i)))
	}
	queueBatch(t, db, fns...)
	if m := db.Metrics(); m.MaxBatch != 3 {
		t.Fatalf("max batch %d, want 3", m.MaxBatch)
	}
}

var errApp = errors.New("the job's own check failed")

// A job's own error rolls back that job alone (ADR-0059 Decision 2).
func TestJobErrorIsIsolated(t *testing.T) {
	db := open(t, Options{})
	mustWrite(t, db, insert("taken"))
	res := queueBatch(t, db,
		insert("a"),
		insert("taken"), // UNIQUE constraint
		func(tx *Tx) error { // writes, then fails its own check
			if err := insert("c")(tx); err != nil {
				return err
			}
			return errApp
		},
		func(tx *Tx) error { // bad SQL
			_, err := tx.ExecContext(bg, `INSERT INTO nope VALUES (1)`)
			return err
		},
		func(*Tx) error { panic("boom") },
		insert("d"),
	)
	if res[0] != nil || res[5] != nil {
		t.Fatalf("good jobs failed: %v, %v", res[0], res[5])
	}
	if res[1] == nil || !strings.Contains(res[1].Error(), "UNIQUE") {
		t.Fatalf("constraint job: %v", res[1])
	}
	if !errors.Is(res[2], errApp) {
		t.Fatalf("app error job: %v", res[2])
	}
	for _, i := range []int{1, 3, 4} {
		var be *BatchError
		if res[i] == nil || errors.As(res[i], &be) {
			t.Fatalf("job %d: %v, want its own error", i, res[i])
		}
	}
	if n := count(t, db, "WHERE name IN ('a','d')"); n != 2 {
		t.Fatalf("committed %d of the good jobs", n)
	}
	if n := count(t, db, "WHERE name = 'c'"); n != 0 {
		t.Fatal("the failed job's write was committed")
	}
	if m := db.Metrics(); m.JobErrors != 4 || m.FailedBatches != 0 {
		t.Fatalf("metrics %+v", m)
	}
}

func TestCancelledBeforeStart(t *testing.T) {
	db := open(t, Options{})
	release := make(chan struct{})
	entered := make(chan struct{})
	go func() {
		_ = db.Write(context.Background(), func(*Tx) error { close(entered); <-release; return nil })
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- db.Write(ctx, insert("never")) }()
	waitFor(t, func() bool { return len(db.jobs) == 1 })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	close(release)
	mustWrite(t, db, insert("after"))
	if n := count(t, db, "WHERE name = 'never'"); n != 0 {
		t.Fatal("a cancelled job ran")
	}
}

// setPageLimit caps the database file on the writer's connection, so that
// SQLite reports SQLITE_FULL: a real disk-full error without filling a disk.
// The cap lasts until a failed batch replaces the writer's connection.
func setPageLimit(t *testing.T, db *DB, extraPages int) {
	t.Helper()
	mustWrite(t, db, func(tx *Tx) error {
		var pages int
		if err := tx.QueryRowContext(bg, `PRAGMA page_count`).Scan(&pages); err != nil {
			return err
		}
		_, err := tx.ExecContext(bg, fmt.Sprintf(`PRAGMA max_page_count = %d`, pages+extraPages))
		return err
	})
}

func bigInsert(name string) func(*Tx) error {
	return func(tx *Tx) error {
		body := make([]byte, 1<<20)
		_, _ = rand.Read(body)
		_, err := tx.ExecContext(bg, `INSERT INTO item (name, body) VALUES (?, ?)`, name, body)
		return err
	}
}

// G7: a disk-full error in the middle of a group-commit batch answers every
// job in the batch with an error, commits none of them, keeps reads working,
// and writes resume afterwards.
func TestDiskFullFailsWholeBatch(t *testing.T) {
	db := open(t, Options{})
	mustWrite(t, db, insert("before"))
	setPageLimit(t, db, 4)

	// Job 0 stands for a retrieval: it writes its audit row, and its caller
	// may release the value only if Write returns nil. It ran without error
	// itself, so this checks that a later job's failure reaches it.
	res := queueBatch(t, db, insert("audit-row"), insert("small"), bigInsert("big"), insert("after-big"))
	for i, err := range res {
		var be *BatchError
		if !errors.As(err, &be) || !IsDiskFull(err) {
			t.Fatalf("job %d: %v, want a disk-full BatchError", i, err)
		}
	}
	if !strings.Contains(res[0].Error(), "disk is full") {
		t.Fatalf("unclear error: %v", res[0])
	}
	if n := count(t, db, ""); n != 1 {
		t.Fatalf("%d rows; only the one written before should exist", n)
	}
	if m := db.Metrics(); m.FailedBatches != 1 {
		t.Fatalf("failed batches %d", m.FailedBatches)
	}
	// The failed batch replaced the writer's connection, which lifts the cap
	// (as freeing space would): writing resumes.
	mustWrite(t, db, insert("resumed"))
	if n := count(t, db, "WHERE name = 'resumed'"); n != 1 {
		t.Fatal("writing did not resume")
	}
}

// A job that swallows a batch-failing error still fails the batch.
func TestSwallowedFatalErrorFailsBatch(t *testing.T) {
	db := open(t, Options{})
	setPageLimit(t, db, 4)
	res := queueBatch(t, db, insert("a"), func(tx *Tx) error {
		_ = bigInsert("big")(tx)
		return nil
	})
	for i, err := range res {
		if !IsDiskFull(err) {
			t.Fatalf("job %d: %v", i, err)
		}
	}
	if n := count(t, db, ""); n != 0 {
		t.Fatalf("%d rows committed", n)
	}
}

// When SQLite has already rolled the transaction back, the savepoint
// rollback (after a job's own error) or the release (after success) fails,
// and so does the batch: nothing that was in it may be reported committed.
func TestRolledBackTransactionFailsBatch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result error
	}{{"own error", errApp}, {"success", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			db := open(t, Options{})
			res := queueBatch(t, db, insert("first"), func(tx *Tx) error {
				// Bypass the guard: what SQLite does on its own after some
				// errors.
				if _, err := tx.conn.ExecContext(bg, "ROLLBACK"); err != nil {
					t.Error(err)
				}
				return tc.result
			}, insert("third"))
			for i, err := range res {
				var be *BatchError
				if !errors.As(err, &be) {
					t.Fatalf("job %d: %v, want a BatchError", i, err)
				}
			}
			if n := count(t, db, ""); n != 0 {
				t.Fatalf("%d rows committed", n)
			}
			mustWrite(t, db, insert("resumed"))
		})
	}
}

func TestTransactionControlRefused(t *testing.T) {
	db := open(t, Options{})
	for _, q := range []string{"COMMIT", "  rollback", "-- c\n/* d */ RELEASE job0", "savepoint x", "BEGIN", "end"} {
		err := db.Write(context.Background(), func(tx *Tx) error {
			_, err := tx.ExecContext(bg, q)
			return err
		})
		if !errors.Is(err, errTxControl) {
			t.Errorf("%q: %v", q, err)
		}
		err = db.Write(context.Background(), func(tx *Tx) error {
			var x int
			return tx.QueryRowContext(bg, q).Scan(&x)
		})
		if err == nil || !strings.Contains(err.Error(), errTxControl.Error()) {
			t.Errorf("%q via QueryRow: %v", q, err)
		}
	}
	if got := firstKeyword("/* a */ -- b\n  Insert into"); got != "INSERT" {
		t.Fatalf("firstKeyword: %q", got)
	}
}

func TestWAL(t *testing.T) {
	t.Run("size-triggered TRUNCATE bounds it", func(t *testing.T) {
		db := open(t, Options{PassiveEvery: 20 * time.Millisecond, WALBound: 512 << 10})
		// One batch writes about 4 MiB to the WAL, far over the bound.
		var fns []func(*Tx) error
		for i := range 4 {
			fns = append(fns, bigInsert(fmt.Sprint("b", i)))
		}
		queueBatch(t, db, fns...)
		waitFor(t, func() bool {
			m := db.Metrics()
			return m.Truncates > 0 && m.WALBytes <= 512<<10
		})
		m := db.Metrics()
		if m.LastTruncate.Busy || m.LastTruncate.WALAfter != 0 || m.LastTruncate.WALBefore <= 512<<10 {
			t.Fatalf("last TRUNCATE %+v", m.LastTruncate)
		}
		if m.PassiveCheckpoints == 0 {
			t.Fatal("no PASSIVE checkpoint ran")
		}
	})
	t.Run("under the bound, PASSIVE only", func(t *testing.T) {
		db := open(t, Options{PassiveEvery: 20 * time.Millisecond})
		mustWrite(t, db, insert("a"))
		waitFor(t, func() bool { return db.Metrics().PassiveCheckpoints >= 3 })
		if m := db.Metrics(); m.Truncates != 0 {
			t.Fatalf("%d TRUNCATEs under the bound", m.Truncates)
		}
	})
}

func TestSnapshotDuringWrites(t *testing.T) {
	db := open(t, Options{PassiveEvery: 20 * time.Millisecond, WALBound: 256 << 10})
	for i := range 20 {
		mustWrite(t, db, bigInsert(fmt.Sprint("seed", i)))
	}
	before := count(t, db, "")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var written sync.Map
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			name := fmt.Sprint("during", i)
			if err := db.Write(context.Background(), insert(name)); err != nil {
				t.Error(err)
				return
			}
			written.Store(name, true)
		}
	}()

	dest := filepath.Join(t.TempDir(), "snapshot.db")
	st, err := db.Snapshot(context.Background(), dest, SnapshotOptions{StepPages: 64, Pause: 2 * time.Millisecond})
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if st.Steps < 2 || st.Pages == 0 {
		t.Fatalf("stats %+v", st)
	}
	if st.Truncate.Mode != "TRUNCATE" {
		t.Fatalf("no TRUNCATE after the snapshot: %+v", st.Truncate)
	}
	fi, err := os.Stat(dest)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot file: %v %v", fi, err)
	}

	snap, err := sql.Open("sqlite", "file:"+dest+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	var check string
	if err := snap.QueryRow(`PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		t.Fatalf("integrity_check %q, %v", check, err)
	}
	var n int
	if err := snap.QueryRow(`SELECT count(*) FROM item`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < before {
		t.Fatalf("snapshot has %d rows, %d existed before it started", n, before)
	}
	if _, err := db.Snapshot(context.Background(), dest, SnapshotOptions{}); err == nil {
		t.Fatal("a snapshot overwrote an existing file")
	}
}

func TestSnapshotCancelledRemovesFile(t *testing.T) {
	db := open(t, Options{})
	for i := range 10 {
		mustWrite(t, db, bigInsert(fmt.Sprint("seed", i)))
	}
	ctx, cancel := context.WithCancel(context.Background())
	dest := filepath.Join(t.TempDir(), "snapshot.db")
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if _, err := db.Snapshot(ctx, dest, SnapshotOptions{StepPages: 8, Pause: 5 * time.Millisecond}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("partial snapshot left behind: %v", err)
	}
	mustWrite(t, db, insert("still writable"))
}

func TestCloseFinishesQueuedJobs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "varlatch.db")
	db := open(t, Options{Path: path})
	release := make(chan struct{})
	entered := make(chan struct{})
	go func() {
		_ = db.Write(context.Background(), func(*Tx) error { close(entered); <-release; return nil })
	}()
	<-entered
	results := make(chan error, 5)
	for i := range 5 {
		go func() { results <- db.Write(context.Background(), insert(fmt.Sprint("q", i))) }()
	}
	waitFor(t, func() bool { return len(db.jobs) == 5 })
	closed := make(chan error, 1)
	go func() { closed <- db.Close() }()
	waitFor(t, db.isClosed)
	if err := db.Write(context.Background(), insert("late")); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after Close: %v", err)
	}
	close(release)
	for range 5 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path + "-wal"); err == nil && st.Size() != 0 {
		t.Fatalf("WAL is %d bytes after Close", st.Size())
	}
	db2 := open(t, Options{Path: path})
	if n := count(t, db2, ""); n != 5 {
		t.Fatalf("%d rows after reopening", n)
	}
}

// G7: killing the process during writes loses no committed transaction and
// leaves the database consistent. A child process writes and prints each
// committed name; the parent kills it with SIGKILL and checks every printed
// name is in the database.
func TestKillLosesNoCommittedWrite(t *testing.T) {
	if dir := os.Getenv("STORAGE_KILL_HELPER"); dir != "" {
		killHelper(dir)
		return
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestKillLosesNoCommittedWrite$")
	cmd.Env = append(os.Environ(), "STORAGE_KILL_HELPER="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var committed []string
	sc := bufio.NewScanner(out)
	for sc.Scan() && len(committed) < 400 {
		if name, ok := strings.CutPrefix(sc.Text(), "committed "); ok {
			committed = append(committed, name)
		}
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if len(committed) < 400 {
		t.Fatalf("the helper reported only %d commits", len(committed))
	}

	db := open(t, Options{Path: filepath.Join(dir, "varlatch.db")})
	var check string
	if err := db.Reader().QueryRowContext(bg, `PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		t.Fatalf("integrity_check %q, %v", check, err)
	}
	for _, name := range committed {
		if count(t, db, "WHERE name = ?", name) != 1 {
			t.Fatalf("%s was reported committed but is missing", name)
		}
	}
}

func killHelper(dir string) {
	db, err := Open(context.Background(), Options{Path: filepath.Join(dir, "varlatch.db")})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := db.Write(context.Background(), func(tx *Tx) error {
		_, err := tx.ExecContext(bg, `CREATE TABLE item (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, body BLOB) STRICT`)
		return err
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var mu sync.Mutex
	w := bufio.NewWriter(os.Stdout)
	for g := range 8 {
		go func() {
			for i := 0; ; i++ {
				name := "g" + strconv.Itoa(g) + "-" + strconv.Itoa(i)
				if err := db.Write(context.Background(), insert(name)); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				mu.Lock()
				fmt.Fprintln(w, "committed", name)
				_ = w.Flush()
				mu.Unlock()
			}
		}()
	}
	select {}
}
