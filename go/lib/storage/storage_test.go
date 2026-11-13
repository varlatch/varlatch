// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
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
	select {
	case <-entered:
	case err := <-gateDone:
		t.Fatalf("the gate job did not run: %v", err)
	}
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
	for _, p := range []string{"", filepath.Join(t.TempDir(), "missing", "x.db")} {
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
// The cap lasts until a failed batch replaces the writer's connection. Jobs
// may not set pragmas, so it runs between batches.
func setPageLimit(t *testing.T, db *DB, extraPages int) {
	t.Helper()
	var pages int
	mustWrite(t, db, func(tx *Tx) error {
		return tx.QueryRowContext(bg, `PRAGMA page_count`).Scan(&pages)
	})
	writerPragma(t, db, fmt.Sprintf(`PRAGMA max_page_count = %d`, pages+extraPages))
}

// writerPragma runs a statement on the writer's connection between batches.
func writerPragma(t *testing.T, db *DB, q string) {
	t.Helper()
	err := db.onWriter(bg, func(dc any) error {
		_, err := dc.(driver.ExecerContext).ExecContext(bg, q, nil)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
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
		// SQLite may have rolled the transaction back; a write now would
		// commit on its own. It is refused instead.
		if err := insert("after")(tx); !errors.Is(err, errBatchFailed) {
			t.Errorf("write after the disk-full error: %v", err)
		}
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

// When SQLite rolls the whole transaction back on its own (here an INSERT
// OR ROLLBACK hitting a constraint; a full disk or an I/O error can do the
// same), the batch fails, whatever the job then does: return the error,
// swallow it, keep writing through Tx, or even write behind Tx's back.
func TestRolledBackTransactionFailsBatch(t *testing.T) {
	orRollback := func(tx *Tx) error {
		_, err := tx.ExecContext(bg, `INSERT OR ROLLBACK INTO item (name) VALUES ('taken')`)
		return err
	}
	for _, tc := range []struct {
		name string
		job  func(t *testing.T) func(*Tx) error
	}{
		{"returns the error", func(*testing.T) func(*Tx) error { return orRollback }},
		{"swallows it and writes on", func(t *testing.T) func(*Tx) error {
			return func(tx *Tx) error {
				_ = orRollback(tx)
				if err := insert("next")(tx); !errors.Is(err, errBatchFailed) {
					t.Errorf("statement after the rollback: %v", err)
				}
				return nil
			}
		}},
		{"writes behind Tx's back", func(t *testing.T) func(*Tx) error {
			return func(tx *Tx) error {
				_ = orRollback(tx)
				// In autocommit mode this would commit at once; the commit
				// hook refuses it.
				_, _ = tx.conn.ExecContext(bg, `INSERT INTO item (name) VALUES ('sneaky')`)
				return nil
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := open(t, Options{})
			mustWrite(t, db, insert("taken"))
			res := queueBatch(t, db, insert("first"), tc.job(t), insert("third"))
			for i, err := range res {
				var be *BatchError
				if !errors.As(err, &be) {
					t.Fatalf("job %d: %v, want a BatchError", i, err)
				}
			}
			if n := count(t, db, ""); n != 1 {
				t.Fatalf("%d rows; only 'taken' should exist", n)
			}
			mustWrite(t, db, insert("resumed"))
		})
	}
}

// Jobs cannot end, split or reconfigure the writer's transaction: the
// authorizer refuses it in every statement SQLite compiles, including later
// statements of a multi-statement string. The refusal is the job's own error.
func TestTransactionControlRefused(t *testing.T) {
	db := open(t, Options{})
	for _, q := range []string{
		"COMMIT", "rollback", "-- c\n/* d */ RELEASE job0", "SAVEPOINT x", "BEGIN", "END",
		"SELECT 1; COMMIT", "INSERT INTO item (name) VALUES ('x'); ROLLBACK",
		"PRAGMA synchronous = OFF", "PRAGMA foreign_keys = 0", "PRAGMA journal_mode = DELETE",
		"ATTACH DATABASE ':memory:' AS other",
	} {
		for _, via := range []string{"exec", "query", "queryrow"} {
			res := queueBatch(t, db, insert("ok-"+via+q), func(tx *Tx) error {
				switch via {
				case "exec":
					_, err := tx.ExecContext(bg, q)
					return err
				case "query":
					rows, err := tx.QueryContext(bg, q)
					if err != nil {
						return err
					}
					for rows.Next() {
					}
					return errors.Join(rows.Err(), rows.Close())
				default:
					var x any
					return tx.QueryRowContext(bg, q).Scan(&x)
				}
			})
			if res[0] != nil {
				t.Errorf("%s %q: the other job failed: %v", via, q, res[0])
			}
			code, ok := sqliteCode(res[1])
			if !ok || code&0xff != 23 { // SQLITE_AUTH
				t.Errorf("%s %q: %v, want SQLITE_AUTH", via, q, res[1])
			}
		}
	}
	if n := count(t, db, "WHERE name = 'x'"); n != 0 {
		t.Fatal("a refused job's write was committed")
	}
	if m := db.Metrics(); m.FailedBatches != 0 {
		t.Fatalf("%d failed batches", m.FailedBatches)
	}
	var sync int
	if err := db.Write(context.Background(), func(tx *Tx) error {
		return tx.QueryRowContext(bg, `PRAGMA synchronous`).Scan(&sync)
	}); err != nil || sync != 2 {
		t.Fatalf("synchronous %d, %v", sync, err)
	}
	if err := db.Write(context.Background(), func(tx *Tx) error {
		_, err := tx.PrepareContext(bg, `SELECT 1`)
		return err
	}); !errors.Is(err, errPrepare) {
		t.Fatalf("prepare: %v", err)
	}
}

// Pragmas that only read work in jobs, with arguments and in both syntaxes.
func TestReadPragmasAllowed(t *testing.T) {
	db := open(t, Options{})
	for _, q := range []string{
		`PRAGMA table_info(item)`, `PRAGMA table_xinfo(item)`, `PRAGMA index_list(item)`,
		`PRAGMA foreign_key_list(item)`, `PRAGMA foreign_key_check(item)`, `PRAGMA table_list`,
		`PRAGMA integrity_check(5)`, `PRAGMA quick_check`, `PRAGMA page_count`, `PRAGMA synchronous`,
		`SELECT * FROM pragma_table_info('item')`, `SELECT * FROM pragma_index_list('item')`,
	} {
		if err := db.Write(context.Background(), func(tx *Tx) error {
			rows, err := tx.QueryContext(bg, q)
			if err != nil {
				return err
			}
			for rows.Next() {
			}
			return errors.Join(rows.Err(), rows.Close())
		}); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
	var cols int
	mustWrite(t, db, func(tx *Tx) error {
		return tx.QueryRowContext(bg, `SELECT count(*) FROM pragma_table_info('item')`).Scan(&cols)
	})
	if cols != 3 {
		t.Fatalf("pragma_table_info saw %d columns", cols)
	}
}

// An error that fails the batch fails it even when the job meets it through
// a query whose rows it then ignores.
func TestSwallowedQueryErrorFailsBatch(t *testing.T) {
	db := open(t, Options{})
	setPageLimit(t, db, 4)
	body := make([]byte, 1<<20)
	res := queueBatch(t, db, insert("first"), func(tx *Tx) error {
		rows, err := tx.QueryContext(bg, `INSERT INTO item (name, body) VALUES ('r', ?) RETURNING id`, body)
		if err != nil {
			return nil // swallowed
		}
		for rows.Next() {
		}
		_ = rows.Close() // rows.Err() ignored
		return nil
	})
	for i, err := range res {
		if !IsDiskFull(err) {
			t.Fatalf("job %d: %v, want a disk-full BatchError", i, err)
		}
	}
	if n := count(t, db, ""); n != 0 {
		t.Fatalf("%d rows committed", n)
	}
	mustWrite(t, db, insert("resumed"))
}

// realDiskFull returns a genuine SQLITE_FULL error from modernc.
func realDiskFull(t *testing.T) error {
	t.Helper()
	d, err := sql.Open("sqlite", fileURI(filepath.Join(t.TempDir(), "full.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetMaxOpenConns(1)
	if _, err := d.Exec(`CREATE TABLE t (b BLOB); PRAGMA max_page_count = 3`); err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`INSERT INTO t VALUES (?)`, make([]byte, 1<<20))
	if !IsDiskFull(err) {
		t.Fatalf("no disk-full error: %v", err)
	}
	return err
}

type stubRows struct {
	driver.Rows
	errAfter int
	err      error
}

func (r *stubRows) Next([]driver.Value) error {
	if r.errAfter == 0 {
		return r.err
	}
	r.errAfter--
	return nil
}

type stubStmt struct {
	driver.Stmt
	err error
}

func (s stubStmt) ExecContext(context.Context, []driver.NamedValue) (driver.Result, error) {
	return nil, s.err
}

func (s stubStmt) QueryContext(context.Context, []driver.NamedValue) (driver.Rows, error) {
	return &stubRows{errAfter: 1, err: s.err}, nil
}

// Errors met while stepping rows (after the first) or through statements
// reach the batch while a job runs, and are left alone otherwise.
func TestDriverWrappersObserveErrors(t *testing.T) {
	full := realDiskFull(t)
	for _, inJob := range []bool{true, false} {
		ws := &writerState{}
		ws.inJob.Store(inJob)
		rows := &guardedRows{Rows: &stubRows{errAfter: 2, err: full}, state: ws}
		for range 2 {
			if err := rows.Next(nil); err != nil {
				t.Fatal(err)
			}
		}
		if err := rows.Next(nil); err != full {
			t.Fatalf("Next returned %v", err)
		}
		if got := ws.fatalErr(); (got != nil) != inJob {
			t.Fatalf("inJob %v: fatal %v", inJob, got)
		}

		ws = &writerState{}
		ws.inJob.Store(inJob)
		st := &guardedStmt{Stmt: stubStmt{err: full}, state: ws}
		if _, err := st.ExecContext(bg, nil); err != full {
			t.Fatal(err)
		}
		if got := ws.fatalErr(); (got != nil) != inJob {
			t.Fatalf("stmt exec, inJob %v: fatal %v", inJob, got)
		}
		ws.reset()
		ws.inJob.Store(inJob)
		r, _ := st.QueryContext(bg, nil)
		_ = r.Next(nil)
		_ = r.Next(nil)
		if got := ws.fatalErr(); (got != nil) != inJob {
			t.Fatalf("stmt rows, inJob %v: fatal %v", inJob, got)
		}
	}
	// A job's own error, and the end of the rows, are not batch failures.
	ws := &writerState{}
	ws.inJob.Store(true)
	_ = ws.observe(io.EOF)
	_ = ws.observe(errApp)
	if ws.fatalErr() != nil {
		t.Fatal("io.EOF or a job's own error was taken as a batch failure")
	}
}

// A batch failing while a snapshot runs replaces the connection the
// snapshot reads from: the snapshot ends with an error (no crash), its file
// is removed, and both writing and later snapshots work.
func TestSnapshotAbortedByFailedBatch(t *testing.T) {
	db := open(t, Options{})
	for i := range 10 {
		mustWrite(t, db, bigInsert(fmt.Sprint("seed", i)))
	}
	dest := filepath.Join(t.TempDir(), "snapshot.db")
	snapErr := make(chan error, 1)
	go func() {
		_, err := db.Snapshot(context.Background(), dest, SnapshotOptions{StepPages: 4, Pause: 20 * time.Millisecond})
		snapErr <- err
	}()
	waitFor(t, func() bool { _, err := os.Stat(dest); return err == nil })
	time.Sleep(50 * time.Millisecond) // a few steps in
	setPageLimit(t, db, 2)
	if err := db.Write(context.Background(), bigInsert("too big")); !IsDiskFull(err) {
		t.Fatalf("write: %v", err)
	}
	if err := <-snapErr; !errors.Is(err, errSnapshotAborted) {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("aborted snapshot left its file: %v", err)
	}
	mustWrite(t, db, insert("resumed"))
	if _, err := db.Snapshot(context.Background(), dest, SnapshotOptions{StepPages: 1 << 20}); err != nil {
		t.Fatal(err)
	}
}

// File names are passed to SQLite as URIs: characters with a meaning there
// must not change which file is opened or written.
func TestPathsAreEscaped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a%41 b?c#d.db")
	db := open(t, Options{Path: path})
	mustWrite(t, db, insert("x"))
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "a%41 b?c#d.db") {
			t.Fatalf("unexpected file %q next to the database", e.Name())
		}
	}
	if db.Metrics().WALBytes == 0 {
		t.Fatal("the WAL size is read from the wrong file")
	}

	dest := filepath.Join(dir, "snap%41?#.db")
	if _, err := db.Snapshot(context.Background(), dest, SnapshotOptions{}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dest)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() == 0 {
		t.Fatalf("snapshot file: %v, %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "snapA")); !os.IsNotExist(err) {
		t.Fatal("the snapshot went to a decoded name")
	}
	snap, err := sql.Open("sqlite", fileURI(dest, "mode=ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	var n int
	if err := snap.QueryRow(`SELECT count(*) FROM item`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("snapshot rows %d, %v", n, err)
	}
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

// checkpointLog collects what Options.OnCheckpoint reports.
type checkpointLog struct {
	mu sync.Mutex
	rs []CheckpointResult
}

func (l *checkpointLog) add(r CheckpointResult, err error) {
	if err != nil {
		panic(err)
	}
	l.mu.Lock()
	l.rs = append(l.rs, r)
	l.mu.Unlock()
}

func (l *checkpointLog) find(match func(CheckpointResult) bool) (CheckpointResult, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.rs {
		if match(r) {
			return r, true
		}
	}
	return CheckpointResult{}, false
}

func (l *checkpointLog) wait(t *testing.T, what string, match func(CheckpointResult) bool) CheckpointResult {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if r, ok := l.find(match); ok {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("no checkpoint event: %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// completed checks a TRUNCATE that reset the WAL: not busy, every frame
// copied, nothing left.
func completed(t *testing.T, r CheckpointResult) {
	t.Helper()
	if r.Mode != "TRUNCATE" || r.Deferred || r.Busy || r.LogFrames != r.Checkpointed || r.WALAfter != 0 || r.Start.IsZero() || r.Duration <= 0 {
		t.Fatalf("not a completed TRUNCATE: %+v", r)
	}
}

// Every checkpoint is reported with why it ran: the periodic PASSIVE, the
// size trigger, the size trigger deferred by a snapshot, the TRUNCATE a
// snapshot runs when it ends, and the one at Close.
func TestOnCheckpointReportsEveryTrigger(t *testing.T) {
	var log checkpointLog
	db := open(t, Options{WALBound: 256 << 10, PassiveEvery: 20 * time.Millisecond, OnCheckpoint: log.add})

	log.wait(t, "interval PASSIVE", func(r CheckpointResult) bool {
		return r.Trigger == TriggerInterval && r.Mode == "PASSIVE" && !r.Start.IsZero()
	})

	// One transaction larger than the bound: the next tick truncates.
	for i := range 3 {
		mustWrite(t, db, bigInsert(fmt.Sprint("size-", i)))
	}
	size := log.wait(t, "size TRUNCATE", func(r CheckpointResult) bool { return r.Trigger == TriggerSize && !r.Deferred })
	completed(t, size)
	if size.WALBefore <= 256<<10 {
		t.Fatalf("size trigger below the bound: %+v", size)
	}

	// A slow snapshot holds TRUNCATE off: a write past the bound while it
	// runs is reported as deferred, and the snapshot truncates at its end.
	done := make(chan error, 1)
	go func() {
		_, err := db.Snapshot(bg, filepath.Join(t.TempDir(), "snap.db"), SnapshotOptions{StepPages: 4, Pause: 10 * time.Millisecond})
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	mustWrite(t, db, bigInsert("during-snapshot"))
	deferred := log.wait(t, "deferred size trigger", func(r CheckpointResult) bool { return r.Deferred })
	if deferred.Trigger != TriggerSize || deferred.Mode != "TRUNCATE" || deferred.WALBefore <= 256<<10 {
		t.Fatalf("deferred event: %+v", deferred)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	completed(t, log.wait(t, "snapshot TRUNCATE", func(r CheckpointResult) bool { return r.Trigger == TriggerSnapshot }))
	if db.Metrics().TruncatesDelayed == 0 {
		t.Fatal("metrics missed the deferred trigger")
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if r := log.wait(t, "close TRUNCATE", func(r CheckpointResult) bool { return r.Trigger == TriggerClose }); r.Mode != "TRUNCATE" || r.Busy {
		t.Fatalf("close checkpoint: %+v", r)
	}
}
