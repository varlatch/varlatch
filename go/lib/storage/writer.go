// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// A job is one Write call, queued for the writer.
type job struct {
	fn   func(*Tx) error
	done chan error // buffered: the writer never blocks on it
	// state moves from queued to started (the writer took it) or to
	// cancelled (the caller gave up first), never both.
	state atomic.Int32
}

const (
	queued int32 = iota
	started
	cancelled
)

func (j *job) start() bool { return j.state.CompareAndSwap(queued, started) }

// An op runs on the writer's connection between batches (snapshot steps).
type op struct {
	fn   func(driverConn any) error
	done chan error
}

// BatchError means the write transaction holding a job failed as a whole:
// nothing of the job was committed. Every job of that batch receives it.
type BatchError struct {
	Op  string // "begin", "savepoint", "job", "rollback to savepoint", "release", "commit" or "writer"
	Err error
}

func (e *BatchError) Error() string {
	what := "write batch failed"
	if IsDiskFull(e.Err) {
		what = "write batch failed: the disk is full; reads keep working, writes resume once space is free"
	}
	return fmt.Sprintf("storage: %s (%s): %v", what, e.Op, e.Err)
}

func (e *BatchError) Unwrap() error { return e.Err }

// IsDiskFull reports whether err comes from SQLite finding the disk (or the
// database's page limit) full.
func IsDiskFull(err error) bool {
	code, ok := sqliteCode(err)
	return ok && code&0xff == sqlite3.SQLITE_FULL
}

func sqliteCode(err error) (int, bool) {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code(), true
	}
	return 0, false
}

// jobOwnError reports whether an error a job ran into is the job's own
// (ADR-0059 Decision 2): an error from the job's code, or an SQLite error
// about the statement itself (a constraint, a type mismatch, bad SQL). A
// savepoint rollback undoes it, and only that job fails. Every other SQLite
// error (disk full, I/O, out of memory, corruption, an interrupt, a busy or
// locked database, a rolled-back transaction) fails the whole batch.
func jobOwnError(err error) bool {
	code, ok := sqliteCode(err)
	if !ok {
		return true
	}
	switch code & 0xff {
	case sqlite3.SQLITE_CONSTRAINT, sqlite3.SQLITE_ERROR, sqlite3.SQLITE_MISMATCH,
		sqlite3.SQLITE_RANGE, sqlite3.SQLITE_TOOBIG:
		return true
	}
	return false
}

// Write runs fn as one job of the single writer and returns once the job's
// outcome is known.
//
// The writer runs the queued jobs (up to MaxBatch) in one BEGIN IMMEDIATE
// transaction, each in its own SAVEPOINT, so one fsync covers them all.
//
//   - fn returning an error that is its own (see jobOwnError) rolls back to
//     the job's savepoint: Write returns that error, and the other jobs are
//     unaffected.
//   - Any other error, in this job or another of the batch, or a failed
//     savepoint, release or COMMIT, fails the whole batch: Write returns a
//     *BatchError, and nothing of the job was committed.
//   - nil means the job's savepoint was released and the COMMIT holding it
//     returned success: what it wrote is durable (synchronous=FULL).
//
// So a caller must not release anything that depends on the job (a secret
// whose audit row the job writes) unless Write returned nil.
//
// fn must not make network calls or wait on other work: the write
// transaction is held while it runs. Its statements run under the writer's
// context, never ctx: interrupting one would roll back every job of the
// batch. ctx only abandons a job the writer has not started yet; once it
// started, Write waits for its outcome.
func (db *DB) Write(ctx context.Context, fn func(tx *Tx) error) error {
	j := &job{fn: fn, done: make(chan error, 1)}
	db.mu.RLock()
	if db.closed {
		db.mu.RUnlock()
		return ErrClosed
	}
	select {
	case db.jobs <- j:
		db.mu.RUnlock()
	case <-ctx.Done():
		db.mu.RUnlock()
		return ctx.Err()
	}
	select {
	case err := <-j.done:
		return err
	case <-ctx.Done():
		if j.state.CompareAndSwap(queued, cancelled) {
			return ctx.Err()
		}
		return <-j.done
	}
}

// onWriter runs fn with the writer's driver connection between batches.
// Unlike Write it does not check closed: Close waits for snapshots, the
// only callers, before it stops the writer.
func (db *DB) onWriter(ctx context.Context, fn func(driverConn any) error) error {
	o := &op{fn: fn, done: make(chan error, 1)}
	select {
	case db.ops <- o:
	case <-ctx.Done():
		return ctx.Err()
	}
	return <-o.done
}

func (db *DB) writerLoop() {
	defer db.loops.Done()
	for {
		select {
		case j := <-db.jobs:
			db.runBatch(db.collect(j))
		case o := <-db.ops:
			o.done <- db.runOp(o)
		case <-db.stop:
			// Everything submitted before Close is in the channels: finish it.
			for {
				select {
				case j := <-db.jobs:
					db.runBatch(db.collect(j))
				case o := <-db.ops:
					o.done <- db.runOp(o)
				default:
					return
				}
			}
		}
	}
}

// collect takes first plus whatever else is already queued, up to MaxBatch,
// without waiting for more.
func (db *DB) collect(first *job) []*job {
	batch := []*job{first}
	for len(batch) < db.opts.MaxBatch {
		select {
		case j := <-db.jobs:
			batch = append(batch, j)
		default:
			return batch
		}
	}
	return batch
}

var bg = context.Background()

func (db *DB) openWriter(ctx context.Context) error {
	c, err := db.wdb.Conn(ctx)
	if err != nil {
		return err
	}
	db.wconn = c
	return nil
}

// dropWriter discards the writer's connection after a failed batch, so no
// half-open transaction survives into the next one (closing a connection
// rolls back what it held). The next batch opens a new one.
func (db *DB) dropWriter() {
	if db.wconn == nil {
		return
	}
	_, _ = db.wconn.ExecContext(bg, "ROLLBACK")
	_ = db.wconn.Raw(func(any) error { return driver.ErrBadConn })
	_ = db.wconn.Close()
	db.wconn = nil
}

func (db *DB) ensureWriter() error {
	if db.wconn != nil {
		return nil
	}
	return db.openWriter(bg)
}

func (db *DB) runOp(o *op) error {
	if err := db.ensureWriter(); err != nil {
		return &BatchError{Op: "writer", Err: err}
	}
	return db.wconn.Raw(o.fn)
}

func (db *DB) runBatch(batch []*job) {
	t0 := time.Now()
	results := make([]error, len(batch))
	ran := make([]bool, len(batch)) // started by the writer, so it gets an answer
	var fatal *BatchError
	fail := func(op string, err error) { fatal = &BatchError{Op: op, Err: err} }

	if err := db.ensureWriter(); err != nil {
		fail("writer", err)
	} else if _, err := db.wconn.ExecContext(bg, "BEGIN IMMEDIATE"); err != nil {
		fail("begin", err)
	}
	for i, j := range batch {
		if fatal != nil {
			break
		}
		if !j.start() {
			continue // the caller gave up before the job started
		}
		ran[i] = true
		sp := "job" + strconv.Itoa(i)
		if _, err := db.wconn.ExecContext(bg, "SAVEPOINT "+sp); err != nil {
			fail("savepoint", err)
			break
		}
		tx := &Tx{conn: db.wconn}
		err := runJob(j.fn, tx)
		if tx.fatal != nil {
			// The job hit an error that fails the batch, even if it then
			// swallowed it.
			fail("job", tx.fatal)
			break
		}
		if err != nil {
			if !jobOwnError(err) {
				fail("job", err)
				break
			}
			if _, rerr := db.wconn.ExecContext(bg, "ROLLBACK TO "+sp); rerr != nil {
				fail("rollback to savepoint", rerr)
				break
			}
			results[i] = err
		}
		if _, err := db.wconn.ExecContext(bg, "RELEASE "+sp); err != nil {
			fail("release", err)
			break
		}
	}
	commitStart := time.Now()
	if fatal == nil {
		if _, err := db.wconn.ExecContext(bg, "COMMIT"); err != nil {
			fail("commit", err)
		}
	}
	commit := time.Since(commitStart)

	if fatal != nil {
		db.dropWriter()
		for i, j := range batch {
			if ran[i] || j.start() {
				j.done <- fatal
			}
		}
		db.m.batch(len(batch), 0, true, time.Since(t0), 0)
		return
	}
	ownErrors := 0
	for i, j := range batch {
		if ran[i] {
			if results[i] != nil {
				ownErrors++
			}
			j.done <- results[i]
		}
	}
	db.m.batch(len(batch), ownErrors, false, time.Since(t0), commit)
}

// runJob runs fn and turns a panic into the job's own error: the savepoint
// rollback then undoes whatever it did.
func runJob(fn func(*Tx) error, tx *Tx) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("storage: job panicked: %v", r)
		}
	}()
	return fn(tx)
}

// Tx is a job's view of the write transaction. It has the method set sqlc
// expects of its DBTX. Every statement runs under the writer's context (the
// ctx argument is ignored, see Write), and an SQLite error that fails the
// batch is remembered even if the job ignores it.
type Tx struct {
	conn  *sql.Conn
	fatal error
}

func (t *Tx) observe(err error) error {
	if err != nil && !jobOwnError(err) && t.fatal == nil {
		t.fatal = err
	}
	return err
}

// errTxControl refuses statements that would end or reshape the writer's
// transaction from inside a job.
var errTxControl = errors.New("storage: a job may not run transaction control statements")

func (t *Tx) check(query string) error {
	switch firstKeyword(query) {
	case "BEGIN", "COMMIT", "END", "ROLLBACK", "SAVEPOINT", "RELEASE":
		return errTxControl
	}
	return nil
}

// ExecContext runs a statement in the job.
func (t *Tx) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	if err := t.check(query); err != nil {
		return nil, err
	}
	r, err := t.conn.ExecContext(bg, query, args...)
	return r, t.observe(err)
}

// QueryContext runs a query in the job.
func (t *Tx) QueryContext(_ context.Context, query string, args ...any) (*sql.Rows, error) {
	if err := t.check(query); err != nil {
		return nil, err
	}
	r, err := t.conn.QueryContext(bg, query, args...)
	return r, t.observe(err)
}

// QueryRowContext runs a query for one row in the job.
func (t *Tx) QueryRowContext(_ context.Context, query string, args ...any) *sql.Row {
	if err := t.check(query); err != nil {
		// A *sql.Row cannot carry an error of ours. This query fails with
		// "no such table: storage: a job may not run transaction control
		// statements", which Scan returns to the job.
		query = `SELECT 1 FROM "` + errTxControl.Error() + `"`
		args = nil
	}
	row := t.conn.QueryRowContext(bg, query, args...)
	_ = t.observe(row.Err())
	return row
}

// PrepareContext prepares a statement on the writer's connection.
func (t *Tx) PrepareContext(_ context.Context, query string) (*sql.Stmt, error) {
	if err := t.check(query); err != nil {
		return nil, err
	}
	s, err := t.conn.PrepareContext(bg, query)
	return s, t.observe(err)
}

// firstKeyword returns the first SQL keyword of query, upper-cased, after
// whitespace and comments.
func firstKeyword(query string) string {
	s := query
	for {
		s = strings.TrimLeft(s, " \t\r\n\f\v")
		switch {
		case strings.HasPrefix(s, "--"):
			if i := strings.IndexByte(s, '\n'); i >= 0 {
				s = s[i+1:]
				continue
			}
			return ""
		case strings.HasPrefix(s, "/*"):
			if i := strings.Index(s[2:], "*/"); i >= 0 {
				s = s[i+4:]
				continue
			}
			return ""
		}
		end := strings.IndexFunc(s, func(r rune) bool {
			return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
		})
		if end < 0 {
			end = len(s)
		}
		return strings.ToUpper(s[:end])
	}
}
