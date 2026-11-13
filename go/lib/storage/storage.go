// SPDX-License-Identifier: Apache-2.0

// Package storage is Varlatch's SQLite storage engine (ADR-0059 Decision 2,
// and the snapshot of Decision 7). It owns the database file and gives the
// rest of the program three things:
//
//   - Write: a job run by the single writer, committed together with other
//     queued jobs (group commit), reported as successful only after the
//     commit that holds it returned;
//   - Reader: a pool of read-only connections;
//   - Snapshot: a consistent copy of the database, taken in paced steps on
//     the writer's connection.
//
// A checkpointer bounds the WAL. The settings ADR-0059 fixes (WAL mode,
// synchronous=FULL, a busy timeout, foreign keys) are not options.
//
// The package knows nothing about Varlatch's schema; it is Apache-2.0 so
// that the CLI's host commands can use it as well as varlatchd.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// The policy of ADR-0059 Decision 2. Options may change the checkpoint and
// batch numbers for tests and the G9a harness; nothing changes durability.
const (
	DefaultMaxBatch         = 64
	DefaultPassiveEvery     = 2 * time.Second
	DefaultWALBound         = 64 << 20
	DefaultJournalSizeLimit = 64 << 20
	defaultQueueSize        = 1024

	busyTimeout = 5 * time.Second
)

// ErrClosed is returned for work submitted after Close started.
var ErrClosed = errors.New("storage: closed")

// Options configures Open. Only Path is required; a zero value takes the
// default, which is ADR-0059's value where it names one.
type Options struct {
	// Path is the database file. Its directory must exist.
	Path string
	// ReadConns is the size of the read-only pool (default: the number of
	// CPUs, at least 4).
	ReadConns int
	// MaxBatch is the most jobs one write transaction holds (64).
	MaxBatch int
	// QueueSize is how many jobs may wait for the writer before Write blocks.
	QueueSize int
	// PassiveEvery is the period of PASSIVE checkpoints (2 s).
	PassiveEvery time.Duration
	// WALBound is the WAL size above which the checkpointer runs TRUNCATE
	// (64 MiB).
	WALBound int64
	// JournalSizeLimit is PRAGMA journal_size_limit (64 MiB).
	JournalSizeLimit int64
}

func (o *Options) setDefaults() {
	if o.ReadConns <= 0 {
		o.ReadConns = max(4, runtime.NumCPU())
	}
	if o.MaxBatch <= 0 {
		o.MaxBatch = DefaultMaxBatch
	}
	if o.QueueSize <= 0 {
		o.QueueSize = defaultQueueSize
	}
	if o.PassiveEvery <= 0 {
		o.PassiveEvery = DefaultPassiveEvery
	}
	if o.WALBound <= 0 {
		o.WALBound = DefaultWALBound
	}
	if o.JournalSizeLimit <= 0 {
		o.JournalSizeLimit = DefaultJournalSizeLimit
	}
}

// DB is an open database. Its methods are safe for concurrent use.
type DB struct {
	opts Options

	// The writer: one connection, owned by the writer goroutine.
	wdb    *sql.DB
	wconn  *sql.Conn // nil after a failed batch until the next one reopens it
	ws     *writerState
	backup *activeBackup // the snapshot reading from wconn; writer goroutine only
	jobs   chan *job
	ops    chan *op

	rdb *sql.DB // read-only pool

	// The checkpointer's own connection.
	cdb   *sql.DB
	cconn *sql.Conn
	// ckptMu is held by non-passive checkpoints and for a whole snapshot, so
	// that a snapshot holds TRUNCATE off while it runs.
	ckptMu sync.Mutex

	// mu guards closed against concurrent submissions: Close takes it for
	// writing, so every submission that saw closed == false has been
	// queued before the writer is told to stop.
	mu        sync.RWMutex
	closed    bool
	snapshots sync.WaitGroup
	stop      chan struct{}
	loops     sync.WaitGroup

	m metrics
}

// Open opens (or creates) the database at opts.Path and starts its writer
// and checkpointer.
func Open(ctx context.Context, opts Options) (*DB, error) {
	opts.setDefaults()
	if opts.Path == "" {
		return nil, errors.New("storage: no path")
	}
	path, err := filepath.Abs(opts.Path)
	if err != nil {
		return nil, err
	}
	opts.Path = path
	if st, err := os.Stat(filepath.Dir(path)); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("storage: directory of %s: not a directory or missing", path)
	}

	db := &DB{
		opts: opts,
		ws:   &writerState{},
		jobs: make(chan *job, opts.QueueSize),
		ops:  make(chan *op, 16),
		stop: make(chan struct{}),
	}
	ok := false
	defer func() {
		if !ok {
			db.closeConns()
		}
	}()

	// The writer first: it switches the file to WAL mode. Its connections
	// are wrapped (driver.go).
	wc, err := newWriterConnector(db.dsn(true, false), db.ws)
	if err != nil {
		return nil, err
	}
	db.wdb = sql.OpenDB(wc)
	db.wdb.SetMaxOpenConns(1)
	db.wdb.SetConnMaxLifetime(0)
	db.wdb.SetConnMaxIdleTime(0)
	if err := db.openWriter(ctx); err != nil {
		return nil, err
	}

	if db.rdb, err = sql.Open("sqlite", db.dsn(false, true)); err != nil {
		return nil, err
	}
	db.rdb.SetMaxOpenConns(opts.ReadConns)
	db.rdb.SetMaxIdleConns(opts.ReadConns)

	if db.cdb, err = sql.Open("sqlite", db.dsn(false, false)); err != nil {
		return nil, err
	}
	db.cdb.SetMaxOpenConns(1)
	if db.cconn, err = db.cdb.Conn(ctx); err != nil {
		return nil, err
	}

	for _, c := range []struct {
		name string
		q    queryer
	}{{"writer", db.wconn}, {"reader", db.rdb}, {"checkpointer", db.cconn}} {
		if err := checkSettings(ctx, c.q, db.opts.JournalSizeLimit); err != nil {
			return nil, fmt.Errorf("storage: %s connection: %w", c.name, err)
		}
	}

	db.loops.Add(2)
	go db.writerLoop()
	go db.checkpointLoop()
	ok = true
	return db, nil
}

// dsn builds a modernc.org/sqlite data source name. Every connection gets
// the same durability settings; the writer also sets WAL mode (a property
// of the file), and readers are query-only.
func (db *DB) dsn(writer, reader bool) string {
	p := []string{
		fmt.Sprintf("_pragma=busy_timeout(%d)", busyTimeout.Milliseconds()),
		"_pragma=foreign_keys(1)",
		"_pragma=synchronous(FULL)",
		"_pragma=wal_autocheckpoint(0)",
		fmt.Sprintf("_pragma=journal_size_limit(%d)", db.opts.JournalSizeLimit),
	}
	if writer {
		p = append([]string{"_pragma=journal_mode(WAL)"}, p...)
	}
	if reader {
		p = append(p, "_pragma=query_only(1)")
	}
	return fileURI(db.opts.Path, p...)
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// checkSettings verifies that a connection really runs with the settings
// ADR-0059 fixes, so a driver change cannot silently weaken them.
func checkSettings(ctx context.Context, q queryer, journalLimit int64) error {
	want := []struct {
		pragma string
		value  string
	}{
		{"journal_mode", "wal"},
		{"synchronous", "2"}, // FULL
		{"foreign_keys", "1"},
		{"busy_timeout", fmt.Sprint(busyTimeout.Milliseconds())},
		{"wal_autocheckpoint", "0"},
		{"journal_size_limit", fmt.Sprint(journalLimit)},
	}
	for _, w := range want {
		var got string
		if err := q.QueryRowContext(ctx, "PRAGMA "+w.pragma).Scan(&got); err != nil {
			return fmt.Errorf("PRAGMA %s: %w", w.pragma, err)
		}
		if got != w.value {
			return fmt.Errorf("PRAGMA %s is %s, want %s", w.pragma, got, w.value)
		}
	}
	return nil
}

// Reader is the pool of read-only connections. A statement that writes
// fails on it.
func (db *DB) Reader() *sql.DB { return db.rdb }

// Path is the database file.
func (db *DB) Path() string { return db.opts.Path }

// Close lets queued jobs finish, stops the writer and the checkpointer,
// truncates the WAL and closes every connection. Jobs and snapshots
// submitted afterwards fail with ErrClosed; a snapshot in progress stops at
// its next step.
func (db *DB) Close() error {
	db.mu.Lock()
	if db.closed {
		db.mu.Unlock()
		return nil
	}
	db.closed = true
	db.mu.Unlock()

	db.snapshots.Wait()
	close(db.stop)
	db.loops.Wait()
	if db.cconn != nil {
		db.ckptMu.Lock()
		_, _ = db.checkpointLocked(context.Background(), "TRUNCATE")
		db.ckptMu.Unlock()
	}
	return db.closeConns()
}

func (db *DB) isClosed() bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.closed
}

func (db *DB) closeConns() error {
	var errs []error
	if db.wconn != nil {
		errs = append(errs, db.wconn.Close())
	}
	if db.cconn != nil {
		errs = append(errs, db.cconn.Close())
	}
	for _, d := range []*sql.DB{db.wdb, db.rdb, db.cdb} {
		if d != nil {
			errs = append(errs, d.Close())
		}
	}
	return errors.Join(errs...)
}

// walSize is the WAL file's size, 0 if it does not exist.
func (db *DB) walSize() int64 {
	st, err := os.Stat(db.opts.Path + "-wal")
	if err != nil {
		return 0
	}
	return st.Size()
}
