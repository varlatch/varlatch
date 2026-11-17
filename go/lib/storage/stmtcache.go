// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"container/list"
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"

	"modernc.org/sqlite"
)

// The read pool's connections keep the statements they run prepared.
//
// database/sql and modernc's driver prepare a query's SQL on every call
// that does not go through a prepared *sql.Stmt, and the server's reads
// (sqlc's generated queries, in read transactions) never do: in the G9a
// smoke's CPU profile, parsing SQL took more of the disclosure path than
// running it (ADR-0059 step 4, decision 7's follow-up). Each reader
// connection therefore keeps a small cache of driver statements by SQL
// text, least recently used first out:
//
//   - a query whose statement is cached and idle runs on it: modernc keeps
//     a single statement's compiled program and resets it when the rows
//     close, so nothing is parsed again;
//   - a query whose statement is still in use on the connection (its rows
//     are open, as when a read transaction runs the same query inside a
//     loop over its results) runs as a one-off statement, as before, and
//     so does a new query when every slot holds a statement in use: the
//     cache never holds more than its size;
//   - a statement is reset when its rows close, so a cached statement holds
//     no read transaction open and never holds a checkpoint off.
//
// Only the read pool does this. The writer's connection and the
// checkpointer's are unchanged: jobs run plain statements (errPrepare), and
// the single writer, group commit and crash safety (G7) do not depend on
// how a read is compiled. SQLite recompiles a cached statement by itself
// when the schema changed since it was prepared.

// readerStmtCacheSize is how many statements one reader connection keeps.
// The server's hot reads are a few dozen sqlc queries; statements built
// from variable lists push older ones out instead of growing the cache.
const readerStmtCacheSize = 128

// readerConnector opens the read pool's connections through modernc's own
// connector and gives each a statement cache.
type readerConnector struct {
	inner driver.Connector
	size  int
	stats readerStmtStats
}

// readerStmtStats counts, over every reader connection, the statements
// prepared into a cache, the queries a cached statement answered, the
// queries run as one-off statements, and the cached statements closed.
// The tests read it.
type readerStmtStats struct {
	prepared, reused, oneOff, closed atomic.Int64
}

func newReaderConnector(dsn string, size int) (*readerConnector, error) {
	inner, err := sqlite.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	return &readerConnector{inner: inner, size: size}, nil
}

func (c *readerConnector) Driver() driver.Driver { return c.inner.Driver() }

func (c *readerConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	_, ok1 := conn.(driver.ConnPrepareContext)
	_, ok2 := conn.(driver.QueryerContext)
	_, ok3 := conn.(driver.ExecerContext)
	if !ok1 || !ok2 || !ok3 {
		_ = conn.Close()
		return nil, errors.New("storage: driver connection lacks the context methods the read pool needs")
	}
	return &cachingConn{Conn: conn, conn: c, lru: list.New(), byQuery: map[string]*list.Element{}}, nil
}

// cachingConn is a reader's driver connection with its statement cache.
// database/sql uses a connection from one goroutine at a time, but rows
// can be closed from another (a cancelled context), so the cache has its
// own lock.
type cachingConn struct {
	driver.Conn
	conn *readerConnector

	mu      sync.Mutex
	lru     *list.List // of *cachedStmt, most recently used first
	byQuery map[string]*list.Element
	closed  bool
}

// cachedStmt is one prepared statement and whether rows of it are open.
type cachedStmt struct {
	query string
	stmt  driver.Stmt
	busy  bool
}

func (c *cachingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	cs, err := c.take(ctx, query)
	if err != nil {
		return nil, err
	}
	if cs == nil {
		c.conn.stats.oneOff.Add(1)
		return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	}
	rows, err := cs.stmt.(driver.StmtQueryContext).QueryContext(ctx, args)
	if err != nil {
		c.release(cs)
		return nil, err
	}
	return newCachedRows(rows, func() { c.release(cs) }), nil
}

// take returns query's cached statement, marked busy, preparing and caching
// it first if it is not cached; nil if it is busy, or if it is not cached
// and the cache is full of busy statements (the caller runs a one-off
// statement, as it does when the cache has no room at all).
func (c *cachingConn) take(ctx context.Context, query string) (*cachedStmt, error) {
	if c.conn.size <= 0 {
		return nil, nil // no cache (the benchmark's baseline)
	}
	c.mu.Lock()
	if e, ok := c.byQuery[query]; ok {
		cs := e.Value.(*cachedStmt)
		if cs.busy {
			c.mu.Unlock()
			return nil, nil
		}
		cs.busy = true
		c.lru.MoveToFront(e)
		c.mu.Unlock()
		c.conn.stats.reused.Add(1)
		return cs, nil
	}
	// Not cached: make room first, closing the least recently used idle
	// statements. With every slot in use, it is not cached at all.
	for e := c.lru.Back(); e != nil && c.lru.Len() >= c.conn.size; {
		prev := e.Prev()
		if old := e.Value.(*cachedStmt); !old.busy {
			c.lru.Remove(e)
			delete(c.byQuery, old.query)
			_ = c.closeStmt(old)
		}
		e = prev
	}
	full := c.lru.Len() >= c.conn.size
	c.mu.Unlock()
	if full {
		return nil, nil
	}

	// Prepare it. Only this goroutine runs queries on the connection, so
	// nobody else can cache a statement meanwhile: the slot stays free.
	stmt, err := c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	c.conn.stats.prepared.Add(1)
	cs := &cachedStmt{query: query, stmt: stmt, busy: true}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byQuery[query] = c.lru.PushFront(cs)
	return cs, nil
}

// release marks cs idle once its rows closed. A statement leaves the cache
// only while idle, so cs is still in it unless the connection closed.
func (c *cachingConn) release(cs *cachedStmt) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cs.busy = false
	if c.closed {
		return // the connection closed it (Close)
	}
	if e, ok := c.byQuery[cs.query]; !ok || e.Value.(*cachedStmt) != cs {
		_ = c.closeStmt(cs) // not reached: kept so that no statement leaks
	}
}

// closeStmt finalizes a statement that left the cache.
func (c *cachingConn) closeStmt(cs *cachedStmt) error {
	c.conn.stats.closed.Add(1)
	return cs.stmt.Close()
}

func (c *cachingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

func (c *cachingConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, query)
}

func (c *cachingConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

func (c *cachingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.Conn.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return c.Conn.Begin() //nolint:staticcheck // fallback for drivers without BeginTx
}

func (c *cachingConn) Ping(ctx context.Context) error {
	if p, ok := c.Conn.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (c *cachingConn) ResetSession(ctx context.Context) error {
	if r, ok := c.Conn.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *cachingConn) IsValid() bool {
	if v, ok := c.Conn.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

// Close closes the cached statements, then the connection. database/sql
// closes a connection only once its rows are closed, so none is busy.
func (c *cachingConn) Close() error {
	c.mu.Lock()
	c.closed = true
	var errs []error
	for e := c.lru.Front(); e != nil; e = e.Next() {
		errs = append(errs, c.closeStmt(e.Value.(*cachedStmt)))
	}
	c.lru.Init()
	clear(c.byQuery)
	c.mu.Unlock()
	errs = append(errs, c.Conn.Close())
	return errors.Join(errs...)
}

// cachedRows are the rows of a cached statement: closing them resets the
// statement (modernc) and gives it back to the cache, once.
type cachedRows struct {
	driver.Rows
	once    sync.Once
	release func()
}

func newCachedRows(r driver.Rows, release func()) *cachedRows {
	return &cachedRows{Rows: r, release: release}
}

func (r *cachedRows) Close() error {
	err := r.Rows.Close()
	r.once.Do(r.release)
	return err
}

// The column type methods modernc's rows have, so that wrapping hides none.

func (r *cachedRows) ColumnTypeDatabaseTypeName(i int) string {
	if t, ok := r.Rows.(driver.RowsColumnTypeDatabaseTypeName); ok {
		return t.ColumnTypeDatabaseTypeName(i)
	}
	return ""
}

func (r *cachedRows) ColumnTypeLength(i int) (int64, bool) {
	if t, ok := r.Rows.(driver.RowsColumnTypeLength); ok {
		return t.ColumnTypeLength(i)
	}
	return 0, false
}

func (r *cachedRows) ColumnTypeNullable(i int) (bool, bool) {
	if t, ok := r.Rows.(driver.RowsColumnTypeNullable); ok {
		return t.ColumnTypeNullable(i)
	}
	return false, false
}

func (r *cachedRows) ColumnTypePrecisionScale(i int) (int64, int64, bool) {
	if t, ok := r.Rows.(driver.RowsColumnTypePrecisionScale); ok {
		return t.ColumnTypePrecisionScale(i)
	}
	return 0, 0, false
}

func (r *cachedRows) ColumnTypeScanType(i int) reflect.Type {
	if t, ok := r.Rows.(driver.RowsColumnTypeScanType); ok {
		return t.ColumnTypeScanType(i)
	}
	return reflect.TypeFor[any]()
}
