// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"

	"modernc.org/sqlite"
)

// The writer's connection is wrapped so that the engine sees everything a
// job does to it, whatever API the job uses:
//
//   - an authorizer, active while a job runs, refuses transaction control,
//     savepoints, ATTACH/DETACH and PRAGMA assignments in every statement
//     SQLite compiles (several statements in one string included);
//   - a commit hook refuses any commit while a job runs, so nothing a job
//     does can commit on its own, even after SQLite ended the transaction;
//   - a rollback hook notes at once that SQLite rolled the batch's
//     transaction back, after which every further statement of the batch is
//     refused;
//   - every error from an execution, a query, a row step or a statement is
//     classified while a job runs: one that fails the batch is remembered
//     even if the job ignores it.

// writerState is shared by the writer goroutine, the wrapped connection and
// SQLite's callbacks on it.
type writerState struct {
	inJob       atomic.Bool // a job's code is running
	batchActive atomic.Bool // between our BEGIN and our COMMIT or ROLLBACK
	txLost      atomic.Bool // SQLite rolled the batch back on its own
	fatal       atomic.Pointer[error]
}

func (s *writerState) noteFatal(err error) {
	s.fatal.CompareAndSwap(nil, &err)
}

func (s *writerState) fatalErr() error {
	if p := s.fatal.Load(); p != nil {
		return *p
	}
	if s.txLost.Load() {
		return errTxLost
	}
	return nil
}

func (s *writerState) reset() {
	s.inJob.Store(false)
	s.batchActive.Store(false)
	s.txLost.Store(false)
	s.fatal.Store(nil)
}

var (
	// errTxLost: SQLite rolled back the batch's transaction on its own.
	errTxLost = errors.New("storage: SQLite rolled back the write transaction")
	// errBatchFailed refuses a statement after the batch already failed.
	errBatchFailed = errors.New("storage: the write batch already failed; statement not run")
	// errPrepare: jobs run plain statements; a prepared statement could
	// outlive the job.
	errPrepare = errors.New("storage: jobs may not prepare statements")
)

// observe classifies an error from the writer's connection while a job runs.
func (s *writerState) observe(err error) error {
	if err != nil && err != io.EOF && s.inJob.Load() && !jobOwnError(err) {
		s.noteFatal(err)
	}
	return err
}

func (s *writerState) authorize(action sqlite.AuthorizerActionCode, arg1, arg2, _, _ string) sqlite.AuthorizerReturnCode {
	if !s.inJob.Load() {
		return sqlite.AuthorizerOK
	}
	switch action {
	case sqlite.AuthTransaction, sqlite.AuthSavepoint, sqlite.AuthAttach, sqlite.AuthDetach:
		return sqlite.AuthorizerDeny
	case sqlite.AuthPragma:
		// Reading a pragma is fine; setting one could change durability
		// (synchronous, journal_mode) or checks (foreign_keys).
		if arg2 != "" {
			return sqlite.AuthorizerDeny
		}
	}
	return sqlite.AuthorizerOK
}

func (s *writerState) onCommit() int32 {
	if s.inJob.Load() {
		s.noteFatal(errors.New("storage: a commit was attempted while a job ran"))
		return 1 // non-zero turns the commit into a rollback
	}
	return 0
}

func (s *writerState) onRollback() {
	if s.batchActive.Load() {
		s.txLost.Store(true)
	}
}

// writerConnector opens the writer's connections through modernc's own
// connector and wraps them.
type writerConnector struct {
	inner driver.Connector
	state *writerState
}

func newWriterConnector(dsn string, state *writerState) (*writerConnector, error) {
	inner, err := sqlite.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	return &writerConnector{inner: inner, state: state}, nil
}

func (c *writerConnector) Driver() driver.Driver { return c.inner.Driver() }

func (c *writerConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	auth, ok1 := conn.(sqlite.AuthorizerRegisterer)
	hooks, ok2 := conn.(sqlite.HookRegisterer)
	_, ok3 := conn.(driver.ExecerContext)
	_, ok4 := conn.(driver.QueryerContext)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		_ = conn.Close()
		return nil, fmt.Errorf("storage: driver connection %T lacks the authorizer, hooks or context methods the writer needs", conn)
	}
	if err := auth.RegisterAuthorizer(c.state.authorize); err != nil {
		_ = conn.Close()
		return nil, err
	}
	hooks.RegisterCommitHook(c.state.onCommit)
	hooks.RegisterRollbackHook(c.state.onRollback)
	return &guardedConn{Conn: conn, state: c.state}, nil
}

// guardedConn is the writer's driver connection.
type guardedConn struct {
	driver.Conn
	state *writerState
}

// unwrapConn returns modernc's own connection from a Raw callback's argument.
func unwrapConn(dc any) any {
	if g, ok := dc.(*guardedConn); ok {
		return g.Conn
	}
	return dc
}

func (c *guardedConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	r, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
	return r, c.state.observe(err)
}

func (c *guardedConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	r, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	if err != nil {
		return nil, c.state.observe(err)
	}
	return &guardedRows{Rows: r, state: c.state}, nil
}

func (c *guardedConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	var s driver.Stmt
	var err error
	if p, ok := c.Conn.(driver.ConnPrepareContext); ok {
		s, err = p.PrepareContext(ctx, query)
	} else {
		s, err = c.Conn.Prepare(query)
	}
	if err != nil {
		return nil, c.state.observe(err)
	}
	return &guardedStmt{Stmt: s, state: c.state}, nil
}

func (c *guardedConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

func (c *guardedConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.Conn.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return c.Conn.Begin() //nolint:staticcheck // fallback for drivers without BeginTx
}

func (c *guardedConn) CheckNamedValue(nv *driver.NamedValue) error {
	if ch, ok := c.Conn.(driver.NamedValueChecker); ok {
		return ch.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

func (c *guardedConn) ResetSession(ctx context.Context) error {
	if r, ok := c.Conn.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *guardedConn) IsValid() bool {
	if v, ok := c.Conn.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

type guardedRows struct {
	driver.Rows
	state *writerState
}

func (r *guardedRows) Next(dest []driver.Value) error {
	return r.state.observe(r.Rows.Next(dest))
}

type guardedStmt struct {
	driver.Stmt
	state *writerState
}

func (s *guardedStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if e, ok := s.Stmt.(driver.StmtExecContext); ok {
		r, err := e.ExecContext(ctx, args)
		return r, s.state.observe(err)
	}
	return nil, errors.New("storage: statement lacks ExecContext")
}

func (s *guardedStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	q, ok := s.Stmt.(driver.StmtQueryContext)
	if !ok {
		return nil, errors.New("storage: statement lacks QueryContext")
	}
	r, err := q.QueryContext(ctx, args)
	if err != nil {
		return nil, s.state.observe(err)
	}
	return &guardedRows{Rows: r, state: s.state}, nil
}

// fileURI builds an SQLite URI for path with query parameters. SQLite
// decodes %HH escapes in a URI's path, so '%', '?' and '#' in the path are
// escaped; nothing else needs to be.
func fileURI(path string, params ...string) string {
	var b strings.Builder
	b.WriteString("file:")
	for i := 0; i < len(path); i++ {
		switch c := path[i]; c {
		case '%', '?', '#':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	if len(params) > 0 {
		b.WriteString("?")
		b.WriteString(strings.Join(params, "&"))
	}
	return b.String()
}
