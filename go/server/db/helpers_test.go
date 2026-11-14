// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
)

const testRelease = "0.0.0-test"

// openDB opens a new database file through lib/storage and initializes it.
func openDB(t *testing.T) *storage.DB {
	t.Helper()
	s, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	st, err := Init(context.Background(), s, testRelease)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Created || st.Version != SchemaVersion {
		t.Fatalf("Init on a new file: %+v", st)
	}
	return s
}

// write runs fn as one job and fails the test on an error.
func write(t *testing.T, s *storage.DB, fn func(ctx context.Context, q *query.Queries, tx *storage.Tx) error) {
	t.Helper()
	if err := tryWrite(s, fn); err != nil {
		t.Fatal(err)
	}
}

func tryWrite(s *storage.DB, fn func(ctx context.Context, q *query.Queries, tx *storage.Tx) error) error {
	ctx := context.Background()
	return s.Write(ctx, func(tx *storage.Tx) error { return fn(ctx, query.New(tx), tx) })
}

// exec runs statements as one job.
func exec(t *testing.T, s *storage.DB, stmts ...string) {
	t.Helper()
	write(t, s, func(ctx context.Context, _ *query.Queries, tx *storage.Tx) error {
		for _, stmt := range stmts {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		return nil
	})
}

// tryExec runs one statement as a job and returns its error.
func tryExec(s *storage.DB, stmt string, args ...any) error {
	return tryWrite(s, func(ctx context.Context, _ *query.Queries, tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, stmt, args...)
		return err
	})
}

// refusedBy fails the test unless err is SQLite refusing a statement with a
// message containing want (a constraint or trigger name).
func refusedBy(t *testing.T, err error, want string) {
	t.Helper()
	var be *storage.BatchError
	switch {
	case err == nil:
		t.Fatalf("succeeded, want a refusal by %s", want)
	case errors.As(err, &be):
		t.Fatalf("the whole batch failed (%v), want only the job refused by %s", err, want)
	case !strings.Contains(err.Error(), want):
		t.Fatalf("refused with %q, want %s", err, want)
	}
}

func ns(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
func ni(n int64) sql.NullInt64   { return sql.NullInt64{Int64: n, Valid: true} }
