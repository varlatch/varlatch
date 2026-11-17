// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// testGuard refuses when told to, and records its holds and releases.
type testGuard struct {
	mu              sync.Mutex
	refuse          error
	holds, releases int
}

func (g *testGuard) Hold() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.holds++
	return g.refuse
}

func (g *testGuard) Release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.releases++
}

// A guard that refuses rolls its own job back (and only it); one that
// holds is released once; a job that failed on its own is never held.
func TestCommitGuard(t *testing.T) {
	db := open(t, Options{})
	insert := func(name string) func(tx *Tx) error {
		return func(tx *Tx) error {
			_, err := tx.ExecContext(bg, `INSERT INTO item (name) VALUES (?)`, name)
			return err
		}
	}
	closed := errors.New("access closed")
	refusing := &testGuard{refuse: closed}
	if err := db.Write(WithCommitGuard(context.Background(), refusing), insert("refused")); !errors.Is(err, closed) {
		t.Fatalf("a refusing guard: %v", err)
	}
	holding := &testGuard{}
	if err := db.Write(WithCommitGuard(context.Background(), holding), insert("kept")); err != nil {
		t.Fatal(err)
	}
	failing := &testGuard{}
	if err := db.Write(WithCommitGuard(context.Background(), failing), func(*Tx) error { return errors.New("its own") }); err == nil {
		t.Fatal("a failing job succeeded")
	}
	if err := db.Write(context.Background(), insert("unguarded")); err != nil {
		t.Fatal(err)
	}
	var names []string
	rows, err := db.Reader().QueryContext(bg, `SELECT name FROM item ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		names = append(names, n)
	}
	_ = rows.Close()
	if len(names) != 2 || names[0] != "kept" || names[1] != "unguarded" {
		t.Fatalf("rows: %v", names)
	}
	if refusing.holds != 1 || refusing.releases != 0 || holding.holds != 1 || holding.releases != 1 || failing.holds != 0 || failing.releases != 0 {
		t.Fatalf("holds and releases: refusing %d/%d, holding %d/%d, failing %d/%d",
			refusing.holds, refusing.releases, holding.holds, holding.releases, failing.holds, failing.releases)
	}
}
