// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"strings"
	"testing"
)

// A job may turn defer_foreign_keys on (the migration's import, whose tables
// refer to each other in a cycle): rows that refer to each other insert in
// either order, and every foreign key is still checked at the commit, so a
// job that leaves one unresolved commits nothing. It lasts for that one
// batch only. Every other assignment stays refused
// (TestTransactionControlRefused).
func TestAJobMayDeferForeignKeys(t *testing.T) {
	db := open(t, Options{})
	mustWrite(t, db, func(tx *Tx) error {
		_, err := tx.ExecContext(bg, `CREATE TABLE a (id TEXT PRIMARY KEY, b_id TEXT REFERENCES b (id)) STRICT;
			CREATE TABLE b (id TEXT PRIMARY KEY, a_id TEXT REFERENCES a (id)) STRICT`)
		return err
	})
	// The cycle, child first: refused without deferring.
	cycle := func(tx *Tx) error {
		_, err := tx.ExecContext(bg, `INSERT INTO a VALUES ('a1', 'b1'); INSERT INTO b VALUES ('b1', 'a1')`)
		return err
	}
	if err := db.Write(context.Background(), cycle); err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
		t.Fatalf("the cycle without deferring: %v", err)
	}
	mustWrite(t, db, func(tx *Tx) error {
		if _, err := tx.ExecContext(bg, `PRAGMA defer_foreign_keys = ON`); err != nil {
			return err
		}
		return cycle(tx)
	})
	var n int
	if err := db.Reader().QueryRowContext(bg, `SELECT (SELECT count(*) FROM a) + (SELECT count(*) FROM b)`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("the cycle deferred: %d rows, %v", n, err)
	}
	// Deferred and left unresolved: checked at the commit, nothing kept.
	err := db.Write(context.Background(), func(tx *Tx) error {
		if _, err := tx.ExecContext(bg, `PRAGMA defer_foreign_keys = 1`); err != nil {
			return err
		}
		_, err := tx.ExecContext(bg, `INSERT INTO a VALUES ('a2', 'nowhere')`)
		return err
	})
	if err == nil {
		t.Fatal("an unresolved foreign key committed")
	}
	if err := db.Reader().QueryRowContext(bg, `SELECT count(*) FROM a WHERE id = 'a2'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the refused batch kept %d rows, %v", n, err)
	}
	// The next batch checks at once again.
	if err := db.Write(context.Background(), func(tx *Tx) error {
		_, err := tx.ExecContext(bg, `INSERT INTO a VALUES ('a3', 'nowhere')`)
		return err
	}); err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
		t.Fatalf("deferring outlived its batch: %v", err)
	}
	for _, v := range []string{"ON", "on", "1", "true", "yes", "'on'"} {
		if !deferringForeignKeys("defer_foreign_keys", v) {
			t.Errorf("%q not allowed", v)
		}
	}
	for _, c := range [][2]string{{"defer_foreign_keys", "OFF"}, {"defer_foreign_keys", "0"}, {"foreign_keys", "ON"}, {"synchronous", "1"}} {
		if deferringForeignKeys(c[0], c[1]) {
			t.Errorf("%s = %s allowed", c[0], c[1])
		}
	}
}
