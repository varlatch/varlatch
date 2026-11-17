// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// stmtStats returns the read pool's statement counts.
func stmtStats(db *DB) (prepared, reused, oneOff int64) {
	s := &db.rconn.stats
	return s.prepared.Load(), s.reused.Load(), s.oneOff.Load()
}

// A query the read pool runs again reuses its prepared statement, on the
// pool and in read transactions, and answers as a fresh one would.
func TestReaderKeepsStatementsPrepared(t *testing.T) {
	db := open(t, Options{ReadConns: 1})
	for i := range 3 {
		mustWrite(t, db, insert(fmt.Sprint("n", i)))
	}
	p0, r0, _ := stmtStats(db)
	for i := range 20 {
		if n := count(t, db, "WHERE name = ?", fmt.Sprint("n", i%3)); n != 1 {
			t.Fatalf("count: %d", n)
		}
		tx, err := db.Reader().BeginTx(bg, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		var name string
		if err := tx.QueryRowContext(bg, `SELECT name FROM item WHERE id = ?`, i%3+1).Scan(&name); err != nil || name != fmt.Sprint("n", i%3) {
			t.Fatalf("in a transaction: %q %v", name, err)
		}
		_ = tx.Rollback()
	}
	p, r, _ := stmtStats(db)
	if p-p0 != 2 || r-r0 != 38 {
		t.Errorf("40 queries of 2 statements on one connection: %d prepared, %d reused; want 2 and 38", p-p0, r-r0)
	}
}

// The same query run again while its rows are open runs as a one-off
// statement, and both read their own rows to the end.
func TestReaderStatementInUse(t *testing.T) {
	db := open(t, Options{ReadConns: 1})
	for i := range 5 {
		mustWrite(t, db, insert(fmt.Sprint("n", i)))
	}
	const q = `SELECT id, name FROM item WHERE id >= ? ORDER BY id`
	tx, err := db.Reader().BeginTx(bg, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	outer, err := tx.QueryContext(bg, q, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, _, o0 := stmtStats(db)
	var pairs []string
	for outer.Next() {
		var id int
		var name string
		if err := outer.Scan(&id, &name); err != nil {
			t.Fatal(err)
		}
		inner, err := tx.QueryContext(bg, q, id)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for inner.Next() {
			n++
		}
		if err := inner.Close(); err != nil {
			t.Fatal(err)
		}
		pairs = append(pairs, fmt.Sprintf("%s:%d", name, n))
	}
	if err := outer.Err(); err != nil {
		t.Fatal(err)
	}
	outer.Close()
	if got := fmt.Sprint(pairs); got != "[n0:5 n1:4 n2:3 n3:2 n4:1]" {
		t.Errorf("rows: %s", got)
	}
	if _, _, o := stmtStats(db); o-o0 != 5 {
		t.Errorf("%d one-off statements while the cached one was busy, want 5", o-o0)
	}
	// Idle again: the next run reuses it.
	_, r0, _ := stmtStats(db)
	var n int
	if err := tx.QueryRowContext(bg, `SELECT count(*) FROM (`+q+`)`, 1).Scan(&n); err != nil || n != 5 {
		t.Fatal(n, err)
	}
	rows, err := tx.QueryContext(bg, q, 3)
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if _, r, _ := stmtStats(db); r-r0 != 1 {
		t.Errorf("the idle statement was not reused: %d", r-r0)
	}
}

// A cancelled query and an error leave the cached statement usable.
func TestReaderStatementAfterCancelAndError(t *testing.T) {
	db := open(t, Options{ReadConns: 1})
	for i := range 50 {
		mustWrite(t, db, insert(fmt.Sprint("n", i)))
	}
	const q = `SELECT name FROM item ORDER BY id`
	ctx, cancel := context.WithCancel(bg)
	rows, err := db.Reader().QueryContext(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	rows.Next()
	cancel()
	for rows.Next() {
	}
	rows.Close()
	// An argument SQLite cannot take fails the query, not the statement.
	if _, err := db.Reader().QueryContext(bg, `SELECT name FROM item WHERE id = ?`, struct{}{}); err == nil {
		t.Fatal("a struct argument was accepted")
	}
	for range 3 {
		got, err := db.Reader().QueryContext(bg, q)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for got.Next() {
			n++
		}
		if err := errors.Join(got.Err(), got.Close()); err != nil || n != 50 {
			t.Fatalf("after the cancel: %d rows, %v", n, err)
		}
	}
}

// Past the cache's size the least recently used statements go, and every
// query still answers.
func TestReaderStatementCacheBounded(t *testing.T) {
	db := open(t, Options{ReadConns: 1})
	mustWrite(t, db, insert("a"))
	for i := range readerStmtCacheSize + 40 {
		var n int
		if err := db.Reader().QueryRowContext(bg, fmt.Sprintf(`SELECT count(*) + %d FROM item`, i)).Scan(&n); err != nil || n != i+1 {
			t.Fatalf("query %d: %d %v", i, n, err)
		}
	}
	conn, err := db.Reader().Conn(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Raw(func(dc any) error {
		c := dc.(*cachingConn)
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.lru.Len() != readerStmtCacheSize || len(c.byQuery) != readerStmtCacheSize {
			return fmt.Errorf("%d statements cached (%d by query), want %d", c.lru.Len(), len(c.byQuery), readerStmtCacheSize)
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}

// The cache never holds more than its size, even with every slot's rows
// open: 256 distinct queries open at once on one connection cache 128
// and run the rest as one-off statements; once their rows closed, the
// same 256 queries again keep the cache at 128.
func TestReaderStatementCacheBoundedWhileBusy(t *testing.T) {
	db := open(t, Options{ReadConns: 1})
	mustWrite(t, db, insert("a"))
	conn, err := db.Reader().Conn(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cached := func() (n int) {
		t.Helper()
		if err := conn.Raw(func(dc any) error {
			c := dc.(*cachingConn)
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.lru.Len() != len(c.byQuery) {
				return fmt.Errorf("%d listed, %d by query", c.lru.Len(), len(c.byQuery))
			}
			n = c.lru.Len()
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	const queries = 2 * readerStmtCacheSize
	q := func(i int) string { return fmt.Sprintf(`SELECT %d, name FROM item`, i) }
	_, _, o0 := stmtStats(db)
	var open []*sql.Rows
	// On a failure, the rows close before the connection (Close waits for
	// open rows).
	defer func() {
		for _, rows := range open {
			_ = rows.Close()
		}
	}()
	for i := range queries {
		rows, err := conn.QueryContext(bg, q(i))
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, rows)
		if n := cached(); n > readerStmtCacheSize {
			t.Fatalf("after %d queries with their rows open: %d statements cached", i+1, n)
		}
	}
	if _, _, o := stmtStats(db); o-o0 != queries-readerStmtCacheSize {
		t.Errorf("%d one-off statements with every slot in use, want %d", o-o0, queries-readerStmtCacheSize)
	}
	for i, rows := range open {
		var n int
		var name string
		if !rows.Next() {
			t.Fatalf("query %d: no row", i)
		}
		if err := rows.Scan(&n, &name); err != nil || n != i || name != "a" {
			t.Fatalf("query %d: %d %q %v", i, n, name, err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if n := cached(); n != readerStmtCacheSize {
		t.Errorf("after the rows closed: %d statements cached, want %d", n, readerStmtCacheSize)
	}
	// Reused, and queries the cache did not hold pushing older ones out:
	// never above the size.
	for range 2 {
		for i := range queries {
			var n int
			var name string
			if err := conn.QueryRowContext(bg, q(i)).Scan(&n, &name); err != nil || n != i {
				t.Fatalf("query %d again: %d %v", i, n, err)
			}
			if c := cached(); c > readerStmtCacheSize {
				t.Fatalf("query %d again: %d statements cached", i, c)
			}
		}
	}
	// Every statement that left the cache was finalized.
	prepared, _, _ := stmtStats(db)
	if closed := db.rconn.stats.closed.Load(); prepared-closed != int64(cached()) {
		t.Errorf("%d prepared, %d closed, %d cached", prepared, closed, cached())
	}
}

// A schema change by the writer, as a migration makes, reaches every
// statement the readers keep: SQLite checks the schema each time a
// statement starts and compiles it again when it changed, so no cached
// statement answers from the old schema.
func TestReaderStatementSeesSchemaChange(t *testing.T) {
	db := open(t, Options{ReadConns: 2})
	mustWrite(t, db, insert("a"))
	migrate := func(stmts ...string) {
		t.Helper()
		mustWrite(t, db, func(tx *Tx) error {
			for _, q := range stmts {
				if _, err := tx.ExecContext(bg, q); err != nil {
					return err
				}
			}
			return nil
		})
	}
	// read runs q on every reader connection at once (each has its own
	// cache) and returns the column names and the first row.
	read := func(q string) (cols []string, row []any, err error) {
		t.Helper()
		tx, err := db.Reader().BeginTx(bg, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		other, err := db.Reader().BeginTx(bg, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		defer other.Rollback()
		for _, x := range []*sql.Tx{other, tx} {
			rows, qerr := x.QueryContext(bg, q)
			if qerr != nil {
				return nil, nil, qerr
			}
			cols, _ = rows.Columns()
			row = make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range row {
				ptrs[i] = &row[i]
			}
			if rows.Next() {
				err = rows.Scan(ptrs...)
			}
			err = errors.Join(err, rows.Err(), rows.Close())
		}
		return cols, row, err
	}
	const all = `SELECT * FROM item ORDER BY id`
	if c, _, err := read(all); err != nil || len(c) != 3 {
		t.Fatalf("before: %v %v", c, err)
	}
	p0, _, _ := stmtStats(db)

	// A column added.
	migrate(`ALTER TABLE item ADD COLUMN extra TEXT NOT NULL DEFAULT 'x'`)
	if c, r, err := read(all); err != nil || len(c) != 4 || c[3] != "extra" || r[3] != "x" {
		t.Errorf("after ADD COLUMN: %v %v %v", c, r, err)
	}
	// A column renamed: a statement naming the old name now fails, one
	// naming the new name works.
	const byName = `SELECT name FROM item ORDER BY id`
	if _, r, err := read(byName); err != nil || r[0] != "a" {
		t.Fatalf("before RENAME: %v %v", r, err)
	}
	migrate(`ALTER TABLE item RENAME COLUMN name TO label`)
	if _, _, err := read(byName); err == nil || !strings.Contains(err.Error(), "no such column") {
		t.Errorf("a cached statement over a renamed column: %v", err)
	}
	if _, r, err := read(`SELECT label FROM item ORDER BY id`); err != nil || r[0] != "a" {
		t.Errorf("the renamed column: %v %v", r, err)
	}
	// The table rebuilt, as SQLite migrations do (new table, copy, drop,
	// rename): the cached SELECT * reads the new table's columns and rows.
	migrate(
		`CREATE TABLE item_new (id INTEGER PRIMARY KEY, label TEXT NOT NULL UNIQUE, n INTEGER NOT NULL) STRICT`,
		`INSERT INTO item_new (id, label, n) SELECT id, label || '-v2', 7 FROM item`,
		`DROP TABLE item`,
		`ALTER TABLE item_new RENAME TO item`,
	)
	if c, r, err := read(all); err != nil || fmt.Sprint(c) != "[id label n]" || r[1] != "a-v2" || r[2] != int64(7) {
		t.Errorf("after the rebuild: %v %v %v", c, r, err)
	}
	// The table dropped: the cached statement fails; recreated, it works.
	migrate(`DROP TABLE item`)
	if _, _, err := read(all); err == nil || !strings.Contains(err.Error(), "no such table") {
		t.Errorf("a cached statement over a dropped table: %v", err)
	}
	migrate(`CREATE TABLE item (id INTEGER PRIMARY KEY, z TEXT) STRICT`, `INSERT INTO item (z) VALUES ('z')`)
	if c, r, err := read(all); err != nil || fmt.Sprint(c) != "[id z]" || r[1] != "z" {
		t.Errorf("after the table came back: %v %v %v", c, r, err)
	}
	// SELECT * was kept prepared throughout: no new statement for it.
	if p, _, _ := stmtStats(db); p-p0 > 6 {
		t.Errorf("%d statements prepared across the migrations", p-p0)
	}
}

// A statement the readers keep holds no read transaction once its rows
// closed: a TRUNCATE checkpoint empties the WAL right after cached reads.
func TestReaderStatementsHoldNoCheckpointOff(t *testing.T) {
	log := &checkpointLog{}
	db := open(t, Options{ReadConns: 2, OnCheckpoint: log.add})
	for i := range 100 {
		mustWrite(t, db, insert(fmt.Sprint("n", i)))
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 50 {
				var n int
				if err := db.Reader().QueryRowContext(bg, `SELECT count(*) FROM item WHERE name = ?`, fmt.Sprint("n", i)).Scan(&n); err != nil {
					t.Error(err)
					return
				}
				rows, err := db.Reader().QueryContext(bg, `SELECT id FROM item ORDER BY id LIMIT 3`)
				if err != nil {
					t.Error(err)
					return
				}
				rows.Next() // closed before the end
				rows.Close()
			}
		}()
	}
	wg.Wait()
	db.ckptMu.Lock()
	r, err := db.checkpointLocked(bg, "TRUNCATE", TriggerSize)
	db.ckptMu.Unlock()
	if err != nil || r.Busy || db.walSize() != 0 {
		t.Errorf("TRUNCATE after cached reads: %+v %v, WAL %d bytes", r, err, db.walSize())
	}
}

// Closing the database finalizes every statement the readers kept, those
// pushed out of a cache before included, and closes every connection.
func TestReaderStatementsClosedWithTheDB(t *testing.T) {
	db := open(t, Options{ReadConns: 4})
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range readerStmtCacheSize + 20 {
				var n int
				if err := db.Reader().QueryRowContext(bg, fmt.Sprintf(`SELECT count(*) + %d FROM item`, i%(readerStmtCacheSize/2+g*20))).Scan(&n); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	prepared, _, _ := stmtStats(db)
	if closed := db.rconn.stats.closed.Load(); prepared == 0 || closed != prepared {
		t.Errorf("%d statements prepared into the caches, %d closed", prepared, closed)
	}
	if open := db.Reader().Stats().OpenConnections; open != 0 {
		t.Errorf("%d reader connections still open", open)
	}
	if _, err := db.Reader().QueryContext(bg, `SELECT 1`); err == nil {
		t.Error("a query after Close succeeded")
	}
}

// The cost a cached statement saves: a read transaction running one
// query with a join, a subquery and a sort, as the server's grant reads
// do, prepared every time (no cache) and kept prepared.
func BenchmarkReaderQuery(b *testing.B) {
	const q = `SELECT a.id, a.name, (SELECT count(*) FROM item c WHERE c.id < a.id) AS before
		FROM item a JOIN item b ON b.id = a.id
		WHERE a.name >= ? AND b.name IS NOT NULL
		ORDER BY a.name LIMIT 10`
	for _, c := range []struct {
		name string
		size int
	}{{"prepared each time", 0}, {"kept prepared", readerStmtCacheSize}} {
		b.Run(c.name, func(b *testing.B) {
			db, err := Open(bg, Options{Path: b.TempDir() + "/b.db", ReadConns: 1})
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			db.rconn.size = c.size
			if err := db.Write(bg, func(tx *Tx) error {
				if _, err := tx.ExecContext(bg, `CREATE TABLE item (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE) STRICT`); err != nil {
					return err
				}
				for i := range 100 {
					if _, err := tx.ExecContext(bg, `INSERT INTO item (name) VALUES (?)`, fmt.Sprintf("n%03d", i)); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for b.Loop() {
				tx, err := db.Reader().BeginTx(bg, &sql.TxOptions{ReadOnly: true})
				if err != nil {
					b.Fatal(err)
				}
				rows, err := tx.QueryContext(bg, q, "n050")
				if err != nil {
					b.Fatal(err)
				}
				for rows.Next() {
				}
				rows.Close()
				_ = tx.Rollback()
			}
		})
	}
}
