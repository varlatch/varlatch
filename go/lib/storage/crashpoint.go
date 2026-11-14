// SPDX-License-Identifier: Apache-2.0

//go:build crashpoint

package storage

import (
	"context"
	"os"
	"strconv"
	"time"
)

// Crash points for G7's kill tests (go test -tags crashpoint): a build with
// this tag, run with VARLATCH_CRASHPOINT_LOG set, appends one line per
// point the engine reaches (crashPoint in storage.go) to that file, once
// armed: when VARLATCH_CRASHPOINT_ARM names a file, after it exists. Then:
//
//   - VARLATCH_CRASHPOINT_PAUSE=<point>: the first time the point is reached
//     armed, the line "paused <point>" is written and the goroutine blocks
//     for good, so the test kills the process exactly there ("commit":
//     inside SQLite's commit of a write batch, before its WAL frames);
//   - VARLATCH_CRASHPOINT_BALLAST=<bytes>: once armed, one write job inserts
//     that many bytes (rows of 1 MiB), so that its batch takes long to write
//     to the WAL and the next checkpoint long to copy it; "ballast-start" and
//     "ballast-committed" bracket it.
//
// A release has none of this.
func init() {
	path := os.Getenv("VARLATCH_CRASHPOINT_LOG")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		panic(err)
	}
	arm := os.Getenv("VARLATCH_CRASHPOINT_ARM")
	pause := os.Getenv("VARLATCH_CRASHPOINT_PAUSE")
	ballast, _ := strconv.ParseInt(os.Getenv("VARLATCH_CRASHPOINT_BALLAST"), 10, 64)
	armed := func() bool {
		if arm == "" {
			return true
		}
		_, err := os.Stat(arm)
		return err == nil
	}
	write := func(line string) { _, _ = f.Write([]byte(line + "\n")) }
	paused := make(chan struct{}, 1)
	crashPoint = func(db *DB, point string) {
		if point == "open" {
			if ballast > 0 {
				go writeBallast(db, armed, ballast, write)
			}
			return
		}
		if !armed() {
			return
		}
		write(point)
		if point == pause {
			select {
			case paused <- struct{}{}:
				write("paused " + point)
				select {}
			default:
			}
		}
	}
}

func writeBallast(db *DB, armed func() bool, size int64, write func(string)) {
	for !armed() {
		time.Sleep(10 * time.Millisecond)
	}
	ctx := context.Background()
	if err := db.Write(ctx, func(tx *Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS crashpoint_ballast (id INTEGER PRIMARY KEY, b BLOB NOT NULL) STRICT`)
		return err
	}); err != nil {
		write("ballast-error " + err.Error())
		return
	}
	write("ballast-start")
	err := db.Write(ctx, func(tx *Tx) error {
		for n := int64(0); n < size; n += 1 << 20 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO crashpoint_ballast (b) VALUES (randomblob(1048576))`); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		write("ballast-error " + err.Error())
		return
	}
	write("ballast-committed")
}
