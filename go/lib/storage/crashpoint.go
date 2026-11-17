// SPDX-License-Identifier: Apache-2.0

//go:build crashpoint

package storage

import (
	"context"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// Crash points for G7's kill tests (go test -tags crashpoint): a build with
// this tag, run with VARLATCH_CRASHPOINT_LOG set, appends one line per
// point the engine reaches (see crashpoint_off.go for the points) to that
// file, once armed: when VARLATCH_CRASHPOINT_ARM names a file, after it
// exists. Then:
//
//   - VARLATCH_CRASHPOINT_ARM_ON=<point>: the run arms itself when it
//     reaches that point (a named point of CrashPoint), so a pause at
//     "commit" pauses in the commit of the batch whose job reached it;
//   - VARLATCH_CRASHPOINT_PAUSE=<point>: the first time the point is reached
//     armed, the line "paused <point>" is written and the goroutine blocks
//     for good, so the test kills the process exactly there ("commit":
//     inside SQLite's commit of a write batch, before its WAL frames);
//   - VARLATCH_CRASHPOINT_BALLAST=<bytes>: once armed, one write job inserts
//     that many bytes (rows of 1 MiB), so that its batch takes long to write
//     to the WAL and the next checkpoint long to copy it. Its course is
//     logged as it happens: "ballast-start" before the job is queued,
//     "ballast-inserted" when the job's inserts are done (inside the
//     transaction), "ballast-commit" from the commit hook of its batch
//     (the commit begins; its remaining frames are not yet written),
//     "ballast-durable" when that COMMIT returned, and "ballast-committed"
//     when Write returned.
//
// A release has none of this: without the tag crashPoint does nothing.

var cp struct {
	log   *os.File
	arm   string
	armOn string
	pause string
	// armedOn is set once armOn was reached.
	armedOn atomic.Bool
	size    int64
	// ballast is the large batch's phase: 0 none, 1 queued, 2 inserted,
	// 3 its commit began, 4 its COMMIT returned.
	ballast atomic.Int32
	paused  atomic.Bool
}

func init() {
	path := os.Getenv("VARLATCH_CRASHPOINT_LOG")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		panic(err)
	}
	cp.log, cp.arm, cp.pause = f, os.Getenv("VARLATCH_CRASHPOINT_ARM"), os.Getenv("VARLATCH_CRASHPOINT_PAUSE")
	cp.armOn = os.Getenv("VARLATCH_CRASHPOINT_ARM_ON")
	cp.size, _ = strconv.ParseInt(os.Getenv("VARLATCH_CRASHPOINT_BALLAST"), 10, 64)
}

func armed() bool {
	if cp.armedOn.Load() {
		return true
	}
	if cp.arm == "" {
		return true
	}
	_, err := os.Stat(cp.arm)
	return err == nil
}

// mark writes one line: one write call, so lines never interleave.
func mark(line string) { _, _ = cp.log.Write([]byte(line + "\n")) }

func crashPoint(db *DB, point string) {
	if cp.log == nil {
		return
	}
	if point == "open" {
		if cp.size > 0 {
			go writeBallast(db)
		}
		return
	}
	if cp.armOn != "" && point == cp.armOn {
		cp.armedOn.Store(true)
	}
	if !armed() {
		return
	}
	mark(point)
	switch {
	case point == "commit" && cp.ballast.CompareAndSwap(2, 3):
		mark("ballast-commit")
	case point == "committed" && cp.ballast.CompareAndSwap(3, 4):
		mark("ballast-durable")
	}
	if point == cp.pause && cp.paused.CompareAndSwap(false, true) {
		mark("paused " + point)
		select {}
	}
}

func writeBallast(db *DB) {
	for !armed() {
		time.Sleep(10 * time.Millisecond)
	}
	ctx := context.Background()
	if err := db.Write(ctx, func(tx *Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS crashpoint_ballast (id INTEGER PRIMARY KEY, b BLOB NOT NULL) STRICT`)
		return err
	}); err != nil {
		mark("ballast-error " + err.Error())
		return
	}
	mark("ballast-start")
	cp.ballast.Store(1)
	err := db.Write(ctx, func(tx *Tx) error {
		for n := int64(0); n < cp.size; n += 1 << 20 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO crashpoint_ballast (b) VALUES (randomblob(1048576))`); err != nil {
				return err
			}
		}
		mark("ballast-inserted")
		cp.ballast.Store(2)
		return nil
	})
	if err != nil {
		mark("ballast-error " + err.Error())
		return
	}
	mark("ballast-committed")
}
