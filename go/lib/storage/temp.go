// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync/atomic"
)

// SQLite's temporary files: a job's savepoint or statement journal once it
// is past 64 KiB (16 pages changed), a sort or a subquery's result larger
// than the cache, VACUUM's copy. With nowhere to put one, the statement that
// needs it fails with SQLITE_IOERR_GETTEMPPATH (6410), and only that one:
// small writes go on, so an installation with a read-only root filesystem
// and no writable temporary directory looks healthy until its first larger
// write.
//
// They go to a directory, not to memory (PRAGMA temp_store = MEMORY, which
// the driver honours too): in memory, what they hold counts against
// varlatchd's own memory, without a bound, at the moment it already holds
// the large write or sort that needed them. Measured on one workload (a
// sort, a 20,000 row update and VACUUM), the peak was 307 MB in memory
// against 150 MB in a directory.

// envTempDir is the variable SQLite asks first.
const envTempDir = "SQLITE_TMPDIR"

// PrepareTemp sees to it that SQLite has a directory for its temporary
// files, and returns it: the first one SQLite itself would use when that is
// writable (SQLITE_TMPDIR, TMPDIR, /var/tmp, /usr/tmp, /tmp), otherwise dir,
// which is the data directory, by setting SQLITE_TMPDIR in this process's
// environment. SQLite reads the variable once, when the process opens its
// first database: PrepareTemp comes before that, and Open calls it with the
// database's own directory for a process that did not. Open proves that a
// temporary file can be written all the same.
//
// A temporary file is mode 0600 and has no name in the directory (O_TMPFILE,
// or unlinked as soon as it is open), so nothing of it stays there.
func PrepareTemp(dir string) (string, error) {
	return prepareTemp(dir, os.Getenv, os.Setenv, usableTemp)
}

func prepareTemp(dir string, env func(string) string, setenv func(string, string) error, usable func(string) bool) (string, error) {
	if !tempFromEnvironment {
		return "", nil
	}
	for _, d := range []string{env(envTempDir), env("TMPDIR"), "/var/tmp", "/usr/tmp", "/tmp"} {
		if d != "" && usable(d) {
			return d, nil
		}
	}
	if dir != "" && usable(dir) {
		return dir, setenv(envTempDir, dir)
	}
	return "", noTemp(dir)
}

func noTemp(dir string) error {
	return fmt.Errorf("SQLite has no directory for its temporary files, so a larger write or read would fail: none of %s, TMPDIR, /var/tmp, /usr/tmp, /tmp and %s is a directory this user can write; set %s to one that is", envTempDir, dir, envTempDir)
}

// tempProven is set once this process has written an SQLite temporary file.
var tempProven atomic.Bool

// tempProof sorts 4 MiB, more than SQLite sorts in memory (1 MiB with this
// cache size), so its answer needs a temporary file. It takes a few
// milliseconds.
const (
	tempProofCache = "PRAGMA cache_size = 1"
	tempProof      = "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM c WHERE n < 64) SELECT zeroblob(65536) || n AS x FROM c ORDER BY x DESC"
)

// proveTemp writes one SQLite temporary file, on a connection of its own:
// what PrepareTemp found is what SQLite really uses, and a file can be
// written there.
func proveTemp(ctx context.Context, dir string) error {
	if tempProven.Load() {
		return nil
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, tempProofCache); err != nil {
		return err
	}
	var first []byte
	switch err := db.QueryRowContext(ctx, tempProof).Scan(&first); {
	case err != nil && ctx.Err() != nil:
		return err
	case err != nil:
		return fmt.Errorf("%w (%v)", noTemp(dir), err)
	}
	tempProven.Store(true)
	return nil
}
