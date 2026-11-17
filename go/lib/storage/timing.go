// SPDX-License-Identifier: Apache-2.0

package storage

import "time"

// JobTiming is how one write job spent its time outside its own code: the
// wait for the writer, and the COMMIT of the batch that held it (which
// holds the fsync); and what that batch wrote to the WAL.
type JobTiming struct {
	QueueWait time.Duration
	Commit    time.Duration
	// WALBytes is what the batch holding the job wrote to the WAL: its
	// pages (SQLite's SQLITE_DBSTATUS_CACHE_WRITE on the writer's
	// connection, every page written to the WAL in WAL mode) times a
	// frame's size (the page size and its 24-byte header). BatchJobs is
	// how many jobs that batch ran, the job among them: a batch's pages
	// cannot be divided between its jobs, so a job's share is an estimate
	// when BatchJobs > 1 and exact when it is 1.
	WALBytes  int64
	BatchJobs int
}
