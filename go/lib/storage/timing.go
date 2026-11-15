// SPDX-License-Identifier: Apache-2.0

package storage

import "time"

// JobTiming is how one write job spent its time outside its own code: the
// wait for the writer, and the COMMIT of the batch that held it (which
// holds the fsync).
type JobTiming struct {
	QueueWait time.Duration
	Commit    time.Duration
}
