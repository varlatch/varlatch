// SPDX-License-Identifier: AGPL-3.0-or-later

package write

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
)

// The gate tracer: the counterpart of the TypeScript server's lock-trace
// harness (test/helpers/lock-trace.ts). Two mistakes would let gates
// deadlock or stall the writer, and Acquire refuses both with an
// *OrderError:
//
//   - a gate that comes before one the caller already holds (the order is
//     Level, then name, then key; Acquire takes a set of gates in order by
//     itself, so this only happens across two Acquire calls);
//   - a gate taken inside a write job: the job runs on the writer, which
//     would then wait for a gate while every other job waits for it.
//
// The order check runs always (it is a comparison). The job check reads
// the goroutine's stack, so it runs in test binaries only (every go test
// of a package that writes), never in a release.

// tracing is whether the job check runs: in any test binary.
var tracing = testing.Testing()

// OrderError is a gate taken out of order or inside a write job.
type OrderError struct {
	Gate  Gate
	After *Gate // the held gate it does not come after, if any
	InJob bool
}

func (e *OrderError) Error() string {
	if e.InJob {
		return fmt.Sprintf("write: gate %s taken inside a write job: gates are taken before the job is queued", e.Gate)
	}
	return fmt.Sprintf("write: gate %s taken after %s, out of the order (level, name, key)", e.Gate, e.After)
}

// jobFrame is the storage engine's function every write job runs under.
var jobFrame = []byte("varlatch/go/lib/storage.runJob(")

func checkOrder(already held, want []Gate) error {
	if tracing && inJob() {
		return &OrderError{Gate: want[0], InJob: true}
	}
	if len(already) == 0 {
		return nil
	}
	last := already[len(already)-1]
	for _, h := range already {
		if compare(h, last) > 0 {
			last = h
		}
	}
	if compare(want[0], last) <= 0 {
		return &OrderError{Gate: want[0], After: &last}
	}
	return nil
}

// inJob reports whether the calling goroutine is running a write job.
func inJob() bool {
	buf := make([]byte, 64<<10)
	n := runtime.Stack(buf, false)
	return bytes.Contains(buf[:n], jobFrame)
}
