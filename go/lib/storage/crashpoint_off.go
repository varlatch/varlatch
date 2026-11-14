// SPDX-License-Identifier: Apache-2.0

//go:build !crashpoint

package storage

// crashPoint is where the engine tells a crash test which point it reached
// (crashpoint.go, a build with the crashpoint tag): "open" (Open is done),
// "commit" (inside SQLite's commit of a write batch, before its WAL frames
// are written), "committed" (the batch's COMMIT returned), "checkpoint" and
// "checkpointed" (around every checkpoint). In every other build it does
// nothing, and the compiler removes the calls.
func crashPoint(*DB, string) {}
