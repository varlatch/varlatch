// SPDX-License-Identifier: Apache-2.0

//go:build !g9a

package storage

import (
	"sync/atomic"
	"testing"
	"unsafe"
)

// A release job is the size it was before the g9a build's timings: their
// state exists in that build only (timing_off.go).
func TestReleaseJobSize(t *testing.T) {
	type before struct {
		fn    func(*Tx) error
		guard CommitGuard
		done  chan error
		state atomic.Int32
	}
	if got, want := unsafe.Sizeof(job{}), unsafe.Sizeof(before{}); got != want {
		t.Errorf("job is %d bytes, %d without timings", got, want)
	}
}
