// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !g9a

package stages

import (
	"context"
	"testing"
	"unsafe"
)

// Outside the g9a build a mark holds nothing and costs nothing: Mark is
// empty (Start has nowhere to keep a clock reading) and the calls allocate
// nothing. The release build's request path keeps no instrumentation
// (go.yml's check of the varlatchd binary: no time.Now in the marked
// functions).
func TestMarksAreEmpty(t *testing.T) {
	if unsafe.Sizeof(Mark{}) != 0 || Start() != (Mark{}) {
		t.Fatal("Mark holds something")
	}
	ctx := context.Background()
	if n := testing.AllocsPerRun(100, func() {
		m := Start()
		Since(ctx, "snapshot", m)
		Admitted(ctx)
	}); n != 0 {
		t.Errorf("%v allocations", n)
	}
}
