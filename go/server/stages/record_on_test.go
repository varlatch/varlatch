// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g9a

package stages

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
)

// A request's stages are summed and handed over once, at Flush: two
// authorization decisions are one sample; the storage engine's queue wait
// and commit of a write made with the request's context count too. Without
// a Recorder nothing is recorded.
func TestStages(t *testing.T) {
	ctx := context.Background()
	Since(ctx, "snapshot", Start())
	Admitted(ctx)
	Flush(ctx)

	h := NewHistogram()
	rctx := With(ctx, h, time.Now().Add(-3*time.Millisecond))
	Admitted(rctx)
	Since(rctx, "authorization", Mark{time.Now().Add(-time.Millisecond)})
	Since(rctx, "authorization", Mark{time.Now().Add(-2 * time.Millisecond)})
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "s.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Write(rctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(rctx, "CREATE TABLE x (a INTEGER) STRICT")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(ctx, func(*storage.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(h.Summaries()) != 0 {
		t.Fatal("recorded before Flush")
	}
	Flush(rctx)
	Flush(rctx) // once
	got := map[string]Summary{}
	var order []string
	for _, s := range h.Summaries() {
		got[s.Stage] = s
		order = append(order, s.Stage)
	}
	want := []string{"admission", "authorization", "queue", "commit"}
	if len(order) != len(want) {
		t.Fatalf("stages %v", order)
	}
	for i, s := range want {
		if order[i] != s || got[s].Count != 1 {
			t.Fatalf("stages %v %+v", order, got)
		}
	}
	if a := got["admission"]; a.P50Ms < 3 || a.P50Ms > 3.5 {
		t.Errorf("admission %+v", a)
	}
	if a := got["authorization"]; a.P50Ms < 3 || a.P50Ms > 3.2 {
		t.Errorf("authorization, summed: %+v", a)
	}
	if c := got["commit"]; c.MaxMs <= 0 {
		t.Errorf("commit %+v", c)
	}
}
