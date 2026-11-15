// SPDX-License-Identifier: AGPL-3.0-or-later

package stages

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
)

// Without a Recorder the marks record nothing; with one, every stage and the
// storage engine's queue wait and commit of a write made with the context.
func TestStages(t *testing.T) {
	ctx := context.Background()
	Since(ctx, "snapshot", time.Now()) // no Recorder: nothing to record, no panic
	Admitted(ctx)

	h := NewHistogram()
	rctx := With(ctx, h, time.Now().Add(-3*time.Millisecond))
	Admitted(rctx)
	Since(rctx, "authorization", time.Now().Add(-time.Millisecond))
	Since(rctx, "authorization", time.Now().Add(-2*time.Millisecond))
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
	// A write without the context reports nothing.
	if err := store.Write(ctx, func(tx *storage.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
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
		if order[i] != s {
			t.Fatalf("stages %v, want %v", order, want)
		}
	}
	if a := got["admission"]; a.Count != 1 || a.P50Ms < 3 || a.P50Ms > 3.5 {
		t.Errorf("admission %+v", a)
	}
	if a := got["authorization"]; a.Count != 2 || a.P50Ms < 1 || a.P50Ms > 1.1 || a.MaxMs < 2 || a.MaxMs > 2.1 {
		t.Errorf("authorization %+v", a)
	}
	if c := got["commit"]; c.Count != 1 || c.MaxMs <= 0 {
		t.Errorf("commit %+v", c)
	}
}

// The buckets hold every time from under 100 ns to beyond 100 s, within 2 %.
func TestBuckets(t *testing.T) {
	for _, d := range []time.Duration{0, 50, 100, 101, time.Microsecond, 7 * time.Millisecond, time.Second, 99 * time.Second, time.Hour} {
		i := bucketOf(d)
		if i < 0 || i >= bucketCount {
			t.Fatalf("%v: bucket %d", d, i)
		}
		if d > bucketBase && d < 100*time.Second {
			if up := upper(i); up < d || float64(up) > float64(d)*1.0201 {
				t.Errorf("%v: bucket %d up to %v", d, i, up)
			}
		}
	}
}
