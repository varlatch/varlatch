// SPDX-License-Identifier: AGPL-3.0-or-later

package publictls_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/publictls"
)

// TestStoreIssuances: the count in the database: attempts begun and ended
// issued, or left started, count within the window, refused ones do not,
// other names do not; an attempt prunes those past 30 days.
func TestStoreIssuances(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := db.Init(ctx, store, "test"); err != nil {
		t.Fatal(err)
	}
	s := publictls.StoreIssuances{DB: store}
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	begin := func(name string, at time.Time, outcome string) {
		t.Helper()
		id, err := s.Begin(ctx, name, at)
		if err != nil {
			t.Fatal(err)
		}
		if outcome != "" {
			if err := s.End(ctx, id, outcome, at.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
	}
	begin("vault.varlatch.test", now.Add(-40*24*time.Hour), publictls.OutcomeIssued)
	begin("vault.varlatch.test", now.Add(-8*24*time.Hour), publictls.OutcomeIssued)
	begin("vault.varlatch.test", now.Add(-6*24*time.Hour), publictls.OutcomeIssued)
	begin("vault.varlatch.test", now.Add(-5*24*time.Hour), "")
	begin("vault.varlatch.test", now.Add(-4*24*time.Hour), publictls.OutcomeRefused)
	begin("other.varlatch.test", now.Add(-time.Hour), publictls.OutcomeIssued)
	n, oldest, err := s.Count(ctx, "vault.varlatch.test", now.Add(-publictls.IssuanceWindow))
	if err != nil || n != 2 || !oldest.Equal(now.Add(-6*24*time.Hour)) {
		t.Fatalf("count %d from %v, %v", n, oldest, err)
	}
	var kept int
	if err := store.Reader().QueryRowContext(ctx, "SELECT count(*) FROM certificate_issuances").Scan(&kept); err != nil || kept != 5 {
		t.Errorf("%d rows kept (%v): the one past 30 days is pruned", kept, err)
	}
	if n, oldest, err := s.Count(ctx, "nothing.varlatch.test", now.Add(-publictls.IssuanceWindow)); err != nil || n != 0 || !oldest.IsZero() {
		t.Errorf("no attempts: %d %v %v", n, oldest, err)
	}
}
