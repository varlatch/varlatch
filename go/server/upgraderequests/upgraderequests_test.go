// SPDX-License-Identifier: AGPL-3.0-or-later

package upgraderequests

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/upgraderequest"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/write"
)

func newTestService(t *testing.T, now *time.Time) (*Service, *storage.DB) {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := db.Init(ctx, store, "test"); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		DataDir:   t.TempDir(),
		ConfigDir: t.TempDir(),
		Version:   "0.51.0",
		Writer:    &write.Writer{Store: store, Gates: write.NewGates()},
		Now:       func() time.Time { return *now },
	}
	return svc, store
}

func countExpiredEvents(t *testing.T, store *storage.DB, requestID string) int {
	t.Helper()
	var n int
	err := store.Reader().QueryRowContext(context.Background(),
		`SELECT count(*) FROM audit_events WHERE event_type = ? AND actor_identity_id IS NULL AND json_extract(metadata, '$.requestId') = ? AND json_extract(metadata, '$.reason') = 'expired'`,
		CancelledEvent, requestID).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// An expired request.json with no last.json is removed at its expiry and
// audited once (installation.upgrade_cancelled, reason expired).
func TestExpiredRequestWithoutLastIsRemovedAndAuditedOnce(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	svc, store := newTestService(t, &now)
	ctx := context.Background()

	id := "upr_" + strings.Repeat("a", 26)
	req := upgraderequest.NewRequest(id, "0.52.0", "idn_"+strings.Repeat("b", 26), now)
	if err := upgraderequest.WriteRequest(svc.DataDir, req); err != nil {
		t.Fatal(err)
	}

	// Still valid: stays in place, nothing audited.
	if err := svc.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	if r, err := upgraderequest.ReadRequest(svc.DataDir); err != nil || r == nil || r.ID != id {
		t.Fatalf("before expiry: %+v %v", r, err)
	}
	if n := countExpiredEvents(t, store, id); n != 0 {
		t.Fatalf("audited before expiry: %d", n)
	}

	// At expiry: removed and audited once across repeated passes.
	now = now.Add(upgraderequest.Lifetime)
	for range 2 {
		if err := svc.Pass(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if r, err := upgraderequest.ReadRequest(svc.DataDir); err != nil || r != nil {
		t.Fatalf("after expiry, request still there: %+v %v", r, err)
	}
	if _, err := os.Stat(filepath.Join(svc.dir(), lastFile)); !os.IsNotExist(err) {
		t.Fatalf("unexpected last.json: %v", err)
	}
	if n := countExpiredEvents(t, store, id); n != 1 {
		t.Fatalf("expected 1 expiry event, got %d", n)
	}
	if st, err := svc.Read(ctx); err != nil || st.State != "none" {
		t.Fatalf("state after expiry: %+v %v", st, err)
	}
}

// A stray expired request.json beside an earlier last.json for another
// request is removed and audited once without disturbing last.json.
func TestExpiredStrayRequestPreservesLast(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	svc, store := newTestService(t, &now)
	ctx := context.Background()

	prev := Last{
		ID:          "upr_" + strings.Repeat("a", 26),
		From:        "0.51.0",
		Version:     "0.52.0",
		RequestedBy: "idn_" + strings.Repeat("b", 26),
		RequestedAt: now.Format(upgraderequest.TimeLayout),
		ExpiresAt:   now.Add(upgraderequest.Lifetime).Format(upgraderequest.TimeLayout),
		Ended:       "cancelled",
	}
	if err := svc.writeLast(prev); err != nil {
		t.Fatal(err)
	}
	strayID := "upr_" + strings.Repeat("c", 26)
	stray := upgraderequest.NewRequest(strayID, "0.52.0", prev.RequestedBy, now)
	if err := upgraderequest.WriteRequest(svc.DataDir, stray); err != nil {
		t.Fatal(err)
	}

	now = now.Add(upgraderequest.Lifetime)
	if err := svc.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	if r, err := upgraderequest.ReadRequest(svc.DataDir); err != nil || r != nil {
		t.Fatalf("stray request not removed: %+v %v", r, err)
	}
	if n := countExpiredEvents(t, store, strayID); n != 1 {
		t.Fatalf("expected 1 expiry event for stray request, got %d", n)
	}
	if st, err := svc.Read(ctx); err != nil || st.State != "cancelled" || st.Request == nil || st.Request.ID != prev.ID {
		t.Fatalf("last.json disturbed: %+v %v", st, err)
	}
}

// With upgrade-request replaced by a symlink, Pass neither follows the link
// nor removes the target's request, records no bogus cancellation, warns
// once per file, and Read reports the records unreadable rather than
// interrupted.
func TestSymlinkedUpgradeRequestDirIsRefusedAndUntouched(t *testing.T) {
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	svc, store := newTestService(t, &now)
	var logged strings.Builder
	svc.Log = slog.New(slog.NewTextHandler(&logged, nil))
	ctx := context.Background()

	id := "upr_" + strings.Repeat("a", 26)
	req := upgraderequest.NewRequest(id, "0.52.0", "idn_"+strings.Repeat("b", 26), now)
	last := Last{
		ID:          id,
		From:        "0.51.0",
		Version:     "0.52.0",
		RequestedBy: req.RequestedBy,
		RequestedAt: req.RequestedAt,
		ExpiresAt:   req.ExpiresAt,
	}
	if err := svc.writeLast(last); err != nil {
		t.Fatal(err)
	}
	if err := upgraderequest.WriteRequest(svc.DataDir, req); err != nil {
		t.Fatal(err)
	}

	// Replace upgrade-request with a symlink to another directory holding
	// the files.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Rename(svc.dir(), elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, svc.dir()); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable on this Windows host: %v", err)
		}
		t.Fatal(err)
	}

	// Past expiry: target untouched, no cancellation audited, warnings logged
	// once, and Read reports unreadable records instead of interrupted.
	now = now.Add(upgraderequest.Lifetime + time.Minute)
	for range 3 {
		if err := svc.Pass(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(elsewhere, upgraderequest.RequestFile)); err != nil {
		t.Fatalf("target request.json was touched: %v", err)
	}
	rawLast, err := os.ReadFile(filepath.Join(elsewhere, lastFile))
	if err != nil {
		t.Fatalf("target last.json was touched: %v", err)
	}
	var gotLast Last
	if err := json.Unmarshal(rawLast, &gotLast); err != nil || gotLast.Ended != "" {
		t.Fatalf("target last.json changed: %+v %v", gotLast, err)
	}
	if n := countExpiredEvents(t, store, id); n != 0 {
		t.Fatalf("audited expiry through symlink: %d", n)
	}
	st, err := svc.Read(ctx)
	if err != nil || st.State != "waiting" || st.Request != nil ||
		!slices.Equal(st.Unreadable, []string{unreadableLast, unreadableStatus, unreadableRequest}) {
		t.Fatalf("state with symlinked dir: %+v %v", st, err)
	}
	if n := strings.Count(logged.String(), "cannot be read"); n != 3 {
		t.Fatalf("expected 3 warnings (once per record), got %d:\n%s", n, logged.String())
	}
}
