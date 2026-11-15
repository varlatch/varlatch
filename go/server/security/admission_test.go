// SPDX-License-Identifier: AGPL-3.0-or-later

package security_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/security"
)

// The report loop's passes enter the maintenance admission, as
// startSecurityReportLoop's do: while a gate is open a pass writes
// nothing, and one admitted is counted until it has written.
func TestRunLoopEntersMaintenanceAdmission(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 10, 20, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	if err := wd.store.Write(ctx, func(tx *storage.Tx) error {
		return security.CountWouldBlock(ctx, tx, wd.org, []security.WouldBlock{{Control: "admin-step-up", ConfigVersion: 1, Operation: "grant.create", ActorIdentityID: "idn_a", Reason: "no-approval"}}, now.UnixMicro(), clock)
	}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	summaries := func() int {
		return len(paritytest.Rows(t, wd.store, `SELECT id FROM audit_events WHERE event_type = 'security_control.would_block'`))
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	run := func(admit func() (func(), bool)) {
		loopCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); security.RunLoop(loopCtx, wd.w, time.Hour, clock, log, admit) }()
		// The first pass runs at once; the next would be an hour later.
		time.Sleep(200 * time.Millisecond)
		cancel()
		<-done
	}

	var mu sync.Mutex
	asked, left := 0, 0
	run(func() (func(), bool) { mu.Lock(); asked++; mu.Unlock(); return nil, false })
	if asked != 1 || summaries() != 0 {
		t.Fatalf("during maintenance: asked %d, %d summaries", asked, summaries())
	}
	var during int
	run(func() (func(), bool) {
		return func() { mu.Lock(); during = summaries(); left++; mu.Unlock() }, true
	})
	if left != 1 || during != 1 || summaries() != 1 {
		t.Fatalf("admitted: left %d, %d summaries when it left, %d after", left, during, summaries())
	}
}
