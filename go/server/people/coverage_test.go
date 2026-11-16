// SPDX-License-Identifier: AGPL-3.0-or-later

package people

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// The report's coverage while a backfill (copied from a TypeScript
// installation, step 7) is unfinished: from the first event after its
// cursor to the event it stops at. A Go installation starts finished
// (complete), as the fixtures' do.
func TestCoverageWhileTheBackfillRuns(t *testing.T) {
	ctx := context.Background()
	s, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := db.Init(ctx, s, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	if got := string(jsvalue.Stringify(must(backfillCoverage(ctx, s.Reader())))); got != `{"complete":true}` {
		t.Fatalf("a new installation: %s", got)
	}
	var events []audit.Recorded
	if err := s.Write(ctx, func(tx *storage.Tx) error {
		for range 3 {
			recorded, err := audit.Record(ctx, tx, audit.Event{Type: "installation.initialized", Decision: audit.Info})
			if err != nil {
				return err
			}
			events = append(events, recorded[0])
		}
		_, err := tx.ExecContext(ctx, `UPDATE exposure_backfill SET cursor = ?, until_order = ?, finished_at = NULL`, events[0].Position, events[2].Position)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	want := `{"complete":false,"from":"` + audit.ISOTime(events[1].OccurredAt) + `","to":"` + audit.ISOTime(events[2].OccurredAt) + `"}`
	if got := string(jsvalue.Stringify(must(backfillCoverage(ctx, s.Reader())))); got != want {
		t.Errorf("an unfinished backfill: %s, want %s", got, want)
	}
}

func must(v any, err error) any {
	if err != nil {
		panic(err)
	}
	return v
}
