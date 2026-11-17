// SPDX-License-Identifier: AGPL-3.0-or-later

package paritytest

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
)

// A replay that starts a second before an hour ends runs in the next
// one, from its start; one with more than HourMargin left runs on the real
// clock. Either way two minutes later it is still in the hour it began in,
// two minutes on, and never before the real time it began.
func TestHourClockKeepsAReplayInOneHour(t *testing.T) {
	for _, start := range []time.Time{
		time.Date(2026, 11, 15, 22, 59, 59, 500_000_000, time.UTC),
		time.Date(2026, 11, 15, 22, 10, 0, 0, time.UTC),
	} {
		real := start
		clock := hourClock(func() time.Time { return real })
		first := clock()
		if first.Before(start) {
			t.Errorf("began at %v, before the real %v", first, start)
		}
		if start.Minute() == 59 && !first.Equal(time.Date(2026, 11, 15, 23, 0, 0, 0, time.UTC)) {
			t.Errorf("began at %v, not the next hour's start", first)
		}
		if start.Minute() == 10 && !first.Equal(start) {
			t.Errorf("began at %v, not the real %v", first, start)
		}
		real = real.Add(2 * time.Minute)
		later := clock()
		if later.Truncate(time.Hour) != first.Truncate(time.Hour) {
			t.Errorf("%v left the hour %v began in", later, first)
		}
		if d := later.Sub(first); d != 2*time.Minute {
			t.Errorf("%v elapsed, want 2m0s", d)
		}
	}
}

// A replay whose clock leaves the hour it began in fails, saying so,
// rather than splitting its report counts between two hours.
func TestHourOverrunFails(t *testing.T) {
	began := time.Date(2026, 11, 15, 22, 0, 0, 0, time.UTC)
	if err := hourOverrun(began, began.Add(59*time.Minute+59*time.Second)); err != nil {
		t.Errorf("within the hour: %v", err)
	}
	err := hourOverrun(began, began.Add(time.Hour))
	if err == nil || !strings.Contains(err.Error(), "ran into the next hour") {
		t.Errorf("past the hour: %v", err)
	}
}

// errors records a check's errors without failing the test.
type errors struct {
	testing.TB
	got []string
}

func (e *errors) Errorf(format string, args ...any) {
	e.got = append(e.got, fmt.Sprintf(format, args...))
}
func (e *errors) Helper() {}

// checkTimes checks every exposure time a request set: in a row it
// inserted, both times; in a row it changed, the time that changed, even
// before the request (a first time set too early), and nothing in a row
// it left alone.
func TestCheckTimesSeesEveryExposureTimeARequestSet(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := db.Init(ctx, store, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if err := store.Write(ctx, func(tx *storage.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
	exec(`INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'acme', 'Acme', '{}')`)
	row := func(version string, first, last int64) {
		exec(`INSERT INTO member_exposure (organization_id, identity_id, version_id, item_name, environment_id, way, first_at, last_at)
			VALUES ('org_a', 'idn_a', ?, 'S', 'env_a', 'written', ?, ?)
			ON CONFLICT (organization_id, identity_id, version_id, environment_id, way) DO UPDATE SET first_at = excluded.first_at, last_at = excluded.last_at`,
			version, first, last)
	}
	sent := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	done := sent.Add(time.Second)
	in, early := sent.Add(time.Millisecond).UnixMicro(), sent.Add(-time.Hour).UnixMicro()
	row("ver_untouched", early, early)
	row("ver_changed", early, early)
	before := exposureTimes(t, store)
	row("ver_new", in, in)          // inserted, both times in the request: fine
	row("ver_changed", early-1, in) // its first time moved, to before the request
	row("ver_new_early", early, in) // inserted with a first time before the request
	e := &errors{TB: t}
	checkTimes(e, "req", store, 1<<62, before, sent, done)
	if len(e.got) != 2 || !strings.Contains(strings.Join(e.got, "\n"), "ver_changed/env_a/written first_at") ||
		!strings.Contains(strings.Join(e.got, "\n"), "ver_new_early/env_a/written first_at") {
		t.Errorf("errors:\n%s", strings.Join(e.got, "\n"))
	}
}

// RecordedClock runs from the rows' last audit event, moved on by the
// time the replay takes on its wall clock, whatever date that says; and
// like HourClock it moves forward to the next hour with less than
// HourMargin of the recording's hour left.
func TestRecordedClock(t *testing.T) {
	rows := func(last string) map[string][]Row {
		return map[string][]Row{"audit_events": {{"occurred_at": "2026-11-16T09:00:00.000Z"}, {"occurred_at": last}, {"occurred_at": "2026-11-16T09:10:00.000Z"}}}
	}
	for _, c := range []struct {
		name, last string
		want       time.Time
	}{
		{"with the margin left", "2026-11-16T09:20:00.000Z", time.Date(2026, 11, 16, 9, 20, 0, 0, time.UTC)},
		{"too little of the hour left", "2026-11-16T09:40:00.000Z", time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)},
	} {
		t.Run(c.name, func(t *testing.T) {
			wall := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC) // a later date
			clock, err := RecordedClock(rows(c.last), func() time.Time { return wall })
			if err != nil {
				t.Fatal(err)
			}
			if got := clock(); !got.Equal(c.want) {
				t.Fatalf("at the start: %s, want %s", got, c.want)
			}
			wall = wall.Add(90 * time.Second)
			if got := clock(); !got.Equal(c.want.Add(90 * time.Second)) {
				t.Fatalf("90 s on: %s, want %s", got, c.want.Add(90*time.Second))
			}
		})
	}
	if _, err := RecordedClock(map[string][]Row{}, time.Now); err == nil {
		t.Fatal("rows without an audit event dated a recording")
	}
}
