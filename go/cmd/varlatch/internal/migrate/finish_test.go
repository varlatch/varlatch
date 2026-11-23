// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

// RollbackWindowOpen is varlatch upgrade's question (decision 17, #368's
// endsRollbackWindow): open while the Go installation's journal is open,
// switched within RollbackWindow, and not ended by an upgrade; or while a
// reverse is under way. Closed for an installation never migrated, once
// --finish ended the window (or a reverse rolled it back), past 30 days,
// and once an upgrade recorded it ended.
func TestRollbackWindowOpen(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	if open, err := RollbackWindowOpen(dir, now); err != nil || open {
		t.Fatalf("no migration: %v %v", open, err)
	}
	switched := []Step{{Phase: Switched, At: now.Add(-24 * time.Hour).Format(time.RFC3339Nano)}}
	for _, c := range []struct {
		phase Phase
		open  bool
	}{
		{Started, false}, {Transfer, false}, {Switched, false}, {Open, true}, {Rollback, true}, {RollbackChecked, true},
		{RollbackTransfer, true}, {RolledBack, false}, {Finished, false}, {Released, false},
	} {
		if err := writeJournal(dir, &Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: c.phase, History: switched}); err != nil {
			t.Fatal(err)
		}
		if open, err := RollbackWindowOpen(dir, now); err != nil || open != c.open {
			t.Errorf("%s: %v %v, want %v", c.phase, open, err, c.open)
		}
	}
	for name, c := range map[string]struct {
		j    Journal
		open bool
	}{
		"no switch recorded":                  {Journal{Phase: Open, History: []Step{}}, false},
		"switched 30 days ago, to the second": {Journal{Phase: Open, History: []Step{{Phase: Switched, At: now.Add(-RollbackWindow).Format(time.RFC3339Nano)}}}, true},
		"switched 31 days ago":                {Journal{Phase: Open, History: []Step{{Phase: Switched, At: now.Add(-31 * 24 * time.Hour).Format(time.RFC3339Nano)}}}, false},
		"ended by an upgrade":                 {Journal{Phase: Open, History: switched, WindowEnded: &WindowEndedRecord{Release: "0.50.1", At: now.Format(time.RFC3339Nano)}}, false},
		"a reverse under way past 30 days":    {Journal{Phase: Rollback, History: []Step{{Phase: Switched, At: now.Add(-40 * 24 * time.Hour).Format(time.RFC3339Nano)}}}, true},
	} {
		c.j.Format, c.j.ID = 1, "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa"
		if err := writeJournal(dir, &c.j); err != nil {
			t.Fatal(err)
		}
		if open, err := RollbackWindowOpen(dir, now); err != nil || open != c.open {
			t.Errorf("%s: %v %v, want %v", name, open, err, c.open)
		}
	}
}

// archiveRunner is a Docker whose services start as up starts them: up
// fails part way, having started only the first service it was asked for;
// ps answers what runs.
type archiveRunner struct {
	running []string
	stopped []string
}

func (a *archiveRunner) Run(_ context.Context, _, _ string, args []string, _ []byte) (Ran, error) {
	for len(args) > 2 && args[0] == "compose" && (args[1] == "-f" || strings.HasPrefix(args[1], "--project-")) {
		args = append([]string{"compose"}, args[3:]...)
	}
	switch j := strings.Join(args, " "); {
	case strings.HasPrefix(j, "ps -a -q --no-trunc --filter label="):
		return Ran{}, nil
	case j == "compose ps --status running --services":
		return Ran{Answer: []byte(strings.Join(a.running, "\n") + "\n")}, nil
	case j == "compose config --no-interpolate --format json":
		return Ran{Answer: []byte(`{"name":"varlatch","services":{"varlatchd":{}}}`)}, nil
	case strings.HasPrefix(j, "compose up -d --no-deps --no-recreate "):
		a.running = append(a.running, args[5])
		return Ran{Code: 1, Said: []byte("dependency failed to start")}, nil
	case strings.HasPrefix(j, "compose stop "):
		a.stopped = append(a.stopped, args[2:]...)
		return Ran{}, nil
	}
	return Ran{Code: 1, Said: []byte("unexpected " + strings.Join(args, " "))}, nil
}

// A start for the final archive that failed part way names what it did
// start (running now, not before), so that is stopped again; what ran
// before is never named.
func TestServeForArchiveAPartialStart(t *testing.T) {
	run := &archiveRunner{running: []string{"postgres"}}
	c := stockCompose(t, run)
	started, err := c.ServeForArchive(context.Background())
	if err == nil || !slices.Equal(started, []string{"varlatchd"}) {
		t.Fatalf("a partial start: started %v, %v", started, err)
	}
	if err := c.StopStarted(context.Background(), started); err != nil || !slices.Equal(run.stopped, []string{"varlatchd"}) {
		t.Fatalf("stopped %v, %v", run.stopped, err)
	}
	// Everything running already: nothing started, nothing to stop.
	run = &archiveRunner{running: []string{"postgres", "varlatchd", "convex-backend"}}
	if started, err := stockCompose(t, run).ServeForArchive(context.Background()); err != nil || len(started) != 0 {
		t.Fatalf("all running: %v %v", started, err)
	}
}
