// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// RollbackWindowOpen is varlatch upgrade's question (decision 17, #368's
// endsRollbackWindow): open while the Go installation's journal is open or
// a reverse is under way; closed for an installation never migrated, or
// once --finish ended the window (or a reverse rolled it back).
func TestRollbackWindowOpen(t *testing.T) {
	dir := t.TempDir()
	if open, err := RollbackWindowOpen(dir); err != nil || open {
		t.Fatalf("no migration: %v %v", open, err)
	}
	for _, c := range []struct {
		phase Phase
		open  bool
	}{
		{Started, false}, {Transfer, false}, {Switched, false}, {Open, true}, {Rollback, true}, {RollbackChecked, true},
		{RollbackTransfer, true}, {RolledBack, false}, {Finished, false}, {Released, false},
	} {
		if err := writeJournal(dir, &Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: c.phase, History: []Step{}}); err != nil {
			t.Fatal(err)
		}
		if open, err := RollbackWindowOpen(dir); err != nil || open != c.open {
			t.Errorf("%s: %v %v, want %v", c.phase, open, err, c.open)
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
	switch j := strings.Join(args, " "); {
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
	c := &Compose{Directory: t.TempDir(), Run: run}
	started, err := c.ServeForArchive(context.Background())
	if err == nil || !slices.Equal(started, []string{"varlatchd"}) {
		t.Fatalf("a partial start: started %v, %v", started, err)
	}
	if err := c.StopStarted(context.Background(), started); err != nil || !slices.Equal(run.stopped, []string{"varlatchd"}) {
		t.Fatalf("stopped %v, %v", run.stopped, err)
	}
	// Everything running already: nothing started, nothing to stop.
	run = &archiveRunner{running: []string{"postgres", "varlatchd", "convex-backend"}}
	if started, err := (&Compose{Directory: t.TempDir(), Run: run}).ServeForArchive(context.Background()); err != nil || len(started) != 0 {
		t.Fatalf("all running: %v %v", started, err)
	}
}
