// SPDX-License-Identifier: Apache-2.0

//go:build linux

package upgrade

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	journal "github.com/varlatch/varlatch/go/lib/upgradejournal"
)

// An upgrade the web app asked for (ADR-0065 Decision 5) takes its snapshot
// with `admin backup run --json --verify-remote`: without a backup
// destination it is refused, and a failed upload fails it, both before
// varlatchd is stopped (the same process still serves), undone with nothing
// changed. OnStep hears the steps in order, the snapshot's before the stop.
func TestVerifyRemoteFailsBeforeTheStop(t *testing.T) {
	for _, c := range []struct {
		name, destination, said string
	}{
		{"no destination", "", "No backup destination is configured"},
		{"the upload fails", `{"offsite":{"endpoint":"http://127.0.0.1:1","region":"us-east-1","bucket":"b","writeCredentialsFile":"write.json"}}`, "connection refused"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHost(t)
			if c.destination != "" {
				dests := filepath.Join(h.dir, "keys", "destinations.json")
				credentials, _ := json.Marshal(map[string]string{"accessKeyId": "a", "secretAccessKey": "b"})
				if os.WriteFile(dests, []byte(c.destination), 0o600) != nil || os.WriteFile(filepath.Join(h.dir, "keys", "write.json"), credentials, 0o600) != nil {
					t.Fatal("cannot write the destination")
				}
				conf, _ := os.ReadFile(h.conf)
				if err := h.svc.Stop(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(h.conf, append(conf, []byte("backup_destinations_file = "+dests+"\n")...), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := h.svc.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				h.upgrader(nil).mustServe(t, fromVersion, fromSchema)
			}
			inst := h.inspect(t)
			serving := h.svc.cmd.Process.Pid
			u := h.upgrader(nil)
			u.VerifyRemote = true
			var steps []journal.Step
			u.OnStep = func(_ *journal.Journal, s journal.Step) { steps = append(steps, s) }
			j, err := u.Run(context.Background(), inst, h.release(t, "to", safe))
			if err == nil || !strings.Contains(err.Error(), "the pre-upgrade snapshot") || !strings.Contains(err.Error(), c.said) || !strings.Contains(err.Error(), "it was undone") {
				t.Fatalf("%v", err)
			}
			if !slices.Equal(steps, []journal.Step{journal.Verified}) || j.Reached(journal.Snapshot) {
				t.Fatalf("steps %v, journal %+v", steps, j)
			}
			if h.svc.cmd == nil || h.svc.cmd.Process.Pid != serving {
				t.Fatal("varlatchd was stopped")
			}
			previousServes(t, h, j)
		})
	}
}

// OnStep is told every step of a run, in order, each once it is recorded;
// at Snapshot varlatchd has not been stopped yet.
func TestOnStepHearsEveryStep(t *testing.T) {
	h := newHost(t)
	inst := h.inspect(t)
	u := h.upgrader(nil)
	var steps []journal.Step
	runningAtSnapshot := false
	u.OnStep = func(j *journal.Journal, s journal.Step) {
		if on, err := journal.Read(filepath.Dir(h.conf)); err != nil || on.Step != s || on.ID != j.ID {
			t.Errorf("at %s the journal says %+v, %v", s, on, err)
		}
		if s == journal.Snapshot {
			runningAtSnapshot = h.svc.cmd != nil
		}
		steps = append(steps, s)
	}
	j, err := u.Run(context.Background(), inst, h.release(t, "to", safe))
	if err != nil || j.State != journal.Done {
		t.Fatalf("%+v, %v", j, err)
	}
	if !slices.Equal(steps, journal.Steps) || !runningAtSnapshot {
		t.Fatalf("steps %v, running at the snapshot %v", steps, runningAtSnapshot)
	}
}
