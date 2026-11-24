// SPDX-License-Identifier: Apache-2.0

package upgradejournal

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestJournal(t *testing.T) {
	dir := t.TempDir()
	if j, err := Read(dir); j != nil || err != nil || j.Pending() {
		t.Fatalf("no journal: %+v, %v", j, err)
	}
	j := &Journal{ID: "0011223344556677", From: "0.50.0-rc.1", To: "0.50.0-rc.2", FromSchema: 1, ToSchema: 2, State: InProgress, Step: Snapshot}
	if err := Write(dir, j); err != nil {
		t.Fatal(err)
	}
	// Windows has no Unix permission bits: a file there reads back 0666.
	if info, err := os.Stat(filepath.Join(dir, File)); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o644) {
		t.Fatalf("mode: %v, %v", info, err)
	}
	back, err := Read(dir)
	if err != nil || back.ID != j.ID || back.Format != Format || !back.Pending() || back.Step != Snapshot {
		t.Fatalf("read back: %+v, %v", back, err)
	}
	for _, c := range []struct {
		step Step
		want bool
	}{{None, true}, {Verified, true}, {Snapshot, true}, {Stopped, false}, {Checked, false}} {
		if back.Reached(c.step) != c.want {
			t.Errorf("at %q, reached %q: %v", back.Step, c.step, !c.want)
		}
	}
	for _, s := range []State{Done, Undone} {
		j.State = s
		if err := Write(dir, j); err != nil {
			t.Fatal(err)
		}
		if back, _ := Read(dir); back.Pending() {
			t.Fatalf("%s is not pending", s)
		}
	}
	j.State = Failed
	_ = Write(dir, j)
	if back, _ := Read(dir); !back.Pending() {
		t.Fatal("a failed undo is pending")
	}
}

func TestJournalRefuses(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ body, want string }{
		{`{"format":3,"id":"x","from":"0.50.0","to":"0.50.1","state":"done","step":""}`, "format 3"},
		{`{"format":1,"id":"x","from":"0.50.0","to":"0.50.1","state":"done","step":"","undo":"files-back"}`, "a later format"},
		{`{"format":1,"id":"x","from":"0.50.0","to":"0.50.1","state":"in-progress","step":"kept"}`, "a later format"},
		{`{"format":2,"id":"x","from":"0.50.0","to":"0.50.1","state":"done","step":"","undo":"x"}`, `undo "x"`},
		{`{"format":1,"id":"","from":"0.50.0","to":"0.50.1","state":"done","step":""}`, "no upgrade id"},
		{`{"format":1,"id":"x","from":"0.50","to":"0.50.1","state":"done","step":""}`, "no release version"},
		{`{"format":1,"id":"x","from":"0.50.0","to":"0.50.1","state":"paused","step":""}`, `state "paused"`},
		{`{"format":1,"id":"x","from":"0.50.0","to":"0.50.1","state":"done","step":"later"}`, `step "later"`},
		{`{"format":1,"id":"x","from":"0.50.0","to":"0.50.1","state":"done","step":"","extra":1}`, "not a journal"},
	} {
		if err := os.WriteFile(filepath.Join(dir, File), []byte(c.body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(dir); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.body, err)
		}
	}
	if err := Write(dir, &Journal{ID: "x", From: "0.50.0", To: "0.50.1", State: "paused"}); err == nil {
		t.Fatal("a journal in no state was written")
	}
}

// Holds and Allows: from the stop until the checks passed, only the start
// the journal names, in the boot it names.
func TestJournalHolds(t *testing.T) {
	for _, c := range []struct {
		state State
		step  Step
		want  bool
	}{
		{InProgress, None, false}, {InProgress, Snapshot, false}, {InProgress, Stopping, true}, {InProgress, Kept, true}, {InProgress, Started, true},
		{InProgress, Checked, true}, {Failed, Swapped, true}, {Failed, Snapshot, false}, {Done, Checked, false}, {Undone, Swapped, false},
	} {
		j := &Journal{State: c.state, Step: c.step}
		if j.Holds() != c.want {
			t.Errorf("%s at %q: %v", c.state, c.step, !c.want)
		}
	}
	var none *Journal
	if none.Holds() || none.Settled("a") {
		t.Error("no journal holds")
	}
	// Checked is settled in another boot than it was written in, and only
	// where there is one to compare.
	for _, c := range []struct {
		step         Step
		wrote, reads string
		want         bool
	}{{Checked, "a", "b", true}, {Checked, "a", "a", false}, {Checked, "", "b", false}, {Checked, "a", "", false}, {Started, "a", "b", false}} {
		j := &Journal{State: InProgress, Step: c.step, Start: &Start{Version: "0.50.0", BootID: c.wrote}}
		if j.Settled(c.reads) != c.want {
			t.Errorf("%s written in %q, read in %q: %v", c.step, c.wrote, c.reads, !c.want)
		}
		j.Start = nil
		if j.Settled(c.reads) {
			t.Errorf("%s with no start is settled", c.step)
		}
	}
	j := &Journal{State: InProgress, Step: Swapped}
	if j.Allows("0.50.0", "a") {
		t.Error("no start is allowed")
	}
	j.Start = &Start{Version: "0.50.0", BootID: "a"}
	if !j.Allows("0.50.0", "a") || j.Allows("0.50.1", "a") || j.Allows("0.50.0", "b") || j.Allows("0.50.0", "") {
		t.Error("the start allowed is that release's in that boot")
	}
	j.Start.BootID = ""
	if j.Allows("0.50.0", "") {
		t.Error("a boot without an identity")
	}
}

// A journal of format 1 is read, and written again in it.
func TestJournalFormatOne(t *testing.T) {
	dir := t.TempDir()
	body := `{"format":1,"id":"0011223344556677","from":"0.50.0-rc.2","to":"0.50.0-rc.3","fromSchema":2,"toSchema":2,"rollbackSafe":true,` +
		`"state":"in-progress","step":"swapped","startedAt":"2026-11-24T10:00:00Z","updatedAt":"2026-11-24T10:01:00Z","binDir":"/usr/local/bin",` +
		`"releases":"/usr/local/lib/varlatch/releases","dataDir":"/var/lib/varlatch","work":"/var/lib/varlatch/upgrades/0011223344556677","snapshot":"/s.vltbak"}`
	if err := os.WriteFile(filepath.Join(dir, File), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	j, err := Read(dir)
	if err != nil || !j.Holds() || j.Reached(Kept) != true || !j.Reached(Prepared) {
		t.Fatalf("%+v, %v", j, err)
	}
	j.State = Undone
	if err := Write(dir, j); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, File))
	for _, later := range []string{`"undo"`, `"start"`, `"binaries"`, `"snapshotSha256"`, `"snapshotAt"`} {
		if strings.Contains(string(b), later) {
			t.Errorf("format 1 with %s:\n%s", later, b)
		}
	}
	if j, err := Read(dir); err != nil || j.Format != FormatOne {
		t.Fatalf("%+v, %v", j, err)
	}
}
