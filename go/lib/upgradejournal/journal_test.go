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
		{`{"format":2,"id":"x","from":"0.50.0","to":"0.50.1","state":"done","step":""}`, "format 2"},
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

// A journal 0.50.0-rc.2 wrote: an upgrade that declared nothing and dated
// no snapshot.
func TestJournalOfRC2(t *testing.T) {
	dir := t.TempDir()
	body := `{"format":1,"id":"0011223344556677","from":"0.50.0-rc.2","to":"0.50.0-rc.3","fromSchema":4,"toSchema":4,"rollbackSafe":true,` +
		`"state":"done","step":"checked","startedAt":"2026-11-24T10:00:00Z","updatedAt":"2026-11-24T10:01:00Z","binDir":"/usr/local/bin",` +
		`"releases":"/usr/local/lib/varlatch/releases","dataDir":"/var/lib/varlatch","work":"/var/lib/varlatch/upgrades/0011223344556677","snapshot":"/s.vltbak"}`
	if err := os.WriteFile(filepath.Join(dir, File), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	j, err := Read(dir)
	if err != nil || j.Kind != Upgrade || j.DeclaredRollbackSafe || j.SnapshotAt != "" || j.Pending() || !j.Reached(Checked) {
		t.Fatalf("%+v, %v", j, err)
	}
}
