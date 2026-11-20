// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --finish's journal (go-step7 decision 17, slice 7.6a):
//   - after a forward migration, finished is written beside the running
//     varlatchd (the journal's word alone: it serves as before), and
//     varlatchd starts on it; from it, no barrier (no reverse) and no other
//     phase;
//   - after a reverse, Go's journal stays rolled back; its copy is discarded
//     (database and the reverse's frozen copy, the journal kept) with
//     varlatchd stopped, and a new migration's journal may then replace the
//     rolled back one, never while the copy is there.
func TestTheFinishedJournal(t *testing.T) {
	in, _ := migrated(t)
	r := start(t, in)
	if code, _, errOut := migrateWith(t, in.conf, journalText(migA, "finished"), "state", "--write"); code != ExitOK {
		t.Fatalf("finished beside the running varlatchd: %q", errOut)
	}
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c == http.StatusServiceUnavailable {
		t.Fatal("isolated once finished")
	}
	if code, _, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "in phase finished") {
		t.Errorf("a barrier once finished: %d %q", code, errOut)
	}
	for _, phase := range []string{"open", "rollback", "released", "rolled-back"} {
		if code, _, errOut := migrateWith(t, in.conf, journalText(migA, phase), "state", "--write"); code != ExitFailure {
			t.Errorf("%s after finished: %d %q", phase, code, errOut)
		}
	}
	r.stop(t)
	// Offline too: no phase but finished, released (an undo) included.
	for _, phase := range []string{"released", "open", "rolled-back"} {
		if code, _, errOut := migrateWith(t, in.conf, journalText(migA, phase), "state", "--write"); code != ExitFailure || !strings.Contains(errOut, "stays finished") {
			t.Errorf("%s after finished, offline: %d %q", phase, code, errOut)
		}
	}
	r = start(t, in)
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c == http.StatusServiceUnavailable {
		t.Fatal("isolated at start once finished")
	}
	r.stop(t)
	if code, _, errOut := migrateWith(t, in.conf, nil, "discard", "--id", migA); code != ExitFailure || !strings.Contains(errOut, "past its switch") {
		t.Errorf("a discard once finished: %d %q", code, errOut)
	}

	// Rolled back: the copy is discarded, then a new migration may begin.
	in2, _ := migrated(t)
	r2 := start(t, in2)
	if code, _, errOut := migrateWith(t, in2.conf, journalText(migA, "rollback"), "state", "--write"); code != ExitOK {
		t.Fatal(errOut)
	}
	if code, _, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--config", in2.conf); code != ExitOK {
		t.Fatal(errOut)
	}
	if code, _, errOut := migrateWith(t, in2.conf, nil, "discard", "--id", migA); code != ExitFailure || !strings.Contains(errOut, "varlatchd is running") {
		t.Errorf("a discard beside the running varlatchd: %d %q", code, errOut)
	}
	r2.stop(t)
	for _, phase := range []string{"rollback-exported", "rollback-imported", "rollback-checked", "rollback-transfer", "rolled-back"} {
		if code, _, errOut := migrateWith(t, in2.conf, journalText(migA, phase), "state", "--write"); code != ExitOK {
			t.Fatal(errOut)
		}
	}
	if code, _, errOut := migrateWith(t, in2.conf, journalText(migA, "finished"), "state", "--write"); code != ExitFailure {
		t.Errorf("finished over rolled back: %d %q", code, errOut)
	}
	if code, _, errOut := migrateWith(t, in2.conf, journalText(migB, "started"), "state", "--write"); code != ExitFailure {
		t.Errorf("a new migration over Go's kept copy: %d %q", code, errOut)
	}
	if code, out, errOut := migrateWith(t, in2.conf, nil, "discard", "--id", migA); code != ExitOK || !strings.Contains(out, "varlatch.db") || !strings.Contains(out, FrozenCopyName(migA)) {
		t.Fatalf("the rolled back copy discarded: %d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(in2.data, "varlatch.db")); !os.IsNotExist(err) {
		t.Fatalf("the database after the discard: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(in2.data, JournalFile)); !strings.Contains(string(b), `"rolled-back"`) {
		t.Fatalf("the journal after the discard: %s", b)
	}
	var errOut syncBuffer
	if code := Serve(Options{ConfigPath: in2.conf, Stderr: &errOut, Signals: make(chan os.Signal, 1)}); code == ExitOK || !strings.Contains(errOut.String(), "was reversed") {
		t.Fatalf("varlatchd on the discarded copy: %d %q", code, errOut.String())
	}
	if code, _, errOut := migrateWith(t, in2.conf, journalText(migB, "started"), "state", "--write"); code != ExitOK {
		t.Fatalf("a new migration once the copy is discarded: %q", errOut)
	}
}
