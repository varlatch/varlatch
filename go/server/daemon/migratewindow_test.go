// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/backup"
)

// An upgrade that ends the rollback window records it in Go's journal
// beside the running varlatchd (go-step7 decision 17, slice 7.6b): open
// over open is the journal's word alone once no transfer gate stands, so
// it is written while varlatchd serves, and varlatchd goes on serving. With
// the migration's transfer gate still standing, open over open would
// remove it: refused beside the running varlatchd, as before.
func TestTheWindowEndsBesideTheRunningVarlatchd(t *testing.T) {
	in, _ := migrated(t)
	r := start(t, in)
	var j map[string]any
	if err := json.Unmarshal(journalText(migA, "open"), &j); err != nil {
		t.Fatal(err)
	}
	j["windowEnded"] = map[string]any{"release": "0.50.1", "at": "2026-11-21T12:00:00Z"}
	ended, _ := json.Marshal(j)

	gate := filepath.Join(in.data, backup.GateFile)
	transfer, _ := json.Marshal(backup.Gate{ID: migA, Kind: "migration", Phase: "transfer"})
	if err := os.WriteFile(gate, transfer, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := migrateWith(t, in.conf, ended, "state", "--write"); code != ExitFailure || !strings.Contains(errOut, "stop it first") {
		t.Errorf("open over open with the transfer gate standing: %d %q", code, errOut)
	}
	if b, _ := os.ReadFile(gate); string(b) != string(transfer) {
		t.Errorf("the transfer gate after the refusal: %s", b)
	}
	if err := os.Remove(gate); err != nil {
		t.Fatal(err)
	}

	if code, _, errOut := migrateWith(t, in.conf, ended, "state", "--write"); code != ExitOK {
		t.Fatalf("the window ended beside the running varlatchd: %d %q", code, errOut)
	}
	if b, _ := os.ReadFile(filepath.Join(in.data, JournalFile)); !strings.Contains(string(b), `"windowEnded":{`) || !strings.Contains(string(b), `"release":"0.50.1"`) {
		t.Errorf("the journal: %s", b)
	}
	if _, err := os.Stat(gate); !os.IsNotExist(err) {
		t.Errorf("a gate after the write: %v", err)
	}
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c == http.StatusServiceUnavailable {
		t.Error("isolated once the window ended")
	}
	// No reverse starts once it ended.
	if code, _, errOut := runAdmin(t, "migrate", "barrier", "--id", migA, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "rollback window ended with the upgrade to varlatchd 0.50.1") {
		t.Errorf("a reverse's barrier once the window ended: %d %q", code, errOut)
	}
	r.stop(t)
	r = start(t, in)
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c == http.StatusServiceUnavailable {
		t.Error("isolated at start once the window ended")
	}
}
