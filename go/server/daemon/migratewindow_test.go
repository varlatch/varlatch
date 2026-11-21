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
// beside the running varlatchd (go-step7 decision 17, slice 7.6b): the one
// open-over-open write that is the journal's word alone, once no transfer
// gate stands, is windowEnded added to the same journal and nothing else.
// The record is checked (a release version and a time), never changed or
// removed once written, and kept when a later write of the same migration
// comes without it (migrate's source journal does not carry it).
func TestTheWindowEndsBesideTheRunningVarlatchd(t *testing.T) {
	in, _ := migrated(t)
	journal := func(phase string, change func(map[string]any)) []byte {
		t.Helper()
		var j map[string]any
		if err := json.Unmarshal(journalText(migA, phase), &j); err != nil {
			t.Fatal(err)
		}
		j["history"] = []any{map[string]any{"phase": "switched", "at": "2026-11-20T12:00:00Z"}, map[string]any{"phase": "open", "at": "2026-11-20T12:00:01Z"}}
		if change != nil {
			change(j)
		}
		b, _ := json.Marshal(j)
		return b
	}
	ends := func(release string) func(map[string]any) {
		return func(j map[string]any) {
			j["windowEnded"] = map[string]any{"release": release, "at": "2026-11-21T12:00:00Z"}
		}
	}
	read := func() string {
		b, _ := os.ReadFile(filepath.Join(in.data, JournalFile))
		return string(b)
	}
	// The open journal with its history, written while varlatchd is stopped.
	if code, _, errOut := migrateWith(t, in.conf, journal("open", nil), "state", "--write"); code != ExitOK {
		t.Fatal(errOut)
	}
	r := start(t, in)

	gate := filepath.Join(in.data, backup.GateFile)
	transfer, _ := json.Marshal(backup.Gate{ID: migA, Kind: "migration", Phase: "transfer"})
	if err := os.WriteFile(gate, transfer, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := migrateWith(t, in.conf, journal("open", ends("0.50.1")), "state", "--write"); code != ExitFailure || !strings.Contains(errOut, "stop it first") {
		t.Errorf("the window ended with the transfer gate standing: %d %q", code, errOut)
	}
	if err := os.Remove(gate); err != nil {
		t.Fatal(err)
	}

	// Beside the running varlatchd, refused (stop it first): anything else
	// changed along with the record, the history rewritten, a record that
	// is no release and time (its text never repeated).
	for name, next := range map[string][]byte{
		"another field changed": journal("open", func(j map[string]any) { ends("0.50.1")(j); j["drainSeconds"] = 99 }),
		"the switch dropped": journal("open", func(j map[string]any) {
			ends("0.50.1")(j)
			j["history"] = []any{map[string]any{"phase": "open", "at": "2026-11-20T12:00:01Z"}}
		}),
		"no release": journal("open", ends("next week's")),
		"an unknown field": journal("open", func(j map[string]any) {
			j["windowEnded"] = map[string]any{"release": "0.50.1", "at": "2026-11-21T12:00:00Z", "by": "x"}
		}),
		"open, no record": journal("open", nil),
	} {
		code, out, errOut := migrateWith(t, in.conf, next, "state", "--write")
		if code != ExitFailure || strings.Contains(out+errOut, "next week") {
			t.Errorf("%s beside the running varlatchd: %d %q %q", name, code, out, errOut)
		}
		if strings.Contains(read(), "windowEnded") {
			t.Fatalf("%s: written: %s", name, read())
		}
	}

	// The record alone: written beside it, varlatchd goes on serving.
	if code, _, errOut := migrateWith(t, in.conf, journal("open", ends("0.50.1")), "state", "--write"); code != ExitOK {
		t.Fatalf("the window ended beside the running varlatchd: %d %q", code, errOut)
	}
	if j := read(); !strings.Contains(j, `"windowEnded":{`) || !strings.Contains(j, `"release":"0.50.1"`) || !strings.Contains(j, `"switched"`) {
		t.Errorf("the journal: %s", j)
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
	// Un-ending it beside the running varlatchd: refused.
	if code, _, errOut := migrateWith(t, in.conf, journal("open", nil), "state", "--write"); code != ExitFailure || !strings.Contains(errOut, "stop it first") {
		t.Errorf("the record removed beside the running varlatchd: %d %q", code, errOut)
	}

	// Stopped: another record refused, the record kept when a write comes
	// without it, and varlatchd starts on it.
	r.stop(t)
	if code, _, errOut := migrateWith(t, in.conf, journal("open", ends("0.50.2")), "state", "--write"); code != ExitFailure || !strings.Contains(errOut, "ended already, with varlatchd 0.50.1") {
		t.Errorf("another record: %d %q", code, errOut)
	}
	if code, _, errOut := migrateWith(t, in.conf, journal("open", ends("garbage text")), "state", "--write"); code != ExitFailure || strings.Contains(errOut, "garbage") {
		t.Errorf("no release, offline: %d %q", code, errOut)
	}
	if code, _, errOut := migrateWith(t, in.conf, journal("open", nil), "state", "--write"); code != ExitOK || !strings.Contains(read(), `"release":"0.50.1"`) {
		t.Errorf("a write without the record: %d %q; %s", code, errOut, read())
	}
	r = start(t, in)
	if c := httpStatus(t, r, "GET", "/v1/whoami"); c == http.StatusServiceUnavailable {
		t.Error("isolated at start once the window ended")
	}
}
