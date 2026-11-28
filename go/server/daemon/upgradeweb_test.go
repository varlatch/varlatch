// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/upgradejournal"
	"github.com/varlatch/varlatch/go/server/config"
)

// upgradedEvents are the installation.upgraded events in in's database, in
// order, as their metadata.
func upgradedEvents(t *testing.T, in install) []map[string]any {
	t.Helper()
	store, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, config.DatabaseFile)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rows, err := store.Reader().QueryContext(context.Background(), `SELECT metadata, actor_identity_id, organization_id FROM audit_events WHERE event_type = ? ORDER BY event_order`, UpgradedEvent)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var meta string
		var actor, org sql.NullString
		if err := rows.Scan(&meta, &actor, &org); err != nil {
			t.Fatal(err)
		}
		if actor.Valid || org.Valid {
			t.Errorf("an actor or an Organization: %v %v", actor, org)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(meta), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// done is root's journal of an upgrade to this build, done, as `varlatch
// upgrade` leaves it.
func done(id, installation string) *upgradejournal.Journal {
	return &upgradejournal.Journal{Format: upgradejournal.Format, ID: id, From: "0.51.0", To: buildinfo.Version, State: upgradejournal.Done, Step: upgradejournal.Checked,
		StartedAt: "2026-11-28T10:00:00Z", UpdatedAt: "2026-11-28T10:01:30Z", SnapshotArchive: "0b0b0b0b-0000-4000-8000-000000000001", Installation: installation,
		Binaries: &upgradejournal.Binaries{To: upgradejournal.BinarySums{Varlatch: strings.Repeat("a", 64), Varlatchd: strings.Repeat("b", 64)}}}
}

func installationOf(t *testing.T, in install) string {
	t.Helper()
	store, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(in.data, config.DatabaseFile)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, err := (&backend{store: store}).InstallationID(context.Background())
	if err != nil || id == "" {
		t.Fatalf("no installation: %v", err)
	}
	return id
}

// installation.upgraded (ADR-0065 Decision 7): an upgrade's done record in
// root's journal, read by the release it upgraded to when it starts, is
// recorded once per journal id, with no actor and source host; a
// rollback's journal, an undone upgrade, an upgrade to another release or
// of another installation records nothing.
func TestUpgradedRecordedOncePerJournal(t *testing.T) {
	in := newInstall(t, "")
	start(t, in).stop(t)
	installation := installationOf(t, in)

	writeUpgrade(t, in.dir, done("1111111111111111", installation))
	start(t, in).stop(t)
	start(t, in).stop(t)
	events := upgradedEvents(t, in)
	if len(events) != 1 {
		t.Fatalf("after two starts: %d events %v", len(events), events)
	}
	want := map[string]any{"from": "0.51.0", "to": buildinfo.Version, "journalId": "1111111111111111", "varlatchSha256": strings.Repeat("a", 64), "varlatchdSha256": strings.Repeat("b", 64),
		"snapshotArchiveId": "0b0b0b0b-0000-4000-8000-000000000001", "startedAt": "2026-11-28T10:00:00Z", "finishedAt": "2026-11-28T10:01:30Z", "source": "host", "requestId": nil}
	for k, v := range want {
		if events[0][k] != v {
			t.Errorf("%s: %v, want %v", k, events[0][k], v)
		}
	}

	for name, j := range map[string]*upgradejournal.Journal{
		"undone":                {Format: upgradejournal.Format, ID: "2222222222222222", From: "0.51.0", To: buildinfo.Version, State: upgradejournal.Undone, Step: upgradejournal.Started},
		"to another release":    {Format: upgradejournal.Format, ID: "3333333333333333", From: "0.51.0", To: "0.51.1", State: upgradejournal.Done, Step: upgradejournal.Checked},
		"of another one":        done("4444444444444444", "inst_another"),
		"a rollback, done":      {Format: upgradejournal.Format, ID: "5555555555555555", Kind: upgradejournal.Rollback, From: "0.52.0", To: buildinfo.Version, State: upgradejournal.Done, Upgraded: done("1111111111111111", installation)},
		"an upgrade not over":   {Format: upgradejournal.Format, ID: "6666666666666666", From: "0.51.0", To: buildinfo.Version, State: upgradejournal.InProgress, Step: upgradejournal.Snapshot},
		"the same one, again":   done("1111111111111111", installation),
		"from a format 1 build": {Format: upgradejournal.FormatOne, ID: "7777777777777777", From: "0.50.0-rc.2", To: "0.50.0-rc.3", State: upgradejournal.Done, Step: upgradejournal.Checked},
	} {
		writeUpgrade(t, in.dir, j)
		start(t, in).stop(t)
		if events := upgradedEvents(t, in); len(events) != 1 {
			t.Fatalf("%s: %d events", name, len(events))
		}
	}

	// The next upgrade is its own event.
	writeUpgrade(t, in.dir, done("8888888888888888", ""))
	start(t, in).stop(t)
	if events := upgradedEvents(t, in); len(events) != 2 || events[1]["journalId"] != "8888888888888888" || events[1]["snapshotArchiveId"] != "0b0b0b0b-0000-4000-8000-000000000001" {
		t.Fatalf("the next upgrade: %v", events)
	}
}

// The upgrade's own start is held; its event is recorded once the journal
// says the upgrade is done, by the release that then serves, and not again
// at the next start.
func TestUpgradedRecordedWhenTheHoldEnds(t *testing.T) {
	inThisBoot(t)
	in := newInstall(t, "")
	start(t, in).stop(t)
	installation := installationOf(t, in)

	j := done("9999999999999999", installation)
	j.State, j.Start = upgradejournal.InProgress, &upgradejournal.Start{Version: buildinfo.Version, BootID: thisBoot, At: "2026-11-28T10:01:00Z"}
	writeUpgrade(t, in.dir, j)
	r := start(t, in)
	if code := getJSON(t, "http://"+r.addr+"/readyz", nil); code == http.StatusOK {
		t.Fatal("not held")
	}
	j.State, j.Start = upgradejournal.Done, nil
	writeUpgrade(t, in.dir, j)
	open := false
	for deadline := time.Now().Add(10 * time.Second); !open && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		open = getJSON(t, "http://"+r.addr+"/readyz", nil) == http.StatusOK
	}
	if !open {
		t.Fatalf("not open once done: %s", r.stderr.String())
	}
	// The event follows the opening.
	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(r.stderr.String(), "recorded the upgrade in the audit log"); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("not recorded once open: %s", r.stderr.String())
		}
	}
	r.stop(t)
	if events := upgradedEvents(t, in); len(events) != 1 || events[0]["journalId"] != "9999999999999999" || events[0]["source"] != "host" {
		t.Fatalf("held, then done: %v", events)
	}
	start(t, in).stop(t)
	if events := upgradedEvents(t, in); len(events) != 1 {
		t.Fatalf("again at the next start: %v", events)
	}
}

// The pre-flight's rollback window is `varlatch migrate`'s: an open
// migration switched no more than 30 days ago whose window no upgrade
// ended, or a reverse under way.
func TestMigrationWindowOpen(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	if open, err := migrationWindowOpen(dir, now); open || err != nil {
		t.Fatalf("never migrated: %v %v", open, err)
	}
	write := func(phase string, switched time.Time, ended bool) {
		t.Helper()
		j := map[string]any{"format": 1, "id": "mig_" + strings.Repeat("a", 26), "phase": phase,
			"history": []map[string]string{{"phase": "switched", "at": switched.Format(time.RFC3339Nano)}}}
		if ended {
			j["windowEnded"] = map[string]string{"release": "0.51.0"}
		}
		b, _ := json.Marshal(j)
		if err := os.WriteFile(filepath.Join(dir, JournalFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, c := range map[string]struct {
		phase    string
		switched time.Duration
		ended    bool
		open     bool
	}{
		"open, a day after its switch": {"open", 24 * time.Hour, false, true},
		"open, 31 days after":          {"open", 31 * 24 * time.Hour, false, false},
		"ended by an upgrade":          {"open", time.Hour, true, false},
		"finished":                     {"finished", time.Hour, false, false},
		"a reverse under way":          {"rollback-exported", 40 * 24 * time.Hour, false, true},
	} {
		write(c.phase, now.Add(-c.switched), c.ended)
		if open, err := migrationWindowOpen(dir, now); open != c.open || err != nil {
			t.Errorf("%s: %v %v", name, open, err)
		}
	}
}
