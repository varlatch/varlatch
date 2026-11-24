// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/upgradejournal"
	"github.com/varlatch/varlatch/go/server/maintenance"
)

const thisBoot = "0f0f0f0f-0000-4000-8000-000000000001"

// upgradeTo is a journal of an upgrade from 0.50.0-rc.3 to this build.
func upgradeTo(format int, state upgradejournal.State, step upgradejournal.Step, start *upgradejournal.Start) *upgradejournal.Journal {
	return &upgradejournal.Journal{Format: format, ID: "00", From: "0.50.0-rc.3", To: buildinfo.Version, State: state, Step: step, Start: start}
}

func writeUpgrade(t *testing.T, dir string, j *upgradejournal.Journal) {
	t.Helper()
	if err := upgradejournal.Write(dir, j); err != nil {
		t.Fatal(err)
	}
}

func inThisBoot(t *testing.T) {
	t.Helper()
	was := upgradeBootID
	upgradeBootID = func() string { return thisBoot }
	t.Cleanup(func() { upgradeBootID = was })
}

// What the journal says to a varlatchd about to serve, at every step, in
// both formats, with and without the start it allows.
func TestUpgradeStart(t *testing.T) {
	inThisBoot(t)
	allowed := &upgradejournal.Start{Version: buildinfo.Version, BootID: thisBoot, At: "2026-11-24T08:00:00Z"}
	held := []upgradejournal.Step{upgradejournal.Stopping, upgradejournal.Stopped, upgradejournal.Prepared, upgradejournal.Kept, upgradejournal.Installed, upgradejournal.Swapped, upgradejournal.Started}
	for _, step := range append([]upgradejournal.Step{upgradejournal.None}, upgradejournal.Steps...) {
		for _, state := range []upgradejournal.State{upgradejournal.InProgress, upgradejournal.Failed, upgradejournal.Done, upgradejournal.Undone} {
			holds := slices.Contains(held, step) && (state == upgradejournal.InProgress || state == upgradejournal.Failed)
			for name, start := range map[string]*upgradejournal.Start{
				"none": nil, "this": allowed,
				"another release": {Version: "0.50.0-rc.3", BootID: thisBoot},
				"another boot":    {Version: buildinfo.Version, BootID: "0f0f0f0f-0000-4000-8000-000000000002"},
				"no boot":         {Version: buildinfo.Version},
			} {
				dir := t.TempDir()
				writeUpgrade(t, dir, upgradeTo(upgradejournal.Format, state, step, start))
				got, err := upgradeStart(dir, buildinfo.Version)
				wantHeld := holds && name == "this"
				wantErr := holds && !wantHeld
				if got != wantHeld || (err != nil) != wantErr || err != nil && !strings.Contains(err.Error(), "run sudo varlatch upgrade") {
					t.Errorf("%s at %q, start %s: held %v, %v; want held %v, refused %v", state, step, name, got, err, wantHeld, wantErr)
				}
				if over := upgradeOver(dir); (over != nil) != holds {
					t.Errorf("%s at %q: an offline command: %v, want refused %v", state, step, over, holds)
				}
			}
		}
	}
	// Before format 2 nothing names the start: the swap is recorded, then the
	// new varlatchd is started. Held, in any boot, and only then, and only the
	// release the upgrade goes to.
	for _, step := range append([]upgradejournal.Step{upgradejournal.None}, upgradejournal.Steps...) {
		if step == upgradejournal.Kept || step == upgradejournal.Installed {
			continue // not of format 1
		}
		for _, state := range []upgradejournal.State{upgradejournal.InProgress, upgradejournal.Failed} {
			dir := t.TempDir()
			writeUpgrade(t, dir, upgradeTo(upgradejournal.FormatOne, state, step, nil))
			wantHeld := state == upgradejournal.InProgress && (step == upgradejournal.Swapped || step == upgradejournal.Started)
			wantErr := slices.Contains(held, step) && !wantHeld
			if got, err := upgradeStart(dir, buildinfo.Version); got != wantHeld || (err != nil) != wantErr {
				t.Errorf("format 1, %s at %q: held %v, %v", state, step, got, err)
			}
			if got, err := upgradeStart(dir, "0.50.0-rc.9"); got || (err != nil) != slices.Contains(held, step) {
				t.Errorf("format 1, %s at %q, another release: held %v, %v", state, step, got, err)
			}
		}
	}
	// None, and what cannot be read.
	if got, err := upgradeStart(t.TempDir(), buildinfo.Version); got || err != nil {
		t.Errorf("no journal: %v, %v", got, err)
	}
	for name, text := range map[string]string{"not JSON": "{", "a later format": `{"format":3,"id":"00","from":"0.50.0-rc.3","to":"0.50.0-rc.4","state":"done","step":"checked"}`,
		"a member of a later one": `{"format":2,"id":"00","from":"0.50.0-rc.3","to":"0.50.0-rc.4","state":"done","step":"checked","later":1}`, "empty": ""} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, upgradejournal.File), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := upgradeStart(dir, buildinfo.Version); got || err == nil || !strings.Contains(err.Error(), "cannot be read") {
			t.Errorf("%s: held %v, %v", name, got, err)
		}
		if err := upgradeOver(dir); err == nil {
			t.Errorf("%s: an offline command goes on", name)
		}
	}
}

func readyStatus(t *testing.T, conf string) (serving, ready bool) {
	t.Helper()
	code, out, errOut := runAdmin(t, "status", "--json", "--config", conf)
	var st statusJSON
	if code != ExitOK || json.Unmarshal([]byte(out), &st) != nil {
		t.Fatalf("admin status: %d %q %q", code, out, errOut)
	}
	return st.Serving, st.Ready.Schema && st.Ready.RootKEK && st.Ready.Installation
}

// varlatchd through an upgrade: refused where no start is allowed, with
// nothing made; held where one is, answering 503 alone, its readiness real on
// the control socket; and open once the journal says so.
func TestServeDuringAnUpgrade(t *testing.T) {
	inThisBoot(t)
	in := newInstall(t, "backup_interval = off\n")
	allowed := &upgradejournal.Start{Version: buildinfo.Version, BootID: thisBoot}
	refuse := func(why string) {
		t.Helper()
		var errOut syncBuffer
		if code := Serve(Options{ConfigPath: in.conf, Stderr: &errOut, Signals: make(chan os.Signal, 1)}); code != ExitConfig || !strings.Contains(errOut.String(), "varlatchd does not start") || !strings.Contains(errOut.String(), "varlatch upgrade") {
			t.Fatalf("%s: %d %q", why, code, errOut.String())
		}
		if code, _, errOut := runAdmin(t, "bootstrap", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "nothing was written") {
			t.Fatalf("%s: an offline command: %d %q", why, code, errOut)
		}
		if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); !os.IsNotExist(err) {
			t.Fatalf("%s: a database was made: %v", why, err)
		}
	}
	writeUpgrade(t, in.dir, upgradeTo(0, upgradejournal.InProgress, upgradejournal.Prepared, nil))
	refuse("no start")
	writeUpgrade(t, in.dir, upgradeTo(0, upgradejournal.InProgress, upgradejournal.Swapped, &upgradejournal.Start{Version: buildinfo.Version, BootID: "another"}))
	refuse("after a reboot")
	if err := os.WriteFile(filepath.Join(in.dir, upgradejournal.File), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	refuse("a journal that is none")

	for name, j := range map[string]*upgradejournal.Journal{
		"format 2": upgradeTo(0, upgradejournal.InProgress, upgradejournal.Swapped, allowed),
		"format 1": upgradeTo(upgradejournal.FormatOne, upgradejournal.InProgress, upgradejournal.Swapped, nil),
	} {
		t.Run(name, func(t *testing.T) {
			writeUpgrade(t, in.dir, j)
			r := start(t, in)
			closed := func(when string) {
				t.Helper()
				for _, path := range []string{"/readyz", "/v1/meta", "/v1/whoami"} {
					if code := getJSON(t, "http://"+r.addr+path, nil); code != http.StatusServiceUnavailable {
						t.Fatalf("%s: %s answered %d", when, path, code)
					}
				}
				// What the upgrade checks, and only there.
				if serving, ready := readyStatus(t, in.conf); !serving || !ready {
					t.Fatalf("%s: admin status: serving %v, ready %v", when, serving, ready)
				}
				if code, _, errOut := runAdmin(t, "bootstrap", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, MaintenanceRefusal) {
					t.Fatalf("%s: a command that writes: %d %q", when, code, errOut)
				}
			}
			closed("held")
			next := *j
			next.Step = upgradejournal.Started
			writeUpgrade(t, in.dir, &next)
			time.Sleep(3 * upgradeHoldEvery)
			closed("started")
			// Unreadable, then gone: that says nothing.
			if err := os.WriteFile(filepath.Join(in.dir, upgradejournal.File), []byte("{"), 0o644); err != nil {
				t.Fatal(err)
			}
			time.Sleep(3 * upgradeHoldEvery)
			closed("unreadable")
			if err := os.Remove(filepath.Join(in.dir, upgradejournal.File)); err != nil {
				t.Fatal(err)
			}
			time.Sleep(3 * upgradeHoldEvery)
			closed("gone")
			next.Step, next.Start = upgradejournal.Checked, nil
			writeUpgrade(t, in.dir, &next)
			open := false
			for deadline := time.Now().Add(10 * time.Second); !open && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
				open = getJSON(t, "http://"+r.addr+"/readyz", nil) == http.StatusOK
			}
			if !open {
				t.Fatalf("not open once checked: %s", r.stderr.String())
			}
			if code := getJSON(t, "http://"+r.addr+"/v1/meta", nil); code != http.StatusOK {
				t.Fatalf("/v1/meta: %d", code)
			}
			// It does not close again for a later upgrade, which stops it.
			writeUpgrade(t, in.dir, upgradeTo(0, upgradejournal.InProgress, upgradejournal.Stopping, nil))
			time.Sleep(3 * upgradeHoldEvery)
			if code := getJSON(t, "http://"+r.addr+"/readyz", nil); code != http.StatusOK {
				t.Fatalf("closed again: %d", code)
			}
			r.stop(t)
		})
	}
	// Over by an undo, too.
	writeUpgrade(t, in.dir, upgradeTo(0, upgradejournal.Undone, upgradejournal.Started, nil))
	r := start(t, in)
	if code := getJSON(t, "http://"+r.addr+"/readyz", nil); code != http.StatusOK {
		t.Fatalf("after an undo: %d", code)
	}
	r.stop(t)
}

// The hold is beside a gate, and leaves it as it was; a run that ends before
// the journal does ends the watch.
func TestEndUpgradeHold(t *testing.T) {
	dir, data := t.TempDir(), t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := maintenance.Open(data, nil)
	a.HoldForUpgrade()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	writeUpgrade(t, dir, upgradeTo(0, upgradejournal.InProgress, upgradejournal.Started, nil))
	go func() { endUpgradeHold(ctx, dir, a, log); close(done) }()
	time.Sleep(3 * upgradeHoldEvery)
	if !a.Isolated() {
		t.Fatal("lifted while the journal holds")
	}
	cancel()
	<-done
	if !a.Isolated() {
		t.Fatal("lifted by a stop")
	}
	if _, err := a.Begin(time.Minute); err != nil {
		t.Fatal(err)
	}
	a.EndUpgrade()
	if _, ok := a.Enter(); ok || !a.Isolated() {
		t.Fatal("the lease went with the hold")
	}
}
