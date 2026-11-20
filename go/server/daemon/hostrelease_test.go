// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/server/db"
)

// admin status is a running varlatchd's answer, or nothing's: it never
// opens the database or takes the lock.
func TestAdminStatus(t *testing.T) {
	in := newInstall(t, "")
	code, out, errOut := runAdmin(t, "status", "--json", "--config", in.conf)
	if code != ExitFailure || out != "" || !strings.Contains(errOut, "it is not running") {
		t.Fatalf("not running: %d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); !os.IsNotExist(err) {
		t.Fatalf("status opened the database: %v", err)
	}
	r := start(t, in)
	code, out, errOut = runAdmin(t, "status", "--json", "--config", in.conf)
	var st statusJSON
	if code != ExitOK || json.Unmarshal([]byte(out), &st) != nil {
		t.Fatalf("running: %d %q %q", code, out, errOut)
	}
	if st.Version != buildinfo.Version || st.SchemaVersion != db.SchemaVersion || !st.Serving || !st.Ready.Schema || !st.Ready.RootKEK || !st.Ready.Installation {
		t.Fatalf("status: %+v", st)
	}
	if code, out, _ = runAdmin(t, "status", "--config", in.conf); code != ExitOK || !strings.Contains(out, "is running; serving: true") {
		t.Fatalf("text: %d %q", code, out)
	}
	r.stop(t)
	for _, args := range [][]string{{"status", "--json", "--json"}, {"status", "--wait"}} {
		if code, _, errOut := runAdmin(t, append(args, "--config", in.conf)...); code != 64 || !strings.Contains(errOut, statusUsage) {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}

// admin release-check record writes the record GET /v1/installation/release
// reads, beside a running varlatchd or not.
func TestAdminReleaseCheck(t *testing.T) {
	in := newInstall(t, "")
	r := start(t, in)
	code, out, errOut := runAdmin(t, "release-check", "record", "--repo", "varlatch/varlatch", "--version", "0.50.0-rc.2", "--published-at", "2026-11-19T16:12:41Z", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"version":"0.50.0-rc.2"`) {
		t.Fatalf("found: %d %q %q", code, out, errOut)
	}
	r.stop(t)
	code, _, errOut = runAdmin(t, "release-check", "record", "--repo", "varlatch/varlatch", "--failed", "unreachable", "--config", in.conf)
	if code != ExitOK {
		t.Fatalf("failed: %d %q", code, errOut)
	}
	rc, err := release.ReadReleaseCheck(in.data)
	if err != nil || rc.LastSuccess == nil || rc.LastSuccess.Latest.Version != "0.50.0-rc.2" || *rc.LastAttempt.Failed != "unreachable" {
		t.Fatalf("the record: %+v, %v", rc, err)
	}
	for _, args := range [][]string{
		{"release-check"}, {"release-check", "record"}, {"release-check", "record", "--repo", "a/b"},
		{"release-check", "record", "--repo", "a/b", "--version", "1.0.0", "--failed", "unreachable"},
		{"release-check", "record", "--repo", "a/b", "--failed", "unreachable", "--published-at", "2026-11-19T16:12:41Z"},
		{"release-check", "record", "--repo", "a/b", "--version", "1.0.0", "--version", "1.0.1"},
	} {
		if code, _, errOut := runAdmin(t, append(args, "--config", in.conf)...); code != 64 || !strings.Contains(errOut, releaseCheckUsage) {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
	if code, _, errOut := runAdmin(t, "release-check", "record", "--repo", "a/b", "--failed", "timeout", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "nothing was written") {
		t.Errorf("an unknown failure: %d %q", code, errOut)
	}
}

// admin schema upgrade --database upgrades a copy, beside a running
// varlatchd too; the live database under another name is not a copy.
func TestAdminSchemaUpgradeOfACopy(t *testing.T) {
	in := newInstall(t, "")
	r := start(t, in)
	code, out, _ := runAdmin(t, "schema", "status", "--json", "--config", in.conf)
	var st struct {
		DataDir string `json:"dataDir"`
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &st) != nil || st.DataDir != in.data {
		t.Fatalf("status names the data directory: %d %q", code, out)
	}
	r.stop(t)
	raw, err := os.ReadFile(filepath.Join(in.data, "varlatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	copyPath := filepath.Join(work, "varlatch.db")
	if err := os.WriteFile(copyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	r = start(t, in)
	code, out, errOut := runAdmin(t, "schema", "upgrade", "--json", "--database", copyPath, "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"changed":false`) {
		t.Fatalf("a copy beside a running varlatchd: %d %q %q", code, out, errOut)
	}
	// The live database through a link is the live database: refused while
	// varlatchd runs.
	link := filepath.Join(work, "live.db")
	if err := os.Symlink(filepath.Join(in.data, "varlatch.db"), link); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut = runAdmin(t, "schema", "upgrade", "--database", link, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "varlatchd is running") {
		t.Fatalf("the live database by another name: %d %q", code, errOut)
	}
	r.stop(t)
	if code, _, errOut = runAdmin(t, "schema", "upgrade", "--database", filepath.Join(work, "missing.db"), "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "the database copy") {
		t.Fatalf("a missing copy: %d %q", code, errOut)
	}
	if code, _, errOut = runAdmin(t, "schema", "status", "--database", copyPath, "--config", in.conf); code != 64 {
		t.Fatalf("--database with status: %d %q", code, errOut)
	}
}
