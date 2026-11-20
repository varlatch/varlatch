// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/doctor"
)

// tree is every entry under dir: its type, mode, size and modification
// time (a directory's changes when an entry is added or removed).
func tree(t *testing.T, dir string, skip func(rel string) bool) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		if skip != nil && skip(rel) {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		out[rel] = fmt.Sprintf("%v %d %d", info.Mode(), info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// settled is dir's tree once two looks 2.5 seconds apart agree (within
// 30 seconds).
func settled(t *testing.T, dir string, skip func(string) bool) map[string]string {
	t.Helper()
	prev := tree(t, dir, skip)
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		time.Sleep(2500 * time.Millisecond)
		next := tree(t, dir, skip)
		if maps.Equal(prev, next) {
			return next
		}
		prev = next
	}
	t.Fatal("the data directory did not settle")
	return nil
}

func sameTree(t *testing.T, what string, before, after map[string]string) {
	t.Helper()
	var diffs []string
	for k, v := range before {
		if after[k] != v {
			diffs = append(diffs, fmt.Sprintf("%s: %q -> %q", k, v, after[k]))
		}
	}
	for k, v := range after {
		if _, ok := before[k]; !ok {
			diffs = append(diffs, fmt.Sprintf("%s: new (%s)", k, v))
		}
	}
	sort.Strings(diffs)
	if len(diffs) > 0 {
		t.Errorf("doctor changed %s:\n  %s", what, strings.Join(diffs, "\n  "))
	}
}

func auditCount(t *testing.T, in install) int {
	t.Helper()
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(in.data, "varlatch.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var n int
	if err := conn.QueryRow("SELECT count(*) FROM audit_events").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func runDoctorJSON(t *testing.T, in install) (int, doctor.Report, string, string) {
	t.Helper()
	code, out, errOut := runAdmin(t, "doctor", "--json", "--config", in.conf)
	var r doctor.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("doctor --json printed %q (%q): %v", out, errOut, err)
	}
	return code, r, out, errOut
}

func reportCheck(t *testing.T, r doctor.Report, id string) doctor.Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %s", id)
	return doctor.Check{}
}

// TestDoctorNeverWrites (step 6.5's acceptance): `varlatchd admin doctor`
// changes nothing in the data directory or in the configuration's
// directory (standing for /etc/varlatch), with varlatchd running (asked
// through its control socket) and with it stopped (no lock taken, no
// database opened), and records no audit event. Its fsync probe's file
// has no name, so it never appears. While varlatchd runs, the database's
// own WAL and shared-memory files are its, and only those are left out of
// the comparison.
func TestDoctorNeverWrites(t *testing.T) {
	in := newInstall(t, "public_url = https://vault.example.com\n")
	r := start(t, in)
	ownFiles := func(rel string) bool { return rel == "varlatch.db-wal" || rel == "varlatch.db-shm" }
	// The daemon's own start writes settle first: its passive checkpoint
	// (every 2 seconds) copies them into the database file.
	before := settled(t, in.data, ownFiles)
	beforeConf, events := tree(t, in.dir, func(rel string) bool { return strings.HasPrefix(rel, "data") }), auditCount(t, in)

	code, rep, out, errOut := runDoctorJSON(t, in)
	if rep.Via != "daemon" || rep.Facts.InstallationID == nil {
		t.Fatalf("doctor through the daemon: %d %s %s", code, out, errOut)
	}
	for _, id := range []string{"secret-plane.ready", "config.public-url", "files.data-dir", "files.keys", "storage.wal", "storage.checkpoints"} {
		if c := reportCheck(t, rep, id); c.Status != doctor.Pass {
			t.Errorf("%s: %+v", id, c)
		}
	}
	if code, text, _ := runAdmin(t, "doctor", "--config", in.conf); !strings.Contains(text, "PASS    secret-plane.ready") || code != rep2code(rep) {
		t.Errorf("doctor's text: %d %q", code, text)
	}
	sameTree(t, "the data directory", before, tree(t, in.data, ownFiles))
	sameTree(t, "the configuration's directory", beforeConf, tree(t, in.dir, func(rel string) bool { return strings.HasPrefix(rel, "data") }))
	if n := auditCount(t, in); n != events {
		t.Errorf("doctor recorded %d audit events", n-events)
	}
	r.stop(t)

	// Stopped: nothing answers; the server's checks are unknown, and not a
	// file changes, the database's included.
	before, beforeConf = tree(t, in.data, nil), tree(t, in.dir, func(rel string) bool { return strings.HasPrefix(rel, "data") })
	_, rep, out, _ = runDoctorJSON(t, in)
	if rep.Via != "offline" || reportCheck(t, rep, "secret-plane.ready").Status != doctor.Unknown || reportCheck(t, rep, "storage.wal").Status != doctor.Unknown {
		t.Errorf("doctor without varlatchd: %s", out)
	}
	sameTree(t, "the stopped installation's data directory", before, tree(t, in.data, nil))
	sameTree(t, "the stopped installation's configuration directory", beforeConf, tree(t, in.dir, func(rel string) bool { return strings.HasPrefix(rel, "data") }))
	if _, err := os.Stat(filepath.Join(in.data, "varlatchd.lock")); err == nil && before["varlatchd.lock"] == "" {
		t.Error("doctor made the lock file")
	}
}

func rep2code(r doctor.Report) int {
	if r.Failed() {
		return ExitFailure
	}
	return ExitOK
}

// TestDoctorShowsNoKey: doctor never opens a key file, and nothing of
// one, or of a credential in its environment, appears in its report.
func TestDoctorShowsNoKey(t *testing.T) {
	bek := filepath.Join(t.TempDir(), "bek")
	bekMaterial := strings.Repeat("ab", 32)
	if err := os.WriteFile(bek, []byte(bekMaterial+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := newInstall(t, "public_url = https://vault.example.com\nbackup_key_file = "+bek+"\n")
	kek, err := os.ReadFile(in.kekFile)
	if err != nil {
		t.Fatal(err)
	}
	r := start(t, in)
	defer r.stop(t)
	token := "vlt_cli_" + strings.Repeat("Q", 40)
	t.Setenv("VARLATCH_TOKEN", token)
	for _, args := range [][]string{{"doctor", "--json", "--config", in.conf}, {"doctor", "--config", in.conf}} {
		_, out, errOut := runAdmin(t, args...)
		for name, secret := range map[string]string{"the Root KEK": strings.TrimSpace(string(kek)), "the backup key": bekMaterial, "a token": token} {
			if strings.Contains(out+errOut, secret) {
				t.Errorf("%v shows %s", args, name)
			}
		}
	}
}

// TestDoctorUsage: --json only; anything else is a usage error that never
// reaches the daemon.
func TestDoctorUsage(t *testing.T) {
	in := newInstall(t, "")
	for _, args := range [][]string{{"doctor", "--live"}, {"doctor", "--fix"}, {"doctor", "extra"}} {
		if code, _, errOut := runAdmin(t, append(args, "--config", in.conf)...); code != 64 || !strings.Contains(errOut, "Usage: varlatchd admin doctor") {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}

// TestDoctorSaysWhyItCouldNotAsk (#328 review): when the data directory or
// its control socket refuses this user (here: something that is not a
// socket where the socket goes), doctor says so on stderr, as route does,
// and reports varlatchd unasked, never stopped.
func TestDoctorSaysWhyItCouldNotAsk(t *testing.T) {
	in := newInstall(t, "public_url = https://vault.example.com\n")
	if err := os.WriteFile(filepath.Join(in.data, ControlSocket), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, rep, out, errOut := runDoctorJSON(t, in)
	if rep.Via != "unasked" || !strings.Contains(errOut, "is not a socket owned by the data directory's owner") || !strings.Contains(errOut, "the running varlatchd was not asked") {
		t.Fatalf("%d %s %q", code, out, errOut)
	}
	if c := reportCheck(t, rep, "secret-plane.ready"); c.Status != doctor.Unknown || !strings.Contains(c.Remedy, "sudo varlatch doctor") {
		t.Errorf("readiness: %+v", c)
	}
}
