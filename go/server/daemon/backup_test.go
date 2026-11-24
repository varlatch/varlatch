// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
)

var archiveCreated = regexp.MustCompile(`^Archive created: (\S+) \(([0-9a-f-]{36})\)\nSnapshot \d+\.\d s, sealing \d+\.\d s, \d+\.\d MiB; checks: integrity true, compatibility true, Root KEK match true\.\n$`)

// `admin maintenance` and `admin backup`, through the daemon: a lease
// isolates the running server at once (503 MAINTENANCE, /readyz not
// ready) and refuses a backup; once it ends, a backup runs and its status
// is what getInstallationBackups reads. Offline, under the lock, a lease
// written before a start isolates the daemon that starts.
func TestBackupAndMaintenanceCommands(t *testing.T) {
	dir := t.TempDir()
	bek := filepath.Join(dir, "bek")
	if err := os.WriteFile(bek, []byte(hex.EncodeToString(envelope.GenerateKey())), 0o600); err != nil {
		t.Fatal(err)
	}
	in := newInstall(t, "backup_key_file = "+bek+"\nbackup_interval = off\n")
	r := start(t, in)
	base := "http://" + r.addr

	code, out, errOut := runAdmin(t, "maintenance", "begin", "--ttl", "1m", "--config", in.conf)
	var gate backup.Gate
	if code != ExitOK || json.Unmarshal([]byte(out), &gate) != nil || gate.Kind != "capture" {
		t.Fatalf("maintenance begin: %d %q %q", code, out, errOut)
	}
	res, err := http.Get(base + "/v1/meta")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 503 || res.Header.Get("Retry-After") != "5" {
		t.Errorf("during maintenance: %d %v", res.StatusCode, res.Header)
	}
	if code := getJSON(t, base+"/readyz", nil); code != 503 {
		t.Errorf("readyz during maintenance: %d", code)
	}
	if code := getJSON(t, base+"/healthz", nil); code != 200 {
		t.Errorf("healthz during maintenance: %d", code)
	}
	if code, out, _ := runAdmin(t, "maintenance", "status", "--config", in.conf); code != ExitOK || !strings.Contains(out, gate.ID) {
		t.Errorf("maintenance status: %d %q", code, out)
	}
	if code, _, errOut := runAdmin(t, "backup", "run", "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "Installation maintenance is active") {
		t.Errorf("a backup during maintenance: %d %q", code, errOut)
	}
	if code, out, errOut := runAdmin(t, "maintenance", "end", gate.ID, "--config", in.conf); code != ExitOK || out != "Maintenance ended.\n" {
		t.Fatalf("maintenance end: %d %q %q", code, out, errOut)
	}
	if code := getJSON(t, base+"/readyz", nil); code != 200 {
		t.Errorf("readyz after maintenance: %d", code)
	}

	// --verify-remote with no destination: refused before an archive is
	// made (varlatch migrate --finish trusts only the remote copy).
	if code, out, errOut := runAdmin(t, "backup", "run", "--json", "--verify-remote", "--config", in.conf); code != ExitFailure || out != "" || !strings.Contains(errOut, "No backup destination is configured") {
		t.Errorf("--verify-remote with no destination: %d %q %q", code, out, errOut)
	}
	code, out, errOut = runAdmin(t, "backup", "run", "--config", in.conf)
	m := archiveCreated.FindStringSubmatch(out)
	if code != ExitOK || m == nil || m[1] != filepath.Join(in.data, "backups", m[2]+".vltbak") {
		t.Fatalf("backup run: %d %q %q", code, out, errOut)
	}
	code, out, _ = runAdmin(t, "backup", "status", "--config", in.conf)
	var st backup.Status
	if code != ExitOK || json.Unmarshal([]byte(out), &st) != nil || len(st.Archives) != 1 || st.Archives[0].ArchiveID != m[2] {
		t.Errorf("backup status: %d %q", code, out)
	}
	// A lease ends by itself on the running server: it is ready again once
	// the lease expired, and the expired lease's id ends nothing.
	code, out, errOut = runAdmin(t, "maintenance", "begin", "--ttl", "2s", "--config", in.conf)
	if code != ExitOK || json.Unmarshal([]byte(out), &gate) != nil {
		t.Fatalf("a short lease: %d %q %q", code, out, errOut)
	}
	if code := getJSON(t, base+"/readyz", nil); code != 503 {
		t.Errorf("readyz during the short lease: %d", code)
	}
	ready := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if getJSON(t, base+"/readyz", nil) == 200 {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("not ready after the lease expired")
	}
	if code, _, errOut := runAdmin(t, "maintenance", "end", gate.ID, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "Maintenance ownership lost") {
		t.Errorf("ending the expired lease: %d %q", code, errOut)
	}
	if code := getJSON(t, base+"/readyz", nil); code != 200 {
		t.Errorf("readyz after the expired lease's end was refused: %d", code)
	}
	// Usage errors never reach the daemon.
	for _, args := range [][]string{{"backup"}, {"backup", "run", "--now"}, {"maintenance", "begin"}, {"maintenance", "begin", "--ttl", "soon"}, {"maintenance", "end"}} {
		if code, _, errOut := runAdmin(t, append(args, "--config", in.conf)...); code != 64 || !strings.Contains(errOut, "Usage: varlatchd admin "+args[0]) {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
	r.stop(t)

	// Offline: a lease opened while varlatchd is stopped isolates it when
	// it starts, until the lease is ended through its socket.
	code, out, errOut = runAdmin(t, "maintenance", "begin", "--ttl", "10m", "--config", in.conf)
	if code != ExitOK || json.Unmarshal([]byte(out), &gate) != nil {
		t.Fatalf("offline maintenance begin: %d %q %q", code, out, errOut)
	}
	r = start(t, in)
	if code := getJSON(t, "http://"+r.addr+"/readyz", nil); code != 503 {
		t.Errorf("readyz after a restart under a lease: %d", code)
	}
	if code, _, errOut := runAdmin(t, "maintenance", "end", gate.ID, "--config", in.conf); code != ExitOK {
		t.Errorf("maintenance end: %d %q", code, errOut)
	}
	if code := getJSON(t, "http://"+r.addr+"/readyz", nil); code != 200 {
		t.Errorf("readyz after the lease: %d", code)
	}
	r.stop(t)
	// An offline backup, under the lock.
	if code, out, errOut := runAdmin(t, "backup", "run", "--json", "--config", in.conf); code != ExitOK || !strings.HasPrefix(out, `{"archiveId":"`) {
		t.Errorf("offline backup run: %d %q %q", code, out, errOut)
	}
}

// Every host command that writes is refused while a maintenance gate is
// open, as the TypeScript admin CLI refuses its ordinary commands: through
// the daemon's socket under a lease, and offline under a persisted lease,
// before the database is opened. The maintenance and backup status
// commands stay available.
func TestWritingCommandsRefusedDuringMaintenance(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	r := start(t, in)
	code, out, errOut := runAdmin(t, "bootstrap", "--cli-credential", "--config", in.conf)
	m := bootstrapCLI.FindStringSubmatch(out)
	if code != ExitOK || m == nil {
		t.Fatalf("bootstrap: %d %q %q", code, out, errOut)
	}
	admin := m[1]
	writing := [][]string{
		{"bootstrap"},
		{"bootstrap", "--cli-credential"},
		{"recover", "--identity", admin},
		{"recover", "--new-admin", "--cli-credential"},
		{"security", "reset", "--org", "acme", "--all"},
		{"unfreeze", "--org", "acme", "--confirm", "acme"},
	}
	refused := func(where string) {
		t.Helper()
		for _, args := range writing {
			code, out, errOut := runAdmin(t, append(args, "--config", in.conf)...)
			if want := "varlatchd admin " + args[0] + ": " + MaintenanceRefusal + "\n"; code != ExitFailure || out != "" || errOut != want {
				t.Errorf("%s, %v: %d %q %q", where, args, code, out, errOut)
			}
		}
		for _, args := range [][]string{{"maintenance", "status"}, {"backup", "status"}} {
			if code, _, errOut := runAdmin(t, append(args, "--config", in.conf)...); code != ExitOK {
				t.Errorf("%s, %v: %d %q", where, args, code, errOut)
			}
		}
	}

	code, out, _ = runAdmin(t, "maintenance", "begin", "--ttl", "10m", "--config", in.conf)
	var gate backup.Gate
	if code != ExitOK || json.Unmarshal([]byte(out), &gate) != nil {
		t.Fatalf("maintenance begin: %d %q", code, out)
	}
	refused("through the daemon")
	if code, _, errOut := runAdmin(t, "maintenance", "end", gate.ID, "--config", in.conf); code != ExitOK {
		t.Fatalf("maintenance end: %d %q", code, errOut)
	}
	if code, out, errOut := runAdmin(t, "recover", "--identity", admin, "--config", in.conf); code != ExitOK || !recoveryURL.MatchString(out) {
		t.Errorf("recover after the lease: %d %q %q", code, out, errOut)
	}
	r.stop(t)

	// Offline, under a lease that outlived the daemon.
	code, out, _ = runAdmin(t, "maintenance", "begin", "--ttl", "10m", "--config", in.conf)
	if code != ExitOK || json.Unmarshal([]byte(out), &gate) != nil {
		t.Fatalf("offline maintenance begin: %d %q", code, out)
	}
	refused("offline")
	if code, _, errOut := runAdmin(t, "maintenance", "end", gate.ID, "--config", in.conf); code != ExitOK {
		t.Fatalf("offline maintenance end: %d %q", code, errOut)
	}
	if code, out, errOut := runAdmin(t, "recover", "--identity", admin, "--config", in.conf); code != ExitOK || !recoveryURL.MatchString(out) {
		t.Errorf("offline recover after the lease: %d %q %q", code, out, errOut)
	}

	// A fresh data directory under a persisted lease: every command either
	// is refused or works on the directory's files, and none creates the
	// database (and with it the installation) or any other state. The
	// lock file, empty, is what flock serializes on.
	fresh := newInstall(t, "")
	expires := time.Now().Add(time.Hour).UnixMilli()
	if err := backup.DurableJSON(filepath.Join(fresh.data, backup.GateFile), backup.Gate{ID: "lease", Kind: "capture", Phase: "draining", ExpiresAt: &expires}, true); err != nil {
		t.Fatal(err)
	}
	files := func() string {
		t.Helper()
		var names []string
		_ = filepath.WalkDir(fresh.data, func(p string, d fs.DirEntry, err error) error {
			if err == nil && p != fresh.data {
				names = append(names, strings.TrimPrefix(p, fresh.data+"/"))
			}
			return nil
		})
		return strings.Join(names, " ")
	}
	for _, c := range []struct {
		args []string
		code int
		err  string
	}{
		{[]string{"bootstrap"}, ExitFailure, "varlatchd admin bootstrap: " + MaintenanceRefusal + "\n"},
		{[]string{"recover", "--new-admin"}, ExitFailure, "varlatchd admin recover: " + MaintenanceRefusal + "\n"},
		{[]string{"security", "reset", "--org", "acme", "--all"}, ExitFailure, "varlatchd admin security: " + MaintenanceRefusal + "\n"},
		{[]string{"unfreeze", "--org", "acme", "--confirm", "acme"}, ExitFailure, "varlatchd admin unfreeze: " + MaintenanceRefusal + "\n"},
		{[]string{"backup", "run"}, ExitFailure, "varlatchd admin backup run: Installation maintenance is active; no backup was taken\n"},
		{[]string{"backup", "status"}, ExitOK, ""},
		{[]string{"maintenance", "status"}, ExitOK, ""},
		{[]string{"maintenance", "begin", "--ttl", "1m"}, ExitFailure, "varlatchd admin maintenance begin: Installation maintenance is already active\n"},
	} {
		code, _, errOut := runAdmin(t, append(c.args, "--config", fresh.conf)...)
		if code != c.code || errOut != c.err {
			t.Errorf("%v on a fresh directory under a lease: %d %q", c.args, code, errOut)
		}
		if got := files(); got != "maintenance.json varlatchd.lock" {
			t.Errorf("%v left %q in the data directory", c.args, got)
		}
	}
	if code, _, errOut := runAdmin(t, "maintenance", "end", "lease", "--config", fresh.conf); code != ExitOK {
		t.Errorf("maintenance end: %d %q", code, errOut)
	}
	if got := files(); got != "varlatchd.lock" {
		t.Errorf("after the lease ended the data directory holds %q", got)
	}
}
