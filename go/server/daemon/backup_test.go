// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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
