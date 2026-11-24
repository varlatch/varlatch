// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
)

// TestAdminChild is not a test: it is `varlatchd admin` in a process of its
// own, for the tests that run it as root (it changes its user).
func TestAdminChild(t *testing.T) {
	raw := os.Getenv("VL_TEST_ADMIN_CHILD")
	if raw == "" {
		t.Skip("run by TestAdminAsRoot*")
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatal(err)
	}
	status := Admin(args, os.Stdout, os.Stderr)
	if os.Getenv("VL_TEST_ADMIN_IDS") != "" {
		groups, _ := syscall.Getgroups()
		d, _ := dumpable()
		fmt.Printf("\nids %d %d %d %d groups %v dumpable %d\n", os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), groups, d)
	}
	os.Exit(status)
}

const serviceUID = 65534

// rootHost is a host whose data directory is another user's, with keys only
// root reads.
type rootHost struct {
	t                        *testing.T
	dir, data, conf, private string
}

func newRootHost(t *testing.T) *rootHost {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("runs varlatchd admin as root (go.yml's Go container)")
	}
	dir := t.TempDir()
	h := &rootHost{t: t, dir: dir, data: filepath.Join(dir, "data"), conf: filepath.Join(dir, "etc", "varlatchd.conf"), private: filepath.Join(dir, "private")}
	for _, d := range []string{h.data, filepath.Dir(h.conf), h.private} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"root-kek", "backup-key"} {
		if err := os.WriteFile(filepath.Join(h.private, name), []byte(hex.EncodeToString(envelope.GenerateKey())+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The path to the data directory is open to its owner, as /var/lib is.
	for p := dir; p != os.TempDir() && p != "/"; p = filepath.Dir(p) {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(h.data, serviceUID, serviceUID); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf("listen = 127.0.0.1:0\ndata_dir = %s\nroot_kek_file = %s\nbackup_key_file = %s\nbackup_interval = off\n",
		h.data, filepath.Join(h.private, "root-kek"), filepath.Join(h.private, "backup-key"))
	if err := os.WriteFile(h.conf, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *rootHost) admin(args ...string) (string, int) {
	h.t.Helper()
	raw, _ := json.Marshal(append(args, "--config", h.conf))
	cmd := exec.Command(os.Args[0], "-test.run=^TestAdminChild$")
	cmd.Env = append(os.Environ(), "VL_TEST_ADMIN_CHILD="+string(raw), "VL_TEST_ADMIN_IDS=1", "TMPDIR="+h.private)
	cmd.Dir = h.private
	out, err := cmd.CombinedOutput()
	if err != nil && cmd.ProcessState == nil {
		h.t.Fatal(err)
	}
	return string(out), cmd.ProcessState.ExitCode()
}

// owned fails for each entry of the data directory that is not its
// owner's.
func (h *rootHost) owned(after string) {
	h.t.Helper()
	_ = filepath.WalkDir(h.data, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			h.t.Fatal(err)
		}
		info, err := os.Lstat(p)
		if err != nil {
			h.t.Fatal(err)
		}
		if st := info.Sys().(*syscall.Stat_t); st.Uid != serviceUID || st.Gid != serviceUID {
			h.t.Errorf("after %s, %s is %d:%d's", after, p, st.Uid, st.Gid)
		}
		return nil
	})
}

// Every host command that writes in the data directory, run as root with
// varlatchd stopped, works with the keys only root reads, and leaves the
// owner's files only.
func TestAdminAsRootWorksAsTheOwner(t *testing.T) {
	h := newRootHost(t)
	run := func(args ...string) string {
		t.Helper()
		out, status := h.admin(args...)
		if status != ExitOK {
			t.Fatalf("admin %s: %d\n%s", strings.Join(args, " "), status, out)
		}
		want := fmt.Sprintf("ids %d %d %d %d groups [] dumpable 0", serviceUID, serviceUID, serviceUID, serviceUID)
		if !staysRoot(args[0], args[1:]) && !strings.Contains(out, want) {
			t.Fatalf("admin %s ran as %s", strings.Join(args, " "), out[strings.LastIndex(out, "\nids"):])
		}
		h.owned(strings.Join(args, " "))
		return out
	}
	run("bootstrap")
	run("schema", "status", "--json")
	run("schema", "upgrade")
	// A copy an upgrade's varlatch made as root.
	copied := filepath.Join(h.data, "upgrades", "x", "db")
	if err := os.MkdirAll(copied, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{copied, filepath.Dir(copied), filepath.Dir(filepath.Dir(copied))} {
		if err := os.Chown(d, serviceUID, serviceUID); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(h.data, "varlatch.db")); err != nil || os.WriteFile(filepath.Join(copied, "varlatch.db"), b, 0o600) != nil {
		t.Fatal(err)
	}
	run("schema", "upgrade", "--json", "--database", filepath.Join(copied, "varlatch.db"))
	run("backup", "status")
	archive := h.archive(run("backup", "run", "--json"))
	run("custody", "attest", "--key", "backup-key", "--method", "copy")
	run("custody", "status")
	run("bootstrap-status")
	run("release-check", "record", "--repo", "varlatch/varlatch", "--version", "0.50.0")
	run("certificate", "issuances", "--json")
	run("move-facts")
	run("outbound", "check")
	run("kek", "verify")
	lease := run("maintenance", "begin", "--ttl", "10m")
	if _, err := os.Stat(filepath.Join(h.data, backup.GateFile)); err != nil {
		t.Fatalf("no gate: %v\n%s", err, lease)
	}
	gate, err := backup.ReadGate(h.data)
	if err != nil {
		t.Fatal(err)
	}
	run("maintenance", "status")
	run("maintenance", "end", gate.ID)
	// doctor reads as root; what it says is not this test's.
	if out, status := h.admin("doctor", "--json"); status != ExitOK && status != ExitFailure {
		t.Fatalf("doctor: %d %s", status, out)
	}
	h.owned("doctor")

	// A restore over the installation, and into the directory emptied.
	kept := filepath.Join(h.private, "archive.vltbak")
	if b, err := os.ReadFile(archive); err != nil || os.WriteFile(kept, b, 0o600) != nil {
		t.Fatal(err)
	}
	run("backup", "restore", "--in", archive)
	entries, _ := os.ReadDir(h.data)
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(h.data, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	run("backup", "restore", "--in", "archive.vltbak", "--backup-key-file", filepath.Join(h.private, "backup-key"))
	run("backup", "run")
	// A destination and its credentials are root's too.
	destinations := filepath.Join(h.private, "destinations.json")
	if err := os.WriteFile(destinations, []byte(`{"offsite":{"endpoint":"http://127.0.0.1:1","region":"us-east-1","bucket":"b","writeCredentialsFile":"write.json"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials, _ := json.Marshal(map[string]string{"accessKeyId": "a", "secretAccessKey": "b"})
	if err := os.WriteFile(filepath.Join(h.private, "write.json"), credentials, 0o600); err != nil {
		t.Fatal(err)
	}
	conf, _ := os.ReadFile(h.conf)
	if err := os.WriteFile(h.conf, append(conf, []byte("backup_destinations_file = "+destinations+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	// Read, and used: the upload fails, not the reading.
	if out, status := h.admin("backup", "run"); status != ExitFailure || strings.Contains(out, "permission denied") || !strings.Contains(out, "connection refused") {
		t.Fatalf("a destination: %d %s", status, out)
	}
	h.owned("backup run with a destination")
}

// archive is the path a backup run's JSON names, in the output of a child.
func (h *rootHost) archive(out string) string {
	h.t.Helper()
	for _, line := range strings.Split(out, "\n") {
		var res struct {
			Path string `json:"path"`
		}
		if json.Unmarshal([]byte(line), &res) == nil && res.Path != "" {
			return res.Path
		}
	}
	h.t.Fatalf("no archive in %s", out)
	return ""
}

// A link where a command writes, in the directory its owner may write,
// leads root nowhere.
func TestAdminAsRootFollowsNoLink(t *testing.T) {
	h := newRootHost(t)
	if out, status := h.admin("bootstrap"); status != ExitOK {
		t.Fatal(out)
	}
	out, status := h.admin("backup", "run", "--json")
	if status != ExitOK {
		t.Fatal(out)
	}
	archive := h.archive(out)
	target := filepath.Join(h.private, "roots")
	if err := os.WriteFile(target, []byte("root's"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"varlatch.db.restore", "varlatch.db-wal", "release-check.json", ".restore-work", backup.GateFile} {
		path := filepath.Join(h.data, name)
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := os.Lchown(path, serviceUID, serviceUID); err != nil {
			t.Fatal(err)
		}
		_, _ = h.admin("backup", "restore", "--in", archive)
		_, _ = h.admin("release-check", "record", "--repo", "varlatch/varlatch", "--version", "0.50.0")
		_, _ = h.admin("maintenance", "begin", "--ttl", "10m")
		b, err := os.ReadFile(target)
		info, serr := os.Stat(target)
		if err != nil || serr != nil || string(b) != "root's" || info.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Fatalf("%s: root's file is %q, %v %v", name, b, err, serr)
		}
		_ = os.Remove(path)
	}
}

// giveFiles gives away only root's own regular files with one name.
func TestGiveFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changes owners, as root (go.yml's Go container)")
	}
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	copied := filepath.Join(dir, "varlatch.db")
	for _, p := range []string{outside, copied} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, copied+"-wal"); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, copied+"-shm"); err != nil {
		t.Fatal(err)
	}
	giveFiles(serviceUID, serviceUID, copied, copied+"-wal", copied+"-shm", filepath.Join(dir, "missing"))
	for p, want := range map[string]uint32{copied: serviceUID, outside: 0} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Sys().(*syscall.Stat_t).Uid; got != want {
			t.Errorf("%s: uid %d, want %d", p, got, want)
		}
	}
}

// A migration's target is the owner's after each of its commands, run as
// root (its keys are root's), so varlatchd starts on it; and what an earlier
// release's commands left as root's is handed over by the next command.
func TestMigrateAsRootLeavesTheOwnersFiles(t *testing.T) {
	h := newRootHost(t)
	s := migrationtest.Load(t)
	bundle := filepath.Join(h.private, "bundle")
	if err := os.WriteFile(bundle, migrationtest.Bundle(t, s, migrationtest.Options{}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.private, "root-kek"), []byte(hex.EncodeToString(s.RootKEK)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, status := h.admin("migrate", "import", "--in", bundle); status != ExitOK {
		t.Fatalf("import: %d %s", status, out)
	}
	h.owned("migrate import")
	if out, status := h.admin("migrate", "state"); status != ExitOK {
		t.Fatalf("state: %d %s", status, out)
	}
	h.owned("migrate state")

	for _, name := range []string{LockFile, "varlatch.db"} {
		if err := os.Chown(filepath.Join(h.data, name), 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	if out, status := h.admin("backup", "run"); status != ExitOK {
		t.Fatalf("after an earlier release's: %d %s", status, out)
	}
	h.owned("an earlier release's files")
}

// A data directory that is root's keeps root's commands root's, and a path
// its owner could have changed is refused.
func TestAdminAsRootWhoseDirectory(t *testing.T) {
	h := newRootHost(t)
	if err := os.Chown(h.data, 0, 0); err != nil {
		t.Fatal(err)
	}
	if out, status := h.admin("bootstrap"); status != ExitOK || !strings.Contains(out, "ids 0 0 0 0") {
		t.Fatalf("root's directory: %d %s", status, out)
	}
	if err := os.Chown(h.data, serviceUID, serviceUID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.data, 0o770); err != nil {
		t.Fatal(err)
	}
	if out, status := h.admin("schema", "status"); status != ExitConfig || !strings.Contains(out, "may be written by its group") || !strings.Contains(out, "nothing was sent or written") {
		t.Fatalf("a directory its group writes: %d %s", status, out)
	}
}

func TestStaysRoot(t *testing.T) {
	for _, args := range [][]string{{"kek", "verify"}, {"config", "check"}, {"doctor"}, {"outbound", "check"}, {"migrate", "state"}, {"tailnet", "reaches"}} {
		if !staysRoot(args[0], args[1:]) {
			t.Errorf("%q", args)
		}
	}
	for _, args := range [][]string{{"backup", "restore"}, {"schema", "status"}, {"tailnet", "enroll"}, {"tailnet", "take-name"}, {"maintenance", "begin"}, {"status"}} {
		if staysRoot(args[0], args[1:]) {
			t.Errorf("%q", args)
		}
	}
}
