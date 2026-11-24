// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/config"
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
	stdin                    string
	env                      []string
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
	cmd.Env = append(cmd.Env, h.env...)
	cmd.Dir = h.private
	if h.stdin != "" {
		cmd.Stdin = strings.NewReader(h.stdin)
	}
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

func (h *rootHost) cfg() *config.Config { return &config.Config{DataDir: h.data} }

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
		if !staysRoot(h.cfg(), args[0], args[1:]) && !strings.Contains(out, want) {
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
	// A copy elsewhere is its caller's: root's, in a directory of root's.
	elsewhere := filepath.Join(h.private, "copy.db")
	if b, err := os.ReadFile(filepath.Join(h.data, "varlatch.db")); err != nil || os.WriteFile(elsewhere, b, 0o600) != nil {
		t.Fatal(err)
	}
	if out := run("schema", "upgrade", "--json", "--database", elsewhere); !strings.Contains(out, "ids 0 0 0 0") {
		t.Fatalf("a copy elsewhere: %s", out)
	}
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
// leads root nowhere: the command replaces it, or refuses.
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
	for _, c := range []struct {
		name string
		args []string
		ok   bool
		want string
	}{
		{"varlatch.db.restore", []string{"backup", "restore", "--in", archive}, true, "Restore completed"},
		{".restore-work", []string{"backup", "restore", "--in", archive}, true, "Restore completed"},
		{"varlatch.db-shm", []string{"backup", "restore", "--in", archive}, false, "unable to open database file"},
		{"varlatch.db-wal", []string{"backup", "run"}, false, "unable to open database file"},
		{"varlatch.db", []string{"backup", "run"}, false, "unable to open database file"},
		{LockFile, []string{"backup", "run"}, false, "cannot lock the data directory"},
		{backup.GateFile, []string{"maintenance", "begin", "--ttl", "10m"}, false, "Maintenance state is unreadable"},
		{"release-check.json", []string{"release-check", "record", "--repo", "varlatch/varlatch", "--version", "0.50.0"}, true, `"0.50.0"`},
	} {
		path := filepath.Join(h.data, c.name)
		aside := filepath.Join(h.private, "aside")
		if err := os.Rename(path, aside); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := os.Lchown(path, serviceUID, serviceUID); err != nil {
			t.Fatal(err)
		}
		out, status := h.admin(c.args...)
		if (status == ExitOK) != c.ok || !strings.Contains(out, c.want) {
			t.Errorf("%s: %d, want ok %v and %q:\n%s", c.name, status, c.ok, c.want, out)
		}
		b, err := os.ReadFile(target)
		info, serr := os.Stat(target)
		if err != nil || serr != nil || string(b) != "root's" || info.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Fatalf("%s: root's file is %q, %v %v", c.name, b, err, serr)
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			_ = os.Remove(path)
		}
		if err := os.Rename(aside, path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}

// What an earlier release's commands, run as root, left in the data
// directory is the owner's after the next command: a store of backups, a
// stopped restore, the lock, the database. Nothing of root's elsewhere is
// given, by a link, by a hard link, or through a mount.
func TestAdminAsRootGivesWhatWasLeft(t *testing.T) {
	h := newRootHost(t)
	if out, status := h.admin("bootstrap"); status != ExitOK {
		t.Fatal(out)
	}
	if out, status := h.admin("backup", "run"); status != ExitOK {
		t.Fatal(out)
	}
	outside := filepath.Join(h.dir, "outside")
	if err := os.WriteFile(outside, []byte("root's"), 0o600); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(h.data, ".restore-work", "varlatch-backup-1")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "varlatch.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(h.data, func(p string, _ fs.DirEntry, err error) error {
		if err != nil || p == h.data {
			return err
		}
		return os.Lchown(p, 0, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(h.data, "hard")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(h.data, "soft")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h.private, filepath.Join(h.data, "dir")); err != nil {
		t.Fatal(err)
	}
	// What is none of varlatchd's stays root's, and is named: a file of the
	// operator's, one with an archive's name elsewhere, a directory, one with
	// a name of varlatchd's in it, one where varlatchd makes no such name.
	theirs := []string{"notes", "x.vltbak", "kept/varlatch.db", "kept", "backups/notes", "upgrades/a/b/varlatch.db"}
	for _, name := range theirs {
		p := filepath.Join(h.data, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("root's"), 0o600); err != nil && !os.IsExist(err) && name != "kept" {
			t.Fatal(err)
		}
	}
	out, status := h.admin("backup", "status")
	if status != ExitOK || !strings.Contains(out, "left as it is in the data directory, root's and not varlatchd's: ") {
		t.Fatalf("%d %s", status, out)
	}
	for _, name := range []string{"notes", "x.vltbak", "kept", "backups/notes", "upgrades/a/b", "hard", "soft", "dir"} {
		if !strings.Contains(out, strconv.Quote(filepath.Join(h.data, name))) {
			t.Errorf("%s is not named: %s", name, out)
		}
	}
	for _, name := range theirs {
		info, err := os.Lstat(filepath.Join(h.data, name))
		if err != nil || info.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Errorf("%s: %v %v", name, info, err)
		}
	}
	for _, name := range []string{"notes", "x.vltbak", "kept", "backups/notes", "upgrades/a"} {
		if err := os.RemoveAll(filepath.Join(h.data, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"backup", "status"}, {"backup", "run"}, {"schema", "status"}} {
		if out, status := h.admin(args...); status != ExitOK {
			t.Fatalf("%q: %d %s", args, status, out)
		}
	}
	archives, _ := filepath.Glob(filepath.Join(h.data, "backups", "*.vltbak"))
	if out, status := h.admin("backup", "restore", "--in", archives[0]); status != ExitOK {
		t.Fatalf("a restore over a stopped one: %d %s", status, out)
	}
	for _, p := range []string{outside, h.private, filepath.Join(h.private, "root-kek")} {
		info, err := os.Stat(p)
		if err != nil || info.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Errorf("%s: %v %v", p, info, err)
		}
	}
	for _, name := range []string{"hard", "soft", "dir"} {
		if err := os.Remove(filepath.Join(h.data, name)); err != nil {
			t.Fatal(err)
		}
	}
	h.owned("an earlier release's leftovers")
}

// tailnet take-name, its authority and the node's key root's only: it goes
// as far as the node it does not find held.
func TestAdminAsRootTakeName(t *testing.T) {
	h := newRootHost(t)
	for name, content := range map[string]string{"auth-key": "key", "oauth.json": `{"clientId":"a","clientSecret":"b"}`} {
		if err := os.WriteFile(filepath.Join(h.private, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	conf, _ := os.ReadFile(h.conf)
	if err := os.WriteFile(h.conf, append(conf, []byte("tailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = "+filepath.Join(h.private, "auth-key")+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	oauth := filepath.Join(h.private, "oauth.json")
	out, status := h.admin("tailnet", "take-name", "--oauth-client-file", oauth)
	if status != ExitFailure || !strings.Contains(out, "the node is not held for a handoff") || !strings.Contains(out, fmt.Sprintf("ids %d ", serviceUID)) {
		t.Fatalf("%d %s", status, out)
	}
	h.owned("tailnet take-name")
	if err := os.Chmod(oauth, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, status := h.admin("tailnet", "take-name", "--oauth-client-file", oauth); status != ExitFailure || !strings.Contains(out, "tighten it to 0600") {
		t.Fatalf("an authority open to others: %d %s", status, out)
	}
}

// The trusted certificates of SSL_CERT_FILE, root's only, are loaded before
// root's identity goes: an upload to a server of that authority works.
func TestAdminAsRootTrustsACAOnlyRootReads(t *testing.T) {
	h := newRootHost(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no such bucket", http.StatusNotFound) }))
	defer srv.Close()
	ca := filepath.Join(h.private, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	destinations := filepath.Join(h.private, "destinations.json")
	if err := os.WriteFile(destinations, []byte(`{"offsite":{"endpoint":"`+srv.URL+`","region":"us-east-1","bucket":"b","writeCredentialsFile":"write.json"}}`), 0o600); err != nil {
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
	if out, status := h.admin("bootstrap"); status != ExitOK {
		t.Fatal(out)
	}
	h.env = []string{"SSL_CERT_FILE=" + ca}
	out, status := h.admin("backup", "run")
	if status != ExitFailure || strings.Contains(out, "x509") || strings.Contains(out, "certificate") || !strings.Contains(out, "Archive created") {
		t.Fatalf("%d %s", status, out)
	}
	h.env = nil
	if out, _ := h.admin("backup", "run"); !strings.Contains(out, "certificate") {
		t.Fatalf("without the authority: %s", out)
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

	id := "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	h.stdin = `{"format":1,"id":"` + id + `","phase":"open"}`
	if out, status := h.admin("migrate", "state", "--write"); status != ExitOK {
		t.Fatalf("state --write: %d %s", status, out)
	}
	h.owned("migrate state --write")
	h.stdin = ""
	if out, status := h.admin("migrate", "barrier", "--id", id); status != ExitOK {
		t.Fatalf("barrier: %d %s", status, out)
	}
	h.owned("migrate barrier")
	if out, status := h.admin("migrate", "release", "--id", id); status != ExitOK {
		t.Fatalf("release: %d %s", status, out)
	}
	h.owned("migrate release")

	// What varlatch migrate stages for the target's user (Options.StageAs),
	// in a directory of that user's: the dry run's scratch database, and the
	// reverse bundle with its kept copy.
	stage := filepath.Join(h.dir, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(stage, serviceUID, serviceUID); err != nil {
		t.Fatal(err)
	}
	if out, status := h.admin("migrate", "import", "--in", bundle, "--scratch", filepath.Join(stage, "data")); status != ExitOK {
		t.Fatalf("import --scratch: %d %s", status, out)
	}
	if out, status := h.admin("migrate", "export", "--reverse", "--out", filepath.Join(stage, "reverse.jsonl"), "--keep", filepath.Join(stage, "keep")); status != ExitOK {
		t.Fatalf("export: %d %s", status, out)
	}
	for _, name := range []string{"data/varlatch.db", "reverse.jsonl", "keep/varlatch.db"} {
		info, err := os.Stat(filepath.Join(stage, name))
		if err != nil || info.Sys().(*syscall.Stat_t).Uid != serviceUID {
			t.Errorf("%s: %v %v", name, info, err)
		}
	}
	h.owned("migrate export")

	// A reverse bundle in a directory only root enters is root's, made
	// before the command becomes the owner, and gone when it fails.
	out := filepath.Join(h.private, "reverse.jsonl")
	if text, status := h.admin("migrate", "export", "--reverse", "--out", out, "--keep", filepath.Join(h.private, "keep")); status == ExitOK || !strings.Contains(text, "--keep") {
		t.Fatalf("a kept copy the owner cannot make: %d %s", status, text)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("a failed export left its bundle: %v", err)
	}
	if text, status := h.admin("migrate", "export", "--reverse", "--out", out); status != ExitOK {
		t.Fatalf("export to root's directory: %d %s", status, text)
	}
	info, err := os.Stat(out)
	if err != nil || info.Size() == 0 || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Errorf("%v %v", info, err)
	}
	if text, status := h.admin("migrate", "export", "--reverse", "--out", out); status != ExitFailure || !strings.Contains(text, "new file") {
		t.Fatalf("over a file: %d %s", status, text)
	}
	if again, err := os.Stat(out); err != nil || again.Size() != info.Size() {
		t.Errorf("the bundle there changed: %v %v", again, err)
	}
	h.owned("migrate export to root's directory")
}

// The keys are root's, and nothing is made in the data directory for them.
func TestMigrateKeysAsRoot(t *testing.T) {
	h := newRootHost(t)
	kek, bek := filepath.Join(h.private, "root-kek"), filepath.Join(h.private, "backup-key")
	kekText, _ := os.ReadFile(kek)
	bekText, _ := os.ReadFile(bek)
	for _, p := range []string{kek, bek} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	in, _ := json.Marshal(map[string][]byte{"rootKek": kekText, "bek": bekText})
	h.stdin = string(in)
	out, status := h.admin("migrate", "keys")
	if status != ExitOK || !strings.Contains(out, "ids 0 0 0 0") {
		t.Fatalf("%d %s", status, out)
	}
	for _, p := range []string{kek, bek} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Errorf("%s: %v %v", p, info, err)
		}
	}
	if entries, _ := os.ReadDir(h.data); len(entries) != 0 {
		t.Errorf("the data directory holds %v", entries)
	}
}

// A key file whose directory another user may change is written as the
// data directory's owner, never by root at a path that user can lead
// elsewhere.
func TestMigrateKeysAsRootBelowTheDataDirectory(t *testing.T) {
	h := newRootHost(t)
	keys := filepath.Join(h.data, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(keys, serviceUID, serviceUID); err != nil {
		t.Fatal(err)
	}
	kekText, _ := os.ReadFile(filepath.Join(h.private, "root-kek"))
	in, _ := json.Marshal(map[string][]byte{"rootKek": kekText})
	h.stdin = string(in)
	conf, _ := os.ReadFile(h.conf)
	if err := os.WriteFile(h.conf, []byte(strings.ReplaceAll(string(conf), h.private, keys)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, status := h.admin("migrate", "keys")
	if want := fmt.Sprintf("ids %d %d", serviceUID, serviceUID); status != ExitOK || !strings.Contains(out, want) {
		t.Fatalf("%d %s", status, out)
	}
	h.owned("migrate keys")
	// One of them elsewhere: root's directory is not the owner's to write in.
	if err := os.Remove(filepath.Join(keys, "root-kek")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(h.private, "taken"), filepath.Join(keys, "root-kek")); err != nil {
		t.Fatal(err)
	}
	if out, status := h.admin("migrate", "keys"); status == ExitOK {
		t.Fatalf("through a link: %s", out)
	}
	if _, err := os.Lstat(filepath.Join(h.private, "taken")); !os.IsNotExist(err) {
		t.Fatalf("root wrote through a link: %v", err)
	}
}

// schema upgrade --database keeps root for root's own database only: what
// leads to the configured one, by any path, is the owner's work.
func TestAdminAsRootSchemaOfADatabase(t *testing.T) {
	h := newRootHost(t)
	if out, status := h.admin("bootstrap"); status != ExitOK {
		t.Fatal(out)
	}
	live := filepath.Join(h.data, "varlatch.db")
	owners := fmt.Sprintf("ids %d %d", serviceUID, serviceUID)
	upgrade := func(path string) (string, int) { return h.admin("schema", "upgrade", "--database", path) }

	alias := filepath.Join(h.dir, "alias")
	if err := os.Symlink(h.data, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{live, filepath.Join(alias, "varlatch.db"), filepath.Join(h.private, "..", "data", "varlatch.db")} {
		if out, status := upgrade(path); status != ExitOK || !strings.Contains(out, owners) {
			t.Errorf("%s: %d %s", path, status, out)
		}
	}
	link, hard := filepath.Join(h.private, "link.db"), filepath.Join(h.private, "hard.db")
	if err := os.Symlink(live, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(live, hard); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, hard} {
		if out, status := upgrade(path); status == ExitOK || !strings.Contains(out, owners) {
			t.Errorf("%s: %d %s", path, status, out)
		}
	}
	if err := os.Remove(hard); err != nil {
		t.Fatal(err)
	}
	// Root's own copy, in root's directory.
	b, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(h.private, "own.db")
	if err := os.WriteFile(own, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, status := upgrade(own); status != ExitOK || !strings.Contains(out, "ids 0 0 0 0") {
		t.Errorf("root's own: %d %s", status, out)
	}
	h.owned("schema upgrade --database")
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
	if out, status := h.admin("schema", "status"); status != ExitConfig || !strings.Contains(out, "may be written by its group") {
		t.Fatalf("a directory its group writes: %d %s", status, out)
	}
}

func TestStaysRoot(t *testing.T) {
	cfg := &config.Config{DataDir: "/var/lib/varlatch"}
	for _, args := range [][]string{{"kek", "verify"}, {"config", "check"}, {"doctor"}, {"outbound", "check"}, {"migrate", "keys"}, {"tailnet", "reaches"}} {
		if !staysRoot(cfg, args[0], args[1:]) {
			t.Errorf("%q", args)
		}
	}
	for _, args := range [][]string{{"backup", "restore"}, {"schema", "status"}, {"tailnet", "enroll"}, {"tailnet", "take-name"}, {"maintenance", "begin"}, {"status"},
		{"migrate", "import", "--in", "x"}, {"migrate", "open"}, {"migrate", "barrier"}, {"migrate", "state"},
		{"schema", "upgrade"}, {"schema", "upgrade", "--database", "/var/lib/varlatch/upgrades/x/db/varlatch.db"}, {"schema", "upgrade", "--database", "/root/../var/lib/varlatch/x.db"}, {"schema", "upgrade", "--database", "/nowhere/varlatch.db"}} {
		if staysRoot(cfg, args[0], args[1:]) {
			t.Errorf("%q", args)
		}
	}
}
