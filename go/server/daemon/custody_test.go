// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
)

// The key custody host commands, as the TypeScript admin CLI runs them:
// the escrow blob and the Shamir split both give the Root KEK back,
// checked against the installation's canary (or, on a fresh host, with a
// warning), a wrong key fails verify, and the attestations are recorded
// through the daemon and offline and read back for the current key
// version. During maintenance kek and custody attest are refused, and
// custody status is not.
func TestKeyCustodyCommands(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	dir := in.dir
	pass := filepath.Join(dir, "passphrase")
	if err := os.WriteFile(pass, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	material, _ := os.ReadFile(in.kekFile)
	rootKEK, err := envelope.ParseRootKEK(string(material))
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		t.Helper()
		return runAdmin(t, append(args, "--config", in.conf)...)
	}
	keyHex := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v", path, st.Mode())
		}
		return strings.TrimSpace(string(b))
	}

	// A fresh host: no database yet. The key is written with a warning.
	// Existing output files are replaced with mode 0600.
	for _, name := range []string{"blob.json", "restored2", "combined"} {
		os.WriteFile(filepath.Join(dir, name), []byte("old"), 0o644)
	}
	mode := func(name string) os.FileMode {
		t.Helper()
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return st.Mode().Perm()
	}
	code, out, errOut := run("kek", "export", "--out", filepath.Join(dir, "blob.json"), "--passphrase-file", pass)
	if code != ExitOK || out != "Escrow blob written to "+filepath.Join(dir, "blob.json")+".\n" || !strings.Contains(errOut, "only the passphrase must be custodied separately") {
		t.Fatalf("export: %d %q %q", code, out, errOut)
	}
	if mode("blob.json") != 0o600 {
		t.Errorf("the escrow blob's mode is %v", mode("blob.json"))
	}
	code, out, errOut = run("kek", "restore", "--in", filepath.Join(dir, "blob.json"), "--out", filepath.Join(dir, "restored"), "--passphrase-file", pass)
	if code != ExitOK || !strings.HasPrefix(errOut, "WARNING: could not reach the database to verify the restored KEK") || keyHex(filepath.Join(dir, "restored")) != hex.EncodeToString(rootKEK) {
		t.Fatalf("restore on a fresh host: %d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); !os.IsNotExist(err) {
		t.Errorf("kek created the database: %v", err)
	}

	r := start(t, in)
	code, out, errOut = run("kek", "verify")
	if code != ExitOK || out != "KEK backup matches this installation.\n" {
		t.Errorf("verify: %d %q %q", code, out, errOut)
	}
	wrong := filepath.Join(dir, "wrong")
	os.WriteFile(wrong, []byte(hex.EncodeToString(envelope.GenerateKey())), 0o600)
	if code, _, errOut := run("kek", "verify", "--file", wrong); code != ExitFailure || errOut != "KEK verification failed.\n" {
		t.Errorf("verify a wrong key: %d %q", code, errOut)
	}
	code, out, errOut = run("kek", "restore", "--in", filepath.Join(dir, "blob.json"), "--out", filepath.Join(dir, "restored2"), "--passphrase-file", pass)
	if code != ExitOK || out != "restored KEK verified against the installation canary.\nKEK written to "+filepath.Join(dir, "restored2")+" (mode 0600).\n" ||
		keyHex(filepath.Join(dir, "restored2")) != hex.EncodeToString(rootKEK) {
		t.Errorf("restore: %d %q %q", code, out, errOut)
	}
	bad := filepath.Join(dir, "badpass")
	os.WriteFile(bad, []byte("not the passphrase at all"), 0o600)
	if code, _, errOut := run("kek", "restore", "--in", filepath.Join(dir, "blob.json"), "--out", filepath.Join(dir, "x"), "--passphrase-file", bad); code != ExitFailure || errOut != "Decryption failed: authentication error\n" {
		t.Errorf("restore with a wrong passphrase: %d %q", code, errOut)
	}

	code, out, errOut = run("kek", "split", "--shares", "5", "--threshold", "3")
	shares := strings.Fields(out)
	if code != ExitOK || len(shares) != 5 || !regexp.MustCompile(`^Any 3 of these 5 shares reconstruct the KEK; fewer reveal nothing\.\nGive each share to a different custodian; never store two together\.\nSplit fingerprint: [0-9a-f]{8}\n\n$`).MatchString(errOut) {
		t.Fatalf("split: %d %q %q", code, out, errOut)
	}
	code, out, errOut = run("kek", "combine", "--out", filepath.Join(dir, "combined"), "--share", shares[4], "--share", shares[0], "--share", shares[2])
	if code != ExitOK || !strings.HasPrefix(out, "combined KEK verified against the installation canary.\n") || keyHex(filepath.Join(dir, "combined")) != hex.EncodeToString(rootKEK) {
		t.Errorf("combine: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := run("kek", "combine", "--out", filepath.Join(dir, "y"), "--share", shares[0], "--share", shares[1]); code != ExitFailure || errOut != "Need 3 distinct shares, got 2\n" {
		t.Errorf("combine with too few: %d %q", code, errOut)
	}
	if code, _, errOut := run("kek", "split", "--shares", "five", "--threshold", "3"); code != ExitFailure || !strings.HasPrefix(errOut, "Usage: admin kek split") {
		t.Errorf("split usage: %d %q", code, errOut)
	}

	if left, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}

	// Attestations, through the daemon.
	code, out, errOut = run("custody", "attest", "--key", "root-kek", "--method", "shamir-split")
	var a struct {
		Key, Method, At string
		KeyVersion      *int
	}
	if code != ExitOK || json.Unmarshal([]byte(out), &a) != nil || a.Key != "root-kek" || a.Method != "shamir-split" || a.KeyVersion == nil || *a.KeyVersion != 1 {
		t.Fatalf("attest: %d %q %q", code, out, errOut)
	}
	if code, out, _ := run("custody", "attest", "--key", "backup-key", "--method", "copy"); code != ExitOK || !strings.HasSuffix(out, `"keyVersion":null}`+"\n") {
		t.Errorf("attest the backup key: %d %q", code, out)
	}
	if code, _, errOut := run("custody", "attest", "--key", "bek", "--method", "copy"); code != ExitFailure || !strings.Contains(errOut, "key must be one of root-kek, backup-key") {
		t.Errorf("attest another key: %d %q", code, errOut)
	}
	code, out, _ = run("custody", "status")
	if want := `{"rootKekVersion":1,"attestations":{"root-kek":{"key":"root-kek","method":"shamir-split","at":"` + a.At + `","keyVersion":1},"backup-key":{"key":"backup-key","method":"copy","at":`; code != ExitOK || !strings.HasPrefix(out, want) {
		t.Errorf("status: %d %q", code, out)
	}

	// During maintenance.
	code, out, _ = run("maintenance", "begin", "--ttl", "1m")
	var gate backup.Gate
	if code != ExitOK || json.Unmarshal([]byte(out), &gate) != nil {
		t.Fatal(out)
	}
	if code, _, errOut := run("kek", "verify"); code != ExitFailure || !strings.Contains(errOut, MaintenanceRefusal) {
		t.Errorf("kek during maintenance: %d %q", code, errOut)
	}
	if code, _, errOut := run("custody", "attest", "--key", "backup-key", "--method", "copy"); code != ExitFailure || !strings.Contains(errOut, MaintenanceRefusal) {
		t.Errorf("attest during maintenance: %d %q", code, errOut)
	}
	if code, _, errOut := run("custody", "status"); code != ExitOK {
		t.Errorf("status during maintenance: %d %q", code, errOut)
	}
	run("maintenance", "end", gate.ID)
	r.stop(t)

	// Offline.
	if code, out, errOut := run("custody", "attest", "--key", "root-kek", "--method", "passphrase-escrow"); code != ExitOK || !strings.Contains(out, `"method":"passphrase-escrow"`) {
		t.Errorf("attest offline: %d %q %q", code, out, errOut)
	}
	time.Sleep(2 * time.Millisecond)
	if code, out, _ := run("custody", "status"); code != ExitOK || !strings.Contains(out, `"root-kek":{"key":"root-kek","method":"passphrase-escrow"`) {
		t.Errorf("status offline: %d %q", code, out)
	}
}

// varlatchd admin run by hand outside the unit (what doctor's remedies and
// the README give): the configuration names no key file, and the keys are
// beside it, where the unit's LoadCredential reads them. Offline and
// through the running daemon, the admin commands find them there; with no
// Root KEK beside the configuration they say what is lacking.
func TestAdminFindsTheKeysBesideTheConfiguration(t *testing.T) {
	in := newInstall(t, "")
	if err := os.WriteFile(filepath.Join(in.dir, "backup-key"), []byte(hex.EncodeToString(envelope.GenerateKey())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := "listen = 127.0.0.1:0\ndata_dir = " + in.data + "\naccess_log = " + in.accessLog + "\nbackup_interval = off\n"
	if err := os.WriteFile(in.conf, []byte(conf), 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if code, out, errOut := runAdmin(t, "bootstrap-status", "--config", in.conf); code != ExitOK {
		t.Fatalf("bootstrap-status on a fresh host: %d %q %q", code, out, errOut)
	}
	// The daemon as its unit runs it, its credentials handed in.
	t.Setenv("CREDENTIALS_DIRECTORY", in.dir)
	r := start(t, in)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if code, out, errOut := runAdmin(t, "backup", "run", "--json", "--config", in.conf); code != ExitOK || !strings.Contains(out, `"keyMatch":true`) {
		t.Fatalf("backup run: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := runAdmin(t, "custody", "status", "--config", in.conf); code != ExitOK {
		t.Fatalf("custody status: %d %q %q", code, out, errOut)
	}
	r.stop(t)
	if code, out, errOut := runAdmin(t, "custody", "status", "--config", in.conf); code != ExitOK {
		t.Fatalf("custody status offline: %d %q %q", code, out, errOut)
	}

	elsewhere := filepath.Join(t.TempDir(), "varlatchd.conf")
	if err := os.WriteFile(elsewhere, []byte(conf), 0o640); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runAdmin(t, "custody", "status", "--config", elsewhere); code != ExitConfig || !strings.Contains(errOut, "no Root KEK") {
		t.Fatalf("no Root KEK beside the configuration: %d %q", code, errOut)
	}
}
