// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// forwardBundle is a forward bundle of a fresh installation, and its Root
// KEK file: what a migration's import reads.
func forwardBundle(t *testing.T) (string, []byte) {
	t.Helper()
	src := newInstall(t, "backup_interval = off\n")
	start(t, src).stop(t)
	out := filepath.Join(t.TempDir(), "reverse.jsonl")
	if code, _, errOut := runAdmin(t, "migrate", "export", "--reverse", "--out", out, "--config", src.conf); code != ExitOK {
		t.Fatalf("export: %d %q", code, errOut)
	}
	rev, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	fwd := filepath.Join(t.TempDir(), "forward.jsonl")
	if err := os.WriteFile(fwd, asForward(t, rev), 0o600); err != nil {
		t.Fatal(err)
	}
	kek, err := os.ReadFile(src.kekFile)
	if err != nil {
		t.Fatal(err)
	}
	return fwd, kek
}

// enrolLike leaves in dir what `admin tailnet enroll` leaves: the node's
// state directory, its pin, the hold and the listeners report.
func enrolLike(t *testing.T, dir string, hold bool) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, tailnet.StateDir, "certs"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		filepath.Join(tailnet.StateDir, "tailscaled.state"): "{}",
		tailnet.PinFile:       `{"suffix":"corp.ts.net"}`,
		tailnet.ListenersFile: "{}",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if hold {
		if err := tailnet.SaveHold(dir, &tailnet.Hold{Hostname: "vault-vl-0a1b2c3d4e5f-n", Since: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
}

// The import accepts a target whose tailnet node was enrolled, held, for
// the migration's handoff (go-step7 decision 11) and keeps its files; it
// still refuses anything else in the data directory: a stray file, a node
// no handoff holds, a look-alike of the node's files.
func TestTheImportBesideAHeldNode(t *testing.T) {
	fwd, kek := forwardBundle(t)
	target := func(t *testing.T) install {
		in := newInstall(t, "backup_interval = off\n")
		if err := os.WriteFile(in.kekFile, kek, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(in.data, 0o700); err != nil {
			t.Fatal(err)
		}
		return in
	}
	refused := func(t *testing.T, in install, want string) {
		t.Helper()
		code, _, errOut := runAdmin(t, "migrate", "import", "--in", fwd, "--config", in.conf)
		if code != ExitFailure || !strings.Contains(errOut, want) {
			t.Fatalf("import: %d %q, want %q", code, errOut, want)
		}
		if _, err := os.Stat(filepath.Join(in.data, "varlatch.db")); err == nil {
			t.Fatal("a refused import left a database")
		}
	}

	t.Run("held", func(t *testing.T) {
		in := target(t)
		enrolLike(t, in.data, true)
		if code, out, errOut := runAdmin(t, "migrate", "import", "--in", fwd, "--json", "--config", in.conf); code != ExitOK {
			t.Fatalf("import beside a held node: %d %q %q", code, out, errOut)
		}
		for _, name := range []string{tailnet.StateDir, tailnet.PinFile, tailnet.HoldFile, tailnet.ListenersFile, "varlatch.db"} {
			if _, err := os.Stat(filepath.Join(in.data, name)); err != nil {
				t.Errorf("%s after the import: %v", name, err)
			}
		}
	})
	t.Run("a stray file", func(t *testing.T) {
		in := target(t)
		enrolLike(t, in.data, true)
		if err := os.WriteFile(filepath.Join(in.data, "notes.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, in, "is not empty (notes.txt)")
	})
	t.Run("a node no handoff holds", func(t *testing.T) {
		in := target(t)
		enrolLike(t, in.data, false)
		refused(t, in, "no handoff holds")
	})
	t.Run("a look-alike", func(t *testing.T) {
		in := target(t)
		if err := os.WriteFile(filepath.Join(in.data, tailnet.StateDir), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		refused(t, in, "not what a tailnet enrolment leaves")
		if err := os.Remove(filepath.Join(in.data, tailnet.StateDir)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), filepath.Join(in.data, tailnet.PinFile)); err != nil {
			t.Fatal(err)
		}
		refused(t, in, "not what a tailnet enrolment leaves")
	})
}

// `admin migrate keys` writes the new tailnet node's auth key into the
// target's tailnet_auth_key_file (0600) beside the Root KEK, finds it the
// same on a second run, refuses another before anything is written, and
// prints none; `admin migrate state` reports the tailnet's settings and
// the node's hold, never the key.
func TestTheTailnetAuthKeyAndState(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	keyFile := filepath.Join(filepath.Dir(in.conf), "tailnet-auth-key")
	in.write(t, "backup_interval = off\ntailnet = on\ntailnet_hostname = vault\ntailnet_tags = tag:varlatch\ntailnet_port = 8687\ntailnet_auth_key_file = "+keyFile+"\n")
	_ = os.Remove(in.kekFile)
	kek := []byte(hex.EncodeToString(envelope.GenerateKey()) + "\n")
	authKey := []byte("node-key-" + hex.EncodeToString(envelope.GenerateKey()[:8]))
	doc := func(key []byte) []byte {
		b, err := json.Marshal(struct {
			RootKEK        []byte `json:"rootKek"`
			TailnetAuthKey []byte `json:"tailnetAuthKey"`
		}{kek, key})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	code, out, errOut := runAdmin(t, "migrate", "state", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"tailnet":{"hostname":"vault","tags":["tag:varlatch"],"httpsPort":0,"authKey":false,"enrolled":false,"heldAs":"","pinnedTo":""}`) {
		t.Fatalf("state before: %d %q %q", code, out, errOut)
	}
	code, out, errOut = migrateWith(t, in.conf, doc(authKey), "keys")
	if code != ExitOK || strings.TrimSpace(out) != `{"rootKek":"written","bek":"absent","tailnetAuthKey":"written"}` || strings.Contains(out+errOut, string(authKey)) {
		t.Fatalf("keys: %d %q %q", code, out, errOut)
	}
	if b, err := os.ReadFile(keyFile); err != nil || strings.TrimSpace(string(b)) != string(authKey) {
		t.Fatalf("the auth key file: %q %v", b, err)
	}
	if st, err := os.Stat(keyFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the auth key file's mode: %v %v", st, err)
	}
	code, out, _ = migrateWith(t, in.conf, doc(authKey), "keys")
	if code != ExitOK || strings.TrimSpace(out) != `{"rootKek":"unchanged","bek":"absent","tailnetAuthKey":"unchanged"}` {
		t.Fatalf("keys again: %d %q", code, out)
	}
	if code, _, errOut := migrateWith(t, in.conf, doc([]byte("another-key")), "keys"); code != ExitFailure || !strings.Contains(errOut, "another key") {
		t.Fatalf("another auth key: %d %q", code, errOut)
	}
	enrolLike(t, in.data, true)
	code, out, _ = runAdmin(t, "migrate", "state", "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"authKey":true,"enrolled":true,"heldAs":"vault-vl-0a1b2c3d4e5f-n","pinnedTo":"corp.ts.net"`) || strings.Contains(out, string(authKey)) {
		t.Fatalf("state after: %d %q", code, out)
	}
	// Without tailnet = on, an auth key is refused.
	in.write(t, "backup_interval = off\n")
	if code, _, errOut := migrateWith(t, in.conf, doc(authKey), "keys"); code != ExitConfig || !strings.Contains(errOut, "tailnet_auth_key_file") {
		t.Fatalf("an auth key without the tailnet: %d %q", code, errOut)
	}
}

// The tailnet handoff's journal writes beside the running varlatchd
// (go-step7 decisions 11 and 14): the forward handoff runs in the
// transfer, beside the varlatchd serving under the transfer's gate, and
// saves its state before each act, so each is the same phase again; a
// rollback's runs in the reverse's phases, beside the varlatchd the
// reverse reverses. Every write is taken and read back; open beside it
// still waits for it to stop.
func TestTheHandoffsJournalBesideARunningVarlatchd(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	for _, phase := range []string{"started", "transfer"} {
		if code, _, errOut := migrateWith(t, in.conf, journalText(migA, phase), "state", "--write"); code != ExitOK {
			t.Fatal(errOut)
		}
	}
	withHandoff := func(phase, slot, state string) []byte {
		return []byte(`{"format":1,"id":"` + migA + `","phase":"` + phase + `","tailnet":{"name":"vault","operation":"abcdefghij","` + slot +
			`":{"version":1,"phase":"` + state + `","plan":{"kind":"forward","operation":"abcdefghij","name":"vault"}}},"history":[]}`)
	}
	r := start(t, in)
	for _, state := range []string{"prepared", "switching", "done"} {
		if code, _, errOut := migrateWith(t, in.conf, withHandoff("transfer", "handoff", state), "state", "--write"); code != ExitOK {
			t.Fatalf("the handoff %s beside the running varlatchd: %d %q", state, code, errOut)
		}
		if code, out, _ := migrateWith(t, in.conf, nil, "state"); code != ExitOK || !strings.Contains(out, `"phase":"`+state+`"`) {
			t.Fatalf("the handoff %s read back: %q", state, out)
		}
	}
	if code, _, errOut := migrateWith(t, in.conf, withHandoff("open", "handoff", "done"), "state", "--write"); code != ExitFailure || !strings.Contains(errOut, "varlatchd is running") {
		t.Fatalf("an open beside the running varlatchd: %d %q", code, errOut)
	}
	r.stop(t)
	if code, _, errOut := migrateWith(t, in.conf, withHandoff("open", "handoff", "done"), "state", "--write"); code != ExitOK {
		t.Fatal(errOut)
	}
	// The reverse, beside the varlatchd it reverses.
	r = start(t, in)
	for _, step := range [][2]string{{"rollback", "prepared"}, {"rollback-exported", "prepared"}, {"rollback-transfer", "switching"}, {"rollback-transfer", "done"}} {
		if code, _, errOut := migrateWith(t, in.conf, withHandoff(step[0], "rollback", step[1]), "state", "--write"); code != ExitOK {
			t.Fatalf("%s with the rollback's handoff %s beside the running varlatchd: %d %q", step[0], step[1], code, errOut)
		}
	}
	if code, out, _ := migrateWith(t, in.conf, nil, "state"); code != ExitOK || !strings.Contains(out, `"rollback":{`) || !strings.Contains(out, `"phase":"rollback-transfer"`) {
		t.Fatalf("the reverse's journal read back: %q", out)
	}
	r.stop(t)
}
