// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
)

func migrateWith(t *testing.T, conf string, stdin []byte, args ...string) (int, string, string) {
	t.Helper()
	cfg, err := config.Load(conf)
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := runMigrate(cfg, args, bytes.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func keysJSON(t *testing.T, kek, bek []byte) []byte {
	t.Helper()
	b, err := json.Marshal(struct {
		RootKEK []byte `json:"rootKek"`
		BEK     []byte `json:"bek,omitempty"`
	}{kek, bek})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// `admin migrate keys`: the source's keys written into absent key files
// (0600), found the same on a second run, another refused before either is
// written; a BEK the same as the Root KEK refused; nothing printed of
// either.
func TestAdminMigrateKeys(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	dir := filepath.Dir(in.conf)
	bekFile := filepath.Join(dir, "bek")
	in.write(t, "backup_interval = off\nbackup_key_file = "+bekFile+"\n")
	_ = os.Remove(in.kekFile)
	kek := []byte(hex.EncodeToString(envelope.GenerateKey()) + "\n")
	bek := []byte(hex.EncodeToString(envelope.GenerateKey()) + "\n")
	scan := func(out string) {
		t.Helper()
		for _, k := range [][]byte{kek, bek} {
			if strings.Contains(out, strings.TrimSpace(string(k))) {
				t.Fatal("a key was printed")
			}
		}
	}
	code, out, errOut := migrateWith(t, in.conf, keysJSON(t, kek, bek), "keys")
	scan(out + errOut)
	if code != ExitOK || strings.TrimSpace(out) != `{"rootKek":"written","bek":"written"}` {
		t.Fatalf("keys: %d %q %q", code, out, errOut)
	}
	for _, f := range []struct {
		path string
		want []byte
	}{{in.kekFile, kek}, {bekFile, bek}} {
		st, err := os.Stat(f.path)
		b, _ := os.ReadFile(f.path)
		if err != nil || st.Mode().Perm() != 0o600 || !bytes.Equal(b, f.want) {
			t.Fatalf("%s: %v %v", f.path, st, err)
		}
	}
	code, out, errOut = migrateWith(t, in.conf, keysJSON(t, kek, bek), "keys")
	scan(out + errOut)
	if code != ExitOK || strings.TrimSpace(out) != `{"rootKek":"unchanged","bek":"unchanged"}` {
		t.Fatalf("keys again: %d %q %q", code, out, errOut)
	}
	other := []byte(hex.EncodeToString(envelope.GenerateKey()))
	code, out, errOut = migrateWith(t, in.conf, keysJSON(t, other, bek), "keys")
	scan(out + errOut)
	if code != ExitFailure || !strings.Contains(errOut, "holds another key") || strings.Contains(errOut, string(other)) {
		t.Fatalf("another Root KEK: %d %q", code, errOut)
	}
	if b, _ := os.ReadFile(in.kekFile); !bytes.Equal(b, kek) {
		t.Fatal("the Root KEK file was changed")
	}
	if code, _, errOut = migrateWith(t, in.conf, keysJSON(t, kek, kek), "keys"); code != ExitFailure {
		t.Fatalf("a BEK that is the Root KEK: %d %q", code, errOut)
	}
	for _, bad := range [][]byte{nil, []byte("{}"), []byte(`{"rootKek":"` + hex.EncodeToString(kek) + `"}`), []byte("not json")} {
		if code, _, _ := migrateWith(t, in.conf, bad, "keys"); code != 64 && code != ExitFailure {
			t.Errorf("keys %q: %d", bad, code)
		}
	}
	// No backup_key_file: a BEK has nowhere to go.
	in.write(t, "backup_interval = off\n")
	if code, _, errOut := migrateWith(t, in.conf, keysJSON(t, kek, bek), "keys"); code != ExitConfig || !strings.Contains(errOut, "backup_key_file") {
		t.Fatalf("no backup_key_file: %d %q", code, errOut)
	}
	// From a terminal: refused before a byte is read.
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer ptmx.Close()
	defer tty.Close()
	cfg, _ := config.Load(in.conf)
	var o, e bytes.Buffer
	if code := runMigrate(cfg, []string{"keys"}, tty, &o, &e); code != 64 || !strings.Contains(e.String(), "comes on a pipe") {
		t.Fatalf("keys from a terminal: %d %q", code, e.String())
	}
}

func journalText(id, phase string) []byte {
	return []byte(`{"format":1,"id":"` + id + `","phase":"` + phase + `","source":{"dir":"/srv/old"},"history":[]}`)
}

const (
	migA = "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	migB = "mig_bbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// `admin migrate state`: the journal written as given (0600) and read
// back; it goes forward only, back to started before the barrier or to
// released before the switch; another migration's replaces it only once
// that one was released.
func TestAdminMigrateState(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	code, out, _ := migrateWith(t, in.conf, nil, "state")
	if code != ExitOK || !strings.Contains(out, `"journal":null`) || !strings.Contains(out, `"database":false`) {
		t.Fatalf("no journal: %d %q", code, out)
	}
	write := func(id, phase string) (int, string) {
		code, _, errOut := migrateWith(t, in.conf, journalText(id, phase), "state", "--write")
		return code, errOut
	}
	for _, step := range []struct {
		id, phase string
		ok        bool
	}{
		{migA, "started", true}, {migA, "dry-run", true}, {migA, "started", true}, {migA, "barrier", true},
		{migA, "dry-run", false}, {migA, "started", false}, {migB, "started", false}, {migA, "released", true},
		{migB, "started", true}, {migB, "switched", true}, {migB, "released", false}, {migB, "open", true},
		{migA, "started", false}, {migB, "nowhere", false}, {"mig_bad", "open", false},
	} {
		code, errOut := write(step.id, step.phase)
		if (code == ExitOK) != step.ok {
			t.Fatalf("%s %s: %d %q", step.id, step.phase, code, errOut)
		}
	}
	st, err := os.Stat(filepath.Join(in.data, JournalFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the journal: %v %v", st, err)
	}
	if code, out, _ := migrateWith(t, in.conf, nil, "state"); code != ExitOK || !strings.Contains(out, `"phase":"open"`) {
		t.Fatalf("state: %d %q", code, out)
	}
}

// The start gate: varlatchd does not start on a data directory whose
// journal is not open; once it is, it does.
func TestVarlatchdWaitsForOpen(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	for _, phase := range []string{"checked", "switched", "released"} {
		if err := os.WriteFile(filepath.Join(in.data, JournalFile), journalText(migA, phase), 0o600); err != nil {
			t.Fatal(err)
		}
		var errOut syncBuffer
		code := Serve(Options{ConfigPath: in.conf, Stderr: &errOut, Signals: make(chan os.Signal, 1)})
		if code != ExitConfig || !strings.Contains(errOut.String(), "varlatchd does not start") || !strings.Contains(errOut.String(), migA) {
			t.Fatalf("phase %s: %d %q", phase, code, errOut.String())
		}
	}
	if err := os.WriteFile(filepath.Join(in.data, JournalFile), journalText(migA, "open"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := start(t, in)
	r.stop(t)
}

// `admin migrate discard`: the database of the migration the journal
// names, before its switch; never another's, never after the switch;
// import ignores the journal, and --scratch builds and checks elsewhere.
func TestAdminMigrateDiscardAndScratch(t *testing.T) {
	s := migrationtest.Load(t)
	runKey := envelope.GenerateKey()
	b := migrationtest.Bundle(t, s, migrationtest.Options{Sections: &migrationtest.Sections{Digests: migrationtest.Digests(t, s, runKey)}})
	bundle := filepath.Join(t.TempDir(), "forward.jsonl")
	if err := os.WriteFile(bundle, b, 0o600); err != nil {
		t.Fatal(err)
	}
	in := newInstall(t, "backup_interval = off\n")
	if err := os.WriteFile(in.kekFile, []byte(hex.EncodeToString(s.RootKEK)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The dry run's: built and read in a scratch directory; the data
	// directory untouched.
	scratch := filepath.Join(t.TempDir(), "scratch")
	if code, out, errOut := migrateWith(t, in.conf, nil, "import", "--in", bundle, "--scratch", scratch, "--json"); code != ExitOK || !strings.Contains(out, `"installationId"`) {
		t.Fatalf("import --scratch: %d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(scratch, config.DatabaseFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(in.data, config.DatabaseFile)); !os.IsNotExist(err) {
		t.Fatal("import --scratch wrote the data directory")
	}
	code, out, errOut := migrateWith(t, in.conf, []byte(hex.EncodeToString(runKey)+"\n"), "check", "--in", bundle, "--scratch", scratch, "--json")
	if code != ExitFailure || !strings.Contains(out, `"passed":false`) || !strings.Contains(out, "no decision table") {
		t.Fatalf("check --scratch (no decisions in this bundle): %d %q %q", code, out, errOut)
	}
	// The import into the data directory, beside the journal.
	if code, _, errOut := migrateWith(t, in.conf, journalText(migA, "barrier"), "state", "--write"); code != ExitOK {
		t.Fatal(errOut)
	}
	if code, _, errOut := migrateWith(t, in.conf, nil, "import", "--in", bundle); code != ExitOK {
		t.Fatalf("an import beside the journal: %d %q", code, errOut)
	}
	if code, _, errOut := migrateWith(t, in.conf, nil, "discard", "--id", migB); code != ExitFailure || !strings.Contains(errOut, "not "+migB) {
		t.Fatalf("another migration's discard: %d %q", code, errOut)
	}
	if code, out, errOut := migrateWith(t, in.conf, nil, "discard", "--id", migA); code != ExitOK || !strings.Contains(out, config.DatabaseFile) {
		t.Fatalf("discard: %d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(in.data, config.DatabaseFile)); !os.IsNotExist(err) {
		t.Fatal("the database was not discarded")
	}
	if _, err := os.Stat(filepath.Join(in.data, JournalFile)); err != nil {
		t.Fatal("the journal was discarded")
	}
	// After the switch: never.
	if code, _, errOut := migrateWith(t, in.conf, nil, "import", "--in", bundle); code != ExitOK {
		t.Fatal(errOut)
	}
	for _, phase := range []string{"copied", "checked", "switched"} {
		if code, _, errOut := migrateWith(t, in.conf, journalText(migA, phase), "state", "--write"); code != ExitOK {
			t.Fatal(errOut)
		}
	}
	if code, _, errOut := migrateWith(t, in.conf, nil, "discard", "--id", migA); code != ExitFailure || !strings.Contains(errOut, "past its switch") {
		t.Fatalf("discard after the switch: %d %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(in.data, config.DatabaseFile)); err != nil {
		t.Fatal("a switched database was removed")
	}
	// Usage.
	for _, args := range [][]string{{"keys", "--in", bundle}, {"discard"}, {"state", "--id", migA}, {"import", "--in", bundle, "--scratch", "relative"}} {
		if _, msg := parseMigrate(args); msg == "" {
			t.Errorf("%q parsed", args)
		}
	}
}

// The address transfer (decision 12): the journal entering transfer
// writes the migration's gate; varlatchd starts under it and answers GET
// /v1/meta (its installation's id) and nothing else; open removes the
// gate. Without the gate, a journal in transfer does not start.
func TestTheTransfersGate(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	r := start(t, in)
	r.stop(t)
	for _, phase := range []string{"started", "barrier", "checked"} {
		if code, _, errOut := migrateWith(t, in.conf, journalText(migA, phase), "state", "--write"); code != ExitOK {
			t.Fatal(errOut)
		}
	}
	if code, _, errOut := migrateWith(t, in.conf, journalText(migA, "transfer"), "state", "--write"); code != ExitOK {
		t.Fatal(errOut)
	}
	g, err := backup.ReadGate(in.data)
	if err != nil || g == nil || g.Kind != "migration" || g.ID != migA || g.Phase != "transfer" || g.ExpiresAt != nil {
		t.Fatalf("the gate: %+v %v", g, err)
	}
	if code, out, _ := migrateWith(t, in.conf, nil, "state"); code != ExitOK || !strings.Contains(out, `"release":`) || !strings.Contains(out, `"listen":"127.0.0.1:0"`) {
		t.Fatalf("state: %q", out)
	}
	r = start(t, in)
	get := func(path string) (int, string) {
		res, err := http.Get("http://" + r.addr + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, body := get("/v1/meta"); code != http.StatusOK || !strings.Contains(body, `"serverVersion"`) {
		t.Errorf("/v1/meta under the transfer's gate: %d %s", code, body)
	}
	for _, p := range []string{"/v1/whoami", "/v1/orgs", "/readyz"} {
		if code, body := get(p); code != http.StatusServiceUnavailable {
			t.Errorf("%s under the transfer's gate: %d %s", p, code, body)
		}
	}
	res, err := http.Post("http://"+r.addr+"/v1/meta", "application/json", strings.NewReader("{}"))
	if err == nil {
		res.Body.Close()
		if res.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("POST /v1/meta under the gate: %d", res.StatusCode)
		}
	}
	r.stop(t)
	// No gate: it does not start.
	_ = os.Remove(filepath.Join(in.data, backup.GateFile))
	var errOut syncBuffer
	if code := Serve(Options{ConfigPath: in.conf, Stderr: &errOut, Signals: make(chan os.Signal, 1)}); code != ExitConfig || !strings.Contains(errOut.String(), "holds no gate of it") {
		t.Fatalf("transfer without its gate: %d %q", code, errOut.String())
	}
	if code, _, errOut := migrateWith(t, in.conf, journalText(migA, "transfer"), "state", "--write"); code != ExitOK {
		t.Fatal(errOut)
	}
	// Open removes the gate; varlatchd serves as ever.
	for _, phase := range []string{"switched", "open"} {
		if code, _, errOut := migrateWith(t, in.conf, journalText(migA, phase), "state", "--write"); code != ExitOK {
			t.Fatal(errOut)
		}
	}
	if g, err := backup.ReadGate(in.data); g != nil || err != nil {
		t.Fatalf("the gate after open: %+v %v", g, err)
	}
	r = start(t, in)
	if code, _ := get("/v1/whoami"); code == http.StatusServiceUnavailable {
		t.Error("isolated after open")
	}
	r.stop(t)
}

// Released removes the transfer's gate; another gate is never replaced.
func TestTheTransfersGateIsItsOwn(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	for _, phase := range []string{"started", "transfer", "released"} {
		if code, _, errOut := migrateWith(t, in.conf, journalText(migA, phase), "state", "--write"); code != ExitOK {
			t.Fatal(errOut)
		}
	}
	if g, err := backup.ReadGate(in.data); g != nil || err != nil {
		t.Fatalf("the gate after released: %+v %v", g, err)
	}
	expires := time.Now().Add(time.Hour).UnixMilli()
	lease, _ := json.Marshal(backup.Gate{ID: "lease-1", Kind: "capture", Phase: "draining", ExpiresAt: &expires})
	if err := os.WriteFile(filepath.Join(in.data, backup.GateFile), lease, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"started", "transfer"} {
		code, _, errOut := migrateWith(t, in.conf, journalText(migB, phase), "state", "--write")
		if phase == "transfer" && (code != ExitFailure || !strings.Contains(errOut, "capture gate")) {
			t.Fatalf("the transfer over a lease: %d %q", code, errOut)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(in.data, backup.GateFile)); !bytes.Equal(b, lease) {
		t.Fatal("the lease was replaced")
	}
}

// A gate that cannot be removed: the journal is not written open (it
// stays where it was), and the message names the file to remove by hand.
// The state reads beside a running varlatchd, and says it runs.
func TestAStuckTransferGate(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	for _, phase := range []string{"started", "transfer", "switched"} {
		if code, _, errOut := migrateWith(t, in.conf, journalText(migA, phase), "state", "--write"); code != ExitOK {
			t.Fatal(errOut)
		}
	}
	gate := filepath.Join(in.data, backup.GateFile)
	if err := os.Remove(gate); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(gate, 0o700); err != nil { // unreadable as a gate, and not removable as a file
		t.Fatal(err)
	}
	code, _, errOut := migrateWith(t, in.conf, journalText(migA, "open"), "state", "--write")
	if code != ExitFailure || !strings.Contains(errOut, gate) || !strings.Contains(errOut, "remove that file by hand") || !strings.Contains(errOut, "still says switched") {
		t.Fatalf("a stuck gate: %d %q", code, errOut)
	}
	if code, out, _ := migrateWith(t, in.conf, nil, "state"); code != ExitOK || !strings.Contains(out, `"phase":"switched"`) || !strings.Contains(out, `"migrationGate":true`) {
		t.Fatalf("the journal moved past a stuck gate: %q", out)
	}
	if err := os.Remove(gate); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := migrateWith(t, in.conf, journalText(migA, "open"), "state", "--write"); code != ExitOK {
		t.Fatal(errOut)
	}
	r := start(t, in)
	code, out, errOut := migrateWith(t, in.conf, nil, "state")
	r.stop(t)
	if code != ExitOK || !strings.Contains(out, `"running":true`) || !strings.Contains(out, `"migrationGate":false`) || !strings.Contains(out, `"phase":"open"`) {
		t.Fatalf("state beside a running varlatchd: %d %q %q", code, out, errOut)
	}
}

// Reading the state creates nothing: a target whose data directory does
// not exist yet answers with no journal and no database.
func TestStateReadsWithoutADataDirectory(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	if err := os.Remove(in.data); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := migrateWith(t, in.conf, nil, "state")
	if code != ExitOK || !strings.Contains(out, `"journal":null`) || !strings.Contains(out, `"running":false`) {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(in.data); !os.IsNotExist(err) {
		t.Fatal("reading the state created the data directory")
	}
}

// The switch is written beside the varlatchd serving under the transfer's
// gate, and the live open ends that gate through its control socket: it
// serves at once, its journal open; offline, the same on the data
// directory. Before the switch, or for another migration, refused.
func TestTheLiveOpen(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	for _, phase := range []string{"started", "transfer"} {
		if code, _, errOut := migrateWith(t, in.conf, journalText(migA, phase), "state", "--write"); code != ExitOK {
			t.Fatal(errOut)
		}
	}
	r := start(t, in)
	get := func(path string) int {
		res, err := http.Get("http://" + r.addr + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code, _, errOut := runAdmin(t, "migrate", "open", "--id", migA, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "opens once switched") {
		t.Fatalf("an open before the switch: %d %q", code, errOut)
	}
	if code, _, errOut := migrateWith(t, in.conf, journalText(migA, "switched"), "state", "--write"); code != ExitOK {
		t.Fatalf("the switch beside a running varlatchd: %q", errOut)
	}
	if code, _, errOut := runAdmin(t, "migrate", "open", "--id", migB, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "not "+migB) {
		t.Fatalf("another migration's open: %d %q", code, errOut)
	}
	if get("/v1/whoami") != http.StatusServiceUnavailable {
		t.Fatal("not isolated before the open")
	}
	code, out, errOut := runAdmin(t, "migrate", "open", "--id", migA, "--config", in.conf)
	if code != ExitOK || !strings.Contains(out, `"opened":true`) {
		t.Fatalf("the live open: %d %q %q", code, out, errOut)
	}
	if get("/v1/whoami") == http.StatusServiceUnavailable {
		t.Fatal("isolated after the live open")
	}
	if g, err := backup.ReadGate(in.data); g != nil || err != nil {
		t.Fatalf("the gate after the live open: %+v %v", g, err)
	}
	b, _ := os.ReadFile(filepath.Join(in.data, JournalFile))
	if h, err := parseJournal(b); err != nil || h.Phase != "open" || !strings.Contains(string(b), `{"at":`) {
		t.Fatalf("the journal after the live open: %s %v", b, err)
	}
	// Again: nothing to do.
	if code, _, errOut := runAdmin(t, "migrate", "open", "--id", migA, "--config", in.conf); code != ExitOK {
		t.Fatalf("a second open: %q", errOut)
	}
	r.stop(t)
	// Offline: the same, on the data directory.
	in2 := newInstall(t, "backup_interval = off\n")
	for _, phase := range []string{"started", "transfer", "switched"} {
		if code, _, errOut := migrateWith(t, in2.conf, journalText(migB, phase), "state", "--write"); code != ExitOK {
			t.Fatal(errOut)
		}
	}
	if code, _, errOut := runAdmin(t, "migrate", "open", "--id", migB, "--config", in2.conf); code != ExitOK {
		t.Fatalf("an offline open: %q", errOut)
	}
	if g, _ := backup.ReadGate(in2.data); g != nil {
		t.Fatal("the gate after an offline open")
	}
}

// Beside the varlatchd serving under the transfer's gate: the switch is
// written (the engine switches once the public URL answers from it), and
// the transfer's journal again (its check recorded, an undo begun); open,
// released, going back and another migration's are refused, as before.
func TestTheSwitchBesideARunningVarlatchd(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	for _, phase := range []string{"started", "transfer"} {
		if code, _, errOut := migrateWith(t, in.conf, journalText(migA, phase), "state", "--write"); code != ExitOK {
			t.Fatal(errOut)
		}
	}
	r := start(t, in)
	if code, _, errOut := migrateWith(t, in.conf, journalText(migA, "open"), "state", "--write"); code != ExitFailure || !strings.Contains(errOut, "varlatchd is running") {
		t.Fatalf("an open beside the running varlatchd: %d %q", code, errOut)
	}
	// The same phase again, with what it records (the transfer's check),
	// is written beside it; going back, or another migration, is not.
	verified := []byte(`{"format":1,"id":"` + migA + `","phase":"transfer","transfer":{"origin":"http://x","asked":true,"verifiedAt":"2026-11-20T17:00:00Z"},"undoing":true,"history":[]}`)
	if code, _, errOut := migrateWith(t, in.conf, verified, "state", "--write"); code != ExitOK {
		t.Fatalf("the same phase beside the running varlatchd: %d %q", code, errOut)
	}
	if code, out, _ := migrateWith(t, in.conf, nil, "state"); code != ExitOK || !strings.Contains(out, `"verifiedAt":"2026-11-20T17:00:00Z"`) {
		t.Fatalf("the rewritten journal: %q", out)
	}
	for _, j := range [][]byte{journalText(migA, "checked"), journalText(migA, "released"), journalText(migB, "transfer"), journalText(migB, "switched")} {
		if code, _, errOut := migrateWith(t, in.conf, j, "state", "--write"); code != ExitFailure {
			t.Fatalf("%s beside the running varlatchd: %d %q", j, code, errOut)
		}
	}
	if code, _, errOut := migrateWith(t, in.conf, journalText(migA, "switched"), "state", "--write"); code != ExitOK {
		t.Fatalf("the switch beside the running varlatchd: %d %q", code, errOut)
	}
	if g, err := backup.ReadGate(in.data); err != nil || g == nil || g.Kind != "migration" {
		t.Fatalf("the gate after the switch: %+v %v", g, err)
	}
	res, err := http.Get("http://" + r.addr + "/v1/whoami")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("not isolated after the switch: %d", res.StatusCode)
	}
	r.stop(t)
	code, out, _ := migrateWith(t, in.conf, nil, "state")
	if code != ExitOK || !strings.Contains(out, `"phase":"switched"`) {
		t.Fatalf("the journal: %q", out)
	}
	// Stopped, it opens offline as before.
	if code, _, errOut := migrateWith(t, in.conf, journalText(migA, "open"), "state", "--write"); code != ExitOK {
		t.Fatal(errOut)
	}
}

// A target made setup's way (slice 7.4e) names no key file: its keys are
// the unit's credentials beside its configuration. With
// CREDENTIALS_DIRECTORY set to that directory, as migrate runs varlatchd
// for such a target, `admin migrate keys` writes the source's Root KEK and
// BEK there, 0600, where the unit loads them; without it, the BEK has no
// place and is refused.
func TestAdminMigrateKeysAsCredentials(t *testing.T) {
	dir := t.TempDir()
	creds := filepath.Join(dir, "etc")
	data := filepath.Join(dir, "data")
	for _, d := range []string{creds, data} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	conf := filepath.Join(creds, "varlatchd.conf")
	if err := os.WriteFile(conf, []byte("listen = 127.0.0.1:0\ndata_dir = "+data+"\nbackup_interval = off\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	kek := []byte(hex.EncodeToString(envelope.GenerateKey()) + "\n")
	bek := []byte(hex.EncodeToString(envelope.GenerateKey()) + "\n")
	t.Setenv("CREDENTIALS_DIRECTORY", creds)
	code, out, errOut := migrateWith(t, conf, keysJSON(t, kek, bek), "keys")
	if code != ExitOK || strings.TrimSpace(out) != `{"rootKek":"written","bek":"written"}` {
		t.Fatalf("keys: %d %q %q", code, out, errOut)
	}
	for name, want := range map[string][]byte{"root-kek": kek, "backup-key": bek} {
		b, err := os.ReadFile(filepath.Join(creds, name))
		st, serr := os.Stat(filepath.Join(creds, name))
		if err != nil || serr != nil || !bytes.Equal(b, want) || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", name, err, serr)
		}
	}
	// Found the same: unchanged.
	if code, out, _ := migrateWith(t, conf, keysJSON(t, kek, bek), "keys"); code != ExitOK || strings.TrimSpace(out) != `{"rootKek":"unchanged","bek":"unchanged"}` {
		t.Errorf("again: %d %q", code, out)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	conf2 := filepath.Join(dir, "other.conf")
	if err := os.WriteFile(conf2, []byte("listen = 127.0.0.1:0\ndata_dir = "+data+"\nroot_kek_file = "+filepath.Join(dir, "k")+"\nbackup_interval = off\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := migrateWith(t, conf2, keysJSON(t, kek, bek), "keys"); code != ExitConfig || !strings.Contains(errOut, "names no backup_key_file") {
		t.Errorf("a BEK with no place: %d %q", code, errOut)
	}
}

// `admin migrate state` says why an import into the data directory would
// be refused now, with the import's own words (importableDataDir, which
// both run): Go's backups/ is no reason, another name is. varlatch
// migrate's preflight refuses on it, before the barrier.
func TestStateSaysWhatTheImportWouldRefuse(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	refusal := func() string {
		t.Helper()
		code, out, errOut := migrateWith(t, in.conf, nil, "state")
		var s struct {
			ImportRefusal *string `json:"importRefusal"`
		}
		if code != ExitOK || json.Unmarshal([]byte(out), &s) != nil {
			t.Fatalf("state: %d %q %q", code, out, errOut)
		}
		if s.ImportRefusal == nil {
			return ""
		}
		if *s.ImportRefusal == "" {
			t.Fatal("importRefusal present but empty")
		}
		return *s.ImportRefusal
	}
	if r := refusal(); r != "" {
		t.Fatalf("an empty data directory: %q", r)
	}
	if err := os.MkdirAll(filepath.Join(in.data, "backups"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.data, "backups", "final.vltbak"), []byte("an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := refusal(); r != "" {
		t.Fatalf("Go's backups/: %q", r)
	}
	if err := os.WriteFile(filepath.Join(in.data, "notes.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r := refusal()
	if !strings.Contains(r, "is not empty (notes.txt)") {
		t.Fatalf("a stray name: %q", r)
	}
	// The import refuses it in the same words, before it reads its bundle.
	code, _, errOut := migrateWith(t, in.conf, nil, "import", "--in", filepath.Join(t.TempDir(), "no-bundle.jsonl"))
	if code != ExitFailure || !strings.Contains(errOut, r+"; nothing was imported") {
		t.Fatalf("the import: %d %q, want %q", code, errOut, r)
	}
}
