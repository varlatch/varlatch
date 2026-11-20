// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/creack/pty"

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
