// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/migration/manifest"
)

// asForward is a reverse bundle made into a forward one (the TypeScript
// export's header), sealed again: the same rows, as an import reads them.
func asForward(t *testing.T, rev []byte) []byte {
	t.Helper()
	m, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
	}
	nl := bytes.IndexByte(rev, '\n')
	var h map[string]any
	if err := json.Unmarshal(rev[:nl], &h); err != nil {
		t.Fatal(err)
	}
	fp := h["frozenPoint"].(map[string]any)
	header := `{"bundle":"varlatch-migration","format":1,"manifest":1,"encoding":"canonical-v1","direction":"forward","release":"` +
		m.Source.Release + `","frozenPoint":{"auditPosition":` + strings.TrimSuffix(strings.TrimSuffix(jsonNumber(fp["auditPosition"]), ".0"), "") +
		`,"snapshot":"00000003-0000001B-1"},"sequences":[]}` + "\n"
	body := append([]byte(header), rev[nl+1:bytes.LastIndex(rev[:len(rev)-1], []byte("\n"))+1]...)
	end := rev[bytes.LastIndex(rev[:len(rev)-1], []byte("\n"))+1:]
	sum := sha256.Sum256(body)
	i := bytes.Index(end, []byte(`"sha256":"`)) + len(`"sha256":"`)
	return append(append(append(body, end[:i]...), hex.EncodeToString(sum[:])...), end[i+64:]...)
}

func jsonNumber(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// `admin migrate`: export --reverse from a stopped installation (not while
// it runs, never over a file), and import into an empty data directory with
// the installation's Root KEK (never into one in use); the imported
// installation serves.
func TestAdminMigrate(t *testing.T) {
	in := newInstall(t, "backup_interval = off\n")
	r := start(t, in)
	out := filepath.Join(t.TempDir(), "reverse.jsonl")
	if code, _, errOut := runAdmin(t, "migrate", "export", "--reverse", "--out", out, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "varlatchd is running") {
		t.Fatalf("an export beside varlatchd: %d %q", code, errOut)
	}
	r.stop(t)
	code, stdout, errOut := runAdmin(t, "migrate", "export", "--reverse", "--out", out, "--config", in.conf)
	if code != ExitOK || !strings.Contains(stdout, "Wrote the reverse bundle") || !strings.Contains(stdout, "The database is unchanged") {
		t.Fatalf("export: %d %q %q", code, stdout, errOut)
	}
	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the bundle file: %v %v", st, err)
	}
	if code, _, errOut := runAdmin(t, "migrate", "export", "--reverse", "--out", out, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "a new file") {
		t.Errorf("an export over a file: %d %q", code, errOut)
	}
	rev, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	fwd := filepath.Join(t.TempDir(), "forward.jsonl")
	if err := os.WriteFile(fwd, asForward(t, rev), 0o600); err != nil {
		t.Fatal(err)
	}
	// Into the installation's own data directory: in use, refused.
	if code, _, errOut := runAdmin(t, "migrate", "import", "--in", fwd, "--config", in.conf); code != ExitFailure || !strings.Contains(errOut, "not empty") {
		t.Errorf("an import into a data directory in use: %d %q", code, errOut)
	}
	// A fresh host: the same Root KEK, an empty data directory.
	target := newInstall(t, "backup_interval = off\n")
	kek, _ := os.ReadFile(in.kekFile)
	if err := os.WriteFile(target.kekFile, kek, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, errOut = runAdmin(t, "migrate", "import", "--in", fwd, "--json", "--config", target.conf)
	var res struct {
		InstallationID   string `json:"installationId"`
		Tables           int    `json:"tables"`
		MigratedPosition int64  `json:"migratedPosition"`
	}
	if code != ExitOK || json.Unmarshal([]byte(stdout), &res) != nil || res.InstallationID == "" || res.Tables == 0 {
		t.Fatalf("import: %d %q %q", code, stdout, errOut)
	}
	tr := start(t, target)
	tr.stop(t)
	// Usage.
	for _, args := range [][]string{{"migrate"}, {"migrate", "import"}, {"migrate", "export", "--out", out}, {"migrate", "import", "--in", fwd, "--reverse"}, {"migrate", "both"}} {
		if code, _, _ := runAdmin(t, append(args, "--config", in.conf)...); code != 64 {
			t.Errorf("%q: %d, want 64", args, code)
		}
	}
}
