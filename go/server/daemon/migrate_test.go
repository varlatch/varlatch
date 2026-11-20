// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/check"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
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

// `admin migrate check`: after an import, the seeded migration's checks
// pass through the command, as text and as JSON, the run key read from
// stdin; a fault fails it (exit 1) with its check named; a run key that is
// not one line of 64 hex digits is a usage error; neither output holds the
// run key, the Root KEK or a plaintext.
func TestAdminMigrateCheck(t *testing.T) {
	s := migrationtest.Load(t)
	runKey := make([]byte, 32)
	_, _ = rand.Read(runKey)
	b := migrationtest.Bundle(t, s, migrationtest.Options{Sections: &migrationtest.Sections{Digests: migrationtest.Digests(t, s, runKey)}})
	bundlePath := filepath.Join(t.TempDir(), "forward.jsonl")
	if err := os.WriteFile(bundlePath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	in := newInstall(t, "backup_interval = off\n")
	if err := os.WriteFile(in.kekFile, []byte(hex.EncodeToString(s.RootKEK)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, errOut := runAdmin(t, "migrate", "import", "--in", bundlePath, "--config", in.conf); code != ExitOK {
		t.Fatalf("import: %d %q %q", code, stdout, errOut)
	}
	cfg, err := config.Load(in.conf)
	if err != nil {
		t.Fatal(err)
	}
	// The decision table, evaluated on the import (the TypeScript
	// evaluator's arrives with its export), in the bundle the checks read.
	db, err := openReadOnly(cfg)
	if err != nil || db == nil {
		t.Fatalf("the imported database: %v", err)
	}
	var decisions []bundle.Decision
	rows, err := db.Query("SELECT c.id, coalesce(i.organization_id, m.organization_id) FROM credentials c JOIN identities i ON i.id = c.identity_id LEFT JOIN org_memberships m ON m.identity_id = i.id WHERE c.revoked_at IS NULL AND coalesce(i.organization_id, m.organization_id) IS NOT NULL ORDER BY c.id LIMIT 20")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var d bundle.Decision
		if err := rows.Scan(&d.Credential, &d.Organization); err != nil {
			t.Fatal(err)
		}
		d.State, d.Action = bundle.Active, "organization.read"
		decisions = append(decisions, d)
	}
	rows.Close()
	for i, d := range decisions {
		if decisions[i], err = check.Evaluate(context.Background(), db, d); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	if len(decisions) == 0 {
		t.Fatal("no decision")
	}
	b = migrationtest.Bundle(t, s, migrationtest.Options{Sections: &migrationtest.Sections{Digests: migrationtest.Digests(t, s, runKey), Decisions: decisions, At: 1}})
	if err := os.WriteFile(bundlePath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	checkWith := func(stdin string, args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := runMigrate(cfg, append([]string{"check", "--in", bundlePath}, args...), strings.NewReader(stdin), &stdout, &stderr)
		out := stdout.String() + stderr.String()
		for _, secret := range append(slices.Clone(s.Secrets), runKey) {
			if len(secret) >= 8 && (strings.Contains(out, string(secret)) || strings.Contains(out, hex.EncodeToString(secret)) ||
				strings.Contains(out, base64.StdEncoding.EncodeToString(secret))) {
				t.Fatalf("check %q printed a secret", args)
			}
		}
		return code, stdout.String(), stderr.String()
	}
	key := hex.EncodeToString(runKey) + "\n"
	code, stdout, errOut := checkWith(key)
	if code != ExitOK || !strings.HasPrefix(stdout, "The migration's checks passed") || !strings.Contains(stdout, "encryption-classes: passed") {
		t.Fatalf("check: %d %q %q", code, stdout, errOut)
	}
	code, stdout, errOut = checkWith(key, "--json")
	var rep struct {
		Passed bool `json:"passed"`
		Checks []struct {
			Name   string `json:"name"`
			Passed bool   `json:"passed"`
		} `json:"checks"`
	}
	if code != ExitOK || json.Unmarshal([]byte(stdout), &rep) != nil || !rep.Passed || len(rep.Checks) != 5 {
		t.Fatalf("check --json: %d %q %q", code, stdout, errOut)
	}
	// Another run key: every digest differs.
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	code, stdout, _ = checkWith(hex.EncodeToString(other) + "\n")
	if code != ExitFailure || !strings.Contains(stdout, "encryption-classes: FAILED") || strings.Contains(stdout, hex.EncodeToString(other)) {
		t.Fatalf("check with another run key: %d %q", code, stdout)
	}
	for _, bad := range []string{"", "\n", strings.ToUpper(key), key + "more\n", key[:63] + "\n", strings.TrimSuffix(key, "\n") + "\r\n"} {
		if code, _, errOut := checkWith(bad); code != 64 || !strings.Contains(errOut, "64 lowercase hex digits") || (len(bad) > 8 && strings.Contains(errOut, strings.TrimSpace(bad))) {
			t.Errorf("a run key %d bytes long: %d %q", len(bad), code, errOut)
		}
	}
	// Usage.
	for _, args := range [][]string{{"migrate", "check"}, {"migrate", "check", "--in", bundlePath, "--reverse"}, {"migrate", "check", "--out", bundlePath}} {
		if code, _, _ := runAdmin(t, append(args, "--config", in.conf)...); code != 64 {
			t.Errorf("%q: %d, want 64", args, code)
		}
	}
	// Not beside a running varlatchd.
	r := start(t, in)
	if code, _, errOut := checkWith(key); code != ExitFailure || !strings.Contains(errOut, "varlatchd is running") {
		t.Errorf("a check beside varlatchd: %d %q", code, errOut)
	}
	r.stop(t)
}
