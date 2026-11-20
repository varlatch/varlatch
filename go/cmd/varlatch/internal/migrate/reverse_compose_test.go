// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// .env as the reverse writes it (#370 review): a line longer than a
// scanner's 64 KiB token is read whole and kept byte for byte, never a
// truncated .env written over the operator's; the one line changed or
// added, every other byte as it was (comments, quoting, a missing last
// newline); COMPOSE_FILE removed again restores the file exactly; a .env
// that is a symbolic link is written at its target, the link kept.
func TestTheReverseWritesEnvWhole(t *testing.T) {
	dir := t.TempDir()
	c := &Compose{Directory: dir}
	long := strings.Repeat("x", 200<<10)
	orig := "# the operator's\nVARLATCH_PUBLIC_URL=\"https://vault.example.test\"\nLONG=" + long + "\nBIND_ADDRESS=127.0.0.1"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	env, err := c.envFile()
	if err != nil || env["LONG"] != long || env["BIND_ADDRESS"] != "127.0.0.1" || env["VARLATCH_PUBLIC_URL"] != "https://vault.example.test" {
		t.Fatalf("read: %d values, %v", len(env), err)
	}
	files := "docker-compose.yml:" + OverrideFile
	if err := c.setEnv("COMPOSE_FILE", &files); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if want := orig + "\nCOMPOSE_FILE=" + files + "\n"; string(b) != want {
		t.Fatalf("written: %d bytes, want %d", len(b), len(want))
	}
	if st, _ := os.Stat(filepath.Join(dir, ".env")); st.Mode().Perm() != 0o640 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
	if err := c.setEnv("COMPOSE_FILE", nil); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(dir, ".env"))
	if string(b) != orig+"\n" || !bytes.Contains(b, []byte(long)) {
		t.Errorf("restored: %d bytes, want %d", len(b), len(orig)+1)
	}
	// A line replaced in place.
	other := "docker-compose.yml:docker-compose.caddy.yml"
	if err := c.setEnv("BIND_ADDRESS", &other); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".env")); !strings.HasSuffix(string(b), "LONG="+long+"\nBIND_ADDRESS="+other+"\n") {
		t.Error("the line was not replaced in place")
	}
	if runtime.GOOS == "windows" {
		return
	}
	// A symbolic link: its target written, the link kept.
	real := filepath.Join(t.TempDir(), "env.real")
	if err := os.WriteFile(real, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := t.TempDir()
	if err := os.Symlink(real, filepath.Join(linked, ".env")); err != nil {
		t.Fatal(err)
	}
	lc := &Compose{Directory: linked}
	if err := lc.setEnv("COMPOSE_FILE", &files); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(linked, ".env")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(real); string(b) != "A=1\nCOMPOSE_FILE="+files+"\n" {
		t.Errorf("the target: %q", b)
	}
}

// The project is Compose's own (#371 review P2-2): its files' top-level
// name:, read uninterpolated (the interpolated configuration would carry
// .env's secrets), never the directory's name; the fresh volumes are named
// by it; an answer without a name, or a failed config, refuses.
func TestTheProjectIsCompose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "varlatch-0.23.0")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	run := &scripted{t: t, answers: map[string]Ran{"docker compose config --no-interpolate --format json": {Answer: []byte(`{"name":"varlatch","services":{}}`)}}}
	c := &Compose{Directory: dir, Run: run}
	j := &Journal{ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaabcdefgh", Source: SourceInfo{Digest: "sha256:" + strings.Repeat("a", 64), DigestRepository: "ghcr.io/varlatch/varlatchd"}}
	plan, err := c.RebuildPlan(t.Context(), j)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Volumes[0] != "varlatch_postgres-data-abcdefgh" || plan.Volumes[1] != "varlatch_convex-data-abcdefgh" {
		t.Errorf("the fresh volumes: %v", plan.Volumes)
	}
	for _, bad := range []Ran{{Answer: []byte(`{"services":{}}`)}, {Answer: []byte("not json")}, {Code: 1, Said: []byte("no configuration file provided")},
		{Answer: []byte(`{"name":"a b"}`)}} {
		run.answers["docker compose config --no-interpolate --format json"] = bad
		if _, err := c.RebuildPlan(t.Context(), j); err == nil {
			t.Errorf("%q: no refusal", bad.Answer)
		}
	}
}
