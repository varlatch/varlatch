// SPDX-License-Identifier: Apache-2.0

package clientctx

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The credential store's locations and writes (internal
// docs/design/go-cli.md, decisions 4 and 11), beyond what the vectors and
// transcripts show.

func TestConfigDirOrder(t *testing.T) {
	home := t.TempDir()
	homeVar := "HOME"
	if runtime.GOOS == "windows" {
		homeVar = "USERPROFILE"
	}
	cases := []struct {
		name string
		env  mapEnv
		want string
	}{
		{"VARLATCH_CONFIG_DIR", mapEnv{"VARLATCH_CONFIG_DIR": "/c", "XDG_CONFIG_HOME": "/x", homeVar: home}, "/c"},
		{"XDG_CONFIG_HOME", mapEnv{"XDG_CONFIG_HOME": "/x", homeVar: home}, filepath.Join("/x", "varlatch")},
		{"home", mapEnv{homeVar: home}, filepath.Join(home, ".config", "varlatch")},
		{"empty XDG_CONFIG_HOME", mapEnv{"XDG_CONFIG_HOME": "", homeVar: home}, filepath.Join(home, ".config", "varlatch")},
		{"empty VARLATCH_CONFIG_DIR", mapEnv{"VARLATCH_CONFIG_DIR": "", homeVar: home}, filepath.Join(home, ".config", "varlatch")},
		{"relative VARLATCH_CONFIG_DIR", mapEnv{"VARLATCH_CONFIG_DIR": "rel", homeVar: home}, "rel"},
	}
	for _, c := range cases {
		got, err := ConfigDir(c.env)
		if err != nil || got != c.want {
			t.Errorf("%s: %q (%v), want %q", c.name, got, err, c.want)
		}
	}
}

func TestEmptyHomeIsUnset(t *testing.T) {
	homeVar := "HOME"
	if runtime.GOOS == "windows" {
		homeVar = "USERPROFILE"
	}
	home, err := HomeDir(mapEnv{homeVar: ""})
	if err != nil {
		t.Skipf("no home directory for this user: %v", err)
	}
	if home == "" || !filepath.IsAbs(home) {
		t.Fatalf("an empty %s gave %q, want the user's own home directory", homeVar, home)
	}
}

func TestWritePrivateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(path, "new\n"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "new\n" {
		t.Fatalf("%q (%v)", data, err)
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("left %d files, want the one: no temporary file", len(entries))
	}
}

func TestWritePrivateFileFailureKeepsTheOldFile(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory its owner cannot write")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if err := writePrivateFile(path, "new\n"); err == nil {
		t.Fatal("a write into a read-only directory succeeded")
	}
	if data, _ := os.ReadFile(path); string(data) != "old\n" {
		t.Errorf("the old file became %q", data)
	}
}

func TestSaveThenReadAsTheOtherCLIWrites(t *testing.T) {
	// What saveCredential writes: JSON.stringify(file, null, 2) and a newline.
	dir := t.TempDir()
	env := mapEnv{"VARLATCH_CONFIG_DIR": dir}
	credential := jsjson.Object{{Key: "token", Value: "vlt_cli_fakeAAAA"}, {Key: "issuedAt", Value: "2026-11-17T10:00:00.000Z"}}
	if err := SaveCredential("https://a.example/", credential, env); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "credentials.json"))
	want := "{\n  \"servers\": {\n    \"https://a.example\": {\n      \"token\": \"vlt_cli_fakeAAAA\",\n      \"issuedAt\": \"2026-11-17T10:00:00.000Z\"\n    }\n  }\n}\n"
	if string(data) != want {
		t.Errorf("wrote %q, want %q", data, want)
	}
	if got, _ := StoredServers(env); len(got) != 1 || got[0] != "https://a.example" {
		t.Errorf("stored servers %q", got)
	}
}

func TestAgentRunBlocksTheOperatorsStore(t *testing.T) {
	xdg := t.TempDir()
	store := filepath.Join(xdg, "varlatch")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "credentials.json"), []byte(`{"servers": {"https://a.example": {"token": "t"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string]mapEnv{
		"unset":                {"VARLATCH_AGENT_RUN": "run_1", "XDG_CONFIG_HOME": xdg},
		"empty":                {"VARLATCH_AGENT_RUN": "run_1", "XDG_CONFIG_HOME": xdg, "VARLATCH_CONFIG_DIR": ""},
		"the default, by name": {"VARLATCH_AGENT_RUN": "run_1", "XDG_CONFIG_HOME": xdg, "VARLATCH_CONFIG_DIR": store + string(filepath.Separator)},
	} {
		if got, _ := StoredServers(env); len(got) != 0 {
			t.Errorf("%s: read the operator's store: %q", name, got)
		}
		err := SaveCredential("https://b.example", jsjson.Object{{Key: "token", Value: "u"}}, env)
		if message, ok := IsContextError(err); !ok || !strings.Contains(message, "agent-safe run run_1") {
			t.Errorf("%s: saving gave %v", name, err)
		}
		if err := SetDefaultServer("https://a.example", true, env); err == nil {
			t.Errorf("%s: wrote the operator's settings", name)
		}
	}
	// The negative control: outside a run the same store is read.
	if got, _ := StoredServers(mapEnv{"XDG_CONFIG_HOME": xdg}); len(got) != 1 {
		t.Errorf("outside a run: %q", got)
	}
}

func TestFindRepoRoot(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindRepoRoot(nested); got != "" {
		t.Fatalf("found %q before there is a varlatch.toml", got)
	}
	if err := os.WriteFile(filepath.Join(root, RepoConfigFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := FindRepoRoot(nested); got != root {
		t.Errorf("%q, want %q", got, root)
	}
}
