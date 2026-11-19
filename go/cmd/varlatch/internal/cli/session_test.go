// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSessionExplanationsSurvive: login, logout and whoami name a server
// URL holding a user name and password by its display form, which holds no
// at-sign, so the TypeScript wording is kept and the fail-safe leaves it as
// it is. Pinned through Main, the fail-safe included.
func TestSessionExplanationsSurvive(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, text string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("several/credentials.json", `{"servers": {"https://u:fake@a.example": {"token": "t"}, "https://b.example": {"token": "t"}}}`)
	write("one/credentials.json", `{"servers": {"https://u:fake@a.example": {"token": "t"}}}`)
	write("plain/credentials.json", `{"servers": {"https://a.example": {"token": "t"}, "https://b.example": {"token": "t"}}}`)
	write("repo/varlatch.toml", "organization = \"acme\"\nproject = \"web\"\n")
	for _, c := range []struct {
		config, cwd string
		args        []string
		want        string
	}{
		{"several", "", []string{"logout"}, "Multiple servers stored (https://a.example, https://b.example). Pass --server <url> or --all.\n"},
		{"one", "repo", []string{"logout"}, "No server here: pass --server <url> or --all (stored: https://a.example).\n"},
		{"one", "", []string{"logout", "--server", "https://v:fake@nosuch.example"}, "No stored credential for https://nosuch.example\n"},
		{"several", "", []string{"whoami"}, "varlatch whoami: credentials are stored for https://a.example, https://b.example; pass --server <url>\n" + whoamiUsage + "\n"},
		{"one", "", []string{"whoami"}, "varlatch: https://a.example/v1/meta: a server URL with a user name or password can't be used; remove them and try again\n"},
		{"one", "", []string{"login", "--server", "https://u:fake@a.example", "--token", "vlt_cli_fake"}, "varlatch: https://a.example/v1/meta: a server URL with a user name or password can't be used; remove them and try again\n"},
		// A server without one: the TypeScript wording, byte for byte.
		{"plain", "", []string{"logout"}, "Multiple servers stored (https://a.example, https://b.example). Pass --server <url> or --all.\n"},
		{"plain", "", []string{"logout", "--server", "https://nosuch.example"}, "No stored credential for https://nosuch.example\n"},
		{"plain", "", []string{"whoami"}, "varlatch whoami: credentials are stored for https://a.example, https://b.example; pass --server <url>\n" + whoamiUsage + "\n"},
	} {
		if err := os.MkdirAll(filepath.Join(dir, c.cwd), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(filepath.Join(dir, c.cwd))
		var stdout, stderr bytes.Buffer
		env := MapEnv{"VARLATCH_CONFIG_DIR": filepath.Join(dir, c.config), "HOME": filepath.Join(dir, "home")}
		Main(c.args, env, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		if stderr.String() != c.want || strings.Contains(stdout.String()+stderr.String(), "fake@") {
			t.Errorf("%q with %s: stderr\n%q\nwant\n%q", c.args, c.config, stderr.String(), c.want)
		}
	}
}
