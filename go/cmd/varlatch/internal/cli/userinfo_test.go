// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Go CLI never prints a server URL's user name and password (go/README.md,
// "Diagnostics never print credential values"): every way status, server,
// server use and context show a server, configured or stored, shows
// [redacted] in their place. The TypeScript CLI prints them as they are.
func TestServerURLsNeverShowUserinfo(t *testing.T) {
	const secret = "s3cr3t-pw"
	write := func(path, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	type step struct {
		dir  string // relative to the case's directory
		args []string
	}
	cases := []struct {
		name  string
		files map[string]string
		steps []step
	}{
		{
			name: "stored and default",
			files: map[string]string{
				"config/credentials.json": `{"servers": {"https://u:` + secret + `@a.example": {"token": "t", "expiresAt": "2100-01-01T00:00:00Z"}}}`,
				"config/settings.json":    `{"defaultServer": "https://u:` + secret + `@a.example"}`,
			},
			steps: []step{
				{".", []string{"status"}}, {".", []string{"status", "--json"}},
				{".", []string{"server"}}, {".", []string{"server", "--json"}},
				{".", []string{"server", "use", "https://u:" + secret + "@b.example"}},
				{".", []string{"server", "use", "https://u:" + secret + "@[bad"}},
				{".", []string{"server", "use", "https://u:" + secret + "@a.example"}},
				{".", []string{"server", "use", "--json", "https://u:" + secret + "@a.example/"}},
			},
		},
		{
			name: "a repository's server",
			files: map[string]string{
				"repo/varlatch.toml":         "server = \"https://u:" + secret + "@repo.example\"\norganization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n",
				"local/varlatch.toml":        "server = \"https://u:" + secret + "@repo.example\"\norganization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n",
				"local/.varlatch/local.json": `{"serverOverride": ["https://u:` + secret + `@local.example"]}`,
			},
			steps: []step{
				{"repo", []string{"context"}}, {"repo", []string{"context", "--json"}},
				{"repo", []string{"status", "--json"}}, {"repo", []string{"server"}}, {"repo", []string{"server", "--json"}},
				{"local", []string{"context"}}, {"local", []string{"context", "--json"}}, {"local", []string{"server"}},
				{"repo", []string{"context", "--server", "https://u:" + secret + "@flag.example"}},
			},
		},
		{
			name: "messages",
			files: map[string]string{
				"config/settings.json": `{"defaultServer": "https://u:` + secret + `@a.example"}`,
				"none/varlatch.toml":   "organization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n",
				"bad/varlatch.toml":    "organization = \"acme\"\nproject = \"web\"\nserver = \"https://u:" + secret + "@h.example\" x\n",
			},
			steps: []step{
				{"none", []string{"context"}}, {"bad", []string{"context"}}, {"bad", []string{"server"}},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, text := range c.files {
				write(filepath.Join(dir, filepath.FromSlash(rel)), text)
			}
			env := MapEnv{"VARLATCH_CONFIG_DIR": filepath.Join(dir, "config"), "HOME": filepath.Join(dir, "home")}
			for _, s := range c.steps {
				if err := os.MkdirAll(filepath.Join(dir, s.dir), 0o755); err != nil {
					t.Fatal(err)
				}
				t.Chdir(filepath.Join(dir, s.dir))
				var stdout, stderr bytes.Buffer
				Main(s.args, env, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
				out := stdout.String() + stderr.String()
				if strings.Contains(out, secret) || strings.Contains(out, "u:") {
					t.Errorf("%s %q printed the credentials:\n%s", s.dir, s.args, out)
				}
				if !strings.Contains(out, "[redacted]@") {
					t.Errorf("%s %q shows no redacted server:\n%s", s.dir, s.args, out)
				}
			}
		})
	}
}
