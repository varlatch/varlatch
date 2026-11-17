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

// TestFailuresNeverEchoUserinfo: a failure that echoes what it was given (an
// argument, an option, a command, a help topic, an approval id, a line of
// varlatch.toml) never shows a URL's user name and password, whatever they
// hold (spaces and quotes included). Every failure goes through the masker.
func TestFailuresNeverEchoUserinfo(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	toml := "organization = \"acme\"\nproject = \"web\"\nserver = \"https://alice:fake pass@example.com\" x\n"
	if err := os.WriteFile(filepath.Join(repo, "varlatch.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	// Sol, #265 round 1: varlatch.toml lines whose escapes, quotes and forms hid a password from the scanner.
	tomls := map[string]string{
		"escaped-quote": `server = "https://alice:fake\"pass@example.com" x`,
		"escaped-at":    `server = "https://alice:fake\u0040pass@example.com" x`,
		"newline":       `server = "https://alice:fa\nke@example.com" x`,
		"ftp-password":  `server = "https://alice:ftp:@example.com" x`,
		"bad-host":      `server = "https://[bad\\alice:fake-pass@h" x`,
		"slash":         `server = "https://alice:fake/pass@h" x`,
		"tab-scheme":    "server = \"ht\\ttps:/alice:fake-pass@h\" x",
		// Sol, #265 round 2.
		"triple-escaped-at": "server = \"\"\"https://alice:fake\\U00000040h\"\"\"\nx = = 1",
		"spaced-at":         `server = "https://alice:fake" @=x`,
		"tab-password":      "server = \"https://alice:fake\\tlabel:tail@h\" x",
	}
	var tomlDirs []string
	for name, line := range tomls {
		d := filepath.Join(dir, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "varlatch.toml"), []byte("organization = \"acme\"\nproject = \"web\"\n"+line+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		tomlDirs = append(tomlDirs, d)
	}
	env := MapEnv{"VARLATCH_CONFIG_DIR": filepath.Join(dir, "config"), "HOME": filepath.Join(dir, "home")}
	cases := []struct {
		cwd  string
		args []string
	}{
		{dir, []string{"server", "https://alice:fake-pass@example.com"}},
		{dir, []string{"server", "--json", `https:\\alice:fake-pass@example.com`}},
		{dir, []string{"server", "--server=https://alice:fake-pass@example.com"}},
		{dir, []string{"server", "use", "https://alice:fake pass@[bad"}},
		{dir, []string{"server", "use", "--json", "https://alice:fake-pass@example.com", "http:/bob:fake-two@h"}},
		{dir, []string{"https://alice:fake-pass@example.com"}},
		{dir, []string{"help", "http:/alice:fake-pass@example.com"}},
		{dir, []string{"--approval", "https://alice:fake-pass@example.com", "status"}},
		{repo, []string{"context", "--json"}},
		{repo, []string{"server"}},
		{dir, []string{"server", "https://alice:ftp:@example.com"}},
		{dir, []string{"server", "use", "https://alice:fake/pass@h"}},
		{dir, []string{"server", "--https://alice:fake-review-pass@example.com"}},
		{dir, []string{"server", "https://alice:fake\tlabel:tail@example.com"}},
	}
	for _, d := range tomlDirs {
		cases = append(cases, struct {
			cwd  string
			args []string
		}{d, []string{"context", "--json"}})
	}
	for _, c := range cases {
		t.Chdir(c.cwd)
		var stdout, stderr bytes.Buffer
		Main(c.args, env, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		out := stdout.String() + stderr.String()
		if strings.Contains(out, "fake") {
			t.Errorf("%q printed the credentials:\n%s", c.args, out)
		}
		if !strings.Contains(out, "[redacted]@") {
			t.Errorf("%q shows no redacted URL:\n%s", c.args, out)
		}
	}
}

// TestFailuresKeepTextWithoutCredentials: a varlatch.toml line quoting a
// URL with no user name and password next to a quoted email keeps its
// bytes (the next string's "@" is never taken).
func TestFailuresKeepTextWithoutCredentials(t *testing.T) {
	dir := t.TempDir()
	line := `server = "https://example.com" "ops@example.net"`
	if err := os.WriteFile(filepath.Join(dir, "varlatch.toml"), []byte("organization = \"acme\"\nproject = \"web\"\n"+line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	var stdout, stderr bytes.Buffer
	Main([]string{"context"}, MapEnv{"VARLATCH_CONFIG_DIR": filepath.Join(dir, "config")}, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	if !strings.Contains(stderr.String(), line) || strings.Contains(stderr.String(), "[redacted]") {
		t.Errorf("the line was changed:\n%s", stderr.String())
	}
}
