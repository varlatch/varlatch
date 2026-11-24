// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Go CLI never prints a server URL's user name and password (go/README.md,
// "server-display"): every way status, server, server use and context show
// a server, configured or stored, shows its display form, without them.
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
		dir   string // relative to the case's directory
		args  []string
		shows string // what the output holds: the server's display form, in context
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
				{".", []string{"status"}, "https://a.example  (expires"}, {".", []string{"status", "--json"}, `"server": "https://a.example"`},
				{".", []string{"server"}, "Server here: https://a.example (the default server)"}, {".", []string{"server", "--json"}, `"defaultServer": "https://a.example"`},
				{".", []string{"server", "use", "https://u:" + secret + "@b.example"}, "you are not signed in to https://b.example. Sign in first: varlatch login --server and its URL"},
				{".", []string{"server", "use", "https://u:" + secret + "@[bad"}, "not a URL: [unrecognised server URL]"},
				{".", []string{"server", "use", "https://u:" + secret + "@a.example"}, "Default server: https://a.example"},
				{".", []string{"server", "use", "--json", "https://u:" + secret + "@a.example/"}, `"defaultServer": "https://a.example"`},
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
				{"repo", []string{"context"}, "Server        https://repo.example"}, {"repo", []string{"context", "--json"}, `"server": "https://repo.example"`},
				{"repo", []string{"status", "--json"}, `"server": "https://repo.example"`}, {"repo", []string{"server"}, "Server here: https://repo.example (from varlatch.toml)"},
				{"repo", []string{"server", "--json"}, `"server": "https://repo.example"`},
				{"local", []string{"context"}, "Server        https://local.example"}, {"local", []string{"context", "--json"}, `"https://local.example"`},
				{"local", []string{"server"}, "Server here: https://local.example (from .varlatch/local.json)"},
				{"repo", []string{"context", "--server", "https://u:" + secret + "@flag.example"}, "Server        https://flag.example"},
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
				{"none", []string{"context"}, `for example: server = "https://a.example".`}, {"bad", []string{"context"}, linesNotShown}, {"bad", []string{"server"}, linesNotShown},
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
				// bad's varlatch.toml does not parse: its lines are not shown.
				if !strings.Contains(out, s.shows) {
					t.Errorf("%s %q does not show %q:\n%s", s.dir, s.args, s.shows, out)
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
		toml bool // a varlatch.toml parse error: no excerpt, so no URL either
	}{
		{dir, []string{"server", "https://alice:fake-pass@example.com"}, false},
		{dir, []string{"server", "--json", `https:\\alice:fake-pass@example.com`}, false},
		{dir, []string{"server", "--server=https://alice:fake-pass@example.com"}, false},
		{dir, []string{"server", "use", "https://alice:fake pass@[bad"}, false},
		{dir, []string{"server", "use", "--json", "https://alice:fake-pass@example.com", "http:/bob:fake-two@h"}, false},
		{dir, []string{"https://alice:fake-pass@example.com"}, false},
		{dir, []string{"help", "http:/alice:fake-pass@example.com"}, false},
		{dir, []string{"--approval", "https://alice:fake-pass@example.com", "status"}, false},
		{repo, []string{"context", "--json"}, true},
		{repo, []string{"server"}, true},
		{dir, []string{"server", "https://alice:ftp:@example.com"}, false},
		{dir, []string{"server", "use", "https://alice:fake/pass@h"}, false},
		{dir, []string{"server", "--https://alice:fake-review-pass@example.com"}, false},
		{dir, []string{"server", "https://alice:fake\tlabel:tail@example.com"}, false},
	}
	for _, d := range tomlDirs {
		cases = append(cases, struct {
			cwd  string
			args []string
			toml bool
		}{d, []string{"context", "--json"}, true})
	}
	for _, c := range cases {
		t.Chdir(c.cwd)
		var stdout, stderr bytes.Buffer
		Main(c.args, env, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		out := stdout.String() + stderr.String()
		if strings.Contains(out, "fake") {
			t.Errorf("%q printed the credentials:\n%s", c.args, out)
		}
		if c.toml && !strings.Contains(out, linesNotShown) {
			t.Errorf("%q quotes varlatch.toml:\n%s", c.args, out)
		}
		if !c.toml && !strings.Contains(out, "[redacted]@") && !strings.Contains(out, "=[redacted]") && !strings.Contains(out, "[unrecognised server URL]") {
			t.Errorf("%q shows no redacted URL:\n%s", c.args, out)
		}
	}
}

// linesNotShown ends a varlatch.toml parse error that leaves out the
// file's lines.
const linesNotShown = "(the file may hold a URL's user name and password, so its lines are not shown)"

// TestFailuresKeepTextWithoutCredentials: a varlatch.toml parse error in a
// file without an at-sign quotes its lines as smol-toml does, byte for
// byte; one in a file with an at-sign quotes none of them.
func TestFailuresKeepTextWithoutCredentials(t *testing.T) {
	for line, kept := range map[string]bool{
		`server = "https://example.com" x`:                 true,
		`server = "https://example.com\\path@segment" x`:   false,
		`server = "https://example.com" "ops@example.net"`: false,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "varlatch.toml"), []byte("organization = \"acme\"\nproject = \"web\"\n"+line+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Chdir(dir)
		var stdout, stderr bytes.Buffer
		Main([]string{"context"}, MapEnv{"VARLATCH_CONFIG_DIR": filepath.Join(dir, "config")}, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		if got := strings.Contains(stderr.String(), line); got != kept {
			t.Errorf("%s: kept %v, want %v:\n%s", line, got, kept, stderr.String())
		}
		if got := strings.Contains(stderr.String(), linesNotShown); got == kept {
			t.Errorf("%s: lines left out %v, want %v:\n%s", line, got, !kept, stderr.String())
		}
	}
}

// TestTOMLExcerptLeftOutWhenFileMayHoldCredentials: smol-toml's message
// quotes the lines around a parse error, which can hold a URL's user name
// and password without the at-sign that follows them (a string running on
// past the quoted lines), where neither masking layer sees a URL. A file
// with an at-sign of any form (as the fail-safe detects one) has its parse
// errors shown with the explanation and where it is, and none of its lines
// (Sol, #265 round 5), on stderr and in server's stdout alike.
func TestTOMLExcerptLeftOutWhenFileMayHoldCredentials(t *testing.T) {
	const org = "organization = \"acme\"\nproject = \"web\"\n"
	for _, c := range []struct {
		name, toml string
		args       []string
		stdout     bool
		want       string
	}{
		// Sol's reproducer: the excerpt ends after the line that holds the password.
		{"reproducer", "broken = = 2\nserver = \"\"\"https://alice:fake-review-password\n@example.invalid\"\"\"\n", []string{"context"}, false, "Invalid varlatch.toml: Invalid TOML document: invalid value, line 1, column 10 " + linesNotShown + "\n"},
		{"reproducer, server", "broken = = 2\nserver = \"\"\"https://alice:fake-review-password\n@example.invalid\"\"\"\n", []string{"server"}, true, "Server here: none (Invalid varlatch.toml: Invalid TOML document: invalid value, line 1, column 10 " + linesNotShown + ")\n"},
		// The credential on the line before the error.
		{"line before", org + "server = \"\"\"https://alice:fake-before\n@example.invalid\"\"\"\nbroken = = 2\n", []string{"context"}, false, "Invalid varlatch.toml: Invalid TOML document: invalid value, line 5, column 10 " + linesNotShown + "\n"},
		// The credential several lines after the error.
		{"lines after", org + "broken = = 2\na = 1\nb = 2\nc = 3\nserver = \"https://alice:fake-after@example.invalid\"\n", []string{"context"}, false, "Invalid varlatch.toml: Invalid TOML document: invalid value, line 3, column 10 " + linesNotShown + "\n"},
		{"lines after, server", org + "broken = = 2\na = 1\nb = 2\nc = 3\nserver = \"https://alice:fake-after@example.invalid\"\n", []string{"server"}, true, "Server here: none (Invalid varlatch.toml: Invalid TOML document: invalid value, line 3, column 10 " + linesNotShown + ")\n"},
		// Every at-sign form the fail-safe knows, an escape split by a tab included.
		{"escaped", "broken = = 2\nserver = \"https://alice:fake-escaped\\u0040h\"\n", []string{"context"}, false, "Invalid varlatch.toml: Invalid TOML document: invalid value, line 1, column 10 " + linesNotShown + "\n"},
		{"percent", "broken = = 2\nserver = \"https://alice:fake-percent%40h\"\n", []string{"context"}, false, "Invalid varlatch.toml: Invalid TOML document: invalid value, line 1, column 10 " + linesNotShown + "\n"},
		{"tab-split", "broken = = 2\nx = 'https://alice:fake-tab\\x4\t0h'\n", []string{"context"}, false, "Invalid varlatch.toml: Invalid TOML document: invalid value, line 1, column 10 " + linesNotShown + "\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "varlatch.toml"), []byte(c.toml), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Chdir(dir)
			var stdout, stderr bytes.Buffer
			Main(c.args, MapEnv{"VARLATCH_CONFIG_DIR": filepath.Join(dir, "config")}, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
			got := stderr.String()
			if c.stdout {
				got = stdout.String()
			}
			matches := got == c.want // stderr is the message alone
			if c.stdout {
				matches = strings.Contains(got, c.want)
			}
			if strings.Contains(stdout.String()+stderr.String(), "fake") || !matches {
				t.Errorf("stdout\n%q\nstderr\n%q\nwant %q", stdout.String(), stderr.String(), c.want)
			}
		})
	}
	// A file without an at-sign: smol-toml's message, its lines included.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "varlatch.toml"), []byte(org+"server = \"https://example.com\" x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	var stdout, stderr bytes.Buffer
	Main([]string{"context"}, MapEnv{"VARLATCH_CONFIG_DIR": filepath.Join(dir, "config")}, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	if want := "Invalid varlatch.toml: Invalid TOML document: each key-value declaration must be followed by an end-of-line\n\n" +
		"2:  project = \"web\"\n3:  server = \"https://example.com\" x\n                                   ^\n\n"; stderr.String() != want {
		t.Errorf("stderr\n%q\nwant\n%q", stderr.String(), want)
	}
}

// TestFailureExplanationsSurvive: a message echoing a value with a URL's
// user name and password puts its explanation after the value (an accepted
// wording difference from TypeScript), so what the fail-safe keeps, after
// the last at-sign, still says what went wrong; a message naming a server
// shows its display form instead, which holds no at-sign, in TypeScript's
// wording. Pinned through Main, the fail-safe included, and for 5.1c's
// client messages through Run.finish.
func TestFailureExplanationsSurvive(t *testing.T) {
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
	write("config/credentials.json", `{"servers": {"https://u:fake@a.example": {"token": "t"}}}`)
	write("bad/varlatch.toml", "organization = \"acme\"\nproject = \"web\"\nserver = \"https://alice:fake@h.example\" x\n")
	env := MapEnv{"VARLATCH_CONFIG_DIR": filepath.Join(dir, "config"), "HOME": filepath.Join(dir, "home")}
	for _, c := range []struct {
		cwd  string
		args []string
		want string
	}{
		{"", []string{"server", "https://alice:fake@example.com"}, "varlatch server:[redacted]@example.com: unexpected argument\nUsage: varlatch server [--json]"},
		{"", []string{"server", "--https://alice:fake@example.com"}, "varlatch server:[redacted]@example.com: unknown option\nUsage: varlatch server [--json]"},
		{"", []string{"https://alice:fake@example.com"}, "varlatch:[redacted]@example.com: unknown command\n\nvarlatch: self-host-first"},
		{"", []string{"--approval", "https://alice:fake@x", "status"}, "varlatch:[redacted]@x: not an approval id\n"},
		// A server is shown as its display form (server-display).
		{"", []string{"server", "use", "https://alice:fake@[bad"}, "varlatch server use: not a URL: [unrecognised server URL]\n"},
		{"", []string{"server", "use", "https://alice:fake@z.example"}, "varlatch server use: you are not signed in to https://z.example. Sign in first: varlatch login --server and its URL\nSigned in to: https://a.example\n"},
		{"bad", []string{"context"}, "Invalid varlatch.toml: Invalid TOML document: each key-value declaration must be followed by an end-of-line, line 3, column 41 " + linesNotShown + "\n"},
	} {
		if err := os.MkdirAll(filepath.Join(dir, c.cwd), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(filepath.Join(dir, c.cwd))
		var stdout, stderr bytes.Buffer
		Main(c.args, env, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		if !strings.Contains(stderr.String(), c.want) || strings.Contains(stderr.String(), "fake") {
			t.Errorf("%q: stderr\n%s\nwant it to hold\n%s", c.args, stderr.String(), c.want)
		}
	}
	// 5.1c's client messages, which no command reaches before 5.1e: each
	// error as a command would return it, through Run.finish and so the
	// fail-safe. Nothing here connects: fetch refuses before it does.
	for _, c := range []struct {
		name string
		err  func(r *Run) error
		want string
	}{
		{"not authenticated", func(r *Run) error {
			_, err := r.connectClient("https://alice:fake@n.example")
			return err
		}, "Not authenticated to https://n.example: sign in with varlatch login --server and this server's URL (in a browser on this machine), " +
			"adding --start to approve in a browser on any device, or --token-stdin to pipe a credential\n"},
		{"credentials refused", func(r *Run) error {
			_, err := r.plainClient("https://alice:fake@n.example", "vlt_cli_fake").Meta(context.Background())
			return err
		}, "varlatch: https://n.example/v1/meta: a server URL with a user name or password can't be used; remove them and try again\n"},
		{"does not parse", func(r *Run) error {
			_, err := r.plainClient("https://alice:fake@[bad", "vlt_cli_fake").Meta(context.Background())
			return err
		}, "varlatch: Failed to parse URL from [unrecognised server URL]\n"},
	} {
		r, stderr := testRun(MapEnv{"VARLATCH_CONFIG_DIR": t.TempDir()})
		r.finish(c.err(r))
		if stderr.String() != c.want {
			t.Errorf("%s: stderr\n%q\nwant\n%q", c.name, stderr.String(), c.want)
		}
	}
}
