// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// sessionRun runs the CLI under test with a configuration directory of its
// own, outside any repository.
type sessionRun struct {
	t      *testing.T
	exe    string
	dir    string
	config string
}

func newSessionRun(t *testing.T) *sessionRun {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	if err := os.MkdirAll(config, 0o700); err != nil {
		t.Fatal(err)
	}
	return &sessionRun{t: t, exe: exe, dir: dir, config: config}
}

func (s *sessionRun) store(servers map[string]map[string]any) {
	s.t.Helper()
	data, _ := json.Marshal(map[string]any{"servers": servers})
	if err := os.WriteFile(filepath.Join(s.config, "credentials.json"), data, 0o600); err != nil {
		s.t.Fatal(err)
	}
}

// repo makes the run's directory a repository without a server.
func (s *sessionRun) repo() {
	s.t.Helper()
	if err := os.WriteFile(filepath.Join(s.dir, "varlatch.toml"), []byte("organization = \"acme\"\nproject = \"web\"\n"), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

func (s *sessionRun) run(stdin string, args ...string) (int, string, string) {
	s.t.Helper()
	return s.runEnv(nil, stdin, args...)
}

// runEnv is run with extra environment variables.
func (s *sessionRun) runEnv(env []string, stdin string, args ...string) (int, string, string) {
	s.t.Helper()
	cmd := exec.Command(s.exe, args...)
	cmd.Dir = s.dir
	cmd.Env = append([]string{asCLI + "=1", "HOME=" + s.dir, "VARLATCH_CONFIG_DIR=" + s.config, "PATH=" + os.Getenv("PATH")}, env...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	status := 0
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			s.t.Fatalf("%v: %v", args, err)
		}
		status = exit.ExitCode()
	}
	return status, stdout.String(), stderr.String()
}

// fakeServer answers sign-in's requests for any credential and records the
// Authorization header of each.
func fakeServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/meta":
			_, _ = w.Write([]byte(`{"serverVersion":"0.22.0","apiMajor":1,"capabilities":["identity.whoami"]}`))
		case "/v1/organizations":
			_, _ = w.Write([]byte(`{"items":[]}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":{"code":"NOT_FOUND","message":"no","requestId":"req_1"}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

// TestLoginNeverShowsTheCredential: a credential given to login, on the
// command line or on standard input, never appears in what login prints,
// whether it is accepted, refused as malformed (whitespace, a character an
// HTTP header cannot carry) or refused by the server; and a credential
// fetch cannot send is refused before any request.
func TestLoginNeverShowsTheCredential(t *testing.T) {
	srv, seen := fakeServer(t)
	const secret = "vlt_cli_secretCANARY"
	cases := []struct {
		name   string
		stdin  string
		args   []string
		status int
		stderr string // a substring stderr must hold
		sent   bool
	}{
		{"stdin accepted", secret + "\n", []string{"--token-stdin"}, 0, "", true},
		{"stdin with whitespace", secret + " " + secret + "\n", []string{"--token-stdin"}, 64, "contains whitespace", false},
		{"stdin with two lines", secret + "\n" + secret + "\n", []string{"--token-stdin"}, 64, "contains whitespace", false},
		{"stdin beyond Latin-1", secret + "ĀX\n", []string{"--token-stdin"}, 1, "the credential contains a character that is not allowed in an HTTP header", false},
		{"stdin with a NUL", secret + "\x00X\n", []string{"--token-stdin"}, 1, "the credential contains a character that is not allowed in an HTTP header", false},
		{"stdin with a control character", secret + "\x7fX\n", []string{"--token-stdin"}, 69, "Cannot reach the Varlatch server (network error)", false},
		{"argument beyond Latin-1", "", []string{"--token", secret + "ĀX"}, 1, "the credential contains a character that is not allowed in an HTTP header", false},
		{"argument with a line break", "", []string{"--token", secret + "\nX"}, 1, "the credential contains a character that is not allowed in an HTTP header", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newSessionRun(t)
			before := len(seen())
			status, stdout, stderr := s.run(c.stdin, append([]string{"login", "--server", srv.URL}, c.args...)...)
			if status != c.status || !strings.Contains(stderr, c.stderr) {
				t.Fatalf("status %d, stderr %q; want %d with %q", status, stderr, c.status, c.stderr)
			}
			if strings.Contains(stdout+stderr, "CANARY") {
				t.Errorf("the credential was printed:\n%s%s", stdout, stderr)
			}
			if sent := len(seen()) > before; sent != c.sent {
				t.Errorf("requests sent %v, want %v", sent, c.sent)
			}
		})
	}
}

// TestSessionCommandsNeverShowUserinfo: a server URL with a user name and
// password, given or stored, is printed by login, logout and whoami with
// [redacted] in their place (go/README.md, "Diagnostics never print
// credential values"), and nothing is sent to it.
func TestSessionCommandsNeverShowUserinfo(t *testing.T) {
	const withPassword = "http://user:hunter2pass@127.0.0.1:2"
	const tripleSlash = "http:///user:hunter2pass@127.0.0.1:2"
	const backslashes = "http:\\\\user:hunter2pass@127.0.0.1:3"
	const noSlashes = "http:user:hunter2pass@127.0.0.1:4"
	type check struct {
		name   string
		store  map[string]map[string]any
		args   []string
		status int
		// stdout and stderr, each exactly: an error moving to stdout fails.
		stdout, stderr string
	}
	const whoamiUsage = "Usage: varlatch whoami [--server <url>] [--json]\n"
	// A refusal from the API client (5.1c): the explanation follows the URL.
	const refused = ": a server URL with a user name or password can't be used; remove them and try again"
	checks := []check{
		{"login refuses it", nil, []string{"login", "--server", withPassword, "--token", "vlt_cli_x"}, 1, "",
			"varlatch:[redacted]@127.0.0.1:2/v1/meta" + refused + "\n"},
		{"logout of a stored one", map[string]map[string]any{withPassword: {"token": "vlt_cli_x", "credentialId": "cred_1", "expiresAt": "2100-01-01T00:00:00.000Z"}}, []string{"logout"}, 0,
			"http://[redacted]@127.0.0.1:2: removed locally; server revocation failed (http://[redacted]@127.0.0.1:2/v1/me/credentials/cred_1" + refused + ") — the credential may remain live until 2100-01-01T00:00:00.000Z.\n", ""},
		{"logout naming several", map[string]map[string]any{withPassword: {"token": "a"}, "https://b.example": {"token": "b"}}, []string{"logout"}, 64, "",
			"Multiple servers stored:[redacted]@127.0.0.1:2, https://b.example\nPass --server <url> or --all.\n"},
		{"logout of one not stored", map[string]map[string]any{"https://b.example": {"token": "b"}}, []string{"logout", "--server", "https://u:hunter2pass@nosuch.example"}, 1, "",
			"varlatch logout:[redacted]@nosuch.example: no credential is stored for this server\n"},
		{"logout with no server here", map[string]map[string]any{withPassword: {"token": "a"}}, []string{"logout"}, 64, "",
			"No server here; stored:[redacted]@127.0.0.1:2\nPass --server <url> or --all.\n"},
		{"whoami naming several", map[string]map[string]any{withPassword: {"token": "a"}, "https://b.example": {"token": "b"}}, []string{"whoami"}, 64, "",
			"varlatch whoami:[redacted]@127.0.0.1:2, https://b.example: credentials are stored for each of these; pass --server <url>\n" + whoamiUsage},
		{"whoami refuses it", map[string]map[string]any{withPassword: {"token": "vlt_cli_x"}}, []string{"whoami"}, 1, "",
			"varlatch:[redacted]@127.0.0.1:2/v1/meta" + refused + "\n"},
		// WHATWG's authority variants for a special scheme: any run of "/"
		// and "\\" after the scheme, or none, starts the authority.
		{"logout of a stored one, three slashes", map[string]map[string]any{tripleSlash: {"token": "vlt_cli_x", "credentialId": "cred_1"}}, []string{"logout"}, 0,
			"http:///[redacted]@127.0.0.1:2: removed locally; server revocation failed (http:///[redacted]@127.0.0.1:2/v1/me/credentials/cred_1" + refused + ") — the credential may remain live.\n", ""},
		{"logout --all, three slashes and backslashes", map[string]map[string]any{tripleSlash: {"token": "a"}, backslashes: {"token": "b"}}, []string{"logout", "--all"}, 0,
			"http:///[redacted]@127.0.0.1:2: removed locally; server revocation failed (no credential id recorded by this login) — the credential may remain live.\n" +
				"http:\\\\[redacted]@127.0.0.1:3: removed locally; server revocation failed (no credential id recorded by this login) — the credential may remain live.\n", ""},
		{"logout naming several, three slashes and backslashes", map[string]map[string]any{tripleSlash: {"token": "a"}, backslashes: {"token": "b"}}, []string{"logout"}, 64, "",
			"Multiple servers stored:[redacted]@127.0.0.1:3\nPass --server <url> or --all.\n"},
		{"whoami --json refuses it, three slashes", map[string]map[string]any{tripleSlash: {"token": "vlt_cli_x"}}, []string{"whoami", "--json"}, 1, "",
			"varlatch:[redacted]@127.0.0.1:2/v1/meta" + refused + "\n"},
		{"whoami --json --server refuses it, backslashes", map[string]map[string]any{backslashes: {"token": "vlt_cli_x"}}, []string{"whoami", "--json", "--server", backslashes}, 1, "",
			"varlatch:[redacted]@127.0.0.1:3/v1/meta" + refused + "\n"},
		{"whoami --json naming several, backslashes and no slashes", map[string]map[string]any{backslashes: {"token": "a"}, noSlashes: {"token": "b"}}, []string{"whoami", "--json"}, 64, "",
			"varlatch whoami:[redacted]@127.0.0.1:4: credentials are stored for each of these; pass --server <url>\n" + whoamiUsage},
		{"whoami naming several, three slashes and no slashes", map[string]map[string]any{tripleSlash: {"token": "a"}, noSlashes: {"token": "b"}}, []string{"whoami"}, 64, "",
			"varlatch whoami:[redacted]@127.0.0.1:4: credentials are stored for each of these; pass --server <url>\n" + whoamiUsage},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			s := newSessionRun(t)
			if c.store != nil {
				s.store(c.store)
			}
			if c.name == "logout with no server here" {
				s.repo()
			}
			status, stdout, stderr := s.run("", c.args...)
			// The whole output, exactly: every explanation survives the
			// fail-safe (Run.finish), which masks from a message's first
			// scheme colon to its last at-sign.
			if status != c.status || stdout != c.stdout || stderr != c.stderr {
				t.Fatalf("status %d\nstdout %q\nstderr %q\nwant %d,\nstdout %q\nstderr %q", status, stdout, stderr, c.status, c.stdout, c.stderr)
			}
			if strings.Contains(stdout+stderr, "hunter2pass") {
				t.Errorf("a URL's password was printed:\n%s%s", stdout, stderr)
			}
		})
	}
}

// TestLoginLaterMethodsSayNotYet: the sign-in methods of slice 5.2 are a
// usage error that says so, before anything is read, sent or written.
func TestLoginLaterMethodsSayNotYet(t *testing.T) {
	for _, args := range [][]string{
		{"login", "--server", "http://127.0.0.1:2"},
		{"login", "--server", "http://127.0.0.1:2", "--oidc", "--org", "acme"},
		{"login", "--server", "http://127.0.0.1:2", "--start"},
		{"login", "--server", "http://127.0.0.1:2", "--wait"},
		{"--assisted", "login", "--server", "http://127.0.0.1:2"},
	} {
		s := newSessionRun(t)
		status, stdout, stderr := s.run("", args...)
		if status != 64 || stdout != "" || !strings.Contains(stderr, "not in this build of the Go CLI yet (slice 5.2)") {
			t.Errorf("%v: status %d, stdout %q, stderr %q", args, status, stdout, stderr)
		}
		if entries, _ := os.ReadDir(s.config); len(entries) != 0 {
			t.Errorf("%v: wrote %d files", args, len(entries))
		}
	}
}

// TestUsageErrorsNeverEchoACredential: a usage error never echoes the value
// of an option that holds a credential, nor a token in Varlatch's format,
// wherever it was given: `--token=<value>` is an unknown option to the
// parser, a stray token an unexpected argument or an unknown command
// (go/README.md, "Usage errors never echo a credential").
func TestUsageErrorsNeverEchoACredential(t *testing.T) {
	loginUsage := func(s *sessionRun) string {
		_, stdout, _ := s.run("", "login", "--help")
		return stdout
	}
	for _, c := range []struct {
		args []string
		want string // the first line of stderr
	}{
		{[]string{"login", "--server", "https://a.example", "--token=vlt_cli_secretCANARY"}, "varlatch login: unknown option --token=[redacted]"},
		{[]string{"login", "--server", "https://a.example", "--token=plainCANARY"}, "varlatch login: unknown option --token=[redacted]"},
		{[]string{"login", "--server", "https://a.example", "--oidc", "--org", "acme", "--oidc-token=eyJCANARY"}, "varlatch login: unknown option --oidc-token=[redacted]"},
		{[]string{"login", "--server", "https://a.example", "--token-stdin", "vlt_cli_secretCANARY"}, "varlatch login: unexpected argument [redacted]"},
		{[]string{"whoami", "vlt_cli_secretCANARY"}, "varlatch whoami: unexpected argument [redacted]"},
		{[]string{"vlt_cli_secretCANARY"}, "varlatch: unknown command [redacted]"},
		{[]string{"run-vlt_cli_secretCANARY"}, "varlatch: unknown command run-[redacted]"},
		{[]string{"agents", "install", "--agent", "vlt_cli_secretCANARY"}, ""},
		{[]string{"agents", "install", "--agent=vlt_cli_secretCANARY"}, "varlatch agents install: unknown option --agent=[redacted]"},
	} {
		s := newSessionRun(t)
		status, stdout, stderr := s.run("", c.args...)
		first, _, _ := strings.Cut(stderr, "\n")
		if status != 64 || stdout != "" || c.want != "" && first != c.want || stderr == "" {
			t.Errorf("%q: status %d, stdout %q, stderr %q; want 64 and %q", c.args, status, stdout, stderr, c.want)
		}
		if strings.Contains(stdout+stderr, "CANARY") {
			t.Errorf("%q: the credential was echoed:\n%s", c.args, stderr)
		}
		if c.args[0] == "login" && !strings.HasSuffix(stderr, loginUsage(s)) {
			t.Errorf("%q: the usage does not follow:\n%s", c.args, stderr)
		}
	}
}

// TestLoginServerTokenIsNeverEchoed: a token given as the server is
// refused by the API client as a URL that does not parse; the refusal
// reaches stderr through the fail-safe, which redacts it.
func TestLoginServerTokenIsNeverEchoed(t *testing.T) {
	s := newSessionRun(t)
	status, stdout, stderr := s.run("", "login", "--server", "vlt_cli_secretCANARY", "--token", "vlt_cli_x")
	if status != 1 || stdout != "" || stderr != "varlatch: Failed to parse URL from [redacted]/v1/meta\n" {
		t.Errorf("status %d, stdout %q, stderr %q", status, stdout, stderr)
	}
}

// TestWhoamiJSONShowsOnlyTheDocumentedFields: `whoami --json` shows the
// server it asked, masked, and only the fields of the WhoAmI document,
// whatever else /v1/me answers: a server of the answer's own (with a user
// name and password) never replaces it, and no other field, at the top or
// inside identity and credential, is passed through.
func TestWhoamiJSONShowsOnlyTheDocumentedFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/meta":
			_, _ = w.Write([]byte(`{"serverVersion":"0.22.0","apiMajor":1,"capabilities":["identity.whoami"]}`))
		case "/v1/me":
			_, _ = w.Write([]byte(`{"server":"https://u:hunter2pass@h.example","identity":{"id":"idn_1","name":"Ada","kind":"human","email":null,"token":"vlt_cli_leakCANARY"},` +
				`"organization":{"id":"org_1","slug":"acme","name":"Acme","secret":"CANARY"},"credential":{"id":"cred_1","name":"laptop","kind":"cli","expiresAt":null,"token":{"value":"CANARY"}},` +
				`"listener":"ordinary","token":"vlt_cli_leakCANARY","extra":{"a":"CANARY"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	s := newSessionRun(t)
	s.store(map[string]map[string]any{srv.URL: {"token": "vlt_cli_x"}})
	status, stdout, stderr := s.run("", "whoami", "--json")
	want := "{\n" +
		"  \"version\": 1,\n" +
		"  \"server\": \"" + srv.URL + "\",\n" +
		"  \"identity\": {\n    \"id\": \"idn_1\",\n    \"name\": \"Ada\",\n    \"kind\": \"human\",\n    \"email\": null\n  },\n" +
		"  \"organization\": {\n    \"id\": \"org_1\",\n    \"slug\": \"acme\",\n    \"name\": \"Acme\"\n  },\n" +
		"  \"credential\": {\n    \"id\": \"cred_1\",\n    \"name\": \"laptop\",\n    \"kind\": \"cli\",\n    \"expiresAt\": null\n  },\n" +
		"  \"listener\": \"ordinary\"\n" +
		"}\n"
	if status != 0 || stderr != "" || stdout != want {
		t.Fatalf("status %d, stderr %q\nstdout\n%s\nwant\n%s", status, stderr, stdout, want)
	}
	if strings.Contains(stdout, "CANARY") || strings.Contains(stdout, "hunter2pass") {
		t.Errorf("a field outside the document was shown:\n%s", stdout)
	}
}

// TestOutputNeverShowsAToken: what the server answers, the environment or
// the store holds is printed through the fail-safe (printJSON's
// RedactValue for every --json document, RedactOutput for every stdout
// line), so a Varlatch token anywhere in it is [redacted], at the top of a
// document or nested, in --json and human output alike, and a URL's user
// name and password are masked.
func TestOutputNeverShowsAToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/meta":
			_, _ = w.Write([]byte(`{"serverVersion":"0.22.0","apiMajor":1,"capabilities":["identity.whoami"]}`))
		case "/v1/me":
			_, _ = w.Write([]byte(`{"identity":{"id":"idn_1","name":"see vlt_svc_nestedCANARY here","kind":"human","email":null},"organization":null,` +
				`"credential":{"id":"cred_1","name":"vlt_cli_bearerCANARY","kind":"cli","expiresAt":null},"listener":"ordinary",` +
				`"tailnet":{"recognized":true,"tailnet":"t.ts.net","nodeId":"n1","tags":["tag:vlt_cli_tagCANARY"]}}`))
		case "/v1/organizations/acme/projects/web/environments":
			_, _ = w.Write([]byte(`{"items":[{"name":"vlt_cli_nameCANARY","tier":"https://u:hunter2pass@h.example","kind":"vlt_svc_kindCANARY"},{"name":"dev","tier":"development","kind":"shared"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	s := newSessionRun(t)
	s.store(map[string]map[string]any{srv.URL: {"token": "vlt_cli_x", "name": "vlt_cli_storedCANARY", "issuedAt": "2026-01-01T00:00:00.000Z", "expiresAt": "2100-01-01T00:00:00.000Z"}})
	if err := os.WriteFile(filepath.Join(s.dir, "varlatch.toml"), []byte("server = \""+srv.URL+"\"\norganization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		env  []string
		args []string
		want []string // what stdout must hold
	}{
		{nil, []string{"whoami", "--json"}, []string{`"name": "[redacted]"`, `"name": "see [redacted] here"`, `"tag:[redacted]"`}},
		{nil, []string{"whoami"}, []string{"Identity      see [redacted] here (human, idn_1)", "Credential    [redacted] (cli, cred_1)", "tags tag:[redacted]"}},
		{nil, []string{"env", "list", "--json"}, []string{`"name": "[redacted]"`, `"tier": "https://[redacted]@h.example"`, `"kind": "[redacted]"`}},
		{nil, []string{"env", "list"}, []string{"[redacted]  (https://[redacted]@h.example, [redacted])", "dev  (development, shared, selected)"}},
		{nil, []string{"status", "--json"}, []string{`"name": "[redacted]"`}},
		{[]string{"VARLATCH_SERVER=vlt_cli_serverCANARY"}, []string{"server", "--json"}, []string{`"server": "[redacted]"`}},
		{[]string{"VARLATCH_SERVER=vlt_cli_serverCANARY"}, []string{"server"}, []string{"Server here: [redacted] (from VARLATCH_SERVER)"}},
		{[]string{"VARLATCH_SERVER=https://u:hunter2pass@h.example"}, []string{"server", "--json"}, []string{`"server": "https://[redacted]@h.example"`}},
	} {
		status, stdout, stderr := s.runEnv(c.env, "", c.args...)
		if status != 0 {
			t.Errorf("%v %q: status %d, stderr %q", c.env, c.args, status, stderr)
		}
		for _, w := range c.want {
			if !strings.Contains(stdout, w) {
				t.Errorf("%v %q: stdout does not hold %q:\n%s", c.env, c.args, w, stdout)
			}
		}
		if strings.Contains(stdout+stderr, "CANARY") || strings.Contains(stdout+stderr, "hunter2pass") {
			t.Errorf("%v %q: a token or password was printed:\n%s%s", c.env, c.args, stdout, stderr)
		}
	}
}
