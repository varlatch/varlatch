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

func (s *sessionRun) run(stdin string, args ...string) (int, string, string) {
	s.t.Helper()
	cmd := exec.Command(s.exe, args...)
	cmd.Dir = s.dir
	cmd.Env = []string{asCLI + "=1", "HOME=" + s.dir, "VARLATCH_CONFIG_DIR=" + s.config, "PATH=" + os.Getenv("PATH")}
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
	type check struct {
		name   string
		store  map[string]map[string]any
		args   []string
		status int
		shown  string
	}
	checks := []check{
		{"login refuses it", nil, []string{"login", "--server", withPassword, "--token", "vlt_cli_x"}, 1,
			"Request cannot be constructed from a URL that includes credentials: http://[redacted]@127.0.0.1:2/v1/meta"},
		{"logout of a stored one", map[string]map[string]any{withPassword: {"token": "vlt_cli_x", "credentialId": "cred_1", "expiresAt": "2100-01-01T00:00:00.000Z"}}, []string{"logout"}, 0,
			"http://[redacted]@127.0.0.1:2: removed locally; server revocation failed (Request cannot be constructed from a URL that includes credentials: http://[redacted]@127.0.0.1:2/v1/me/credentials/cred_1)"},
		{"logout naming several", map[string]map[string]any{withPassword: {"token": "a"}, "https://b.example": {"token": "b"}}, []string{"logout"}, 64,
			"Multiple servers stored (http://[redacted]@127.0.0.1:2, https://b.example)."},
		{"logout of one not stored", map[string]map[string]any{"https://b.example": {"token": "b"}}, []string{"logout", "--server", "https://u:hunter2pass@nosuch.example"}, 1,
			"No stored credential for https://[redacted]@nosuch.example"},
		{"whoami naming several", map[string]map[string]any{withPassword: {"token": "a"}, "https://b.example": {"token": "b"}}, []string{"whoami"}, 64,
			"credentials are stored for http://[redacted]@127.0.0.1:2, https://b.example;"},
		{"whoami refuses it", map[string]map[string]any{withPassword: {"token": "vlt_cli_x"}}, []string{"whoami"}, 1,
			"Request cannot be constructed from a URL that includes credentials: http://[redacted]@127.0.0.1:2/v1/meta"},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			s := newSessionRun(t)
			if c.store != nil {
				s.store(c.store)
			}
			status, stdout, stderr := s.run("", c.args...)
			if status != c.status || !strings.Contains(stdout+stderr, c.shown) {
				t.Fatalf("status %d\nstdout %q\nstderr %q\nwant %d with %q", status, stdout, stderr, c.status, c.shown)
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
