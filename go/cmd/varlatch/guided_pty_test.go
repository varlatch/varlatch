// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/creack/pty"
)

// Guided `varlatch init` on a real pseudo-terminal (slice 5.8a): asked for
// what the flags leave out, on a terminal only and outside assisted mode,
// and never showing a value of the .env file it imports.

const guidedValue = "guided-canary-6f2c91e0aa"

type guidedServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []string
}

func newGuidedServer(t *testing.T) *guidedServer {
	s := &guidedServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.requests = append(s.requests, r.Method+" "+r.URL.Path+" "+string(body))
		s.mu.Unlock()
		w.Header().Set("content-type", "application/json")
		path := r.URL.Path
		switch {
		case r.Method == "GET" && path == "/v1/organizations":
			_, _ = io.WriteString(w, `{"items":[{"slug":"acme","name":"Acme"}],"nextCursor":null}`)
		case r.Method == "GET" && strings.HasSuffix(path, "/projects"):
			_, _ = io.WriteString(w, `{"items":[{"slug":"web","name":"Web","contractAuthority":"git"}],"nextCursor":null}`)
		case r.Method == "GET" && strings.HasSuffix(path, "/environments"):
			_, _ = io.WriteString(w, `{"items":[{"name":"development","tier":"development","kind":"shared"},{"name":"production","tier":"production","kind":"shared"}],"nextCursor":null}`)
		case r.Method == "GET" && strings.HasSuffix(path, "/contract"):
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"error":{"code":"RESOURCE_NOT_FOUND","message":"none","requestId":"r"}}`)
		case strings.HasSuffix(path, "/effective-configuration"):
			_, _ = io.WriteString(w, `{"items":[]}`)
		case r.Method == "POST" && strings.HasSuffix(path, "/contract/revisions"):
			_, _ = io.WriteString(w, `{"id":"rev_guidedaaaaaaaaaaaaaaaaaaaaaa","contentHash":"sha256:`+strings.Repeat("a", 64)+`","active":false}`)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// startInit runs `varlatch init <args>` in dir on a new pseudo-terminal.
func startInit(t *testing.T, dir, home string, env []string, args ...string) (*os.File, *exec.Cmd, *bytes.Buffer, *sync.Mutex) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	master, tty, err := pty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = tty.Close() })
	cmd := exec.Command(exe, append([]string{"init"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append([]string{asCLI + "=1", "PATH=" + os.Getenv("PATH"), "HOME=" + home, "VARLATCH_CONFIG_DIR=" + filepath.Join(home, "config"), "TERM=dumb"}, env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	var mu sync.Mutex
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := master.Read(buf)
			mu.Lock()
			out.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return master, cmd, &out, &mu
}

// answer waits for a question and types a line.
func answer(t *testing.T, master *os.File, out *bytes.Buffer, mu *sync.Mutex, question, typed string) {
	t.Helper()
	waitFor(t, out, mu, question)
	mu.Lock()
	out.Reset() // the next question is looked for in what follows
	mu.Unlock()
	if _, err := master.Write([]byte(typed)); err != nil {
		t.Fatal(err)
	}
}

func TestGuidedInitOnATerminal(t *testing.T) {
	server := newGuidedServer(t)
	dir, home := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("API_KEY="+guidedValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	master, cmd, out, mu := startInit(t, dir, home, []string{"VARLATCH_TOKEN=vlt_cli_guidedAAAA"}, "--server", server.URL, "--no-agent-files")
	var shown strings.Builder
	step := func(question, typed string) {
		waitFor(t, out, mu, question)
		mu.Lock()
		shown.WriteString(out.String())
		mu.Unlock()
		answer(t, master, out, mu, question, typed)
	}
	step("Choice: ", "\r")                  // Organization: acme (Enter)
	step("Choice: ", "\r")                  // Project: web (Enter)
	step("Choice: ", "\r")                  // Default environment: development (Enter)
	step("Choice: ", "\r")                  // Import .env into: development (Enter)
	step("or Enter for none: ", "\r")       // Items that are not secret
	step("every environment. [Y/n] ", "\r") // Activate it?
	step("are not affected. [y/N] ", "y\r") // Delete .env?
	status, _, rest := finish(t, cmd, out, mu)
	shown.WriteString(rest)
	all := shown.String()
	if status != 0 || !strings.Contains(all, "Deleted .env.") || !strings.Contains(all, "Done. Run your application") {
		t.Fatalf("status %d, terminal %q", status, all)
	}
	if strings.Contains(all, guidedValue) {
		t.Fatalf("the terminal showed the value: %q", all)
	}
	toml, err := os.ReadFile(filepath.Join(dir, "varlatch.toml"))
	if err != nil || !strings.Contains(string(toml), `organization = "acme"`) || !strings.Contains(string(toml), `project = "web"`) {
		t.Fatalf("varlatch.toml %q, %v", toml, err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); !os.IsNotExist(err) {
		t.Fatalf(".env is still there: %v", err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if !strings.Contains(strings.Join(server.requests, "\n"), "PUT /v1/organizations/acme/projects/web/environments/development/values/API_KEY") {
		t.Fatalf("requests %q", server.requests)
	}
}

// TestGuidedInitNeverOnAssisted: in assisted mode a terminal does not make
// init guided: the flags are needed, and nothing is written.
func TestGuidedInitNeverOnAssisted(t *testing.T) {
	dir, home := t.TempDir(), t.TempDir()
	_, cmd, out, mu := startInit(t, dir, home, []string{"VARLATCH_ASSISTED=1"})
	status, _, shown := finish(t, cmd, out, mu)
	if status != 64 || !strings.Contains(shown, "Usage: varlatch init --org <slug> --project <slug>") || strings.Contains(shown, "Choice: ") {
		t.Fatalf("status %d, terminal %q", status, shown)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("written: %v", entries)
	}
}

// TestGuidedInitInputEnds: the input ending before an answer ends the run
// (1) with the step it was at and nothing written.
func TestGuidedInitInputEnds(t *testing.T) {
	server := newGuidedServer(t)
	dir, home := t.TempDir(), t.TempDir()
	master, cmd, out, mu := startInit(t, dir, home, []string{"VARLATCH_TOKEN=vlt_cli_guidedAAAA"}, "--server", server.URL)
	waitFor(t, out, mu, "Choice: ")
	if _, err := master.Write([]byte{4}); err != nil { // Ctrl-D
		t.Fatal(err)
	}
	status, _, shown := finish(t, cmd, out, mu)
	if status != 1 || !strings.Contains(shown, "varlatch init: reading or creating the organization failed (Error).") {
		t.Fatalf("status %d, terminal %q", status, shown)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("written: %v", entries)
	}
}
