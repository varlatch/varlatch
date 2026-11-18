// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// The hidden prompt of `values set` on a real pseudo-terminal (internal
// docs/design/go-cli.md, slice 5.3a): what is typed is never echoed, the
// value sent is exactly what the editing keys leave, and the terminal is
// restored however the prompt ends: Enter, Ctrl-C, Ctrl-D, or a signal.

type ptyRun struct {
	t      *testing.T
	dir    string
	server *httptest.Server
	mu     sync.Mutex
	bodies []string
}

func newPTYRun(t *testing.T) *ptyRun {
	t.Helper()
	p := &ptyRun{t: t, dir: t.TempDir()}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		p.bodies = append(p.bodies, r.Method+" "+r.URL.Path+" "+string(body))
		p.mu.Unlock()
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"versionId":"ver_1"}`))
	}))
	t.Cleanup(p.server.Close)
	write := func(path, content string) {
		full := filepath.Join(p.dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("repo/varlatch.toml", "server = \""+p.server.URL+"\"\norganization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n")
	write("config/credentials.json", `{"servers": {"`+p.server.URL+`": {"token": "vlt_cli_ptyAAAA"}}}`+"\n")
	return p
}

// start runs `varlatch values set API_KEY` on a new pseudo-terminal and
// returns its master side, the terminal (held, to read its state), the
// state the terminal had before, and the command.
func (p *ptyRun) start(extraEnv ...string) (*os.File, *os.File, *term.State, *exec.Cmd, *bytes.Buffer, *sync.Mutex) {
	p.t.Helper()
	exe, err := os.Executable()
	if err != nil {
		p.t.Fatal(err)
	}
	master, tty, err := pty.Open()
	if err != nil {
		p.t.Skipf("no pseudo-terminal: %v", err)
	}
	p.t.Cleanup(func() { _ = master.Close(); _ = tty.Close() })
	before, err := term.GetState(int(tty.Fd()))
	if err != nil {
		p.t.Fatal(err)
	}
	cmd := exec.Command(exe, "values", "set", "API_KEY")
	cmd.Dir = filepath.Join(p.dir, "repo")
	cmd.Env = append([]string{asCLI + "=1", "PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(p.dir, "home"), "VARLATCH_CONFIG_DIR=" + filepath.Join(p.dir, "config"), "TERM=dumb"}, extraEnv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := cmd.Start(); err != nil {
		p.t.Fatal(err)
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
	return master, tty, before, cmd, &out, &mu
}

// waitFor waits until the terminal shows text.
func waitFor(t *testing.T, out *bytes.Buffer, mu *sync.Mutex, text string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		shown := out.String()
		mu.Unlock()
		if strings.Contains(shown, text) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("the terminal never showed %q; it showed %q", text, out.String())
}

// finish waits for the command and returns its exit status, -1 for a
// signal, and what the terminal showed.
func finish(t *testing.T, cmd *exec.Cmd, out *bytes.Buffer, mu *sync.Mutex) (int, syscall.Signal, string) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the command did not end")
	}
	time.Sleep(100 * time.Millisecond) // what it wrote last reaches the master side
	mu.Lock()
	defer mu.Unlock()
	status := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if status.Signaled() {
		return -1, status.Signal(), out.String()
	}
	return status.ExitStatus(), 0, out.String()
}

func restored(t *testing.T, tty *os.File, before *term.State) {
	t.Helper()
	after, err := term.GetState(int(tty.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("the terminal was not restored:\nbefore %+v\nafter  %+v", before, after)
	}
}

func TestHiddenPromptOnATerminal(t *testing.T) {
	const prompt = "Value for API_KEY (input hidden): "
	cases := []struct {
		name   string
		typed  string
		status int
		value  string // the value sent, "" for none
		shows  string
	}{
		{"enter", "s3cr3t-typed-value\r", 0, "s3cr3t-typed-value", "API_KEY set (version ver_1)."},
		{"editing keys", "abcdefgh\U0001F600\x7f\x1b[Dij\r", 0, "abcdefghij", "API_KEY set (version ver_1)."},
		{"ctrl-d", "s3cr3t-ctrl-d\x04", 0, "s3cr3t-ctrl-d", "API_KEY set (version ver_1)."},
		{"empty", "\r", 1, "", "varlatch: no value entered; nothing was stored"},
		{"ctrl-c", "s3cr3t-half\x03", 130, "", "varlatch: cancelled; nothing was stored"},
		{"ctrl-c after enter in one read", "s3cr3t-x\r\x03", 130, "", "varlatch: cancelled; nothing was stored"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPTYRun(t)
			master, tty, before, cmd, out, mu := p.start()
			waitFor(t, out, mu, prompt)
			if _, err := master.Write([]byte(c.typed)); err != nil {
				t.Fatal(err)
			}
			status, _, shown := finish(t, cmd, out, mu)
			if status != c.status || !strings.Contains(shown, c.shows) {
				t.Errorf("status %d, terminal %q; want %d and %q", status, shown, c.status, c.shows)
			}
			// Nothing typed is echoed: no part of the value, no character of it.
			typed := strings.TrimRight(c.typed, "\r\x03\x04")
			for _, part := range []string{typed, "s3cr3t", "abcdefgh", "ij"} {
				if part != "" && strings.Contains(strings.TrimPrefix(shown, prompt), part) && !strings.Contains(c.shows, part) {
					t.Errorf("the terminal showed %q: %q", part, shown)
				}
			}
			restored(t, tty, before)
			p.mu.Lock()
			defer p.mu.Unlock()
			if c.value == "" {
				if len(p.bodies) != 0 {
					t.Errorf("sent %q, want nothing", p.bodies)
				}
				return
			}
			want, _ := json.Marshal(map[string]string{"value": c.value})
			if len(p.bodies) != 1 || p.bodies[0] != "PUT /v1/organizations/acme/projects/web/environments/dev/values/API_KEY "+string(want) {
				t.Errorf("sent %q, want the value %q", p.bodies, c.value)
			}
		})
	}
}

// TestHiddenPromptRestoresTheTerminalOnASignal: stopped by SIGTERM or
// SIGINT from outside while it waits, the prompt restores the terminal
// before the signal ends the process, and nothing is sent.
func TestHiddenPromptRestoresTheTerminalOnASignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			p := newPTYRun(t)
			master, tty, before, cmd, out, mu := p.start()
			waitFor(t, out, mu, "(input hidden): ")
			if _, err := master.Write([]byte("s3cr3t-partial")); err != nil {
				t.Fatal(err)
			}
			time.Sleep(200 * time.Millisecond)
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			status, got, shown := finish(t, cmd, out, mu)
			if status != -1 || got != sig {
				t.Errorf("ended with status %d signal %v, want the signal %v", status, got, sig)
			}
			if strings.Contains(shown, "s3cr3t") {
				t.Errorf("the terminal showed what was typed: %q", shown)
			}
			restored(t, tty, before)
			p.mu.Lock()
			defer p.mu.Unlock()
			if len(p.bodies) != 0 {
				t.Errorf("sent %q", p.bodies)
			}
		})
	}
}
