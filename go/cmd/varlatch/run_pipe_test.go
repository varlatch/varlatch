// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRunSurvivesAClosedStdout: in a masked run, when whatever reads the
// CLI's stdout goes away, the relay's write fails (EPIPE) instead of the
// Go runtime ending the CLI with SIGPIPE; the relay stops reading, as a
// closed pipe would, so the command's next write ends it with SIGPIPE, and
// `varlatch run` exits with the command's status, 128 + 13, as the
// TypeScript CLI does.
func TestRunSurvivesAClosedStdout(t *testing.T) {
	if _, err := exec.LookPath("yes"); err != nil {
		t.Skip("no yes(1)")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/effective-configuration"):
			_, _ = io.WriteString(w, `{"environmentId": "env_1", "items": [{"name": "API_KEY", "sensitive": true, "source": "self", "value": null}]}`)
		case strings.HasSuffix(r.URL.Path, "/disclosures"):
			_, _ = io.WriteString(w, `{"items": [{"name": "API_KEY", "versionId": "ver_1", "value": "s3cr3t-pipe-value-123"}], "withheld": []}`)
		default:
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"error": {"code": "RESOURCE_NOT_FOUND", "message": "no", "requestId": "r"}}`)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	for path, content := range map[string]string{
		"repo/varlatch.toml":      "server = \"" + server.URL + "\"\norganization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n",
		"config/credentials.json": `{"servers": {"` + server.URL + `": {"token": "vlt_cli_pipeAAAA"}}}` + "\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "--assisted", "run", "--", "yes", "a line")
	cmd.Dir = filepath.Join(dir, "repo")
	cmd.Env = []string{asCLI + "=1", "PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(dir, "home"), "VARLATCH_CONFIG_DIR=" + filepath.Join(dir, "config")}
	cmd.Stdout = write
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = write.Close()
	buf := make([]byte, 64)
	if _, err := io.ReadFull(read, buf); err != nil || !strings.HasPrefix(string(buf), "a line\n") {
		t.Fatalf("%q, %v (%s)", buf, err, stderr.String())
	}
	_ = read.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("varlatch run did not end after its stdout closed")
	}
	status := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if status.Signaled() {
		t.Fatalf("varlatch run was ended by %v (%s)", status.Signal(), stderr.String())
	}
	if code := status.ExitStatus(); code != 128+int(syscall.SIGPIPE) {
		t.Errorf("status %d, want %d (%s)", code, 128+int(syscall.SIGPIPE), stderr.String())
	}
}
