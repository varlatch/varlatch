// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDiagnosticsNeverPrintCredentials runs `status --probe` over stored
// credentials fetch refuses to send: a token holding a character not
// allowed in a header, and servers whose URL holds a user name and password
// (one that parses, two that do not). Neither format shows a token or a
// password anywhere: each server as status shows it, and each probe's
// detail, which names the problem (go/README.md, the Go CLI's accepted
// differences). Nothing is sent.
func TestDiagnosticsNeverPrintCredentials(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	if err := os.MkdirAll(config, 0o700); err != nil {
		t.Fatal(err)
	}
	store := map[string]any{"servers": map[string]map[string]string{
		"http://127.0.0.1:2":                  {"token": "vlt_cli_secretAAAA\nextra"},
		"http://127.0.0.1:3":                  {"token": "vlt_cli_secret\u0100BBBB"},
		"http://user:hunter2pass@127.0.0.1:2": {"token": "vlt_cli_secretCCCC"},
		"http://user:hunter2pass@[::1":        {"token": "vlt_cli_secretDDDD"},
		"http:/user:hunter2pass@[::1":         {"token": "vlt_cli_secretEEEE"},
	}}
	data, _ := json.Marshal(store)
	if err := os.WriteFile(filepath.Join(config, "credentials.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	// By the server as status shows it: with [redacted] for a user name and password.
	want := map[string]string{
		"http://127.0.0.1:2":            "the credential contains a character that is not allowed in an HTTP header",
		"http://127.0.0.1:3":            "the credential contains a character that is not allowed in an HTTP header",
		"http://[redacted]@127.0.0.1:2": "http://[redacted]@127.0.0.1:2/v1/meta: a server URL with a user name or password can't be used; remove them and try again",
		"http://[redacted]@[::1":        "http://[redacted]@[::1/v1/meta: can't be parsed as a URL",
		"http:/[redacted]@[::1":         "http:/[redacted]@[::1/v1/meta: can't be parsed as a URL",
	}
	// Nothing printed may hold a token or a URL's password.
	leaks := func(text string) bool {
		return strings.Contains(text, "secret") || strings.Contains(text, "hunter2pass")
	}
	run := func(args ...string) (string, string) {
		cmd := exec.Command(exe, args...)
		cmd.Dir = dir
		cmd.Env = []string{asCLI + "=1", "HOME=" + dir, "VARLATCH_CONFIG_DIR=" + config, "PATH=" + os.Getenv("PATH")}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, stderr.String())
		}
		return stdout.String(), stderr.String()
	}
	stdout, stderr := run("status", "--probe", "--json")
	var doc struct {
		Servers []struct {
			Server string
			Probe  struct{ State, Detail string }
		}
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Servers) != len(want) || stderr != "" {
		t.Fatalf("%d servers, stderr %q", len(doc.Servers), stderr)
	}
	for _, s := range doc.Servers {
		if s.Probe.State != "unreachable" || s.Probe.Detail != want[s.Server] {
			t.Errorf("%s: %s (%s), want unreachable (%s)", s.Server, s.Probe.State, s.Probe.Detail, want[s.Server])
		}
	}
	if leaks(stdout) {
		t.Errorf("status --probe --json shows a credential:\n%s", stdout)
	}
	human, stderr := run("status", "--probe")
	if leaks(human) || stderr != "" {
		t.Errorf("status --probe shows a credential:\n%s%s", human, stderr)
	}
	for server := range want {
		if !strings.Contains(human, server+"  (") {
			t.Errorf("the human format has no line for %s:\n%s", server, human)
		}
	}
}
