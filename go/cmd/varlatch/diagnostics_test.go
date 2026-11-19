// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	// Each server as status shows it (clientctx.DisplayServer: no user name
	// or password, an unrecognised URL as a placeholder) and its probe's
	// refusal, which names the refused URL the same way.
	want := []string{
		"http://127.0.0.1:2  the credential contains a character that is not allowed in an HTTP header",
		"http://127.0.0.1:3  the credential contains a character that is not allowed in an HTTP header",
		"http://127.0.0.1:2  http://127.0.0.1:2/v1/meta: a server URL with a user name or password can't be used; remove them and try again",
		"[unrecognised server URL]  Failed to parse URL from [unrecognised server URL]",
		"[unrecognised server URL]  Failed to parse URL from [unrecognised server URL]",
	}
	// Nothing printed may hold a token or a URL's user name or password.
	leaks := func(text string) bool {
		return strings.Contains(text, "secret") || strings.Contains(text, "hunter2pass") || strings.Contains(text, "user:")
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
	if stderr != "" {
		t.Fatalf("stderr %q", stderr)
	}
	var got []string
	for _, s := range doc.Servers {
		if s.Probe.State != "unreachable" {
			t.Errorf("%s: %s, want unreachable", s.Server, s.Probe.State)
		}
		got = append(got, s.Server+"  "+s.Probe.Detail)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("status --probe --json: servers and details\n%q\nwant\n%q", got, want)
	}
	if leaks(stdout) {
		t.Errorf("status --probe --json shows a credential:\n%s", stdout)
	}
	human, stderr := run("status", "--probe")
	if leaks(human) || stderr != "" {
		t.Errorf("status --probe shows a credential:\n%s%s", human, stderr)
	}
	// The human format names each server the same way and keeps each
	// refusal as the client wrote it.
	for _, line := range want {
		server, detail, _ := strings.Cut(line, "  ")
		if !strings.Contains(human, server+"  (no expiry recorded, probe: unreachable ("+detail+"))") {
			t.Errorf("the human format has no line for %s (%s):\n%s", server, detail, human)
		}
	}
}

// TestStatusProbeMasksNestedCredentials: a stored server whose query and
// fragment name credentialed URLs, with and without credentials of its
// own, is shown by status --probe, human and --json, and in each probe's
// refusal, as its display form: no user name or password, and the query
// and fragment left out with their markers.
func TestStatusProbeMasksNestedCredentials(t *testing.T) {
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
		"http://127.0.0.1:2/?next=http://a:hunter2pass@b.example#http://c:hunter2pass@d.example":               {"token": "vlt_cli_secretAAAA"},
		"http://u:hunter2pass@127.0.0.1:2/?next=http://a:hunter2pass@b.example#http://c:hunter2pass@d.example": {"token": "vlt_cli_secretBBBB"},
		"//u:hunter2pass@127.0.0.1:2/?next=http://a:hunter2pass@b.example":                                     {"token": "vlt_cli_secretCCCC"},
	}}
	data, _ := json.Marshal(store)
	if err := os.WriteFile(filepath.Join(config, "credentials.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"status", "--probe", "--json"}, {"status", "--probe"}, {"status", "--json"}, {"status"}} {
		cmd := exec.Command(exe, args...)
		cmd.Dir = dir
		cmd.Env = []string{asCLI + "=1", "HOME=" + dir, "VARLATCH_CONFIG_DIR=" + config, "PATH=" + os.Getenv("PATH")}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, stderr.String())
		}
		out := stdout.String() + stderr.String()
		if strings.Contains(out, "hunter2pass") || strings.Contains(out, "secret") || strings.Contains(out, "example") ||
			!strings.Contains(out, "http://127.0.0.1:2/?[redacted]#[redacted]") || !strings.Contains(out, "//127.0.0.1:2/?[redacted]") {
			t.Errorf("%v shows a credential or not each server's display form:\n%s", args, out)
		}
	}
}

// TestNestedCredentialsBehindOuterOnes: a stored server holding
// credentials, its own or nested in its query (a scheme-relative URL with
// outer and inner credentials, a leading space, a token as the nested
// user name with no colon, a percent-encoded nested URL: Sol, #278 rounds
// 4 to 6), is shown by server, context, status --probe (human and --json,
// its probe detail included) and logout --all's revocation reason as its
// display form, with no part of any credential.
func TestNestedCredentialsBehindOuterOnes(t *testing.T) {
	for i, c := range []struct {
		server, shown string
		secrets       []string
	}{
		{"//outer:outer-pass@gateway.example/?next=//alice1:inner-pass@upstream.example", "//gateway.example/?[redacted]", []string{"outer", "pass", "alice1", "upstream"}},
		{" //ci-bot_:example-password@upstream.example", "//upstream.example", []string{"ci-bot", "password"}},
		{"//gateway.example/?next=//ghp_RoundSixCanary@upstream.example", "//gateway.example/?[redacted]", []string{"ghp_", "RoundSix", "upstream"}},
		{"//gateway.example/?next=%2F%2Fci-bot%3ARoundSixPassword%40upstream.example", "//gateway.example/?[redacted]", []string{"ci-bot", "RoundSix", "upstream", "%3A", "%40"}},
	} {
		// Named by index: a test's name is in its temporary directory's path,
		// which context prints.
		t.Run(fmt.Sprint("server ", i), func(t *testing.T) { nestedCredentials(t, c.server, c.shown, c.secrets) })
	}
}

func nestedCredentials(t *testing.T, server, shown string, secrets []string) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	if err := os.MkdirAll(config, 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"servers": map[string]map[string]string{server: {"token": "vlt_cli_x", "credentialId": "cred_1"}}})
	if err := os.WriteFile(filepath.Join(config, "credentials.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	// context runs in a repository, given the server as VARLATCH_SERVER.
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "varlatch.toml"), []byte("organization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"server"}, {"server", "--json"}, {"context"}, {"context", "--json"}, {"status", "--probe"}, {"status", "--probe", "--json"}, {"logout", "--all"}} {
		cmd := exec.Command(exe, args...)
		cmd.Dir = dir
		cmd.Env = []string{asCLI + "=1", "HOME=" + dir, "VARLATCH_CONFIG_DIR=" + config, "PATH=" + os.Getenv("PATH")}
		if args[0] == "context" {
			cmd.Dir = repo
			cmd.Env = append(cmd.Env, "VARLATCH_SERVER="+server)
		}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, stderr.String())
		}
		out := stdout.String() + stderr.String()
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("%v shows %q:\n%s", args, secret, out)
			}
		}
		if !strings.Contains(out, shown) {
			t.Errorf("%v does not show %q:\n%s", args, shown, out)
		}
		if args[0] == "status" && !strings.Contains(out, "Failed to parse URL from "+shown) {
			t.Errorf("%v shows no probe detail naming the display form:\n%s", args, out)
		}
		if args[0] == "logout" && !strings.Contains(out, shown+": removed locally; server revocation failed (Failed to parse URL from "+shown) {
			t.Errorf("%v shows no revocation reason:\n%s", args, out)
		}
	}
}
