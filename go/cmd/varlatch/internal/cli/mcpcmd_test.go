// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
)

// The tests of packages/mcp-server/src/run.test.ts, ported: the flags, the
// refusals, the credential, and the User-Agent.

func mcpRun(env MapEnv) *Run {
	return &Run{IO: IO{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, Env: env, Secrets: &Secrets{}}
}

func startError(t *testing.T, err error) *exitError {
	t.Helper()
	var e *exitError
	if !errors.As(err, &e) {
		t.Fatalf("want a start error, got %v", err)
	}
	return e
}

func TestMcpArgs(t *testing.T) {
	args, err := mcpRun(MapEnv{}).parseMcpArgs([]string{"--server", "https://v.example", "--org", "acme", "--project", "api", "-e", "dev"})
	if err != nil || *args.server != "https://v.example" || *args.organization != "acme" || *args.project != "api" || *args.environment != "dev" || args.allowWrites || args.help {
		t.Fatalf("%+v %v", args, err)
	}
	if args, _ := mcpRun(MapEnv{}).parseMcpArgs([]string{"--allow-writes"}); !args.allowWrites {
		t.Fatal("--allow-writes")
	}
	if args, _ := mcpRun(MapEnv{"VARLATCH_MCP_ALLOW_WRITES": "1"}).parseMcpArgs(nil); !args.allowWrites {
		t.Fatal("VARLATCH_MCP_ALLOW_WRITES=1")
	}
}

func TestMcpRefusesDisclosure(t *testing.T) {
	for _, c := range []struct {
		argv []string
		env  MapEnv
	}{
		{[]string{"--allow-disclose"}, MapEnv{}},
		{[]string{"--allow-writes", "--allow-disclose"}, MapEnv{}},
		{nil, MapEnv{"VARLATCH_MCP_ALLOW_DISCLOSE": "1"}},
		{nil, MapEnv{"VARLATCH_MCP_ALLOW_DISCLOSE": "true"}},
	} {
		_, err := mcpRun(c.env).parseMcpArgs(c.argv)
		e := startError(t, err)
		if e.code != ExitUsage || !strings.Contains(e.message, "secret disclosure through MCP has been removed") {
			t.Fatalf("%v: %d %q", c.argv, e.code, e.message)
		}
	}
	// Unset, empty, and 0 mean off.
	for _, v := range []string{"0", ""} {
		if _, err := mcpRun(MapEnv{"VARLATCH_MCP_ALLOW_DISCLOSE": v}).parseMcpArgs(nil); err != nil {
			t.Fatalf("%q: %v", v, err)
		}
	}
}

func TestMcpRefusesUnknownOptionsAndMissingValues(t *testing.T) {
	for _, argv := range [][]string{{"--bogus"}, {"--server"}} {
		_, err := mcpRun(MapEnv{}).parseMcpArgs(argv)
		if e := startError(t, err); e.code != ExitUsage {
			t.Fatalf("%v: %d", argv, e.code)
		}
	}
}

// operatorStore is the operator's credential in the default location
// (XDG_CONFIG_HOME), with no VARLATCH_CONFIG_DIR.
func operatorStore(t *testing.T, server string) MapEnv {
	t.Helper()
	xdg := t.TempDir()
	dir := filepath.Join(xdg, "varlatch")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store := `{"servers":{"` + server + `":{"token":"vlt_cli_operator"}}}`
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), []byte(store), 0o600); err != nil {
		t.Fatal(err)
	}
	return MapEnv{"XDG_CONFIG_HOME": xdg, "HOME": t.TempDir()}
}

func with(env MapEnv, more MapEnv) MapEnv {
	out := MapEnv{}
	for k, v := range env {
		out[k] = v
	}
	for k, v := range more {
		out[k] = v
	}
	return out
}

func TestMcpCredential(t *testing.T) {
	const server = "https://varlatch.example"
	base := func() *mcpArgs {
		s, o, p, e := server, "acme", "api", "dev"
		return &mcpArgs{server: &s, organization: &o, project: &p, environment: &e}
	}
	t.Chdir(t.TempDir()) // outside any repository

	// Inside an agent-safe run, never the operator's stored credential, even with VARLATCH_CONFIG_DIR unset: 77.
	_, err := mcpRun(with(operatorStore(t, server), MapEnv{"VARLATCH_AGENT_RUN": "run_0123456789abcdef"})).prepareMcp(base())
	e := startError(t, err)
	if e.code != ExitDenied || !strings.Contains(e.message, "inside agent-safe run run_0123456789abcdef, which gives the Agent no Varlatch credential") || !strings.Contains(e.message, "--agent-metadata") {
		t.Fatalf("%d %q", e.code, e.message)
	}

	// VARLATCH_CONFIG_DIR pointed back at the default location does not reopen it.
	store := operatorStore(t, server)
	_, err = mcpRun(with(store, MapEnv{"VARLATCH_AGENT_RUN": "run_1", "VARLATCH_CONFIG_DIR": filepath.Join(store["XDG_CONFIG_HOME"], "varlatch")})).prepareMcp(base())
	if e := startError(t, err); e.code != ExitDenied {
		t.Fatalf("%d", e.code)
	}

	// Negative control, same store: outside an agent-safe run the stored credential is used.
	r := mcpRun(operatorStore(t, server))
	opts, err := r.prepareMcp(base())
	if err != nil || opts.Client.Server() != server || strings.Contains(r.Secrets.Mask("vlt_cli_operator"), "vlt_cli_operator") {
		t.Fatalf("%v", err)
	}

	// Inside an agent-safe run, the agent-run credential is used.
	opts, err = mcpRun(with(operatorStore(t, server), MapEnv{"VARLATCH_AGENT_RUN": "run_1", "VARLATCH_TOKEN": "vlt_agr_1"})).prepareMcp(base())
	if err != nil || opts.Client.Server() != server {
		t.Fatalf("%v", err)
	}

	// Inside an agent-safe run, --allow-writes is refused: the only credential is read-only.
	writes := base()
	writes.allowWrites = true
	_, err = mcpRun(MapEnv{"VARLATCH_AGENT_RUN": "run_1", "VARLATCH_TOKEN": "vlt_agr_1"}).prepareMcp(writes)
	if e := startError(t, err); e.code != ExitUsage || !strings.Contains(e.message, "--allow-writes does not apply here") {
		t.Fatalf("%d %q", e.code, e.message)
	}

	// Without any credential outside a run: 77 with the login instruction.
	_, err = mcpRun(MapEnv{"XDG_CONFIG_HOME": t.TempDir(), "HOME": t.TempDir()}).prepareMcp(base())
	if e := startError(t, err); e.code != ExitDenied || !strings.Contains(e.message, "varlatch login") {
		t.Fatalf("%d %q", e.code, e.message)
	}
}

func TestMcpUserAgent(t *testing.T) {
	if got := FormatMCPUserAgent("0.16.0", "linux", "x64"); got != "varlatch-mcp/0.16.0 (linux; x64)" {
		t.Fatalf("%q", got)
	}
	var sent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"apiMajor":1,"serverVersion":"0.16.0","capabilities":[]}`)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	s := srv.URL
	opts, err := mcpRun(MapEnv{"VARLATCH_TOKEN": "vlt_cli_test"}).prepareMcp(&mcpArgs{server: &s})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opts.Client.(*apiclient.Client).Meta(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := "varlatch-mcp/" + buildinfo.Version + " (" + NodePlatform() + "; " + NodeArch() + ")"; sent != want {
		t.Fatalf("sent %q, want %q", sent, want)
	}
}

// TestMcpNeverShowsTheCredential: a server that echoes the bearer back in
// an error, and a tool answer holding it, reach the host with it masked:
// every line goes through the CLI's fail-safe.
func TestMcpNeverShowsTheCredential(t *testing.T) {
	// Varlatch's own format, and a bearer of any other shape (#297's
	// review: only the vlt_ format was masked in a tool's result).
	for _, token := range []string{"vlt_cli_mcpCanaryAAAA", "plainword_bearer_canary_9f3a"} {
		t.Run(token[:9], func(t *testing.T) { mcpNeverShows(t, token) })
	}
}

func mcpNeverShows(t *testing.T, token string) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/organizations" {
			_, _ = io.WriteString(w, `{"items":[{"slug":"`+token+`"}],"nextCursor":null}`)
			return
		}
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `{"error":{"code":"PERMISSION_DENIED","message":"refused `+r.Header.Get("Authorization")+`","requestId":"r"}}`)
	}))
	defer srv.Close()
	t.Chdir(t.TempDir())
	var stdout, stderr bytes.Buffer
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"varlatch_list_projects","arguments":{"organization":"acme"}}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"varlatch_list_organizations","arguments":{}}}` + "\n"
	code := Main([]string{"mcp", "--server", srv.URL}, MapEnv{"VARLATCH_TOKEN": token, "HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()},
		IO{Stdin: strings.NewReader(in), Stdout: &stdout, Stderr: &stderr})
	out := stdout.String()
	if code != 0 || strings.Count(out, "\n") != 2 || strings.Contains(out, token) || strings.Contains(stderr.String(), token) {
		t.Fatalf("status %d\nstdout %q\nstderr %q", code, out, stderr.String())
	}
	if !strings.Contains(out, "PERMISSION_DENIED") || !strings.Contains(out, "[redacted]") {
		t.Fatalf("stdout %q", out)
	}
}
