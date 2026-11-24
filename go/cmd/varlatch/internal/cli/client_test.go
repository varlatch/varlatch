// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
)

// The CLI's client (connectClient and its warnings). Until slice 5.1e
// ports the commands that use it (env list, whoami, run), these hold what
// apps/cli/test/token-expiry-warning.test.ts and machine-interface.test.ts
// ("not signed in: 77") check of it, against main.ts's text.

func expiringServer(t *testing.T, header string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header != "" {
			w.Header().Set("Varlatch-Credential-Expires", header)
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/organizations" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"error":{"code":"RESOURCE_NOT_FOUND","message":"/v1/organizations","requestId":"req_1"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"capabilities":[]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testRun(env MapEnv) (*Run, *bytes.Buffer) {
	var stderr bytes.Buffer
	r := &Run{IO: IO{Stdout: &bytes.Buffer{}, Stderr: &stderr}, Env: env}
	r.Secrets = &Secrets{Token: r.Getenv("VARLATCH_TOKEN"), Stored: func() []string { return storedTokens(env) }}
	return r, &stderr
}

const tokenWarning = "issue a new one (`varlatch credential issue`) and replace VARLATCH_TOKEN"

func TestEnvTokenExpiryWarningOncePerProcess(t *testing.T) {
	expires := time.Now().Add(72 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	srv := expiringServer(t, expires)
	r, stderr := testRun(MapEnv{"VARLATCH_TOKEN": "vlt_svc_runner", "VARLATCH_CONFIG_DIR": t.TempDir()})
	for i := 0; i < 2; i++ {
		api, err := r.connectClient(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 2; j++ {
			if _, err := api.Meta(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := "varlatch: credential for " + srv.URL + " (VARLATCH_TOKEN) expires " + expires + "; " + tokenWarning + " before then\n"
	if stderr.String() != want {
		t.Errorf("stderr %q, want %q", stderr.String(), want)
	}
}

func TestEnvTokenExpiredOnARefusedRequest(t *testing.T) {
	srv := expiringServer(t, "2026-01-01T00:00:00.000Z")
	r, stderr := testRun(MapEnv{"VARLATCH_TOKEN": "vlt_svc_runner", "VARLATCH_CONFIG_DIR": t.TempDir()})
	api, err := r.connectClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.Request(context.Background(), "GET", "/v1/organizations", nil, nil)
	if err == nil {
		t.Fatal("no error")
	}
	if !strings.Contains(stderr.String(), "varlatch: credential for "+srv.URL+" (VARLATCH_TOKEN) expired 2026-01-01T00:00:00.000Z; "+tokenWarning+"\n") {
		t.Errorf("stderr %q", stderr.String())
	}
	var exit *exitError
	if !errors.As(r.mapClientError(err), &exit) || exit.code != ExitFailure || exit.message != "Error RESOURCE_NOT_FOUND: /v1/organizations" {
		t.Errorf("mapped %v", r.mapClientError(err))
	}
}

func TestNoHeaderWarningForAStoredCredentialOrInsideAnAgentRun(t *testing.T) {
	srv := expiringServer(t, time.Now().Add(72*time.Hour).UTC().Format(time.RFC3339))
	config := t.TempDir()
	if err := os.WriteFile(filepath.Join(config, "credentials.json"), []byte(`{"servers":{"`+srv.URL+`":{"token":"vlt_cli_stored"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, env := range map[string]MapEnv{
		"stored":    {"VARLATCH_CONFIG_DIR": config},
		"agent run": {"VARLATCH_TOKEN": "vlt_agr_run", "VARLATCH_AGENT_RUN": "run_0123456789abcdef", "VARLATCH_CONFIG_DIR": t.TempDir(), "HOME": t.TempDir()},
	} {
		r, stderr := testRun(env)
		api, err := r.connectClient(srv.URL)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := api.Meta(context.Background()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if stderr.Len() != 0 {
			t.Errorf("%s: stderr %q", name, stderr.String())
		}
	}
}

func TestStoredCredentialExpiryWarning(t *testing.T) {
	srv := expiringServer(t, "")
	config := t.TempDir()
	issued := time.Now().Add(-23 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	expires := time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	store := `{"servers":{"` + srv.URL + `":{"token":"vlt_cli_stored","issuedAt":"` + issued + `","expiresAt":"` + expires + `"}}}`
	if err := os.WriteFile(filepath.Join(config, "credentials.json"), []byte(store), 0o600); err != nil {
		t.Fatal(err)
	}
	r, stderr := testRun(MapEnv{"VARLATCH_CONFIG_DIR": config})
	for i := 0; i < 2; i++ {
		if _, err := r.connectClient(srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	want := "varlatch: credential for " + srv.URL + " expires " + expires + " — run `varlatch login --server " + srv.URL + "` to renew\n"
	if stderr.String() != want {
		t.Errorf("stderr %q, want %q", stderr.String(), want)
	}
	// VARLATCH_TOKEN wins, and has no stored metadata to judge.
	r, stderr = testRun(MapEnv{"VARLATCH_CONFIG_DIR": config, "VARLATCH_TOKEN": "vlt_svc_env"})
	if _, err := r.connectClient(srv.URL); err != nil || stderr.Len() != 0 {
		t.Errorf("with VARLATCH_TOKEN: %v, stderr %q", err, stderr.String())
	}
}

func TestNotAuthenticated(t *testing.T) {
	const server = "https://v.example"
	r, _ := testRun(MapEnv{"VARLATCH_CONFIG_DIR": t.TempDir()})
	_, err := r.connectClient(server)
	var exit *exitError
	want := "Not authenticated to https://v.example.\nSign in: varlatch login --server https://v.example (in a browser on this machine), " +
		"varlatch login --server https://v.example --start (approve in a browser on any device), " +
		"or pipe a credential to varlatch login --server https://v.example --token-stdin"
	if !errors.As(err, &exit) || exit.code != ExitDenied || exit.message != want {
		t.Errorf("%v", err)
	}
	r, _ = testRun(MapEnv{"VARLATCH_CONFIG_DIR": t.TempDir(), "HOME": t.TempDir(), "VARLATCH_AGENT_RUN": "run_1"})
	_, err = r.connectClient(server)
	want = "Not authenticated to https://v.example: this command runs inside agent-safe run run_1, which gives the Agent no Varlatch credential and never uses the operator's.\n" +
		"For read access to configuration metadata, the operator relaunches the run with --agent-metadata."
	if !errors.As(err, &exit) || exit.code != ExitDenied || exit.message != want {
		t.Errorf("agent run: %v", err)
	}
	// A stored token that is not truthy is no credential.
	config := t.TempDir()
	_ = os.WriteFile(filepath.Join(config, "credentials.json"), []byte(`{"servers":{"https://v.example":{"token":""}}}`), 0o600)
	r, _ = testRun(MapEnv{"VARLATCH_CONFIG_DIR": config})
	if _, err = r.connectClient(server); !errors.As(err, &exit) || exit.code != ExitDenied {
		t.Errorf("empty token: %v", err)
	}
}

// refusing is an address that refuses a connection for as long as the test
// runs. A listener's port, closed, is anyone's again, and another test's
// server may get it (a connected socket's port is given away too). A listener
// is given no port below 1024 it did not ask for; Fetch's bad ports end at 995
// there.
func refusing(t *testing.T) string {
	t.Helper()
	for port := 1023; port > 1000; port-- {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return addr
		}
		conn.Close() // a service of this host's
	}
	t.Fatal("every port from 1001 to 1023 is in use")
	return ""
}

func TestUnreachableServer(t *testing.T) {
	server := "http://" + refusing(t)
	r, _ := testRun(MapEnv{"VARLATCH_CONFIG_DIR": t.TempDir(), "VARLATCH_TOKEN": "vlt_svc_x"})
	api, err := r.connectClient(server)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.Meta(context.Background())
	var exit *exitError
	if !errors.As(r.mapClientError(err), &exit) || exit.code != ExitUnavailable ||
		exit.message != "Cannot reach the Varlatch server (ECONNREFUSED). Check --server, VARLATCH_SERVER, or varlatch.toml, and that the server is running." {
		t.Errorf("%v", r.mapClientError(err))
	}
}

func TestTokenEchoedByTheServerIsMasked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":{"code":"INVALID_CREDENTIAL","message":"bad token stored-token-1234 and env-token-5678"}}`))
	}))
	defer srv.Close()
	config := t.TempDir()
	_ = os.WriteFile(filepath.Join(config, "credentials.json"), []byte(`{"servers":{"https://other.example":{"token":"stored-token-1234"}}}`), 0o600)
	r, _ := testRun(MapEnv{"VARLATCH_CONFIG_DIR": config, "VARLATCH_TOKEN": "env-token-5678"})
	api, err := r.connectClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.Meta(context.Background())
	var exit *exitError
	if !errors.As(r.mapClientError(err), &exit) || exit.code != ExitDenied || exit.message != "Error INVALID_CREDENTIAL: bad token [redacted] and [redacted]" {
		t.Errorf("%v", r.mapClientError(err))
	}
}

// A server URL with a user name and password is shown as its display form,
// without them, by every message the client's use prints; a command to run
// says "this server's URL", since one naming the display form would not work.
func TestClientMessagesNeverShowUserinfo(t *testing.T) {
	const server = "https://user:hunter2pass@v.example"
	const shown = "https://v.example"
	for _, env := range []MapEnv{
		{"VARLATCH_CONFIG_DIR": t.TempDir()},
		{"VARLATCH_CONFIG_DIR": t.TempDir(), "HOME": t.TempDir(), "VARLATCH_AGENT_RUN": "run_1"},
	} {
		r, _ := testRun(env)
		_, err := r.connectClient(server)
		var exit *exitError
		if !errors.As(err, &exit) || exit.code != ExitDenied || strings.Contains(exit.message, "hunter2pass") || !strings.Contains(exit.message, "Not authenticated to "+shown) {
			t.Errorf("%v", err)
		}
	}
	now := float64(time.Now().UnixMilli())
	for _, w := range []string{
		EnvTokenExpiryWarning(server, "2026-01-01T00:00:00.000Z", now),
		EnvTokenExpiryWarning(server, "2100-01-01T00:00:00.000Z", now),
	} {
		if strings.Contains(w, "hunter2pass") || !strings.HasPrefix(w, "varlatch: credential for "+shown+" (VARLATCH_TOKEN) ") {
			t.Errorf("%q", w)
		}
	}
	config := t.TempDir()
	store := `{"servers":{"` + server + `":{"token":"vlt_cli_stored","issuedAt":"2020-01-01T00:00:00.000Z","expiresAt":"2020-01-02T00:00:00.000Z"}}}`
	if err := os.WriteFile(filepath.Join(config, "credentials.json"), []byte(store), 0o600); err != nil {
		t.Fatal(err)
	}
	r, stderr := testRun(MapEnv{"VARLATCH_CONFIG_DIR": config})
	if _, err := r.connectClient(server); err != nil {
		t.Fatal(err)
	}
	// Through the fail-safe (Run.warn), which leaves the display form as it is.
	want := "varlatch: https://v.example: the credential expired 2020-01-02T00:00:00.000Z; run varlatch login --server and this server's URL\n"
	if stderr.String() != want {
		t.Errorf("stderr %q, want %q", stderr.String(), want)
	}
}

// TestNotAuthenticatedReadsAfterTheFailSafe: with a server URL holding a
// user name and password, "Not authenticated" shows its display form once
// and sign-in instructions that name "this server's URL", and the
// fail-safe leaves them as they are.
func TestNotAuthenticatedReadsAfterTheFailSafe(t *testing.T) {
	r, _ := testRun(MapEnv{"VARLATCH_CONFIG_DIR": t.TempDir()})
	_, err := r.connectClient("https://user:hunter2pass@v.example")
	var exit *exitError
	if !errors.As(err, &exit) {
		t.Fatalf("%v", err)
	}
	want := "Not authenticated to https://v.example: sign in with varlatch login --server and this server's URL (in a browser on this machine), " +
		"adding --start to approve in a browser on any device, or --token-stdin to pipe a credential"
	if got := clientctx.MaskUserinfoInText(exit.message); got != want {
		t.Errorf("%q, want %q", got, want)
	}
}
