// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEchoedBearerNeverReachesStdout: a server that echoes the bearer back
// in its answers (in every string it sends), with a bearer of any shape
// (not only Varlatch's vlt_ format), never gets it onto stdout or stderr,
// whichever command prints the answer (#297's review).
func TestEchoedBearerNeverReachesStdout(t *testing.T) {
	const token = "plainword_bearer_canary_9f3a"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		var body any
		switch {
		case r.URL.Path == "/v1/meta":
			body = map[string]any{"serverVersion": "0.22.0", "apiMajor": 1, "capabilities": []string{"identity.whoami"}}
		case r.URL.Path == "/v1/me":
			body = map[string]any{
				"identity":     map[string]any{"id": "idn_1", "name": "Ada " + bearer, "kind": "human"},
				"organization": map[string]any{"id": "org_1", "slug": "acme", "name": "Acme " + bearer},
				"credential":   map[string]any{"id": "cred_a"},
			}
		case r.URL.Path == "/v1/me/credentials":
			body = map[string]any{"items": []any{map[string]any{"id": "cred_a", "current": true, "kind": "cli", "name": "laptop " + bearer,
				"createdAt": "2026-11-01T10:00:00.000Z", "expiresAt": "2100-01-01T00:00:00.000Z"}}, "nextCursor": nil}
		case strings.HasSuffix(r.URL.Path, "/environments"):
			body = map[string]any{"items": []any{map[string]any{"id": "env_1", "name": "dev " + bearer, "tier": "development", "kind": "shared",
				"createdAt": "2026-11-01T10:00:00.000Z"}}, "nextCursor": nil}
		case strings.HasSuffix(r.URL.Path, "/contract"):
			body = map[string]any{"revisionId": "rev_1 " + bearer, "contract": map[string]any{"note": bearer}}
		default:
			w.WriteHeader(403)
			body = map[string]any{"error": map[string]any{"code": "PERMISSION_DENIED", "message": "refused " + bearer, "requestId": "r"}}
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()
	repo := t.TempDir()
	toml := "server = \"" + srv.URL + "\"\norganization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n"
	if err := os.WriteFile(filepath.Join(repo, "varlatch.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repo)
	for _, args := range [][]string{
		{"whoami"},
		{"whoami", "--json"},
		{"status", "--probe", "--json"},
		{"env", "list"},
		{"env", "list", "--json"},
		{"contract", "show"},
		{"values", "list"},
	} {
		var stdout, stderr bytes.Buffer
		code := Main(args, MapEnv{"VARLATCH_TOKEN": token, "HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()},
			IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		if strings.Contains(stdout.String()+stderr.String(), token) {
			t.Errorf("%v: status %d shows the bearer\nstdout %q\nstderr %q", args, code, stdout.String(), stderr.String())
		}
	}
}
