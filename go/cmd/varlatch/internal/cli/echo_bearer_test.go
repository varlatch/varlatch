// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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
//
// A bearer the person gave in VARLATCH_TOKEN is held whatever its length
// (the short one here); `env use` keeps the tier a server answered masked,
// so a later offline `status --json` cannot print it either.
func TestEchoedBearerNeverReachesStdout(t *testing.T) {
	// Named apart from the tokens: a test's temporary directories carry its
	// name.
	for name, token := range map[string]string{"long": "plainword_bearer_canary_9f3a", "short": "q7Zk"} {
		t.Run(name, func(t *testing.T) { echoedBearerNeverShown(t, token) })
	}
}

func echoedBearerNeverShown(t *testing.T, token string) {
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
			body = map[string]any{"items": []any{
				map[string]any{"id": "env_1", "name": "dev", "tier": "development " + bearer, "kind": "shared", "createdAt": "2026-11-01T10:00:00.000Z"},
				map[string]any{"id": "env_2", "name": "dev2 " + bearer, "tier": "development", "kind": "shared", "createdAt": "2026-11-01T10:00:00.000Z"},
			}, "nextCursor": nil}
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
		{"env", "use", "dev"},
		{"status", "--json"},
		{"status"},
	} {
		var stdout, stderr bytes.Buffer
		code := Main(args, MapEnv{"VARLATCH_TOKEN": token, "HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()},
			IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		if strings.Contains(stdout.String()+stderr.String(), token) {
			t.Errorf("%v: status %d shows the bearer\nstdout %q\nstderr %q", args, code, stdout.String(), stderr.String())
		}
	}
	// The tier env use keeps is masked, so a later run that does not know
	// the bearer (no VARLATCH_TOKEN, offline) prints none.
	local, err := os.ReadFile(filepath.Join(repo, ".varlatch", "local.json"))
	if err != nil || !strings.Contains(string(local), `"selectedTier"`) || strings.Contains(string(local), token) {
		t.Fatalf("local.json %q, %v", local, err)
	}
	var stdout, stderr bytes.Buffer
	Main([]string{"status", "--json"}, MapEnv{"HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir()}, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	if !strings.Contains(stdout.String(), "development") || strings.Contains(stdout.String()+stderr.String(), token) {
		t.Fatalf("status --json without the bearer\nstdout %q\nstderr %q", stdout.String(), stderr.String())
	}
}

// TestEveryClientHoldsItsBearer: the CLI makes an API client only through
// Run.newClient, which holds the bearer first, so no call site can forget
// it (a go/ast check across go/cmd/varlatch).
func TestEveryClientHoldsItsBearer(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	found := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasPrefix(filepath.ToSlash(rel), "internal/apiclient/") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			site := filepath.ToSlash(rel) + ":"
			if ok {
				site += fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, isIdent := sel.X.(*ast.Ident); isIdent && pkg.Name == "apiclient" && sel.Sel.Name == "New" {
					found++
					if site != "internal/cli/cli.go:newClient" {
						t.Errorf("%s: apiclient.New outside Run.newClient", fset.Position(call.Pos()))
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found != 1 {
		t.Fatalf("found apiclient.New %d times, want once (in newClient)", found)
	}
}
