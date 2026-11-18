// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Values are secrets: no path of `values`, `validate` or `import` prints
// one, on stdout or stderr, in human text, JSON, a dry run, a usage error,
// a refusal, or a server's error that echoes it (internal
// docs/design/go-cli.md, slice 5.3a; go/README.md, "No message holds a
// value"). Each case gives a canary value one way and checks that neither
// stream holds it, nor any value the run sent.

const canary = "s3cr3t-canary-value-0042"

type valuesServer struct {
	*httptest.Server
	mu   sync.Mutex
	sent []string // every value the CLI sent
	// answers by "METHOD path" (path without the query); a missing one is 200 {"versionId": "ver_1"}.
	answers map[string]struct {
		status int
		body   string
	}
}

func newValuesServer(t *testing.T) *valuesServer {
	s := &valuesServer{answers: map[string]struct {
		status int
		body   string
	}{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body struct{ Value *string }
		received := ""
		if json.Unmarshal(raw, &body) == nil && body.Value != nil {
			received = *body.Value
			s.mu.Lock()
			s.sent = append(s.sent, received)
			s.mu.Unlock()
		}
		w.Header().Set("content-type", "application/json")
		if a, ok := s.answers[r.Method+" "+r.URL.Path]; ok {
			w.WriteHeader(a.status)
			// {{value}}: the server echoes the value it received.
			_, _ = w.Write([]byte(strings.ReplaceAll(a.body, "{{value}}", received)))
			return
		}
		_, _ = w.Write([]byte(`{"versionId": "ver_1", "primaryVersionId": "ver_2", "rotationDeadline": "2026-11-19T10:00:00Z"}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *valuesServer) answer(method, path string, status int, body string) {
	s.answers[method+" "+path] = struct {
		status int
		body   string
	}{status, body}
}

const envPath = "/v1/organizations/acme/projects/web/environments/dev"

// runIn runs the CLI in a repository on the server, signed in.
func runIn(t *testing.T, s *valuesServer, stdin string, files map[string]string, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	dir := t.TempDir()
	write := func(path, content string) {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("repo/varlatch.toml", "server = \""+s.URL+"\"\norganization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n")
	write("config/credentials.json", `{"servers": {"`+s.URL+`": {"token": "vlt_cli_secretTestAAAA"}}}`+"\n")
	for path, content := range files {
		write("repo/"+path, content)
	}
	t.Chdir(filepath.Join(dir, "repo"))
	vars := MapEnv{"HOME": filepath.Join(dir, "home"), "VARLATCH_CONFIG_DIR": filepath.Join(dir, "config")}
	for k, v := range env {
		vars[k] = v
	}
	var stdout, stderr bytes.Buffer
	code := Main(args, vars, IO{Stdin: strings.NewReader(stdin), Stdout: &stdout, Stderr: &stderr})
	return code, stdout.String(), stderr.String()
}

func TestValuesNeverPrintAValue(t *testing.T) {
	const dotenvFile = "API_KEY=" + canary + "\nPORT=8080\nQUOTED=\"" + canary + "-quoted\"\n"
	type setup func(s *valuesServer)
	echo := func(method, path string, status int, code string) setup {
		return func(s *valuesServer) {
			s.answer(method, path, status, `{"error": {"code": "`+code+`", "message": "the value `+canary+` was refused; also `+canary+`-quoted"}}`)
		}
	}
	effective := func(s *valuesServer) {
		s.answer("GET", envPath+"/effective-configuration", 200, `{"items": [{"name": "API_KEY", "sensitive": true, "source": "self", "value": "`+canary+`"}, {"name": "PORT", "sensitive": false, "source": "self", "value": "`+canary+`", "rawValue": "`+canary+`"}]}`)
	}
	contract := func(s *valuesServer) {
		s.answer("GET", "/v1/organizations/acme/projects/web/contract", 200, `{"id": "crv_1", "contract": {"schemaVersion": 1, "items": [{"name": "API_KEY", "required": {"kind": "never"}, "sensitive": true, "type": "string", "rotationHint": "rotate it"}]}}`)
	}
	cases := []struct {
		name  string
		setup []setup
		stdin string
		files map[string]string
		env   map[string]string
		args  []string
	}{
		{name: "set argument", args: []string{"values", "set", "API_KEY", canary}},
		{name: "set argument after --", args: []string{"values", "set", "API_KEY", "--", "-" + canary}},
		{name: "set stdin", stdin: canary + "\n", args: []string{"values", "set", "API_KEY", "--stdin"}},
		{name: "set file", files: map[string]string{"key": canary + "\n"}, args: []string{"values", "set", "API_KEY", "--from-file", "key"}},
		{name: "set echoed by the server", setup: []setup{echo("PUT", envPath+"/values/API_KEY", 400, "VALIDATION_FAILED")}, args: []string{"values", "set", "API_KEY", canary}},
		{name: "set refused", setup: []setup{echo("PUT", envPath+"/values/API_KEY", 403, "PERMISSION_DENIED")}, stdin: canary, args: []string{"values", "set", "API_KEY", "--stdin"}},
		{name: "set a value before --", args: []string{"values", "set", "API_KEY", "-" + canary}},
		{name: "set a value in two words", args: []string{"values", "set", "API_KEY", "first", canary}},
		{name: "set a value with an option", args: []string{"values", "set", "API_KEY", canary, "--stdin"}},
		{name: "set assisted refuses the argument", setup: []setup{contract}, args: []string{"--assisted", "values", "set", "API_KEY", canary}},
		{name: "set assisted marker", setup: []setup{contract}, env: map[string]string{"CLAUDECODE": "1"}, args: []string{"values", "set", "API_KEY", canary}},
		{name: "set assisted existing", setup: []setup{effective}, stdin: canary, args: []string{"--assisted", "values", "set", "API_KEY", "--stdin"}},
		{name: "set generated", args: []string{"values", "set", "API_KEY", "--generate", "hex:32"}},
		{name: "set generated, echoed", setup: []setup{func(s *valuesServer) {
			s.answers["PUT "+envPath+"/values/API_KEY"] = struct {
				status int
				body   string
			}{400, `{"error": {"code": "VALIDATION_FAILED", "message": "not accepted: {{value}}"}}`}
		}}, args: []string{"values", "set", "API_KEY", "--generate", "alnum:40"}},
		{name: "rotate", setup: []setup{contract}, args: []string{"values", "rotate", "API_KEY", canary}},
		{name: "rotate echoed", setup: []setup{contract, echo("POST", envPath+"/values/API_KEY/rotations", 409, "CONFLICT")}, stdin: canary, args: []string{"values", "rotate", "API_KEY", "--stdin", "--grace", "60"}},
		{name: "rotate a value before --", args: []string{"values", "rotate", "API_KEY", "-" + canary}},
		{name: "list", setup: []setup{effective}, args: []string{"values", "list"}},
		{name: "list json", setup: []setup{effective}, args: []string{"values", "list", "--json"}},
		{name: "import", setup: []setup{effective}, files: map[string]string{".env": dotenvFile}, args: []string{"import", ".env"}},
		{name: "import json", setup: []setup{effective}, files: map[string]string{".env": dotenvFile}, args: []string{"import", ".env", "--json", "--delete-source"}},
		{name: "import dry run", setup: []setup{effective}, files: map[string]string{".env": dotenvFile}, args: []string{"import", ".env", "--dry-run", "--json"}},
		{name: "import dry run human", setup: []setup{effective}, files: map[string]string{".env": dotenvFile}, args: []string{"import", ".env", "--dry-run"}},
		{name: "import contract", setup: []setup{effective}, files: map[string]string{".env": dotenvFile}, args: []string{"import", ".env", "--contract", "--plain", "PORT"}},
		{name: "import echoed", setup: []setup{effective, echo("PUT", envPath+"/values/API_KEY", 500, "INTERNAL")}, files: map[string]string{".env": dotenvFile}, args: []string{"import", ".env"}},
		{name: "import assisted", setup: []setup{effective}, files: map[string]string{".env": dotenvFile}, args: []string{"--assisted", "import", ".env"}},
		{name: "import parse error", files: map[string]string{".env": "A=1\nB=\"" + canary + "\nC=" + canary + "\n"}, args: []string{"import", ".env"}},
		{name: "import text after a quote", files: map[string]string{".env": "A='x' " + canary + "\n"}, args: []string{"import", ".env"}},
		{name: "import bad names", files: map[string]string{".env": "lower=" + canary + "\nVARLATCH_TOKEN=" + canary + "\nA=" + canary + "\nA=" + canary + "\nN=a\x00" + canary + "\n"}, args: []string{"import", ".env"}},
		{name: "import a value as a line", files: map[string]string{".env": canary + "\n"}, args: []string{"import", ".env"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newValuesServer(t)
			for _, f := range c.setup {
				f(s)
			}
			_, stdout, stderr := runIn(t, s, c.stdin, c.files, c.env, c.args...)
			s.mu.Lock()
			values := append([]string{canary}, s.sent...)
			s.mu.Unlock()
			for _, v := range values {
				if len(v) >= MinMaskedLength && (strings.Contains(stdout, v) || strings.Contains(stderr, v)) {
					t.Errorf("a value reached the output:\nstdout %q\nstderr %q", stdout, stderr)
				}
			}
			if stdout == "" && stderr == "" {
				t.Errorf("nothing was said")
			}
		})
	}
}
