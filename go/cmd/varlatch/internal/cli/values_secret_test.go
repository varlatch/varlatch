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
	// onPut runs as the server stores a value (a test changes the source file then).
	onPut func()
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
		if r.Method == "PUT" && s.onPut != nil {
			s.onPut()
		}
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
	return runInRepo(t, s, stdin, files, env, nil, args...)
}

// runInWith is runIn with a step that prepares the repository directory.
func runInWith(t *testing.T, s *valuesServer, files map[string]string, prepare func(repo string), args ...string) (int, string, string) {
	t.Helper()
	return runInRepo(t, s, "", files, nil, prepare, args...)
}

func runInRepo(t *testing.T, s *valuesServer, stdin string, files map[string]string, env map[string]string, prepare func(repo string), args ...string) (int, string, string) {
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
	if prepare != nil {
		prepare(filepath.Join(dir, "repo"))
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
				if v != "" && (strings.Contains(stdout, v) || strings.Contains(stderr, v)) {
					t.Errorf("a value reached the output:\nstdout %q\nstderr %q", stdout, stderr)
				}
			}
			if stdout == "" && stderr == "" {
				t.Errorf("nothing was said")
			}
		})
	}
}

// noneShown fails when stdout or stderr holds any of the values.
func noneShown(t *testing.T, stdout, stderr string, values ...string) {
	t.Helper()
	for _, v := range values {
		if strings.Contains(stdout, v) || strings.Contains(stderr, v) {
			t.Errorf("%q reached the output:\nstdout %q\nstderr %q", v, stdout, stderr)
		}
	}
	if stdout == "" && stderr == "" {
		t.Errorf("nothing was said")
	}
}

// TestShortValuesNeverShown: a value in flight is redacted whatever its
// length, when a server echoes it in an error or in a successful answer's
// version id (of the server's shape or not).
func TestShortValuesNeverShown(t *testing.T) {
	for _, value := range []string{"x", "ab", "q7z", "s3c4", "w2x3y", "zzqqxx", "abcdefg"} {
		for name, answer := range map[string]struct {
			status int
			body   string
		}{
			"error echo":          {400, `{"error": {"code": "VALIDATION_FAILED", "message": "bad value {{value}}!"}}`},
			"version id":          {200, `{"versionId": "{{value}}"}`},
			"version id of shape": {200, `{"versionId": "ver_{{value}}` + strings.Repeat("a", 26-len(value)) + `"}`},
		} {
			for _, form := range []struct {
				args  []string
				stdin string
				path  string
			}{
				{[]string{"values", "set", "API_KEY", value}, "", "PUT " + envPath + "/values/API_KEY"},
				{[]string{"values", "set", "API_KEY", "--stdin"}, value + "\n", "PUT " + envPath + "/values/API_KEY"},
				{[]string{"values", "rotate", "API_KEY", "--stdin"}, value + "\n", "POST " + envPath + "/values/API_KEY/rotations"},
			} {
				t.Run(value+"/"+name+"/"+strings.Join(form.args[:2], " ")+"/"+form.args[len(form.args)-1], func(t *testing.T) {
					s := newValuesServer(t)
					a := answer
					if strings.Contains(form.path, "rotations") {
						a.body = strings.ReplaceAll(a.body, `"versionId"`, `"primaryVersionId"`)
					}
					s.answers[form.path] = a
					_, stdout, stderr := runIn(t, s, form.stdin, nil, nil, form.args...)
					noneShown(t, stdout, stderr, value)
				})
			}
		}
	}
	// Import's Secrets, short ones included; a plain value of the Contract is not one.
	s := newValuesServer(t)
	s.answer("GET", "/v1/organizations/acme/projects/web/contract", 200, `{"contract": {"schemaVersion": 1, "items": [{"name": "PORT", "required": {"kind": "never"}, "sensitive": false, "type": "integer"}]}}`)
	s.answer("PUT", envPath+"/values/B", 500, `{"error": {"code": "INTERNAL", "message": "x {{value}} y"}}`)
	_, stdout, stderr := runIn(t, s, "", map[string]string{".env": "A=q7\nB=zk\nPORT=8080\n"}, nil, "import", ".env")
	noneShown(t, stdout, stderr, "q7", "zk")
}

// TestServerFieldsNeverPassThrough: validate and import show only the
// fields the protocol documents, an enumeration's value only when it is
// one, and a server's identifiers only of their shape: an extra field
// holding a value, or a secret where a requirement, a type, an id or a
// hash goes, never reaches stdout or stderr, as --json, human text or a
// dry run.
func TestServerFieldsNeverPassThrough(t *testing.T) {
	report := `{"environmentId": "env_1", "valid": false, "complete": false, "value": "` + canary + `",
		"missing": ["DATABASE_URL"],
		"invalid": [{"name": "PORT", "reason": "expected an integer", "value": "` + canary + `"}],
		"unresolved": [{"name": "U", "reason": "` + canary + `", "value": "` + canary + `"}],
		"notEvaluated": [{"name": "K", "requires": "` + canary + `", "reason": "` + canary + `", "value": "` + canary + `"}]}`
	for _, args := range [][]string{{"validate"}, {"validate", "--json"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			s := newValuesServer(t)
			s.answer("POST", envPath+"/validate", 200, report)
			code, stdout, stderr := runIn(t, s, "", nil, nil, args...)
			noneShown(t, stdout, stderr, canary)
			if code != 1 {
				t.Errorf("status %d, want 1", code)
			}
			if !strings.Contains(stdout+stderr, UnrecognizedRequirement) {
				t.Errorf("the requirement was not shown as unrecognized: %q %q", stdout, stderr)
			}
		})
	}
	contract := `{"id": "` + canary + `", "contract": {"schemaVersion": 1, "value": "` + canary + `", "items": [
		{"name": "API_KEY", "required": {"kind": "never"}, "sensitive": "` + canary + `", "type": "` + canary + `", "value": "` + canary + `"},
		{"name": "PORT", "required": {"kind": "never"}, "sensitive": false, "type": "integer"}]}}`
	for _, args := range [][]string{
		{"import", ".env", "--dry-run"}, {"import", ".env", "--dry-run", "--json"},
		{"import", ".env"}, {"import", ".env", "--json"}, {"import", ".env", "--contract", "--json"}, {"import", ".env", "--contract"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			s := newValuesServer(t)
			s.answer("GET", "/v1/organizations/acme/projects/web/contract", 200, contract)
			s.answer("GET", envPath+"/effective-configuration", 200, `{"items": [{"name": "PORT", "sensitive": false, "source": "self", "value": "8080", "extra": "`+canary+`"}]}`)
			s.answer("POST", "/v1/organizations/acme/projects/web/contract/revisions", 201, `{"id": "`+canary+`", "contentHash": "`+canary+`", "active": "`+canary+`"}`)
			_, stdout, stderr := runIn(t, s, "", map[string]string{".env": "API_KEY=s3cr3t-key\nPORT=9090\nNEW=n3w-value\n"}, nil, args...)
			noneShown(t, stdout, stderr, canary)
			if !strings.Contains(stdout, UnrecognizedType) {
				t.Errorf("the type was not shown as unrecognized: %q", stdout)
			}
		})
	}
}
