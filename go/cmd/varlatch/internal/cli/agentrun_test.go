// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/broker"
)

// agentServer is a fake varlatchd for an agent-safe run: one Secret
// (API_KEY), one agent, and the issuance's answer as given. It records
// every request as "METHOD path".
type agentServer struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

const agentEnvPath = "/v1/organizations/acme/projects/web/environments/dev"

func newAgentServer(t *testing.T, issued string, mintStatus int) *agentServer {
	t.Helper()
	s := &agentServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		s.mu.Lock()
		s.seen = append(s.seen, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		answer := func(status int, body string) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
		switch {
		case r.URL.Path == "/v1/meta":
			answer(200, `{"serverVersion":"0.22.0","capabilities":["capabilities.targets"]}`)
		case strings.HasPrefix(r.URL.Path, agentEnvPath+"/effective-configuration"):
			answer(200, `{"environmentId":"env_1","items":[{"name":"API_KEY","sensitive":true,"source":"self","value":null}],"manifest":{"manifestVersion":1,"contract":null}}`)
		case r.URL.Path == "/v1/organizations/acme/identities":
			answer(200, `{"items":[{"id":"idn_agent","kind":"agent","name":"coder"}]}`)
		case r.Method == "POST" && r.URL.Path == agentEnvPath+"/capabilities":
			answer(201, issued)
		case r.Method == "POST" && r.URL.Path == "/v1/organizations/acme/identities/idn_agent/credentials":
			if mintStatus != 201 {
				answer(mintStatus, `{"error":{"code":"PERMISSION_DENIED","message":"refused","requestId":"r"}}`)
				return
			}
			answer(201, `{"id":"crd_1","token":"vlt_agr_fakeMINTED"}`)
		case r.Method == "DELETE":
			w.WriteHeader(204)
		default:
			answer(404, `{"error":{"code":"RESOURCE_NOT_FOUND","message":"no","requestId":"r"}}`)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *agentServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.seen)
}

// runAgentSafeAgainst runs `varlatch run --agent-safe` in a repository on
// the server, signed in, with the Broker credential set. The command is
// never started in these tests.
func runAgentSafeAgainst(t *testing.T, s *agentServer, flags ...string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	for path, content := range map[string]string{
		"repo/varlatch.toml":      "server = \"" + s.URL + "\"\norganization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n",
		"config/credentials.json": `{"servers": {"` + s.URL + `": {"token": "vlt_cli_agentTestAAAA"}}}` + "\n",
	} {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(filepath.Join(dir, "repo"))
	env := MapEnv{"HOME": filepath.Join(dir, "home"), "VARLATCH_CONFIG_DIR": filepath.Join(dir, "config"), "VARLATCH_BROKER_CREDENTIAL": "vlt_brk_fakeBROKER"}
	args := append([]string{"run", "--agent-safe", "--agent", "coder", "--allow-host", "api.example.com"}, flags...)
	args = append(args, "--", "varlatch-test-never-started")
	var stdout, stderr bytes.Buffer
	code := Main(args, env, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
	return code, stdout.String() + stderr.String()
}

const capRevoke = "DELETE " + agentEnvPath + "/capabilities/cap_1"

func issuedWith(targets string) string {
	return `{"id":"cap_1","secret":"capsecret","destinations":["api.example.com:443"],"targets":` + targets + `}`
}

// TestIssuedTargetsAreReadAsJSONParse: the server's recorded targets are
// read as JSON.parse reads them, an item named twice keeping its last
// list, and the run checks and substitutes that one reading. An answer
// whose list is not the one asked for, or not a list of strings, is
// revoked and refused, nothing started, as in TypeScript.
func TestIssuedTargetsAreReadAsJSONParse(t *testing.T) {
	for _, c := range []struct {
		name, targets string
		accepted      bool
	}{
		{"duplicate key, the last as asked", `{"API_KEY":["query:key"],"API_KEY":["header:authorization"]}`, true},
		{"duplicate key, the first as asked", `{"API_KEY":["header:authorization"],"API_KEY":["query:key"]}`, false},
		{"not a list", `{"API_KEY":"header:authorization"}`, false},
		{"not strings", `{"API_KEY":[1]}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newAgentServer(t, issuedWith(c.targets), 201)
			_, out := runAgentSafeAgainst(t, s, "--target", "API_KEY=header:authorization")
			refused := strings.Contains(out, "the server recorded different substitution targets than this run requested")
			started := strings.Contains(out, "spawn varlatch-test-never-started")
			if refused == c.accepted || started != c.accepted {
				t.Fatalf("accepted %v: output %q", c.accepted, out)
			}
			// Revoked either way: refused at once, or when the run ended.
			if !slices.Contains(s.requests(), capRevoke) {
				t.Errorf("the Capability was not revoked: %q", s.requests())
			}
		})
	}
}

// TestRefusedRunRevokesItsCapability: a run that stops after its
// Capability was issued revokes it (Go is stricter than TypeScript, which
// leaves it to the TTL): targets that cannot be made canonical, a Broker
// that cannot start, an --agent-metadata credential the server refuses.
func TestRefusedRunRevokesItsCapability(t *testing.T) {
	t.Run("targets not canonical", func(t *testing.T) {
		// Five targets: parsed one by one, refused as a set once issued.
		s := newAgentServer(t, issuedWith(`{"API_KEY":["header:a","header:b","header:c","header:d","header:e"]}`), 201)
		code, out := runAgentSafeAgainst(t, s, "--target", "API_KEY=header:a", "--target", "API_KEY=header:b", "--target", "API_KEY=header:c", "--target", "API_KEY=header:d", "--target", "API_KEY=header:e")
		if code != 1 || !strings.Contains(out, "API_KEY has 5 targets; at most 4 are allowed") {
			t.Fatalf("status %d, output %q", code, out)
		}
		if !slices.Contains(s.requests(), capRevoke) {
			t.Errorf("the Capability was not revoked: %q", s.requests())
		}
	})
	t.Run("the Broker cannot start", func(t *testing.T) {
		start := startBroker
		t.Cleanup(func() { startBroker = start })
		startBroker = func(broker.Options) (*broker.Running, error) {
			return nil, errors.New("listen tcp 127.0.0.1:0: no port")
		}
		s := newAgentServer(t, issuedWith(`{"API_KEY":["header:authorization"]}`), 201)
		code, out := runAgentSafeAgainst(t, s, "--target", "API_KEY=header:authorization")
		if code != 1 || !strings.Contains(out, "no port") {
			t.Fatalf("status %d, output %q", code, out)
		}
		if !slices.Contains(s.requests(), capRevoke) {
			t.Errorf("the Capability was not revoked: %q", s.requests())
		}
	})
	t.Run("the metadata credential is refused", func(t *testing.T) {
		s := newAgentServer(t, issuedWith(`{"API_KEY":["header:authorization"]}`), 403)
		code, out := runAgentSafeAgainst(t, s, "--target", "API_KEY=header:authorization", "--agent-metadata")
		if code != 77 || !strings.Contains(out, "PERMISSION_DENIED") {
			t.Fatalf("status %d, output %q", code, out)
		}
		seen := s.requests()
		if !slices.Contains(seen, capRevoke) {
			t.Errorf("the Capability was not revoked: %q", seen)
		}
	})
}

// TestRequestBoundsTheResponseHead: a response head over 16 KiB is refused
// as Node.js's client refuses it (HPE_HEADER_OVERFLOW, 69), its bytes never
// shown; one just under the bound is read.
func TestRequestBoundsTheResponseHead(t *testing.T) {
	for _, c := range []struct {
		name   string
		filler int
		code   int
	}{
		{"over 16 KiB", 17 * 1024, 69},
		{"one header of 16 KiB alone", maxResponseHead, 69},
		{"under 16 KiB", 15 * 1024, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			const marker = "head-canary-"
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				buf := make([]byte, 4096)
				_, _ = conn.Read(buf)
				value := marker + strings.Repeat("x", c.filler)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nX-Big: "+value+"\r\nContent-Length: 3\r\n\r\nok\n")
			}()
			port := ln.Addr().(*net.TCPAddr).Port
			env := MapEnv{"HOME": t.TempDir(), "VARLATCH_CONFIG_DIR": t.TempDir(), "VARLATCH_AGENT_RUN": "run_0123456789abcdef", "HTTPS_PROXY": "http://vlt:x@127.0.0.1:" + strconv.Itoa(port)}
			var stdout, stderr bytes.Buffer
			code := Main([]string{"request", "https://api.example.com/x"}, env, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
			if code != c.code {
				t.Fatalf("status %d, want %d; stderr %q", code, c.code, stderr.String())
			}
			if c.code == 69 {
				want := "varlatch request: cannot reach the Broker at 127.0.0.1:" + strconv.Itoa(port) + " (HPE_HEADER_OVERFLOW)\n"
				if stderr.String() != want || strings.Contains(stdout.String()+stderr.String(), marker) {
					t.Errorf("stdout %q, stderr %q, want %q", stdout.String(), stderr.String(), want)
				}
			} else if stdout.String() != "ok\n" {
				t.Errorf("stdout %q", stdout.String())
			}
		})
	}
}

func TestAgentSafeStrict(t *testing.T) {
	const baseRetrieval = `{"manifest":{"manifestVersion":1,"projectId":"prj_1","environment":{"id":"env_1","rootId":"env_root","tier":"development"},"items":[{"name":"API_KEY","sensitive":true},{"name":"PORT","sensitive":false}],"contract":{"revisionId":"rev_runaaaaaaaaaaaaaaaaaaaaaaa","contentHash":"sha256:abababababababababababababababababababababababababababababababab","semanticsVersion":2}},"contract":{"items":[{"name":"API_KEY","sensitive":true,"type":"string","required":{"kind":"always"}},{"name":"PORT","sensitive":false,"type":"string","required":{"kind":"always"}}]},"items":[{"name":"API_KEY","sensitive":true,"value":null},{"name":"PORT","sensitive":false,"value":"8080"}],"callerView":{"withheld":[],"unexpanded":[]},"stateDigest":"dig_1","validation":{"invalid":[],"unresolved":[],"notEvaluated":[]}}`

	runStrictCase := func(t *testing.T, handler http.HandlerFunc, extraEnv MapEnv, flags ...string) (int, string) {
		t.Helper()
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		dir := t.TempDir()
		for path, content := range map[string]string{
			"repo/varlatch.toml":      "server = \"" + srv.URL + "\"\norganization = \"acme\"\nproject = \"web\"\ndefault_environment = \"dev\"\n",
			"config/credentials.json": `{"servers": {"` + srv.URL + `": {"token": "vlt_cli_agentTestAAAA"}}}` + "\n",
		} {
			full := filepath.Join(dir, path)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		t.Chdir(filepath.Join(dir, "repo"))
		env := MapEnv{"HOME": filepath.Join(dir, "home"), "VARLATCH_CONFIG_DIR": filepath.Join(dir, "config"), "VARLATCH_BROKER_CREDENTIAL": "vlt_brk_fakeBROKER"}
		for k, v := range extraEnv {
			env[k] = v
		}
		args := append([]string{"run", "--strict", "--agent-safe", "--agent", "coder", "--allow-host", "api.example.com"}, flags...)
		args = append(args, "--", "varlatch-test-never-started")
		var stdout, stderr bytes.Buffer
		code := Main(args, env, IO{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr})
		return code, stdout.String() + stderr.String()
	}

	t.Run("server without retrieval.preflight exits 78", func(t *testing.T) {
		code, out := runStrictCase(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"serverVersion":"0.10.0","capabilities":["capabilities.targets"]}`)
		}, nil, "--target", "API_KEY=header:authorization")
		if code != 78 || !strings.Contains(out, "--agent-safe --strict needs the agent-safe preflight and substitution targets") {
			t.Fatalf("status %d, output %q", code, out)
		}
	})

	t.Run("allow-inherited naming a Secret is refused", func(t *testing.T) {
		code, out := runStrictCase(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1/meta":
				_, _ = io.WriteString(w, `{"serverVersion":"0.22.0","capabilities":["retrieval.preflight","capabilities.targets"]}`)
			case "/v1/organizations/acme/identities":
				_, _ = io.WriteString(w, `{"items":[{"id":"idn_agent","kind":"agent","name":"coder"}]}`)
			case agentEnvPath + "/retrievals":
				_, _ = io.WriteString(w, baseRetrieval)
			}
		}, nil, "--target", "API_KEY=header:authorization", "--allow-inherited", "API_KEY")
		if code != 64 || !strings.Contains(out, "--allow-inherited cannot name a Secret in an agent-safe run") {
			t.Fatalf("status %d, output %q", code, out)
		}
	})

	t.Run("agent unauthorized revokes capability and exits 78", func(t *testing.T) {
		revoked := false
		code, out := runStrictCase(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/v1/meta":
				_, _ = io.WriteString(w, `{"serverVersion":"0.22.0","capabilities":["retrieval.preflight","capabilities.targets"]}`)
			case r.URL.Path == "/v1/organizations/acme/identities":
				_, _ = io.WriteString(w, `{"items":[{"id":"idn_agent","kind":"agent","name":"coder"}]}`)
			case r.URL.Path == agentEnvPath+"/retrievals":
				_, _ = io.WriteString(w, baseRetrieval)
			case r.Method == "POST" && r.URL.Path == agentEnvPath+"/capabilities":
				w.WriteHeader(201)
				_, _ = io.WriteString(w, `{"id":"cap_1","secret":"capsecret","destinations":["api.example.com:443"],"targets":{"API_KEY":["header:authorization"]},"preflightItems":[{"name":"API_KEY","present":true,"authorized":false,"reason":"permission"}]}`)
			case r.Method == "DELETE" && r.URL.Path == agentEnvPath+"/capabilities/cap_1":
				revoked = true
				w.WriteHeader(204)
			}
		}, nil, "--target", "API_KEY=header:authorization")
		if code != 78 || !strings.Contains(out, "API_KEY: agent-unauthorized: the Agent lacks secret.use here") || !revoked {
			t.Fatalf("status %d, revoked %v, output %q", code, revoked, out)
		}
	})

	t.Run("STATE_CHANGED retries once then exits 78 on second change", func(t *testing.T) {
		attempts := 0
		code, out := runStrictCase(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/v1/meta":
				_, _ = io.WriteString(w, `{"serverVersion":"0.22.0","capabilities":["retrieval.preflight","capabilities.targets"]}`)
			case r.URL.Path == "/v1/organizations/acme/identities":
				_, _ = io.WriteString(w, `{"items":[{"id":"idn_agent","kind":"agent","name":"coder"}]}`)
			case r.URL.Path == agentEnvPath+"/retrievals":
				_, _ = io.WriteString(w, baseRetrieval)
			case r.Method == "POST" && r.URL.Path == agentEnvPath+"/capabilities":
				attempts++
				w.WriteHeader(409)
				_, _ = io.WriteString(w, `{"error":{"code":"STATE_CHANGED","message":"changed","details":{"categories":["values","contract"]}}}`)
			}
		}, nil, "--target", "API_KEY=header:authorization")
		if code != 78 || attempts != 2 || !strings.Contains(out, "the configuration changed during the preflight twice (values, contract)") {
			t.Fatalf("status %d, attempts %d, output %q", code, attempts, out)
		}
	})

	t.Run("clean preflight issues capability and starts mediated run", func(t *testing.T) {
		revoked := false
		var gotPrecondition string
		code, out := runStrictCase(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/v1/meta":
				_, _ = io.WriteString(w, `{"serverVersion":"0.22.0","capabilities":["retrieval.preflight","capabilities.targets"]}`)
			case r.URL.Path == "/v1/organizations/acme/identities":
				_, _ = io.WriteString(w, `{"items":[{"id":"idn_agent","kind":"agent","name":"coder"}]}`)
			case r.URL.Path == agentEnvPath+"/retrievals":
				_, _ = io.WriteString(w, baseRetrieval)
			case r.Method == "POST" && r.URL.Path == agentEnvPath+"/capabilities":
				b, _ := io.ReadAll(r.Body)
				gotPrecondition = string(b)
				w.WriteHeader(201)
				_, _ = io.WriteString(w, `{"id":"cap_1","secret":"capsecret","destinations":["api.example.com:443"],"targets":{"API_KEY":["header:authorization"]},"preflightItems":[{"name":"API_KEY","present":true,"authorized":true}]}`)
			case r.Method == "DELETE" && r.URL.Path == agentEnvPath+"/capabilities/cap_1":
				revoked = true
				w.WriteHeader(204)
			}
		}, nil, "--target", "API_KEY=header:authorization")
		if code != 1 || !strings.Contains(out, "spawn varlatch-test-never-started") || !strings.Contains(gotPrecondition, `"stateDigest":"dig_1"`) || !revoked {
			t.Fatalf("status %d, revoked %v, precondition %q, output %q", code, revoked, gotPrecondition, out)
		}
	})
}
