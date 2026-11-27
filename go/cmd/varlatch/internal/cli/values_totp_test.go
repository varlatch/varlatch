// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// `values set --totp` and `values rotate --totp` (ADR-0061): a seed goes to
// the server as otpauth, never as a value, from a pipe or a file and never
// from the command line; nothing prints it.

const (
	seedSecret = "JBSWJBSWJBSWJBSWJBSWJBSWJBSWJBSX"
	seedURI    = "otpauth://totp/Portal:alice?secret=" + seedSecret + "&issuer=Portal"
)

type seedServer struct {
	*valuesServer
	mu     sync.Mutex
	bodies []string
}

// newSeedServer answers /v1/meta with the capabilities and echoes what it is
// sent in an error when refuse is set, as a hostile server might.
func newSeedServer(t *testing.T, capabilities string, refuse bool) *seedServer {
	s := &seedServer{valuesServer: newValuesServer(t)}
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("content-type", "application/json")
		switch {
		case r.URL.Path == "/v1/meta":
			_, _ = io.WriteString(w, `{"serverVersion":"0.50.0","capabilities":[`+capabilities+`]}`)
			return
		case r.Method == "GET":
			_, _ = io.WriteString(w, `{"items":[]}`)
			return
		}
		s.mu.Lock()
		s.bodies = append(s.bodies, r.Method+" "+r.URL.Path+" "+string(raw))
		s.mu.Unlock()
		if refuse {
			w.WriteHeader(422)
			echo, _ := json.Marshal(string(raw))
			_, _ = io.WriteString(w, `{"error":{"code":"VALIDATION_FAILED","message":`+string(echo)+`,"requestId":"req_1"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"versionId":"ver_abcdefghijklmnopqrstuvwxyz","primaryVersionId":"ver_abcdefghijklmnopqrstuvwxyz","rotationDeadline":"2026-11-25T10:00:00Z"}`)
	})
	return s
}

func noSeedShown(t *testing.T, stdout, stderr string) {
	t.Helper()
	for _, s := range []string{seedSecret, "otpauth://totp/Portal"} {
		if strings.Contains(stdout+stderr, s) {
			t.Errorf("shown: %q %q", stdout, stderr)
		}
	}
}

func TestValuesSetTOTP(t *testing.T) {
	s := newSeedServer(t, `"values.totp"`, false)
	for what, c := range map[string]struct {
		stdin string
		files map[string]string
		args  []string
		want  string
		says  string
	}{
		"from a pipe":   {seedURI + "\n", nil, []string{"values", "set", "PORTAL_OTP", "--totp", "--stdin"}, "PUT " + envPath + `/values/PORTAL_OTP {"otpauth":"` + seedURI + `"}`, "PORTAL_OTP set (version ver_abcdefghijklmnopqrstuvwxyz) to the seed of one-time codes."},
		"from a file":   {"", map[string]string{"seed.txt": seedURI}, []string{"values", "set", "PORTAL_OTP", "--totp", "--from-file", "seed.txt"}, "PUT " + envPath + `/values/PORTAL_OTP {"otpauth":"` + seedURI + `"}`, "PORTAL_OTP set"},
		"rotate":        {seedURI, nil, []string{"values", "rotate", "PORTAL_OTP", "--totp", "--stdin", "--grace", "600"}, "POST " + envPath + `/values/PORTAL_OTP/rotations {"otpauth":"` + seedURI + `","graceSeconds":600}`, "PORTAL_OTP rotating to another seed of one-time codes"},
		"in assisted":   {seedURI, nil, []string{"--assisted", "values", "set", "PORTAL_OTP", "--totp", "--stdin"}, "PUT " + envPath + `/values/PORTAL_OTP {"otpauth":"` + seedURI + `"}`, "PORTAL_OTP set"},
		"not a seed":    {"plain", nil, []string{"values", "set", "PORTAL_OTP", "--stdin"}, "PUT " + envPath + `/values/PORTAL_OTP {"value":"plain"}`, "PORTAL_OTP set (version ver_abcdefghijklmnopqrstuvwxyz)."},
		"-- and --totp": {"", nil, []string{"values", "set", "PORTAL_OTP", "--", "--totp"}, "PUT " + envPath + `/values/PORTAL_OTP {"value":"--totp"}`, "PORTAL_OTP set"},
	} {
		s.bodies = nil
		code, stdout, stderr := runIn(t, s.valuesServer, c.stdin, c.files, nil, c.args...)
		if code != 0 || len(s.bodies) != 1 || s.bodies[0] != c.want || !strings.Contains(stdout, c.says) {
			t.Errorf("%s: %d %q %q, sent %q, want %q", what, code, stdout, stderr, s.bodies, c.want)
		}
		noSeedShown(t, stdout, stderr)
	}
}

func TestValuesSetTOTPRefuses(t *testing.T) {
	for what, c := range map[string]struct {
		capabilities string
		stdin        string
		args         []string
		code         int
		says         string
	}{
		"on the command line":          {`"values.totp"`, "", []string{"values", "set", "PORTAL_OTP", seedURI, "--totp"}, 64, "never taken from the command line"},
		"on the command line, rotate":  {`"values.totp"`, "", []string{"values", "rotate", "PORTAL_OTP", "--totp", seedURI}, 64, "never taken from the command line"},
		"generated":                    {`"values.totp"`, "", []string{"values", "set", "PORTAL_OTP", "--totp", "--generate", "hex:32"}, 64, "nor generated"},
		"an empty argument":            {`"values.totp"`, "", []string{"values", "set", "PORTAL_OTP", "--totp", ""}, 64, "never taken from the command line"},
		"no terminal":                  {`"values.totp"`, "", []string{"values", "set", "PORTAL_OTP", "--totp"}, 64, "no value given for PORTAL_OTP"},
		"assisted mode, no seed given": {`"values.totp"`, "", []string{"--assisted", "values", "set", "PORTAL_OTP", "--totp"}, 64, "A seed is the human's to enter"},
		"an older server":              {`"values.rotation"`, seedURI, []string{"values", "set", "PORTAL_OTP", "--totp", "--stdin"}, 1, "does not store seeds of one-time codes"},
		"two sources":                  {`"values.totp"`, seedURI, []string{"values", "set", "PORTAL_OTP", "--totp", "--stdin", "--from-file", "x"}, 64, ""},
	} {
		s := newSeedServer(t, c.capabilities, false)
		code, stdout, stderr := runIn(t, s.valuesServer, c.stdin, nil, nil, c.args...)
		if code != c.code || !strings.Contains(stderr, c.says) || len(s.bodies) != 0 {
			t.Errorf("%s: %d %q %q, sent %q", what, code, stdout, stderr, s.bodies)
		}
		noSeedShown(t, stdout, stderr)
	}
	// A server that echoes it is not shown either.
	s := newSeedServer(t, `"values.totp"`, true)
	code, stdout, stderr := runIn(t, s.valuesServer, seedURI, nil, nil, "values", "set", "PORTAL_OTP", "--totp", "--stdin")
	if code == 0 || len(s.bodies) != 1 {
		t.Errorf("%d %q", code, s.bodies)
	}
	noSeedShown(t, stdout, stderr)
}

// What reads an environment with a seed in it: the listing names it, a run
// says it is not delivered, and asks for no seed.
func TestASeedIsListedAndNotDelivered(t *testing.T) {
	const listed = `{"items":[{"name":"API_KEY","sensitive":true,"source":"self","versionId":"ver_1","value":null},
		{"name":"PORTAL_OTP","sensitive":true,"source":"self","versionId":"ver_2","value":null,"totp":{"issuer":"Portal","account":"al\u001b[31mice","algorithm":"SHA1","digits":6,"periodSeconds":30}}]}`
	var mu sync.Mutex
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("content-type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/disclosures") {
			mu.Lock()
			asked = append(asked, string(raw))
			mu.Unlock()
			_, _ = io.WriteString(w, `{"items":[{"name":"API_KEY","versionId":"ver_1","value":"`+canary+`"}],"withheld":[]}`)
			return
		}
		_, _ = io.WriteString(w, listed)
	}))
	t.Cleanup(srv.Close)
	s := &valuesServer{Server: srv}
	code, stdout, stderr := runIn(t, s, "", nil, nil, "values", "list")
	if code != 0 || !strings.Contains(stdout, "PORTAL_OTP  (one-time code, issuer Portal, account al") || strings.Contains(stdout, "\x1b") || !strings.Contains(stdout, "API_KEY  (secret, self)") {
		t.Errorf("list: %d %q %q", code, stdout, stderr)
	}
	code, stdout, stderr = runIn(t, s, "", nil, nil, "values", "list", "--json")
	if code != 0 || !strings.Contains(stdout, `"periodSeconds": 30`) {
		t.Errorf("list --json: %d %q %q", code, stdout, stderr)
	}
	code, stdout, stderr = runIn(t, s, "", nil, nil, append([]string{"run", "--"}, printEnv()...)...)
	if code != 0 || !strings.Contains(stderr, "1 one-time code(s) not delivered") || strings.Contains(stderr, "withheld by policy") ||
		strings.Contains(stdout, "PORTAL_OTP") {
		t.Errorf("run: %d %q %q", code, stdout, stderr)
	}
	for _, body := range asked {
		if strings.Contains(body, "totpSeeds") {
			t.Errorf("asked for a seed: %s", body)
		}
	}
}

// printEnv is a command that prints its environment: env, which Windows
// does not have, or cmd's set there, by its full path (the CLI runs here
// without PATH).
func printEnv() []string {
	if runtime.GOOS == "windows" {
		return []string{filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/c", "set"}
	}
	return []string{"env"}
}
