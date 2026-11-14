// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
)

// testdata/known-differences.json holds the answers the Go server must give
// exactly as the TypeScript server does; services/varlatchd/test/
// go-parity.test.ts runs the same table against the TypeScript app.
type parityTable struct {
	PathVectors  []struct{ Target, Hono string }  `json:"pathVectors"`
	NginxVectors []struct{ Target, Nginx string } `json:"nginxVectors"`
	Routes       []struct {
		Method, Target, Credential, Expect, Code, Text string
		Status                                         int
		GoUntilStep34                                  *struct {
			Status       int
			Expect, Text string
		} `json:"goUntilStep3_4"`
	} `json:"routes"`
	ForwardedFor []struct {
		Peer    string
		Trusted []string
		Lines   []string
		Client  string
	} `json:"forwardedFor"`
	RequestWindow struct {
		Path              string
		Allowed, Status   int
		Code, Message     string
		RetryAfterAtStart string
	} `json:"requestWindow"`
}

func loadParity(t *testing.T) parityTable {
	t.Helper()
	b, err := os.ReadFile("testdata/known-differences.json")
	if err != nil {
		t.Fatal(err)
	}
	var p parityTable
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.PathVectors) == 0 || len(p.NginxVectors) == 0 || len(p.Routes) == 0 || len(p.ForwardedFor) == 0 || p.RequestWindow.Allowed != WindowLimit {
		t.Fatalf("the table is incomplete: %+v", p)
	}
	return p
}

// The path varlatchd routes on, as Hono's getPath gives it (the TypeScript
// side checks the same vectors against getPath itself).
func TestParityPaths(t *testing.T) {
	for _, v := range loadParity(t).PathVectors {
		r := httptest.NewRequest("GET", v.Target, nil)
		if got := honoPath(normalizeTarget(requestTarget(r))); got != v.Hono {
			t.Errorf("%s: %q, want %q", v.Target, got, v.Hono)
		}
	}
}

// The URI the dashboard's nginx selected a location with, from the raw
// target (the vectors are nginx 1.29's own answers).
func TestParityNginxPaths(t *testing.T) {
	for _, v := range loadParity(t).NginxVectors {
		r := httptest.NewRequest("GET", v.Target, nil)
		if got := nginxPath(requestTarget(r)); got != v.Nginx {
			t.Errorf("%s: %q, want %q", v.Target, got, v.Nginx)
		}
	}
}

// Requests from raw targets, parsed as the server parses them
// (httptest.NewRequest reads the request line): Path, RawPath and RawQuery
// are what a client's request gives.
func TestParityRoutes(t *testing.T) {
	s, _, _, logBuf := newTestServer(t, nil)
	index, _ := webFS.ReadFile("index.html")
	for _, c := range loadParity(t).Routes {
		logBuf.Reset()
		status, expect, text := c.Status, c.Expect, c.Text
		if c.GoUntilStep34 != nil {
			status, expect, text = c.GoUntilStep34.Status, c.GoUntilStep34.Expect, c.GoUntilStep34.Text
		}
		r := httptest.NewRequest(c.Method, c.Target, nil)
		r.RemoteAddr = "192.0.2.10:40000"
		switch c.Credential {
		case "valid", "invalid":
			r.Header.Set("Authorization", "Bearer vlt_cli_"+c.Credential)
		case "basic":
			r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		name := fmt.Sprintf("%s %s (%s)", c.Method, c.Target, c.Credential)
		if w.Code != status {
			t.Errorf("%s: %d, want %d: %q", name, w.Code, status, w.Body.String())
			continue
		}
		// What nginx forwarded is counted by varlatchd's request window
		// (but /healthz and /readyz); the dashboard's requests never are.
		var rec AccessRecord
		if err := json.Unmarshal([]byte(strings.TrimSpace(logBuf.String())), &rec); err != nil {
			t.Fatalf("%s: access log %q: %v", name, logBuf.String(), err)
		}
		if want := expect != "dashboard" && rec.Path != "/healthz" && rec.Path != "/readyz"; rec.Window != want {
			t.Errorf("%s: counted in the request window %v, want %v (routed on %q)", name, rec.Window, want, rec.Path)
		}
		head := c.Method == http.MethodHead // a real server sends no body
		ct := w.Header().Get("Content-Type")
		switch expect {
		case "text":
			if ct != "text/plain; charset=UTF-8" || (!head && w.Body.String() != text) {
				t.Errorf("%s: %q %q", name, ct, w.Body.String())
			}
		case "dashboard":
			if w.Header().Get("Content-Security-Policy") != ContentSecurityPolicy || w.Body.String() != string(index) {
				t.Errorf("%s: not the dashboard: %q", name, w.Body.String())
			}
		case "meta":
			var m struct{ ApiMajor int }
			if ct != "application/json" || (!head && (json.Unmarshal(w.Body.Bytes(), &m) != nil || m.ApiMajor != 1)) {
				t.Errorf("%s: %q %q", name, ct, w.Body.String())
			}
		case "code":
			if ct != "application/json" {
				t.Errorf("%s: Content-Type %q", name, ct)
			} else if e := decode(t, w); !head && (e.Error.Code != c.Code ||
				(c.Code == "AUTHENTICATION_REQUIRED" && e.Error.Message != "Provide a Varlatch bearer credential")) {
				t.Errorf("%s: %s", name, w.Body.String())
			}
		default:
			t.Errorf("%s: unknown expectation %q", name, expect)
		}
	}
}

// Every 404 varlatchd gives outside a handler is Hono's: no Go mux text
// ("404 page not found"), whatever the target.
func TestNoGoNotFoundText(t *testing.T) {
	s, _, _, _ := newTestServer(t, nil)
	for _, target := range []string{"/v1%2fmeta", "/v1%2F", "/%2fv1/meta", "/v1/organizations%2f", "//v1", "/install.sh/", "//install.sh", "/.well-known/", "/healthz/", "/v1x/y"} {
		for _, method := range []string{"GET", "POST", "OPTIONS", "PATCH"} {
			r := httptest.NewRequest(method, target, nil)
			r.Header.Set("Authorization", "Bearer x")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if strings.Contains(w.Body.String(), "page not found") || w.Code == http.StatusMethodNotAllowed && strings.HasPrefix(target, "/v1") || w.Code == http.StatusMovedPermanently {
				t.Errorf("%s %s: %d %q", method, target, w.Code, w.Body.String())
			}
		}
	}
}

// X-Forwarded-For in several lines: every line counts, joined as Node
// joins them, and read from the right through trusted proxies.
func TestParityForwardedForLines(t *testing.T) {
	for _, c := range loadParity(t).ForwardedFor {
		trusted := c.Trusted
		s, _, _, logBuf := newTestServer(t, func(o *Options) { o.TrustedProxies = func(a string) bool { return slices.Contains(trusted, a) } })
		r := httptest.NewRequest("GET", "/v1/meta", nil)
		r.RemoteAddr = c.Peer + ":5555"
		for _, line := range c.Lines {
			r.Header.Add("X-Forwarded-For", line)
		}
		s.ServeHTTP(httptest.NewRecorder(), r)
		var rec AccessRecord
		if err := json.Unmarshal([]byte(strings.TrimSpace(logBuf.String())), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Client != c.Client {
			t.Errorf("lines %q from %s: client %s, want %s", c.Lines, c.Peer, rec.Client, c.Client)
		}
		if rec.ForwardedFor == nil || *rec.ForwardedFor != strings.Join(c.Lines, ", ") {
			t.Errorf("lines %q: forwardedFor %v", c.Lines, rec.ForwardedFor)
		}
	}
}

// A forged first line cannot take another client's window: Sol's
// reproduction, a trusted proxy adding the observed client as a second
// line.
func TestForwardedForSecondLineWindow(t *testing.T) {
	s, _, _, _ := newTestServer(t, func(o *Options) { o.TrustedProxies = func(a string) bool { return a == "10.0.0.2" } })
	send := func(forged string) int {
		r := httptest.NewRequest("GET", "/v1/meta", nil)
		r.RemoteAddr = "10.0.0.2:5555"
		r.Header.Add("X-Forwarded-For", forged)
		r.Header.Add("X-Forwarded-For", "203.0.113.7")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < WindowLimit; i++ {
		send(fmt.Sprintf("198.51.100.%d", i%250))
	}
	if code := send("198.51.100.99"); code != http.StatusTooManyRequests {
		t.Errorf("a forged first line evaded the window: %d", code)
	}
}

func TestParityRequestWindow(t *testing.T) {
	w := loadParity(t).RequestWindow
	s, _, _, _ := newTestServer(t, nil)
	for i := 0; i < w.Allowed; i++ {
		if got := do(s, "GET", w.Path, "", nil); got.Code != 200 {
			t.Fatalf("request %d: %d", i+1, got.Code)
		}
	}
	got := do(s, "GET", w.Path, "", nil)
	e := decode(t, got)
	if got.Code != w.Status || got.Header().Get("Retry-After") != w.RetryAfterAtStart || e.Error.Code != w.Code || e.Error.Message != w.Message {
		t.Errorf("%d %q %s", got.Code, got.Header().Get("Retry-After"), got.Body.String())
	}
}
