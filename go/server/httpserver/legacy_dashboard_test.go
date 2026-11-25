// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/realtime"
	"github.com/varlatch/varlatch/go/server/tailnet"
)

// The Go server's HTML (index and every SPA fallback) answers Cache-Control:
// no-cache (except /device, which keeps no-store). Static assets keep their
// existing caching headers, and none of these paths send Clear-Site-Data.
func TestDashboardCacheHeaders(t *testing.T) {
	s, _, _, _ := newTestServer(t, nil)
	cases := []struct {
		path     string
		wantCC   string
		wantHTML bool
	}{
		{"/", "no-cache", true},
		{"/index.html", "no-cache", true},
		{"/o/acme/p/web/e/production", "no-cache", true},
		{"/orgs/acme/projects", "no-cache", true},
		{"/assets", "no-cache", true},
		{"/assets/missing.js", "no-cache", true},
		{"/convex-org", "no-cache", true},
		{"/o/convex/p/web/e/production", "no-cache", true},
		{"/device", "no-store", true},
		{"/assets/app-1234.js", "", false},
		{"/assets/style-5678.css", "", false},
		{"/varlatch-config.js", "no-cache", false},
		{"/brand/favicon-32.png", "", false},
		{"/site.webmanifest", "", false},
	}
	for _, c := range cases {
		w := do(s, "GET", c.path, "", nil)
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", c.path, w.Code)
			continue
		}
		if got := w.Header().Get("Cache-Control"); got != c.wantCC {
			t.Errorf("%s: Cache-Control %q, want %q", c.path, got, c.wantCC)
		}
		if got := w.Header().Get("Clear-Site-Data"); got != "" {
			t.Errorf("%s: unexpected Clear-Site-Data %q", c.path, got)
		}
		if got := w.Header().Get("Content-Security-Policy"); got != ContentSecurityPolicy {
			t.Errorf("%s: CSP %q", c.path, got)
		}
		isHTML := strings.Contains(w.Header().Get("Content-Type"), "text/html")
		if isHTML != c.wantHTML {
			t.Errorf("%s: Content-Type %q (wantHTML=%v)", c.path, w.Header().Get("Content-Type"), c.wantHTML)
		}
	}
}

// Paths only the 0.23.0 dashboard calls (/convex/* and the Better Auth paths
// under /auth/ that varlatchd does not serve) answer 404 as the JSON API error
// envelope with Clear-Site-Data: "cache" (never cookies, never SPA HTML).
func TestLegacyDashboardPaths(t *testing.T) {
	s, _, _, _ := newTestServer(t, nil)
	wsNonce := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	wsHeaders := map[string]string{
		"Connection":            "Upgrade",
		"Upgrade":               "websocket",
		"Sec-WebSocket-Key":     wsNonce,
		"Sec-WebSocket-Version": "13",
	}
	cases := []struct {
		method string
		target string
		header map[string]string
	}{
		{"GET", "/convex", nil},
		{"GET", "/convex/", nil},
		{"GET", "/convex/version", nil},
		{"GET", "/convex/api/1.29.0/sync", nil},
		{"GET", "/convex/api/1.29.0/sync", wsHeaders},
		{"POST", "/convex/api/query", nil},
		{"GET", "/auth/get-session", nil},
		{"POST", "/auth/get-session", nil},
		{"GET", "/auth/passkey/generate-authenticate-options", nil},
		{"POST", "/auth/passkey/verify-authentication", nil},
		{"GET", "/auth/passkey/generate-register-options?name=laptop", nil},
		{"POST", "/auth/passkey/verify-registration", nil},
	}
	for _, c := range cases {
		w := do(s, c.method, c.target, "", c.header)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s: status %d, want 404 (%s)", c.method, c.target, w.Code, w.Body.String())
			continue
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s %s: Content-Type %q, want application/json", c.method, c.target, ct)
		}
		if csd := w.Header().Get("Clear-Site-Data"); csd != `"cache"` {
			t.Errorf("%s %s: Clear-Site-Data %q, want %q", c.method, c.target, csd, `"cache"`)
		}
		if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s %s: Cache-Control %q, want no-store", c.method, c.target, cc)
		}
		if csp := w.Header().Get("Content-Security-Policy"); csp != "" {
			t.Errorf("%s %s: unexpected CSP %q", c.method, c.target, csp)
		}
		if strings.Contains(w.Body.String(), "<title>") || strings.Contains(w.Body.String(), "<!doctype") {
			t.Errorf("%s %s: served HTML: %s", c.method, c.target, w.Body.String())
		}
		e := decode(t, w)
		if e.Error.Code != "RESOURCE_NOT_FOUND" || e.Error.Message == "" ||
			!requestIDPattern.MatchString(e.Error.RequestID) || e.Error.RequestID != w.Header().Get("X-Request-Id") {
			t.Errorf("%s %s: bad error envelope: %+v", c.method, c.target, e)
		}
	}

	// Over a real HTTP/1.1 connection, a WebSocket upgrade to /convex/... gets
	// the same 404 JSON response with Clear-Site-Data: "cache".
	srv := httptest.NewServer(s)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := "GET /convex/api/1.29.0/sync HTTP/1.1\r\n" +
		"Host: " + srv.Listener.Addr().String() + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Key: " + wsNonce + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound ||
		resp.Header.Get("Content-Type") != "application/json" ||
		resp.Header.Get("Clear-Site-Data") != `"cache"` ||
		resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("ws upgrade: status %d, headers %v, body %q", resp.StatusCode, resp.Header, string(body))
	}
	var e envelope
	if err := json.Unmarshal(body, &e); err != nil || e.Error.Code != "RESOURCE_NOT_FOUND" || e.Error.RequestID != resp.Header.Get("X-Request-Id") {
		t.Fatalf("ws upgrade body: %q (%v)", string(body), err)
	}

	// Non-legacy unknown paths stay plain-text 404 with no Clear-Site-Data.
	for _, c := range []struct{ method, target string }{
		{"GET", "/auth/unknown"},
		{"POST", "/auth/unknown"},
		{"GET", "/authx"},
		{"GET", "/v1x"},
		{"GET", "/.well-known/jwks.json"},
	} {
		w := do(s, c.method, c.target, "", nil)
		if w.Code != http.StatusNotFound || w.Body.String() != "404 Not Found" || w.Header().Get("Clear-Site-Data") != "" {
			t.Errorf("%s %s: %d %q Clear-Site-Data=%q", c.method, c.target, w.Code, w.Body.String(), w.Header().Get("Clear-Site-Data"))
		}
	}

	// Tailnet listeners serve no dashboard and never emit Clear-Site-Data.
	name := "laptop"
	peer := tailnet.Resolution{Context: &authz.TailnetContext{Tailnet: "corp.ts.net", NodeID: "n1", NodeName: &name}}
	tl, _, _, _ := newTestServer(t, tailnetListener(peer))
	for _, p := range []string{"/convex/api/1.29.0/sync", "/auth/passkey/generate-authenticate-options"} {
		if w := do(tl, "GET", p, "", nil); w.Code != http.StatusNotFound || w.Header().Get("Clear-Site-Data") != "" {
			t.Errorf("tailnet %s: %d Clear-Site-Data=%q", p, w.Code, w.Header().Get("Clear-Site-Data"))
		}
	}
}

// Paths the Go dashboard, CLI, OpenAPI document or an upgrade use are
// unaffected and never carry Clear-Site-Data.
func TestGoDashboardPathsUnaffected(t *testing.T) {
	s, _, _, _, ta := newTestServerAuth(t, nil)
	s.opts.Realtime = realtime.New(realtime.Options{Store: ta.store})
	b := newBrowser(t, s, "http://127.0.0.1:8686")
	token := b.csrf()

	cases := []struct {
		name       string
		method     string
		target     string
		body       any
		headers    map[string]string
		wantStatus int
		wantCode   string
	}{
		{"session", "GET", "/auth/session", nil, nil, http.StatusOK, ""},
		{"sign-in options", "POST", "/auth/passkey/sign-in/options", map[string]any{}, map[string]string{"Origin": b.origin, CSRFHeader: token}, http.StatusOK, ""},
		{"sign-in bad body", "POST", "/auth/passkey/sign-in", map[string]any{}, map[string]string{"Origin": b.origin, CSRFHeader: token}, http.StatusUnprocessableEntity, "VALIDATION_FAILED"},
		{"registration options no session", "POST", "/auth/passkey/registration/options", map[string]any{}, map[string]string{"Origin": b.origin, CSRFHeader: token}, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED"},
		{"registration bad body", "POST", "/auth/passkey/registration", map[string]any{}, map[string]string{"Origin": b.origin, CSRFHeader: token}, http.StatusUnprocessableEntity, "VALIDATION_FAILED"},
		{"sign-out", "POST", "/auth/sign-out", nil, map[string]string{"Origin": b.origin, CSRFHeader: token}, http.StatusNoContent, ""},
		{"varlatch-token with csrf signed out", "POST", "/auth/varlatch-token", nil, map[string]string{"Origin": b.origin, CSRFHeader: token}, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED"},
		{"varlatch-token with wrong csrf", "POST", "/auth/varlatch-token", nil, map[string]string{"Origin": b.origin, CSRFHeader: token + "x"}, http.StatusForbidden, "PERMISSION_DENIED"},
		{"varlatch-token cross-origin no csrf", "POST", "/auth/varlatch-token", nil, map[string]string{"Origin": "https://evil.example.net"}, http.StatusForbidden, "PERMISSION_DENIED"},
		{"events signed out", "GET", "/auth/events", nil, nil, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED"},
		{"meta", "GET", "/v1/meta", nil, nil, http.StatusOK, ""},
		{"healthz", "GET", "/healthz", nil, nil, http.StatusOK, ""},
		{"readyz", "GET", "/readyz", nil, nil, http.StatusOK, ""},
		{"enroll page", "GET", "/enroll", nil, nil, http.StatusOK, ""},
		{"enroll script", "GET", "/enroll.js", nil, nil, http.StatusOK, ""},
		{"install.sh", "GET", "/install.sh", nil, nil, http.StatusNotFound, ""},
		{"install.ps1", "GET", "/install.ps1", nil, nil, http.StatusNotFound, ""},
		{"cli bundle", "GET", "/cli/varlatch.cjs", nil, nil, http.StatusNotFound, ""},
		{"index", "GET", "/", nil, nil, http.StatusOK, ""},
		{"spa route", "GET", "/o/acme/p/web/e/production", nil, nil, http.StatusOK, ""},
		{"device page", "GET", "/device", nil, nil, http.StatusOK, ""},
		{"hashed asset", "GET", "/assets/app-1234.js", nil, nil, http.StatusOK, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := b.send(c.method, c.target, c.body, c.headers)
			if w.Code != c.wantStatus {
				t.Fatalf("%s %s: status %d, want %d (%s)", c.method, c.target, w.Code, c.wantStatus, w.Body.String())
			}
			if csd := w.Header().Get("Clear-Site-Data"); csd != "" {
				t.Errorf("%s %s: unexpected Clear-Site-Data %q", c.method, c.target, csd)
			}
			if c.wantCode != "" {
				if e := decode(t, w); e.Error.Code != c.wantCode {
					t.Errorf("%s %s: code %q, want %q (%s)", c.method, c.target, e.Error.Code, c.wantCode, w.Body.String())
				}
			}
		})
	}

	// Signed-in Go dashboard POST /auth/varlatch-token still mints a bearer
	// with no Clear-Site-Data header.
	enrollOver(t, b, ta)
	w := b.post("/auth/varlatch-token", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token":"vlt_web_`) || w.Header().Get("Clear-Site-Data") != "" {
		t.Fatalf("signed-in varlatch-token: %d %q Clear-Site-Data=%q", w.Code, w.Body.String(), w.Header().Get("Clear-Site-Data"))
	}

	// Same-origin POST /auth/varlatch-token with no CSRF header at all (as
	// the cached 0.23.0 dashboard sends on load) answers 403 csrf with
	// Clear-Site-Data: "cache" and never touches cookies; a wrong header does
	// not emit Clear-Site-Data.
	noHdr := b.send("POST", "/auth/varlatch-token", nil, map[string]string{"Origin": b.origin})
	if e := decode(t, noHdr); noHdr.Code != http.StatusForbidden || e.Error.Code != "PERMISSION_DENIED" || e.Error.Details["reason"] != "csrf" ||
		noHdr.Header().Get("Clear-Site-Data") != `"cache"` || noHdr.Header().Get("Cache-Control") != "no-store" || len(noHdr.Result().Cookies()) != 0 {
		t.Fatalf("no csrf header: %d %s headers=%v", noHdr.Code, noHdr.Body.String(), noHdr.Header())
	}
	wrongHdr := b.send("POST", "/auth/varlatch-token", nil, map[string]string{"Origin": b.origin, CSRFHeader: token + "x"})
	if e := decode(t, wrongHdr); wrongHdr.Code != http.StatusForbidden || e.Error.Code != "PERMISSION_DENIED" || e.Error.Details["reason"] != "csrf" ||
		wrongHdr.Header().Get("Clear-Site-Data") != "" {
		t.Fatalf("wrong csrf header: %d %s headers=%v", wrongHdr.Code, wrongHdr.Body.String(), wrongHdr.Header())
	}
}
