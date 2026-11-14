// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/auth/authtest"
)

// The browser session over HTTP (ADR-0059 Decision 6): CSRF and the
// Origin header on every POST, the cookies' attributes, and a browser's
// round trip from enrollment to sign-out.

const browserOrigin = "http://localhost:8686"

func browserServer(t *testing.T, public string) (*Server, *testAuth) {
	t.Helper()
	s, _, _, _, ta := newTestServerAuth(t, func(o *Options) { o.PublicURL, _ = url.Parse(public) })
	return s, ta
}

// testBrowser is a browser's cookie jar against one server.
type testBrowser struct {
	t       *testing.T
	s       *Server
	cookies map[string]*http.Cookie
	origin  string
}

func newBrowser(t *testing.T, s *Server, origin string) *testBrowser {
	return &testBrowser{t: t, s: s, cookies: map[string]*http.Cookie{}, origin: origin}
}

func (b *testBrowser) send(method, target string, body any, header map[string]string) *httptest.ResponseRecorder {
	b.t.Helper()
	var r *http.Request
	if body != nil {
		raw, _ := json.Marshal(body)
		r = httptest.NewRequest(method, target, strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.RemoteAddr = "192.0.2.10:40000"
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	b.s.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return w
}

// csrf is the browser's CSRF token, from GET /auth/session.
func (b *testBrowser) csrf() string {
	b.t.Helper()
	w := b.send("GET", "/auth/session", nil, nil)
	var s struct{ CsrfToken string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &s) != nil || s.CsrfToken == "" {
		b.t.Fatalf("session: %d %s", w.Code, w.Body.String())
	}
	return s.CsrfToken
}

// post sends a POST as the page does: its origin and the CSRF header.
func (b *testBrowser) post(target string, body any) *httptest.ResponseRecorder {
	b.t.Helper()
	return b.send("POST", target, body, map[string]string{"Origin": b.origin, CSRFHeader: b.csrf()})
}

func decodeInto(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if w.Code >= 300 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("%s: %v", w.Body.String(), err)
	}
}

// Every POST under /auth is refused without the installation's origin or
// without the CSRF token matching the cookie, before its body is read.
func TestBrowserCSRFAndOrigin(t *testing.T) {
	s, _ := browserServer(t, browserOrigin)
	b := newBrowser(t, s, browserOrigin)
	token := b.csrf()
	for _, path := range []string{"/auth/passkey/sign-in/options", "/auth/passkey/sign-in", "/auth/passkey/registration/options", "/auth/passkey/registration", "/auth/sign-out", "/auth/varlatch-token"} {
		for _, c := range []struct {
			name   string
			header map[string]string
			reason string
		}{
			{"no origin", map[string]string{CSRFHeader: token}, "origin"},
			{"another site", map[string]string{"Origin": "https://evil.example.net", CSRFHeader: token}, "origin"},
			{"another port", map[string]string{"Origin": "http://localhost:9999", CSRFHeader: token}, "origin"},
			{"null origin", map[string]string{"Origin": "null", CSRFHeader: token}, "origin"},
			{"no token", map[string]string{"Origin": browserOrigin}, "csrf"},
			{"wrong token", map[string]string{"Origin": browserOrigin, CSRFHeader: token + "x"}, "csrf"},
		} {
			w := b.send("POST", path, map[string]any{"not": "json the handler would read"}, c.header)
			e := decode(t, w)
			if w.Code != http.StatusForbidden || e.Error.Code != "PERMISSION_DENIED" || e.Error.Details["reason"] != c.reason {
				t.Errorf("%s, %s: %d %s", path, c.name, w.Code, w.Body.String())
			}
		}
	}
	// A browser without the cookie cannot present a token that matches.
	stranger := newBrowser(t, s, browserOrigin)
	w := stranger.send("POST", "/auth/varlatch-token", nil, map[string]string{"Origin": browserOrigin, CSRFHeader: token})
	if e := decode(t, w); w.Code != 403 || e.Error.Details["reason"] != "csrf" {
		t.Errorf("no cookie: %d %s", w.Code, w.Body.String())
	}
	// With both: answered (no session yet).
	w = b.post("/auth/varlatch-token", nil)
	if e := decode(t, w); w.Code != 401 || e.Error.Code != "AUTHENTICATION_REQUIRED" {
		t.Errorf("checked request: %d %s", w.Code, w.Body.String())
	}
}

// The cookies: SameSite=Strict and Path=/; on https Secure, with the
// __Host- prefix; on plain http (a local installation) neither. The
// session cookie is HttpOnly, the CSRF cookie readable by the page.
func TestBrowserCookieAttributes(t *testing.T) {
	for _, c := range []struct {
		public, prefix string
		secure         bool
	}{
		{browserOrigin, "", false},
		{"https://varlatch.example.com", "__Host-", true},
	} {
		s, ta := browserServer(t, c.public)
		b := newBrowser(t, s, c.public)
		b.csrf()
		csrf := b.cookies[c.prefix+"varlatch_csrf"]
		if csrf == nil || csrf.HttpOnly || csrf.Secure != c.secure || csrf.SameSite != http.SameSiteStrictMode || csrf.Path != "/" {
			t.Fatalf("%s: CSRF cookie %+v (cookies %v)", c.public, csrf, b.cookies)
		}
		started := enrollOver(t, b, ta)
		session := b.cookies[c.prefix+"varlatch_session"]
		if session == nil || !session.HttpOnly || session.Secure != c.secure || session.SameSite != http.SameSiteStrictMode ||
			session.Path != "/" || session.MaxAge != int(auth.SessionLifetime.Seconds()) {
			t.Fatalf("%s: session cookie %+v", c.public, session)
		}
		// The cookie holds the token; the database only its hash.
		if n := countRows(t, ta, `SELECT count(*) FROM auth_sessions WHERE token_hash = ?`, auth.HashToken(session.Value)); n != 1 || started == "" {
			t.Fatalf("session row by hash: %d", n)
		}
		if n := countRows(t, ta, `SELECT count(*) FROM auth_sessions WHERE token_hash = ?`, session.Value); n != 0 {
			t.Fatal("a session token stored in plaintext")
		}
	}
}

func countRows(t *testing.T, ta *testAuth, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := ta.store.Reader().QueryRowContext(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// enrollOver runs a bootstrap enrollment through the HTTP endpoints, with
// a software authenticator, and returns the identity it enrolled.
func enrollOver(t *testing.T, b *testBrowser, ta *testAuth) string {
	t.Helper()
	g, err := ta.svc.IssueRecoveryGrant(context.Background(), auth.Recovery{IdentityID: "idn_parity"})
	if err != nil {
		g, err = ta.svc.IssueBootstrapGrant(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	}
	var opts struct{ PublicKey auth.CreationOptions }
	decodeInto(t, b.post("/auth/passkey/registration/options", map[string]any{"token": g.Token}), &opts)
	key := authtest.New(t)
	var reg struct {
		PasskeyID, IdentityID string
		SignedIn              bool
	}
	decodeInto(t, b.post("/auth/passkey/registration", map[string]any{"response": json.RawMessage(key.Register(t, opts.PublicKey, b.origin)), "name": "Test"}), &reg)
	if !reg.SignedIn {
		t.Fatalf("not signed in: %+v", reg)
	}
	return reg.IdentityID
}

// A browser's round trip: enrollment, the bearer, /v1 with it, a CLI
// hand-off exchange, sign-out revoking the bearer and keeping the CLI
// credential.
func TestBrowserRoundTrip(t *testing.T) {
	s, ta := browserServer(t, browserOrigin)
	b := newBrowser(t, s, browserOrigin)
	identity := enrollOver(t, b, ta)
	var sess struct{ IdentityID *string }
	decodeInto(t, b.send("GET", "/auth/session", nil, nil), &sess)
	if sess.IdentityID == nil || *sess.IdentityID != identity {
		t.Fatalf("session %+v", sess)
	}
	var bearer struct{ Token, IdentityID, ExpiresAt string }
	decodeInto(t, b.post("/auth/varlatch-token", nil), &bearer)
	if !strings.HasPrefix(bearer.Token, "vlt_web_") || bearer.IdentityID != identity || !strings.HasSuffix(bearer.ExpiresAt, "Z") {
		t.Fatalf("bearer %+v", bearer)
	}
	me := do(s, "GET", "/v1/me", "", map[string]string{"Authorization": "Bearer " + bearer.Token})
	if me.Code != 200 || !strings.Contains(me.Body.String(), `"kind":"browser"`) || !strings.HasPrefix(me.Body.String(), `{"identity":{"id":"`+identity+`"`) {
		t.Fatalf("whoami %d %s", me.Code, me.Body.String())
	}
	// Cookies never authenticate /v1.
	if w := b.send("GET", "/v1/me", nil, nil); w.Code != 401 {
		t.Fatalf("/v1 with a cookie: %d", w.Code)
	}
	var second struct{ Token string }
	decodeInto(t, b.post("/auth/varlatch-token", nil), &second)
	cli := do(s, "POST", "/v1/me/credentials/cli", `{"ttlSeconds":3600}`, map[string]string{"Authorization": "Bearer " + second.Token, "Content-Type": "application/json", "User-Agent": "varlatch-cli/0.22.0 (linux; x64)"})
	var issued struct{ ID, Token, ExpiresAt string }
	if cli.Code != 201 || json.Unmarshal(cli.Body.Bytes(), &issued) != nil || !strings.HasPrefix(issued.Token, "vlt_cli_") || cli.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("exchange %d %s", cli.Code, cli.Body.String())
	}
	if again := do(s, "POST", "/v1/me/credentials/cli", `{}`, map[string]string{"Authorization": "Bearer " + second.Token}); again.Code != 401 {
		t.Fatalf("second exchange %d", again.Code)
	}
	if w := b.post("/auth/sign-out", nil); w.Code != 204 {
		t.Fatalf("sign-out %d %s", w.Code, w.Body.String())
	}
	if _, ok := b.cookies["varlatch_session"]; ok {
		t.Fatal("session cookie kept")
	}
	if w := do(s, "GET", "/v1/me", "", map[string]string{"Authorization": "Bearer " + bearer.Token}); w.Code != 401 {
		t.Fatalf("bearer after sign-out: %d", w.Code)
	}
	if w := do(s, "GET", "/v1/me", "", map[string]string{"Authorization": "Bearer " + issued.Token}); w.Code != 200 {
		t.Fatalf("CLI hand-off credential after sign-out: %d", w.Code)
	}
	if w := b.post("/auth/varlatch-token", nil); w.Code != 401 {
		t.Fatalf("mint after sign-out: %d", w.Code)
	}
}

// A sign-in's challenge belongs to the browser that asked for it: another
// browser's assertion over it is refused, and the challenge is spent.
func TestBrowserChallengeBoundToBrowser(t *testing.T) {
	s, ta := browserServer(t, browserOrigin)
	b := newBrowser(t, s, browserOrigin)
	enrollOver(t, b, ta)
	var opts struct{ PublicKey auth.RequestOptions }
	decodeInto(t, b.post("/auth/passkey/sign-in/options", nil), &opts)
	other := newBrowser(t, s, browserOrigin)
	key := authtest.New(t)
	resp := key.Assert(t, opts.PublicKey, browserOrigin)
	if w := other.post("/auth/passkey/sign-in", map[string]any{"response": json.RawMessage(resp)}); w.Code != 401 {
		t.Fatalf("another browser: %d %s", w.Code, w.Body.String())
	}
	if w := b.post("/auth/passkey/sign-in", map[string]any{"response": json.RawMessage(resp)}); w.Code != 401 || !strings.Contains(w.Body.String(), "used or expired") {
		t.Fatalf("spent challenge: %d %s", w.Code, w.Body.String())
	}
	// Unknown routes under /auth, and Better Auth's, answer 404.
	if w := b.post("/auth/passkey/verify-authentication", map[string]any{}); w.Code != 404 {
		t.Fatalf("Better Auth's path: %d", w.Code)
	}
}

// The enrollment page and its script.
func TestEnrollPage(t *testing.T) {
	s, _ := browserServer(t, browserOrigin)
	page := do(s, "GET", "/enroll", "", nil)
	if page.Code != 200 || page.Header().Get("Content-Type") != "text/html; charset=UTF-8" || !strings.Contains(page.Body.String(), `<script src="/enroll.js"></script>`) {
		t.Fatalf("page %d %q", page.Code, page.Header())
	}
	js := do(s, "GET", "/enroll.js", "", nil)
	if js.Code != 200 || js.Header().Get("Content-Type") != "text/javascript" || !strings.Contains(js.Body.String(), "window.varlatch = { enroll: enroll, signIn: signIn }") {
		t.Fatalf("script %d", js.Code)
	}
	if w := do(s, "POST", "/enroll", "", nil); w.Code != 404 {
		t.Fatalf("POST /enroll %d", w.Code)
	}
}
