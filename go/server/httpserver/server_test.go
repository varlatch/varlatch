// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

type fakeBackend struct {
	id                         string
	schema, kek, installation  bool
	installationCalls, readies int
	mu                         sync.Mutex
}

func (f *fakeBackend) InstallationID(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installationCalls++
	return f.id, nil
}

func (f *fakeBackend) Ready(context.Context) (bool, bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readies++
	return f.schema, f.kek, f.installation
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var webFS = fstest.MapFS{
	"index.html":            {Data: []byte("<!doctype html><title>Varlatch</title>")},
	"assets/app-1234.js":    {Data: []byte("console.log(1)")},
	"varlatch-config.js":    {Data: []byte("window.__VARLATCH__ = {};")},
	"brand/favicon-32.png":  {Data: []byte("png")},
	"site.webmanifest":      {Data: []byte("{}")},
	"assets/style-5678.css": {Data: []byte("body{}")},
}

func newTestServer(t *testing.T, mod func(*Options)) (*Server, *fakeBackend, *clock, *bytes.Buffer) {
	t.Helper()
	b := &fakeBackend{id: "inst_test", schema: true, kek: true, installation: true}
	c := &clock{t: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	var logBuf bytes.Buffer
	pub, _ := url.Parse("http://127.0.0.1:8686")
	opts := Options{
		Version: "0.50.0-test", PublicURL: pub, Sync: true, Web: webFS, Backend: b,
		AccessLog: NewAccessLog(&logBuf), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: c.now,
	}
	if mod != nil {
		mod(&opts)
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s, b, c, &logBuf
}

func do(s http.Handler, method, target, body string, header map[string]string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.RemoteAddr = "192.0.2.10:40000"
	for k, v := range header {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

type envelope struct {
	Error struct {
		Code      string         `json:"code"`
		Message   string         `json:"message"`
		RequestID string         `json:"requestId"`
		Details   map[string]any `json:"details"`
	} `json:"error"`
}

func decode(t *testing.T, w *httptest.ResponseRecorder) envelope {
	t.Helper()
	var e envelope
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("body %q is not the error envelope: %v", w.Body.String(), err)
	}
	return e
}

var requestIDPattern = regexp.MustCompile(`^req_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Every operation of the OpenAPI document is routed; all but the built ones
// answer the shared stub.
func TestEveryOperationRoutedToStubOrBuilt(t *testing.T) {
	s, _, _, _ := newTestServer(t, nil)
	ops := s.Operations()
	gen, err := os.ReadFile("../api/api.gen.go")
	if err != nil {
		t.Fatal(err)
	}
	want := len(regexp.MustCompile(`(?m)^\tm\.HandleFunc\(`).FindAll(gen, -1))
	if len(ops) != want || want < 150 {
		t.Fatalf("%d operations routed, the generated server has %d", len(ops), want)
	}
	stubbed := s.Stubbed()
	if len(stubbed) != len(ops)-len(BuiltOperations) {
		t.Errorf("%d stubbed of %d with %d built", len(stubbed), len(ops), len(BuiltOperations))
	}
	for _, b := range BuiltOperations {
		if slices.Contains(stubbed, b) || !slices.Contains(ops, b) {
			t.Errorf("%s is not routed to its handler", b)
		}
	}
}

// The stub answers before authentication, CSRF, parameter binding, body
// decoding or storage: no bearer, a body that is not JSON, a path parameter
// that would not bind, all answer the same 501, and the backend is never
// asked anything.
func TestStubAnswersBeforeEverything(t *testing.T) {
	s, b, _, _ := newTestServer(t, nil)
	cases := []struct{ method, path, body string }{
		{"POST", "/v1/organizations", "{not json"},
		{"POST", "/v1/organizations", strings.Repeat("x", 4096)},
		{"GET", "/v1/organizations", ""},
		{"GET", "/v1/organizations/acme?limit=not-a-number", ""},
		{"DELETE", "/v1/organizations/acme/projects/api/environments/development/values/DATABASE_URL", ""},
		{"POST", "/v1/auth/device", ""},
		{"POST", "/auth/varlatch-token", ""},
		{"POST", "/auth/passkey/verify-authentication", "{}"},
		{"GET", "/enroll", ""},
		{"GET", "/enroll.js", ""},
	}
	for _, c := range cases {
		w := do(s, c.method, c.path, c.body, map[string]string{"Content-Type": "application/json", "Authorization": "Bearer nonsense"})
		if w.Code != http.StatusNotImplemented {
			t.Errorf("%s %s: %d %s", c.method, c.path, w.Code, w.Body.String())
			continue
		}
		e := decode(t, w)
		if e.Error.Code != NotImplementedYet || !requestIDPattern.MatchString(e.Error.RequestID) || e.Error.RequestID != w.Header().Get("X-Request-Id") {
			t.Errorf("%s %s: %+v", c.method, c.path, e)
		}
		if w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s %s: Content-Type %q", c.method, c.path, w.Header().Get("Content-Type"))
		}
	}
	if b.installationCalls != 0 || b.readies != 0 {
		t.Errorf("the stub reached the backend: %+v", b)
	}
	// The stub names the operation's route.
	w := do(s, "GET", "/v1/organizations/acme", "", nil)
	if e := decode(t, w); !strings.HasPrefix(e.Error.Message, "GET /v1/organizations/{org} is not built yet") {
		t.Errorf("message %q", e.Error.Message)
	}
}

// A test-only wiring: an operation added to the built ones is served by
// its generated handler, not the stub (here one this package does not
// implement, so the handler is reached and fails as an internal error).
func TestBuiltOperationLeavesTheStub(t *testing.T) {
	s, _, _, _ := newTestServer(t, func(o *Options) { o.Built = []string{"GET /v1/organizations"} })
	w := do(s, "GET", "/v1/organizations", "", nil)
	if w.Code == http.StatusNotImplemented {
		t.Fatalf("still the stub: %s", w.Body.String())
	}
	if _, err := New(Options{Backend: &fakeBackend{}, Built: []string{"GET /v1/nothing"}}); err == nil {
		t.Error("an unknown operation was accepted as built")
	}
}

// Known difference 1 (decision 4): an unknown route under the API paths
// answers Hono's plain-text 404, not the error envelope. The TypeScript
// server: app.ts registers no notFound handler, so Hono's default answers
// c.text("404 Not Found", 404).
func TestUnknownRoutePlainText(t *testing.T) {
	s, _, _, _ := newTestServer(t, nil)
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/nothing-here"},
		{"GET", "/v1"},
		{"GET", "/v1/"},
		{"DELETE", "/v1/meta"},        // a path the document has, a method it does not
		{"GET", "/v1/organizations/"}, // Hono's strict routing: no trailing slash
		{"GET", "/v1//organizations"}, // Go's mux would redirect
		{"GET", "/v1/organizations/../meta"},
		{"GET", "/v1x"},
		{"GET", "/authx"},
		{"POST", "/healthz"},
		{"GET", "/.well-known/jwks.json"}, // the Convex-only JWT signer is not in the Go server
		{"POST", "/enroll"},
	} {
		w := do(s, c.method, c.path, "", nil)
		if w.Code != http.StatusNotFound || w.Body.String() != "404 Not Found" || w.Header().Get("Content-Type") != "text/plain; charset=UTF-8" {
			t.Errorf("%s %s: %d %q %q", c.method, c.path, w.Code, w.Header().Get("Content-Type"), w.Body.String())
		}
		if !requestIDPattern.MatchString(w.Header().Get("X-Request-Id")) {
			t.Errorf("%s %s: no X-Request-Id", c.method, c.path)
		}
	}
}

// Known difference 2 (decision 4) and the window itself, as app.ts keeps
// it: 600 requests per client address per 60 s window from the client's
// first request; the 601st answers 429, code PERMISSION_DENIED, message
// "Request rate exceeded", Retry-After the seconds left (at least 1).
// /healthz and /readyz are not counted; another address has its own
// window; the window reopens when it ends.
func TestRequestWindow(t *testing.T) {
	s, _, c, _ := newTestServer(t, nil)
	from := func(addr, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = addr + ":1234"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	for i := 1; i <= WindowLimit; i++ {
		if w := from("192.0.2.1", "/v1/meta"); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
		if i == 1 {
			c.add(15500 * time.Millisecond)
		}
	}
	w := from("192.0.2.1", "/v1/meta")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("request 601: %d", w.Code)
	}
	e := decode(t, w)
	if e.Error.Code != "PERMISSION_DENIED" || e.Error.Message != "Request rate exceeded" || w.Header().Get("Retry-After") != "45" ||
		w.Header().Get("Content-Type") != "application/json" || e.Error.RequestID != w.Header().Get("X-Request-Id") {
		t.Errorf("refusal: %s, Retry-After %q", w.Body.String(), w.Header().Get("Retry-After"))
	}
	// Refusals count too, and every path under the API side does: a stub,
	// an unknown route.
	if w := from("192.0.2.1", "/v1/organizations"); w.Code != 429 {
		t.Errorf("stubbed operation not limited: %d", w.Code)
	}
	if w := from("192.0.2.1", "/v1/unknown"); w.Code != 429 {
		t.Errorf("unknown route not limited: %d", w.Code)
	}
	for _, p := range []string{"/healthz", "/readyz", "/", "/assets/app-1234.js"} {
		if w := from("192.0.2.1", p); w.Code != 200 {
			t.Errorf("%s limited: %d", p, w.Code)
		}
	}
	if w := from("192.0.2.2", "/v1/meta"); w.Code != 200 {
		t.Errorf("another client limited: %d", w.Code)
	}
	c.add(44*time.Second + 400*time.Millisecond)
	if w := from("192.0.2.1", "/v1/meta"); w.Code != 429 || w.Header().Get("Retry-After") != "1" {
		t.Errorf("last 100 ms: %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	c.add(100 * time.Millisecond)
	if w := from("192.0.2.1", "/v1/meta"); w.Code != 200 {
		t.Errorf("the next window did not open: %d", w.Code)
	}
}

// At MaxWindows open windows a new client is refused with Retry-After 60.
func TestRequestWindowCap(t *testing.T) {
	rw := newRequestWindow(func() time.Time { return time.Unix(0, 0) })
	for i := 0; i < MaxWindows; i++ {
		if ok, _ := rw.admit("c" + strconv.Itoa(i)); !ok {
			t.Fatalf("client %d refused", i)
		}
	}
	if ok, retry := rw.admit("one-more"); ok || retry != "60" {
		t.Errorf("client %d: %v %q", MaxWindows+1, ok, retry)
	}
	if ok, _ := rw.admit("c0"); !ok {
		t.Error("a client with an open window was refused")
	}
}

// The window is per client address behind trusted proxies.
func TestRequestWindowBehindProxy(t *testing.T) {
	s, _, _, _ := newTestServer(t, func(o *Options) { o.TrustedProxies = func(a string) bool { return a == "10.0.0.2" } })
	send := func(xff string) int {
		r := httptest.NewRequest("GET", "/v1/meta", nil)
		r.RemoteAddr = "10.0.0.2:999"
		r.Header.Set("X-Forwarded-For", xff)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < WindowLimit; i++ {
		send("198.51.100.1")
	}
	if send("198.51.100.1") != 429 || send("198.51.100.2") != 200 || send("1.2.3.4, 198.51.100.1") != 429 {
		t.Error("forwarded clients do not have windows of their own")
	}
}

func TestBodyLimit(t *testing.T) {
	s, _, _, _ := newTestServer(t, nil)
	r := httptest.NewRequest("POST", "/v1/organizations", strings.NewReader(strings.Repeat("x", MaxBody+1)))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 413 || decode(t, w).Error.Code != "VALIDATION_FAILED" || decode(t, w).Error.Message != "Request body exceeds 1 MiB" {
		t.Errorf("%d %s", w.Code, w.Body.String())
	}
}

func TestHealthReadyMeta(t *testing.T) {
	s, b, _, _ := newTestServer(t, nil)
	if w := do(s, "GET", "/healthz", "", nil); w.Code != 200 || w.Body.String() != `{"status":"ok"}` {
		t.Errorf("healthz: %d %s", w.Code, w.Body.String())
	}
	if w := do(s, "GET", "/readyz", "", nil); w.Code != 200 || w.Body.String() != `{"ready":true,"checks":{"schema":true,"kek":true,"installation":true}}` {
		t.Errorf("readyz: %d %s", w.Code, w.Body.String())
	}
	b.kek = false
	if w := do(s, "GET", "/readyz", "", nil); w.Code != 503 || w.Body.String() != `{"ready":false,"checks":{"schema":true,"kek":false,"installation":true}}` {
		t.Errorf("readyz with a wrong key: %d %s", w.Code, w.Body.String())
	}

	w := do(s, "GET", "/v1/meta", "", nil)
	if w.Code != 200 {
		t.Fatalf("meta: %d %s", w.Code, w.Body.String())
	}
	var m struct {
		ApiMajor          int      `json:"apiMajor"`
		ServerVersion     string   `json:"serverVersion"`
		SemanticsVersions []int    `json:"semanticsVersions"`
		Capabilities      []string `json:"capabilities"`
		SyncAdapters      []string `json:"syncAdapters"`
		InstallationID    string   `json:"installationId"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.ApiMajor != 1 || m.ServerVersion != "0.50.0-test" || !slices.Equal(m.SemanticsVersions, []int{1, 2, 3}) ||
		!slices.Equal(m.SyncAdapters, []string{"github-actions", "coolify", "convex"}) || m.InstallationID != "inst_test" {
		t.Errorf("meta: %+v", m)
	}
	want := slices.DeleteFunc(slices.Clone(Capabilities), func(c string) bool { return c == "tailnet.browser-reads" || c == "cli.download" })
	if !slices.Equal(m.Capabilities, want) || !slices.Contains(m.Capabilities, "auth.device") {
		t.Errorf("capabilities: %q", m.Capabilities)
	}
	for _, c := range []string{"auth.session", "realtime.sse"} {
		if slices.Contains(m.Capabilities, c) {
			t.Errorf("%s before its step", c)
		}
	}

	// Sync off and no device sign-in base: sync.targets, syncAdapters and
	// auth.device go.
	s2, _, _, _ := newTestServer(t, func(o *Options) { o.Sync = false; o.PublicURL, _ = url.Parse("http://varlatch.example.com") })
	w = do(s2, "GET", "/v1/meta", "", nil)
	if strings.Contains(w.Body.String(), "sync.targets") || strings.Contains(w.Body.String(), "syncAdapters") || strings.Contains(w.Body.String(), "auth.device") {
		t.Errorf("meta with sync off, plain-http public URL: %s", w.Body.String())
	}
	s3, _, _, _ := newTestServer(t, func(o *Options) { o.SyncAdapters = []string{"coolify"} })
	if w := do(s3, "GET", "/v1/meta", "", nil); !strings.Contains(w.Body.String(), `"syncAdapters":["coolify"]`) {
		t.Errorf("narrowed adapters: %s", w.Body.String())
	}
}

// Capabilities and SemanticsVersions are the TypeScript server's.
func TestListsMatchTypeScript(t *testing.T) {
	ts, err := os.ReadFile("../../../packages/protocol/src/errors.ts")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)export const CAPABILITIES = \[(.*?)\] as const`).FindSubmatch(ts)
	if block == nil {
		t.Fatal("CAPABILITIES not found in errors.ts")
	}
	var fromTS []string
	for _, m := range regexp.MustCompile(`(?m)^\s*"([a-z0-9.-]+)",`).FindAllSubmatch(block[1], -1) {
		fromTS = append(fromTS, string(m[1]))
	}
	if !slices.Equal(fromTS, Capabilities) {
		t.Errorf("Capabilities differ from packages/protocol/src/errors.ts:\n go %q\n ts %q", Capabilities, fromTS)
	}
	sem, err := os.ReadFile("../../../packages/contract/src/semantics.ts")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sem, []byte("export const SEMANTICS_VERSIONS = [1, 2, 3] as const;")) {
		t.Error("SEMANTICS_VERSIONS changed in packages/contract/src/semantics.ts")
	}
	sync, err := os.ReadFile("../../../packages/sync/src/types.ts")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sync, []byte(`export const PLATFORMS = ["github-actions", "coolify", "convex"] as const;`)) {
		t.Error("PLATFORMS changed in packages/sync/src/types.ts")
	}
}

func TestCLIDownloadOff(t *testing.T) {
	s, _, _, _ := newTestServer(t, nil)
	for _, p := range []string{"/install.sh", "/install.ps1", "/cli/varlatch.cjs"} {
		w := do(s, "GET", p, "", nil)
		if w.Code != 404 || w.Body.String() != "Not found" || w.Header().Get("Cache-Control") != "no-cache" ||
			w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Content-Security-Policy") != "" {
			t.Errorf("%s: %d %q %v", p, w.Code, w.Body.String(), w.Header())
		}
	}
}

// The dashboard: files of the build where the path names one, index.html
// for every other path, with the CSP; never for /v1, /auth or /enroll.
func TestDashboard(t *testing.T) {
	s, _, _, _ := newTestServer(t, nil)
	for p, want := range map[string]string{
		"/":                   "<!doctype html><title>Varlatch</title>",
		"/index.html":         "<!doctype html><title>Varlatch</title>",
		"/orgs/acme/projects": "<!doctype html><title>Varlatch</title>",
		"/device":             "<!doctype html><title>Varlatch</title>",
		"/assets/app-1234.js": "console.log(1)",
		"/assets/missing.js":  "<!doctype html><title>Varlatch</title>",
		"/varlatch-config.js": "window.__VARLATCH__ = {};",
		"/assets":             "<!doctype html><title>Varlatch</title>",
	} {
		w := do(s, "GET", p, "", nil)
		if w.Code != 200 || w.Body.String() != want {
			t.Errorf("%s: %d %q", p, w.Code, w.Body.String())
		}
		if w.Header().Get("Content-Security-Policy") != ContentSecurityPolicy {
			t.Errorf("%s: CSP %q", p, w.Header().Get("Content-Security-Policy"))
		}
		if (p == "/device") != (w.Header().Get("Cache-Control") == "no-store") {
			t.Errorf("%s: Cache-Control %q", p, w.Header().Get("Cache-Control"))
		}
	}
	if ct := do(s, "GET", "/assets/app-1234.js", "", nil).Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("js served as %q", ct)
	}
	if ct := do(s, "GET", "/", "", nil).Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("index served as %q", ct)
	}
	if w := do(s, "POST", "/orgs", "{}", nil); w.Code != 405 {
		t.Errorf("POST to the dashboard: %d", w.Code)
	}
	for _, p := range []string{"/v1/whatever", "/auth/session", "/enroll", "/healthz"} {
		if w := do(s, "GET", p, "", nil); strings.Contains(w.Body.String(), "<title>Varlatch</title>") || w.Header().Get("Content-Security-Policy") != "" {
			t.Errorf("%s served the dashboard", p)
		}
	}
}

// The access log: one JSON line per request with what the harness's
// request-log needs.
func TestAccessLog(t *testing.T) {
	s, _, c, logBuf := newTestServer(t, func(o *Options) { o.TrustedProxies = func(a string) bool { return a == "10.0.0.2" } })
	r := httptest.NewRequest("POST", "/v1/auth/device?code=SECRET", nil)
	r.RemoteAddr = "10.0.0.2:5555"
	r.Header.Set("X-Forwarded-For", "198.18.0.7")
	s.ServeHTTP(httptest.NewRecorder(), r)
	c.add(time.Second)
	do(s, "GET", "/assets/app-1234.js", "", nil)
	do(s, "GET", "/healthz", "", nil)
	lines := strings.Split(strings.TrimSpace(logBuf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d records: %q", len(lines), logBuf.String())
	}
	if strings.Contains(logBuf.String(), "SECRET") {
		t.Error("the query string was logged")
	}
	var recs []AccessRecord
	for _, l := range lines {
		var rec AccessRecord
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
	}
	first := recs[0]
	if first.Client != "198.18.0.7" || first.Method != "POST" || first.Path != "/v1/auth/device" || first.Status != 501 ||
		first.ForwardedFor == nil || *first.ForwardedFor != "198.18.0.7" || !first.Window || first.Arrived.IsZero() || first.Completed.Before(first.Arrived) ||
		!requestIDPattern.MatchString(first.RequestID) {
		t.Errorf("record %+v", first)
	}
	if recs[1].Window || recs[1].Client != "192.0.2.10" || recs[1].ForwardedFor != nil || recs[1].Status != 200 || recs[1].Bytes != int64(len("console.log(1)")) {
		t.Errorf("static record %+v", recs[1])
	}
	if recs[2].Window || recs[2].Path != "/healthz" {
		t.Errorf("healthz record %+v", recs[2])
	}
}

func TestPanicIsInternal(t *testing.T) {
	s, _, _, logBuf := newTestServer(t, func(o *Options) { o.Backend = panicking{} })
	w := do(s, "GET", "/readyz", "", nil)
	if w.Code != 500 || decode(t, w).Error.Code != "INTERNAL" || decode(t, w).Error.Message != "Internal error" {
		t.Errorf("%d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(logBuf.String(), `"status":500`) {
		t.Errorf("no access record: %q", logBuf.String())
	}
}

type panicking struct{}

func (panicking) InstallationID(context.Context) (string, error) { panic("boom") }
func (panicking) Ready(context.Context) (bool, bool, bool)       { panic("boom") }
