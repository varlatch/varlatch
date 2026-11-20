// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	"github.com/varlatch/varlatch/go/server/tailnet"
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
	s, b, c, logBuf, _ := newTestServerAuth(t, mod)
	return s, b, c, logBuf
}

// newTestServerAuth is newTestServer with its authentication: a database
// with one person and their credentials (authkit_test.go).
func newTestServerAuth(t *testing.T, mod func(*Options)) (*Server, *fakeBackend, *clock, *bytes.Buffer, *testAuth) {
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
	ta := newTestAuth(t, opts.PublicURL, time.Now)
	opts.Auth = ta.svc
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s, b, c, &logBuf, ta
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
	// Every /v1 operation is built: the test stubs three of them.
	s, b, _, _ := newTestServer(t, func(o *Options) {
		o.Stubbed = []string{rotateGitHubAppKeyPattern, listInstallationsPattern, pushSyncTargetPattern}
	})
	cases := []struct{ method, path, body string }{
		{"POST", "/v1/organizations/acme/github-app/key", "{not json"},
		{"POST", "/v1/organizations/acme/github-app/key", strings.Repeat("x", 4096)},
		{"GET", "/v1/organizations/acme/github-app/installations", ""},
		{"GET", "/v1/organizations/acme/github-app/installations?limit=not-a-number", ""},
		{"POST", "/v1/organizations/acme/projects/api/environments/development/sync-targets/core/push", "{not json"},
		{"POST", "/v1/organizations/acme/projects/api/environments/development/sync-targets/core/push?wait=not-a-boolean", "{}"},
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
	w := do(s, "POST", "/v1/organizations/acme/github-app/key", "{}", nil)
	if e := decode(t, w); !strings.HasPrefix(e.Error.Message, "POST /v1/organizations/{org}/github-app/key is not built yet") {
		t.Errorf("message %q", e.Error.Message)
	}
}

// A test-only wiring: an operation stubbed, then added to the built ones,
// is served by its generated handler, not the stub (the handler is reached
// and refuses the bearer).
func TestBuiltOperationLeavesTheStub(t *testing.T) {
	s, _, _, _ := newTestServer(t, func(o *Options) {
		o.Stubbed = []string{pushSyncTargetPattern}
		o.Built = []string{pushSyncTargetPattern}
	})
	w := do(s, "POST", "/v1/organizations/acme/projects/api/environments/development/sync-targets/core/push", "{}", map[string]string{"Authorization": "Bearer x"})
	if w.Code == http.StatusNotImplemented {
		t.Fatalf("still the stub: %s", w.Body.String())
	}
	if _, err := New(Options{Backend: &fakeBackend{}, Built: []string{"GET /v1/nothing"}}); err == nil {
		t.Error("an unknown operation was accepted as built")
	}
	if _, err := New(Options{Backend: &fakeBackend{}, Stubbed: []string{"GET /v1/nothing"}}); err == nil {
		t.Error("an unknown operation was accepted as stubbed")
	}
}

// Known difference 1 (decision 4): an unknown route answers Hono's
// plain-text 404, not the error envelope. Under /v1 the TypeScript server
// authenticates first; parity_test.go runs those cases from the table both
// servers share. Outside /v1 (the other paths varlatchd answers) there is
// no authentication: app.ts registers no notFound handler, so Hono's
// default answers c.text("404 Not Found", 404).
func TestUnknownRoutePlainText(t *testing.T) {
	s, _, _, _ := newTestServer(t, nil)
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1x"},
		{"GET", "/authx"},
		{"POST", "/healthz"},
		{"GET", "/.well-known/jwks.json"}, // the Convex-only JWT signer is not in the Go server
		{"POST", "/enroll"},
		{"DELETE", "/v1/meta"}, // /v1/meta's path needs no authentication
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
	if w := from("192.0.2.1", "/v1/unknown"); w.Code != 429 { // before authentication
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
		if ok, _, _ := rw.admit("c" + strconv.Itoa(i)); !ok {
			t.Fatalf("client %d refused", i)
		}
	}
	if ok, retry, _ := rw.admit("one-more"); ok || retry != "60" {
		t.Errorf("client %d: %v %q", MaxWindows+1, ok, retry)
	}
	if ok, _, _ := rw.admit("c0"); !ok {
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
	// The TypeScript server's, then varlatchd's own browser session
	// (auth.session); server-sent events (realtime.sse) come with step 3.5.
	want := append(slices.DeleteFunc(slices.Clone(Capabilities), func(c string) bool { return c == "tailnet.browser-reads" || c == "cli.download" }), "auth.session")
	if !slices.Equal(m.Capabilities, want) || !slices.Contains(m.Capabilities, "auth.device") {
		t.Errorf("capabilities: %q", m.Capabilities)
	}
	if slices.Contains(m.Capabilities, "realtime.sse") {
		t.Error("realtime.sse before its step")
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

// serve_cli on (step 6.8): the installers and every path under /cli/
// reach the served release once it is ready, and /v1/meta then lists
// cli.download; before, they answer as with serving off. Off, a /cli/ path
// other than the TypeScript bundle's is the dashboard's, as on the
// TypeScript deployment.
func TestCLIDownloadOn(t *testing.T) {
	var ready http.Handler
	served := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("served " + r.URL.Path)) })
	s, _, _, _ := newTestServer(t, func(o *Options) { o.CLI = func() http.Handler { return ready } })
	listed := func(srv http.Handler) bool {
		return strings.Contains(do(srv, "GET", "/v1/meta", "", nil).Body.String(), `"cli.download"`)
	}
	paths := []string{"/install.sh", "/install.ps1", "/cli/v0.50.0/varlatch-0.50.0-linux-amd64", "/cli/v0.50.0/SHA256SUMS"}
	for _, p := range paths {
		if w := do(s, "GET", p, "", nil); w.Code != 404 || w.Body.String() != "Not found" {
			t.Errorf("%s before a release is ready: %d %q", p, w.Code, w.Body.String())
		}
	}
	if listed(s) {
		t.Error("cli.download listed before a release is ready")
	}
	ready = served
	for _, p := range paths {
		if w := do(s, "GET", p, "", nil); w.Code != 200 || w.Body.String() != "served "+p {
			t.Errorf("%s: %d %q", p, w.Code, w.Body.String())
		}
	}
	if w := do(s, "HEAD", "/install.sh", "", nil); w.Code != 200 {
		t.Errorf("HEAD /install.sh: %d", w.Code)
	}
	if w := do(s, "POST", "/install.sh", "", nil); w.Code == 200 && strings.HasPrefix(w.Body.String(), "served") {
		t.Error("POST reached the served release")
	}
	if !listed(s) {
		t.Error("cli.download not listed with a release ready")
	}
	// Off: the TypeScript deployment's paths.
	off, _, _, _ := newTestServer(t, nil)
	if w := do(off, "GET", "/cli/v0.50.0/SHA256SUMS", "", nil); w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("off, a /cli/ path: %d %v", w.Code, w.Header())
	}
}

// With a tailnet browser endpoint, the dashboard's connect-src names it,
// as the TypeScript installation's dashboard container writes it for
// VARLATCH_TAILNET_ENDPOINT (less the Convex origins the Go server has
// none of), so the dashboard can Connect. It follows the endpoint as it is
// now: none before enrolment or once the pin is closed. An endpoint that is
// not exactly an https origin is never written into the header.
func TestDashboardCSPNamesTheBrowserEndpoint(t *testing.T) {
	endpoint := ""
	s, _, _, _ := newTestServer(t, func(o *Options) { o.BrowserEndpoint = func() string { return endpoint } })
	csp := func() string {
		t.Helper()
		w := do(s, "GET", "/orgs/acme", "", nil)
		if w.Code != 200 {
			t.Fatalf("the dashboard: %d", w.Code)
		}
		return w.Header().Get("Content-Security-Policy")
	}
	if got := csp(); got != ContentSecurityPolicy {
		t.Errorf("before enrolment: %q", got)
	}
	endpoint = "https://varlatch.corp.ts.net:8443"
	want := "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self' data:; " +
		"connect-src 'self' https://varlatch.corp.ts.net:8443; manifest-src 'self'; base-uri 'none'; " +
		"form-action 'self' https://github.com; frame-ancestors 'none'; object-src 'none'"
	if got := csp(); got != want {
		t.Errorf("with the endpoint:\n got %q\nwant %q", got, want)
	}
	for _, bad := range []string{
		"https://varlatch.corp.ts.net:8443; script-src *", "http://varlatch.corp.ts.net:8443", "https://Varlatch.corp.ts.net",
		"https://varlatch.corp.ts.net:8443/path", "https://varlatch.corp.ts.net:8443 https://evil.example", "https://-x.ts.net",
	} {
		endpoint = bad
		if got := csp(); got != ContentSecurityPolicy {
			t.Errorf("%q written into the CSP: %q", bad, got)
		}
	}
	endpoint = ""
	if got := csp(); got != ContentSecurityPolicy {
		t.Errorf("once the pin is closed: %q", got)
	}
}

// pinNode is a tailnet node whose status the test sets.
type pinNode struct {
	mu sync.Mutex
	st tailnet.Status
}

func (n *pinNode) Status(context.Context) (tailnet.Status, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.st, nil
}

func (n *pinNode) on(id, suffix string) {
	n.mu.Lock()
	n.st = tailnet.Status{BackendState: "Running", SelfID: "nSelf", DNSName: "varlatch." + suffix, Suffix: suffix, TailnetID: id, Tags: []string{"tag:varlatch"}}
	n.mu.Unlock()
}

// Through the tailnet manager varlatchd wires in (its BrowserEndpoint):
// the dashboard's policy, getTailnetEndpoint and /v1/meta's
// tailnet.browser-reads agree as the pin is taken, closes (the tailnet
// changed), stays closed across a restart and is re-pinned.
func TestTheBrowserEndpointFollowsThePinEverywhere(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	node := &pinNode{st: tailnet.Status{BackendState: "NeedsLogin"}}
	if err := tailnet.BeginEnrolment(dir); err != nil {
		t.Fatal(err)
	}
	manager := func() *tailnet.Manager {
		m, err := tailnet.NewManager(node, "", dir, 8687, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		m.SetBrowser("varlatch", 8443)
		return m
	}
	m := manager()
	s, _, _, _, ta := newTestServerAuth(t, func(o *Options) { o.BrowserEndpoint = func() string { return m.BrowserEndpoint() } })
	seen := func(want string) {
		t.Helper()
		csp := do(s, "GET", "/orgs/acme", "", nil).Header().Get("Content-Security-Policy")
		wantCSP := contentSecurityPolicy(want)
		if want == "" {
			wantCSP = ContentSecurityPolicy
		}
		if csp != wantCSP {
			t.Errorf("the dashboard's policy %q, want the endpoint %q", csp, want)
		}
		var ep struct{ BrowserEndpoint *string }
		w := do(s, "GET", "/v1/tailnet/endpoint", "", map[string]string{"Authorization": "Bearer " + ta.tokens["valid"]})
		if json.Unmarshal(w.Body.Bytes(), &ep) != nil || w.Code != 200 || (ep.BrowserEndpoint == nil) != (want == "") || (ep.BrowserEndpoint != nil && *ep.BrowserEndpoint != want) {
			t.Errorf("getTailnetEndpoint: %d %s, want %q", w.Code, w.Body.String(), want)
		}
		if meta := do(s, "GET", "/v1/meta", "", nil).Body.String(); strings.Contains(meta, `"tailnet.browser-reads"`) != (want != "") {
			t.Errorf("/v1/meta's tailnet.browser-reads with the endpoint %q: %s", want, meta)
		}
	}
	m.Check(ctx)
	seen("")
	node.on("Tabc123", "corp.ts.net")
	m.Check(ctx)
	seen("https://varlatch.corp.ts.net:8443")
	node.on("Tabc123", "corp-new.ts.net")
	m.Check(ctx)
	if m.Closed() != tailnet.PinSuffix {
		t.Fatalf("the pin did not close: %q", m.Closed())
	}
	seen("")
	m = manager() // a restart: the closure is latched
	m.Check(ctx)
	seen("")
	if _, _, err := m.Repin(ctx, false); err != nil {
		t.Fatal(err)
	}
	seen("https://varlatch.corp-new.ts.net:8443")
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
	if first.Client != "198.18.0.7" || first.Method != "POST" || first.Path != "/v1/auth/device" || first.Status != 201 ||
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

// The access log names the request window that counted each request, taken
// at admission (G9a counts each address's windows from it, whatever order
// the answers complete in); a request the window does not count has none.
func TestAccessLogWindowOpened(t *testing.T) {
	s, _, c, logBuf := newTestServer(t, nil)
	from := func(addr, path string) {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = addr + ":1234"
		s.ServeHTTP(httptest.NewRecorder(), r)
	}
	t0 := c.now()
	from("192.0.2.1", "/v1/meta")
	c.add(10 * time.Second)
	from("192.0.2.1", "/v1/meta")
	from("192.0.2.2", "/v1/meta")
	from("192.0.2.1", "/healthz")
	c.add(51 * time.Second)
	from("192.0.2.1", "/v1/meta")
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		var rec AccessRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		opened := "-"
		if rec.WindowOpened != nil {
			opened = rec.WindowOpened.Sub(t0).String()
		}
		got = append(got, rec.Client+" "+rec.Path+" "+opened)
	}
	want := []string{
		"192.0.2.1 /v1/meta 0s",
		"192.0.2.1 /v1/meta 0s",
		"192.0.2.2 /v1/meta 10s",
		"192.0.2.1 /healthz -",
		"192.0.2.1 /v1/meta 1m1s",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("access log:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A request whose client went away fails with context.Canceled: answered as
// any internal error, but logged at debug level only, as the TypeScript
// server (which never cancels a request's work) logs nothing for it. The
// same error on a request still in flight is an error.
func TestCancelledRequestIsNotLoggedAsError(t *testing.T) {
	var logs bytes.Buffer
	s, _, _, _ := newTestServer(t, func(o *Options) { o.Log = slog.New(slog.NewTextHandler(&logs, nil)) })
	failed := fmt.Errorf("query: %w", context.Canceled)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	s.answerError(w, httptest.NewRequest("GET", "/v1/organizations/acme", nil).WithContext(ctx), failed)
	if w.Code != 500 || decode(t, w).Error.Code != "INTERNAL" {
		t.Errorf("cancelled: %d %s", w.Code, w.Body.String())
	}
	if logs.Len() != 0 {
		t.Errorf("a cancelled request was logged at info level or above: %q", logs.String())
	}

	w = httptest.NewRecorder()
	s.answerError(w, httptest.NewRequest("GET", "/v1/organizations/acme", nil), failed)
	if w.Code != 500 || !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "answering a request failed") {
		t.Errorf("in flight: %d, logs %q", w.Code, logs.String())
	}
}
