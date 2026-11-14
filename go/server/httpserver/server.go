// SPDX-License-Identifier: AGPL-3.0-or-later

// Package httpserver is varlatchd's HTTP layer (ADR-0059 step 3.2): the /v1
// strict server generated from the OpenAPI document (go/server/api), the
// shared stub of the operations not built yet, the request window, client
// addresses, the access log, /healthz and /readyz, and the embedded
// dashboard.
//
// The behaviour follows the TypeScript server (services/varlatchd/src/http/
// app.ts) and the dashboard's nginx in front of it (apps/web/nginx.conf),
// since varlatchd now serves both:
//
//   - every response from the API side carries X-Request-Id;
//   - a request body over 1 MiB answers 413 VALIDATION_FAILED;
//   - each client address gets WindowLimit requests per WindowLength;
//     beyond that, 429 with PERMISSION_DENIED and Retry-After;
//   - an unknown route under the API side answers Hono's plain-text
//     "404 Not Found", after the authentication the TypeScript server runs
//     first for /v1 (unknownV1);
//   - every other path serves the dashboard (single-page routing), with
//     its Content-Security-Policy. /v1, /auth and /enroll never do.
package httpserver

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/clientaddr"
)

// MaxBody is the largest request body accepted (Hono's bodyLimit in
// app.ts).
const MaxBody = 1 << 20

// Backend is what the HTTP layer reads from the server's state.
type Backend interface {
	// InstallationID is the installation's ID, or "" when there is none.
	InstallationID(ctx context.Context) (string, error)
	// Ready reports /readyz's checks: the schema is current, the loaded
	// Root KEK opens the installation's canary, and the installation
	// exists.
	Ready(ctx context.Context) (schema, kek, installation bool)
}

// Options configures the handler.
type Options struct {
	// Version is the server version /v1/meta reports.
	Version string
	// PublicURL is the configured public URL; nil when not set.
	PublicURL *url.URL
	// Sync is the outbound sync installation switch; SyncAdapters narrows
	// the adapters (nil: all).
	Sync         bool
	SyncAdapters []string
	// TrustedProxies decides whose X-Forwarded-For is believed; nil trusts
	// no proxy.
	TrustedProxies func(address string) bool
	// AccessLog receives a record per request; nil writes none.
	AccessLog *AccessLog
	// Web is the dashboard: index.html at its root and the files it loads.
	Web fs.FS
	// Backend reads server state.
	Backend Backend
	// Log receives errors (never request bodies or credentials).
	Log *slog.Logger
	// Now is the clock (tests); nil is time.Now.
	Now func() time.Time
	// Built adds operations, by route pattern ("GET /v1/organizations"), to
	// the ones this build has, for tests of the stub's wiring. Each is
	// served by the generated strict handler: a pattern whose operation
	// this package does not implement answers 500 if it is ever reached.
	Built []string
}

// BuiltOperations are the /v1 operations this build serves, by the route
// pattern the generated server registers (method, "/v1" and the path).
// Every other operation answers the shared stub (NotImplementedYet).
var BuiltOperations = []string{
	"GET /v1/meta",
}

// Server is the handler.
type Server struct {
	opts      Options
	window    *requestWindow
	apiMux    *http.ServeMux
	patterns  []string // every operation the generated server registers
	stubbed   []string // the ones answered by the stub
	webIndex  []byte
	webExists bool
}

// New builds the handler.
func New(opts Options) (*Server, error) {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Backend == nil {
		return nil, errors.New("httpserver: no backend")
	}
	s := &Server{opts: opts, window: newRequestWindow(opts.Now)}
	built := map[string]bool{}
	for _, p := range append(append([]string{}, BuiltOperations...), opts.Built...) {
		built[p] = true
	}
	mux := &operationMux{ServeMux: http.NewServeMux(), built: built}
	strict := api.NewStrictHandlerWithOptions(&operations{s: s}, nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			s.opts.Log.Error("answering a request failed", "method", r.Method, "path", r.URL.Path, "requestId", requestIDOf(r), "error", err)
			writeError(w, r, http.StatusInternalServerError, "INTERNAL", "Internal error")
		},
	})
	api.HandlerWithOptions(strict, api.StdHTTPServerOptions{
		BaseURL:    "/v1",
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, r, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		},
	})
	for p := range built {
		if !mux.registered[p] {
			return nil, fmt.Errorf("httpserver: %s is not an operation of the OpenAPI document", p)
		}
	}
	// Anything else under /v1: no such route.
	mux.ServeMux.HandleFunc("/v1/", s.unknownV1)
	s.apiMux = mux.ServeMux
	s.patterns = mux.patterns
	s.stubbed = mux.stubbed
	if opts.Web != nil {
		if b, err := fs.ReadFile(opts.Web, "index.html"); err == nil {
			s.webIndex, s.webExists = b, true
		}
	}
	return s, nil
}

// Operations returns every /v1 route pattern the generated server has.
func (s *Server) Operations() []string { return append([]string{}, s.patterns...) }

// Stubbed returns the route patterns answered by the shared stub.
func (s *Server) Stubbed() []string { return append([]string{}, s.stubbed...) }

// operationMux takes the generated server's routes: an operation this
// build has gets its generated handler; every other one gets the stub,
// which answers before the generated wrapper binds parameters and before
// the strict handler decodes the body, so a request to it is never
// authenticated, validated, decoded or stored.
type operationMux struct {
	*http.ServeMux
	built      map[string]bool
	registered map[string]bool
	patterns   []string
	stubbed    []string
}

func (m *operationMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	if m.registered == nil {
		m.registered = map[string]bool{}
	}
	m.registered[pattern] = true
	m.patterns = append(m.patterns, pattern)
	if m.built[pattern] {
		m.ServeMux.HandleFunc(pattern, h)
		return
	}
	m.stubbed = append(m.stubbed, pattern)
	m.ServeMux.Handle(pattern, notBuilt(pattern))
}

// notBuilt is the shared stub: 501 NOT_IMPLEMENTED_YET, naming the
// operation's route.
func notBuilt(operation string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotImplemented, NotImplementedYet,
			operation+" is not built yet in this varlatchd (ADR-0059: the Go server is being written)")
	})
}

type ctxKey int

const requestIDKey ctxKey = 0

func requestIDOf(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey).(string)
	return id
}

// The paths the dashboard's nginx passed to varlatchd (apps/web/nginx.conf:
// a prefix match, so /authx and /v1x are varlatchd's too, and answer its
// 404), and the CLI download paths (exact).
var (
	apiPrefix = regexp.MustCompile(`^/(auth|v1|enroll|healthz|readyz|\.well-known)`)
	cliPaths  = map[string]bool{"/install.sh": true, "/install.ps1": true, "/cli/varlatch.cjs": true}
)

// ServeHTTP answers a request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	arrived := s.opts.Now()
	id := newRequestID()
	r = r.WithContext(context.WithValue(r.Context(), requestIDKey, id))
	rec := &recorder{ResponseWriter: w}
	p := r.URL.Path
	isAPI := apiPrefix.MatchString(p) || cliPaths[p]
	counted := isAPI && p != "/healthz" && p != "/readyz"
	// Every X-Forwarded-For line, joined as Node joins them: a proxy that
	// adds a line of its own instead of appending to the caller's is read
	// from the right like any other (the caller's forged line stays left).
	client := clientaddr.Of(r.RemoteAddr, headerValue(r, "X-Forwarded-For"), s.opts.TrustedProxies)
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				panic(v)
			}
			s.opts.Log.Error("a request handler panicked", "method", r.Method, "path", p, "requestId", id, "panic", fmt.Sprint(v))
			if rec.status == 0 {
				writeError(rec, r, http.StatusInternalServerError, "INTERNAL", "Internal error")
			}
		}
		s.log(r, rec, arrived, client, counted, id)
	}()
	if isAPI {
		rec.Header().Set("X-Request-Id", id)
		if r.ContentLength > MaxBody {
			writeError(rec, r, http.StatusRequestEntityTooLarge, "VALIDATION_FAILED", "Request body exceeds 1 MiB")
			return
		}
		r.Body = http.MaxBytesReader(rec, r.Body, MaxBody)
	}
	if counted {
		if ok, retry := s.window.admit(client); !ok {
			rec.Header().Set("Retry-After", retry)
			writeError(rec, r, http.StatusTooManyRequests, "PERMISSION_DENIED", RateExceededMessage)
			return
		}
	}
	if !isAPI {
		s.serveWeb(rec, r)
		return
	}
	s.serveAPI(rec, r)
}

func (s *Server) log(r *http.Request, rec *recorder, arrived time.Time, client string, counted bool, id string) {
	if s.opts.AccessLog == nil {
		return
	}
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	record := &AccessRecord{
		Arrived: arrived.UTC(), Completed: s.opts.Now().UTC(), Client: client,
		Method: r.Method, Path: r.URL.Path, Status: status, Bytes: rec.bytes, Window: counted, RequestID: id,
	}
	if v, ok := r.Header["X-Forwarded-For"]; ok {
		joined := strings.Join(v, ", ")
		record.ForwardedFor = &joined
	}
	s.opts.AccessLog.write(record)
}

func isGet(r *http.Request) bool { return r.Method == http.MethodGet || r.Method == http.MethodHead }

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/healthz" && isGet(r):
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case p == "/readyz" && isGet(r):
		s.readyz(w, r)
	case cliPaths[p] && isGet(r):
		// ADR-0058 Decision 3, off (VARLATCH_SERVE_CLI's default): the same
		// answer as a path that does not exist, as the TypeScript server's.
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not found"))
	case p == "/auth" || strings.HasPrefix(p, "/auth/"):
		// The browser's session endpoints (Better Auth's today; varlatchd's
		// own, ADR-0059 step 3.4).
		notBuilt("browser session endpoints "+r.Method+" "+p).ServeHTTP(w, r)
	case (p == "/enroll" || p == "/enroll.js") && isGet(r):
		// The enrollment page (step 3.4).
		notBuilt("GET "+p).ServeHTTP(w, r)
	case p == "/v1" || strings.HasPrefix(p, "/v1/"):
		// Hono matches the path as sent; Go's mux would redirect a path
		// that is not clean (// or a dot segment, a trailing slash). Such a
		// path names no route.
		if p == "/v1" || p != path.Clean(p) {
			s.unknownV1(w, r)
			return
		}
		s.apiMux.ServeHTTP(w, r)
	default:
		writeNotFound(w)
	}
}

// headerValue is a request header as Node and the Fetch Headers give it to
// the TypeScript server: every line of it, joined with ", " (Go's Get would
// return the first line only).
func headerValue(r *http.Request, name string) string {
	return strings.Join(r.Header.Values(name), ", ")
}

// authenticates reports whether the TypeScript server's bearer middleware
// (app.ts, app.use("/v1/*")) authenticates a request to path with method
// before routing it: every /v1 path but /v1/meta (any method), and the
// three operations that authenticate otherwise (the OIDC exchange and
// device sign-in's two CLI calls, POST only).
func authenticates(method, p string) bool {
	if p == "/v1/meta" {
		return false
	}
	if method == http.MethodPost && (p == "/v1/oidc/token" || p == "/v1/auth/device" || p == "/v1/auth/device/token") {
		return false
	}
	return true
}

// unknownV1 answers a /v1 route the OpenAPI document does not describe (a
// path it does not list, or a method that path does not have) in the
// TypeScript server's order: its authentication runs for every /v1 path
// (authenticates) before Hono's not-found answer. So without a bearer
// credential the answer is 401 AUTHENTICATION_REQUIRED, the error
// envelope; the plain-text 404 comes only for a request that passed
// authentication, or one to /v1/meta's path, which needs none.
//
// Known operations not built yet never get here: the stub answers them
// first, before any authentication (operationMux).
func (s *Server) unknownV1(w http.ResponseWriter, r *http.Request) {
	if authenticates(r.Method, r.URL.Path) && !strings.HasPrefix(headerValue(r, "Authorization"), "Bearer ") {
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Provide a Varlatch bearer credential")
		return
	}
	// TODO(ADR-0059 step 3.4): verify the presented credential first, as
	// the TypeScript server does, before this 404: an invalid, revoked or
	// expired one answers 401 INVALID_CREDENTIAL (with its
	// authentication.failed audit event), and an agent-run credential on a
	// method other than GET or HEAD answers 403 PERMISSION_DENIED. Until
	// credentials exist, any bearer is let through to the 404
	// (testdata/known-differences.json, goUntilStep3_4).
	writeNotFound(w)
}

type readiness struct {
	Ready  bool `json:"ready"`
	Checks struct {
		Schema       bool `json:"schema"`
		KEK          bool `json:"kek"`
		Installation bool `json:"installation"`
	} `json:"checks"`
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	var out readiness
	out.Checks.Schema, out.Checks.KEK, out.Checks.Installation = s.opts.Backend.Ready(r.Context())
	out.Ready = out.Checks.Schema && out.Checks.KEK && out.Checks.Installation
	status := http.StatusOK
	if !out.Ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, out)
}
