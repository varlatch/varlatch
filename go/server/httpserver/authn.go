// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/stages"
)

// The /v1 bearer authentication (app.ts, app.use("/v1/*"); ADR-0018 §6):
// every /v1 operation but the few that authenticate otherwise
// (authenticates) needs a bearer credential, resolved here before the
// operation runs. Cookies never authenticate /v1.

// StatusByCode is the HTTP status of each error code (http/support.ts
// STATUS_BY_CODE), and of the browser session's own codes.
var StatusByCode = map[string]int{
	"AUTHENTICATION_REQUIRED":       401,
	"INVALID_CREDENTIAL":            401,
	"PERMISSION_DENIED":             403,
	"RESOURCE_NOT_FOUND":            404,
	"VALIDATION_FAILED":             422,
	"VERSION_CONFLICT":              409,
	"ROTATION_IN_PROGRESS":          409,
	"IDEMPOTENCY_CONFLICT":          409,
	"CONTRACT_INVALID":              422,
	"CONTRACT_DRIFT":                409,
	"CONTRACT_MAPPING_UNRESOLVED":   422,
	"ENVIRONMENT_EXPIRED":           410,
	"TAILNET_CONTEXT_REQUIRED":      403,
	"TAILNET_CONTEXT_UNAVAILABLE":   403,
	"RATE_LIMITED":                  429,
	"MAINTENANCE":                   503,
	"INTERNAL":                      500,
	"STATE_CHANGED":                 409,
	"AUTHORIZATION_PENDING":         428,
	"SLOW_DOWN":                     429,
	"ACCESS_DENIED":                 403,
	"EXPIRED":                       410,
	"CONSUMED":                      410,
	"ORGANIZATION_DELETING":         409,
	"ORGANIZATION_DELETED":          410,
	"STEP_UP_REQUIRED":              403,
	"APPROVAL_INVALID":              409,
	"CONTROL_MODE_UNAVAILABLE":      422,
	"CREDENTIAL_LIFETIME_EXCEEDED":  422,
	"ORGANIZATION_FROZEN":           409,
	"PASSKEY_VERIFICATION_REQUIRED": 403,
	// Builds before the first Go release: an operation, or a path of one,
	// this build does not have yet (NotImplementedYet).
	"NOT_IMPLEMENTED_YET": 501,
	// The browser session's (/auth, not /v1).
	"PASSKEY_NOT_FOUND":          400,
	"PASSKEY_ALREADY_REGISTERED": 400,
}

// CredentialExpiresHeader names a machine credential's expiry in its last
// days (ADR-0054 Decision 8).
const CredentialExpiresHeader = "Varlatch-Credential-Expires"

type principalKey struct{}
type writerKey struct{}
type requestKey struct{}

// principalOf is the request's principal; nil for an operation that
// authenticates otherwise.
func principalOf(ctx context.Context) *auth.Principal {
	p, _ := ctx.Value(principalKey{}).(*auth.Principal)
	return p
}

// writerOf is the response writer of the request being served, for an
// operation to set a header before its response is written.
func writerOf(ctx context.Context) http.ResponseWriter {
	w, _ := ctx.Value(writerKey{}).(http.ResponseWriter)
	return w
}

// httpRequestOf is the request being served.
func httpRequestOf(ctx context.Context) *http.Request {
	r, _ := ctx.Value(requestKey{}).(*http.Request)
	return r
}

// withExchange puts the writer and the request in the request's context.
func withExchange(w http.ResponseWriter, r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), writerKey{}, w)
	r = r.WithContext(ctx)
	return r.WithContext(context.WithValue(r.Context(), requestKey{}, r))
}

// headerError is an error answered with extra response headers.
type headerError struct {
	err     error
	headers map[string]string
}

func (e *headerError) Error() string { return e.err.Error() }
func (e *headerError) Unwrap() error { return e.err }

// writeErrorDetails answers with the error envelope and its details, as
// errorBody does: code, message, requestId, then details when there are
// any.
func writeErrorDetails(w http.ResponseWriter, r *http.Request, status int, code, message string, details jsvalue.Object) {
	e := jsvalue.Object{{Key: "code", Value: code}, {Key: "message", Value: message}, {Key: "requestId", Value: requestIDOf(r)}}
	if details != nil {
		e = append(e, jsvalue.Member{Key: "details", Value: details})
	}
	writeJS(w, status, jsvalue.Object{{Key: "error", Value: e}})
}

// encoded is a body already written as JSON (an operation that times its
// encoding, server/stages).
type encoded []byte

// writeJS writes a JSON value as JSON.stringify does.
func writeJS(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if b, ok := body.(encoded); ok {
		_, _ = w.Write(b)
		return
	}
	_, _ = w.Write(jsvalue.Stringify(body))
}

// answerError answers an operation's error: a domain error with its code's
// status and envelope, an approval polled too soon as SLOW_DOWN with
// Retry-After, anything else as an internal error, logged. A request whose
// client went away is cancelled, and the work under it fails with
// context.Canceled: that is logged at debug level only. The TypeScript
// server never cancels a request's work and logs nothing for one.
func (s *Server) answerError(w http.ResponseWriter, r *http.Request, err error) {
	var he *headerError
	if errors.As(err, &he) {
		for k, v := range he.headers {
			w.Header().Set(k, v)
		}
	}
	var de *domainerr.Error
	var slow *auth.ErrSlowDown
	switch {
	case errors.As(err, &de):
		status, ok := StatusByCode[de.Code]
		if !ok {
			status = http.StatusInternalServerError
		}
		writeErrorDetails(w, r, status, de.Code, de.Message, de.Details)
	case errors.As(err, &slow):
		w.Header().Set("Retry-After", strconv.FormatInt(slow.Interval, 10))
		writeErrorDetails(w, r, http.StatusTooManyRequests, "SLOW_DOWN", slow.Error(), jsvalue.Object{{Key: "interval", Value: slow.Interval}})
	default:
		level := slog.LevelError
		if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
			level = slog.LevelDebug
		}
		s.opts.Log.Log(context.Background(), level, "answering a request failed", "method", r.Method, "path", r.URL.Path, "requestId", requestIDOf(r), "error", err)
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "Internal error")
	}
}

// authenticate resolves the request's bearer credential, answering the
// refusal itself when there is none or it does not authenticate: 401
// AUTHENTICATION_REQUIRED without one; 401 INVALID_CREDENTIAL, with its
// authentication.failed audit event, for one that is invalid, revoked,
// expired, exhausted or of a disabled identity; 403 PERMISSION_DENIED for
// an agent-run credential on anything but GET and HEAD (ADR-0023). A
// machine credential in its last 7 days names its expiry on the response,
// refusals included.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*auth.Principal, bool) {
	header := headerValue(r, "Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		writeError(w, r, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Provide a Varlatch bearer credential")
		return nil, false
	}
	if s.opts.Auth == nil {
		writeError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIAL", "Credential is invalid, revoked, or expired")
		return nil, false
	}
	p, reason, err := s.opts.Auth.Authenticate(r.Context(), strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
	if err != nil {
		s.answerError(w, r, err)
		return nil, false
	}
	if p == nil {
		if err := s.opts.Auth.RecordAuthenticationFailed(r.Context(), requestIDOf(r), reason); err != nil {
			s.answerError(w, r, err)
			return nil, false
		}
		writeError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIAL", "Credential is invalid, revoked, or expired")
		return nil, false
	}
	if notice := s.opts.Auth.ExpiresNotice(p); notice != "" {
		w.Header().Set(CredentialExpiresHeader, notice)
	}
	if p.Credential.Kind == auth.KindAgentRun && !isGet(r) {
		writeError(w, r, http.StatusForbidden, "PERMISSION_DENIED", "Agent-run credentials are read-only: this credential cannot perform write operations")
		return nil, false
	}
	return p, true
}

// withPrincipal runs the rest of the request as the principal: its
// identity and credential, and the client label, attribute every audit
// event its identity records (ADR-0016 §9, ADR-0045).
func withPrincipal(r *http.Request, p *auth.Principal) *http.Request {
	ua := headerValue(r, "User-Agent")
	var uap *string
	if _, ok := r.Header["User-Agent"]; ok {
		uap = &ua
	}
	ctx := context.WithValue(r.Context(), principalKey{}, p)
	a := audit.Attribution{IdentityID: p.Identity.ID, CredentialID: p.Credential.ID, Client: auth.ClientLabel(uap), Listener: "ordinary"}
	// And which listener it came in on, with the device or the reason
	// there is none (ADR-0046 Decision 8).
	if res, ok := resolutionOf(ctx); ok {
		a.Listener, a.Tailnet = "tailnet", res.JSValue()
	}
	ctx = audit.WithAttribution(ctx, a)
	return r.WithContext(ctx)
}

// noStore are the operations answered with Cache-Control: no-store
// whatever their outcome: device sign-in, passkey confirmation and step-up
// approvals.
var noStore = map[string]bool{
	"POST /v1/auth/device":                                true,
	"POST /v1/auth/device/token":                          true,
	"POST /v1/auth/device/lookup":                         true,
	"POST /v1/auth/device/approve":                        true,
	"POST /v1/me/passkeys/{passkey}/confirmation/options": true,
	"POST /v1/me/passkeys/{passkey}/confirmation":         true,
	"GET /v1/me/approvals/{approval}":                     true,
	"POST /v1/me/approvals/{approval}/options":            true,
	"POST /v1/me/approvals/{approval}/approve":            true,
	"POST /v1/me/approvals/{approval}/cancel":             true,
}

// ignoresQuery are the operations whose query the TypeScript server never
// reads: a query parameter, well formed or not, changes nothing.
var ignoresQuery = map[string]bool{
	"GET /v1/organizations": true,
}

// boundQuery is what the generated wrapper binds for an operation that
// reads its own query (readsItself) yet whose document requires a query
// parameter: a fixed value that satisfies the binder, while the operation
// reads the request's own query (keepRaw), as the TypeScript route does.
var boundQuery = map[string]string{
	"GET /v1/organizations/{org}/config-items": "q=_",
}

// builtOperation wraps a built /v1 operation's generated handler:
// authentication first (unless the operation authenticates otherwise),
// then the operation, with the writer and request in its context.
func (s *Server) builtOperation(pattern string, h http.HandlerFunc) http.HandlerFunc {
	method, route, _ := strings.Cut(pattern, " ")
	open := !authenticates(method, route)
	return func(w http.ResponseWriter, r *http.Request) {
		if noStore[pattern] {
			w.Header().Set("Cache-Control", "no-store")
		}
		if schema, ok := bodySchemas[pattern]; ok {
			r = readBody(r, schema)
		}
		if readsItself[pattern] {
			r = keepRaw(r)
		}
		if ignoresQuery[pattern] || readsItself[pattern] {
			u := *r.URL
			u.RawQuery = boundQuery[pattern]
			r.URL = &u
		}
		stages.Admitted(r.Context())
		if !open {
			m := stages.Start()
			p, ok := s.authenticate(w, r)
			stages.Since(r.Context(), "authentication", m)
			if !ok {
				return
			}
			r = withPrincipal(r, p)
		}
		h(w, withExchange(w, r))
	}
}

func retryAfter(seconds int64) map[string]string {
	return map[string]string{"Retry-After": strconv.FormatInt(seconds, 10)}
}
