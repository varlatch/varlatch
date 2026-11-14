// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/server/api/browser"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// The browser session (ADR-0059 Decision 6; varlatchd-core decision 1):
// varlatchd's own endpoints for the dashboard and the enrollment page,
// served at the root under /auth, generated from the OpenAPI document's
// browser-session section (go/server/api/browser). /v1/meta lists
// auth.session, which is how the clients know to use them.
//
// Cookies: the session cookie holds the session's token (HttpOnly); the
// CSRF cookie holds the CSRF token, readable by the page. Both are
// SameSite=Strict and Path=/, Secure and with the __Host- prefix, except
// with a plain-http public URL on this machine (localhost, 127.0.0.1,
// [::1]), the plain-http localhost exception of ADR-0059 Decision 6.
//
// CSRF: every POST under /auth must come from the public URL's origin
// (the Origin header, exactly) and carry the CSRF cookie's value in the
// Varlatch-CSRF header (double submit). A cross-site page can make the
// browser send neither: the cookie is SameSite=Strict, and a custom header
// needs a CORS preflight varlatchd never grants. Checked before the body is
// read.

const (
	sessionCookie = "varlatch_session"
	csrfCookie    = "varlatch_csrf"
	// CSRFHeader carries the CSRF token on every POST under /auth.
	CSRFHeader = "Varlatch-CSRF"
)

// secureCookies is false only for a plain-http public URL on this machine
// (localhost, 127.0.0.1, [::1]), the one exception ADR-0059 Decision 6
// allows; the configuration refuses plain http anywhere else, and a
// handler built with one anyway still marks its cookies Secure.
func (s *Server) secureCookies() bool {
	u := s.opts.PublicURL
	return u == nil || u.Scheme != "http" || !config.LoopbackHost(u.Hostname())
}

func (s *Server) cookieName(base string) string {
	if s.secureCookies() {
		return "__Host-" + base
	}
	return base
}

func (s *Server) cookie(name, value string, maxAge time.Duration, httpOnly bool) *http.Cookie {
	c := &http.Cookie{
		Name: s.cookieName(name), Value: value, Path: "/", HttpOnly: httpOnly,
		Secure: s.secureCookies(), SameSite: http.SameSiteStrictMode,
	}
	switch {
	case maxAge > 0:
		c.MaxAge = int(maxAge.Seconds())
	case maxAge < 0:
		c.MaxAge = -1
	}
	return c
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// browserMux routes the browser session's operations: every POST passes
// the origin and CSRF checks before the generated handler binds anything.
type browserMux struct {
	*http.ServeMux
	s *Server
}

func (m browserMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	method, _, _ := strings.Cut(pattern, " ")
	m.ServeMux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if method == http.MethodPost && !m.s.sameOrigin(w, r) {
			return
		}
		h(w, withExchange(w, r))
	})
}

// sameOrigin is the CSRF check of a state-changing browser request.
func (s *Server) sameOrigin(w http.ResponseWriter, r *http.Request) bool {
	rp := s.opts.Auth.RP()
	origin := headerValue(r, "Origin")
	if rp == nil || origin == "" || origin != rp.Origin {
		writeErrorDetails(w, r, http.StatusForbidden, "PERMISSION_DENIED", "Cross-site request refused: it does not come from this installation's origin",
			jsvalue.Object{{Key: "reason", Value: "origin"}})
		return false
	}
	cookie, header := cookieValue(r, s.cookieName(csrfCookie)), headerValue(r, CSRFHeader)
	if cookie == "" || subtle.ConstantTimeCompare([]byte(cookie), []byte(header)) != 1 {
		writeErrorDetails(w, r, http.StatusForbidden, "PERMISSION_DENIED", "Cross-site request refused: the CSRF token is missing or does not match",
			jsvalue.Object{{Key: "reason", Value: "csrf"}})
		return false
	}
	return true
}

// newBrowserHandler builds the generated browser-session handler.
func (s *Server) newBrowserHandler() http.Handler {
	mux := browserMux{ServeMux: http.NewServeMux(), s: s}
	strict := browser.NewStrictHandlerWithOptions(&browserOps{s: s}, nil, browser.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, r, http.StatusUnprocessableEntity, "VALIDATION_FAILED", err.Error())
		},
		ResponseErrorHandlerFunc: s.answerError,
	})
	browser.HandlerWithOptions(strict, browser.StdHTTPServerOptions{
		BaseURL: "", BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, r, http.StatusUnprocessableEntity, "VALIDATION_FAILED", err.Error())
		},
	})
	// Anything else under /auth: no such route.
	mux.ServeMux.HandleFunc("/auth/", func(w http.ResponseWriter, _ *http.Request) { writeNotFound(w) })
	return mux
}

type browserOps struct{ s *Server }

// browserReply implements the browser operations' response interfaces.
type browserReply struct{ reply }

func (r browserReply) VisitGetBrowserSessionResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r browserReply) VisitStartPasskeySignInResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r browserReply) VisitFinishPasskeySignInResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r browserReply) VisitStartPasskeyRegistrationResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r browserReply) VisitFinishPasskeyRegistrationResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r browserReply) VisitSignOutResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r browserReply) VisitMintBrowserBearerResponse(w http.ResponseWriter) error {
	return r.visit(w)
}

func (o *browserOps) auth() *auth.Service { return o.s.opts.Auth }

// session is the request's live session, or nil.
func (o *browserOps) session(ctx context.Context) (*auth.Session, error) {
	r := httpRequestOf(ctx)
	return o.auth().SessionOf(ctx, cookieValue(r, o.s.cookieName(sessionCookie)))
}

// binding is the ceremony binding of the request's browser: its CSRF
// cookie (already checked against the header).
func (o *browserOps) binding(ctx context.Context) string {
	return auth.CSRFBinding(cookieValue(httpRequestOf(ctx), o.s.cookieName(csrfCookie)))
}

func (o *browserOps) setSession(ctx context.Context, started *auth.Started) {
	w := writerOf(ctx)
	http.SetCookie(w, o.s.cookie(sessionCookie, started.SessionToken, auth.SessionLifetime, true))
}

func clientIP(ctx context.Context) string {
	if r := httpRequestOf(ctx); r != nil {
		if c, ok := r.Context().Value(clientKey{}).(string); ok {
			return c
		}
	}
	return ""
}

func userAgentString(ctx context.Context) string {
	if ua := userAgentOf(ctx); ua != nil {
		return *ua
	}
	return ""
}

// GetBrowserSession is GET /auth/session: the session, if any, and the
// CSRF token, set as the cookie when the browser has none.
func (o *browserOps) GetBrowserSession(ctx context.Context, _ browser.GetBrowserSessionRequestObject) (browser.GetBrowserSessionResponseObject, error) {
	r := httpRequestOf(ctx)
	token := cookieValue(r, o.s.cookieName(csrfCookie))
	if len(token) < 32 || len(token) > 200 {
		token = auth.NewCSRFToken()
		http.SetCookie(writerOf(ctx), o.s.cookie(csrfCookie, token, 0, false))
	}
	session, err := o.session(ctx)
	if err != nil {
		return nil, err
	}
	var identity, expires any
	if session != nil {
		identity, expires = session.IdentityID, iso(session.ExpiresAt)
		// The cookie lives as long as the session, which use extends.
		if remaining := time.Duration(session.ExpiresAt-time.Now().UnixMicro()) * time.Microsecond; remaining > time.Second {
			http.SetCookie(writerOf(ctx), o.s.cookie(sessionCookie, cookieValue(r, o.s.cookieName(sessionCookie)), remaining, true))
		}
	}
	return browserReply{ok(jsvalue.Object{{Key: "csrfToken", Value: token}, {Key: "identityId", Value: identity}, {Key: "expiresAt", Value: expires}})}, nil
}

func publicKey(v any) (browserReply, error) {
	pk, err := optionsJS(v)
	if err != nil {
		return browserReply{}, err
	}
	return browserReply{ok(jsvalue.Object{{Key: "publicKey", Value: pk}})}, nil
}

// StartPasskeySignIn is POST /auth/passkey/sign-in/options.
func (o *browserOps) StartPasskeySignIn(ctx context.Context, _ browser.StartPasskeySignInRequestObject) (browser.StartPasskeySignInResponseObject, error) {
	options, err := o.auth().SignInOptions(o.binding(ctx))
	if err != nil {
		return nil, err
	}
	return publicKey(options)
}

func rawBody(m map[string]any) (json.RawMessage, error) {
	if m == nil {
		return nil, domainerr.New("VALIDATION_FAILED", "response: Invalid input: expected record, received undefined")
	}
	return rawAssertion(m), nil
}

// FinishPasskeySignIn is POST /auth/passkey/sign-in.
func (o *browserOps) FinishPasskeySignIn(ctx context.Context, req browser.FinishPasskeySignInRequestObject) (browser.FinishPasskeySignInResponseObject, error) {
	var m map[string]any
	if req.Body != nil {
		m = req.Body.Response
	}
	response, err := rawBody(m)
	if err != nil {
		return nil, err
	}
	started, err := o.auth().SignIn(ctx, o.binding(ctx), response, clientIP(ctx), userAgentString(ctx))
	if err != nil {
		return nil, err
	}
	o.setSession(ctx, &started)
	return browserReply{ok(jsvalue.Object{{Key: "identityId", Value: started.IdentityID}, {Key: "expiresAt", Value: iso(started.ExpiresAt)}})}, nil
}

// StartPasskeyRegistration is POST /auth/passkey/registration/options.
func (o *browserOps) StartPasskeyRegistration(ctx context.Context, req browser.StartPasskeyRegistrationRequestObject) (browser.StartPasskeyRegistrationResponseObject, error) {
	token := ""
	if req.Body != nil && req.Body.Token != nil {
		token = *req.Body.Token
	}
	var session *auth.Session
	if token == "" {
		var err error
		if session, err = o.session(ctx); err != nil {
			return nil, err
		}
	}
	options, err := o.auth().RegistrationOptions(ctx, o.binding(ctx), token, session)
	if err != nil {
		return nil, err
	}
	return publicKey(options)
}

// FinishPasskeyRegistration is POST /auth/passkey/registration.
func (o *browserOps) FinishPasskeyRegistration(ctx context.Context, req browser.FinishPasskeyRegistrationRequestObject) (browser.FinishPasskeyRegistrationResponseObject, error) {
	var m map[string]any
	name := ""
	if req.Body != nil {
		m = req.Body.Response
		if req.Body.Name != nil {
			if err := checkName(req.Body.Name); err != nil {
				return nil, err
			}
			name = *req.Body.Name
		}
	}
	response, err := rawBody(m)
	if err != nil {
		return nil, err
	}
	session, err := o.session(ctx)
	if err != nil {
		return nil, err
	}
	reg, err := o.auth().Register(ctx, o.binding(ctx), session, response, name, clientIP(ctx), userAgentString(ctx))
	if err != nil {
		return nil, err
	}
	if reg.Session != nil {
		o.setSession(ctx, reg.Session)
	}
	return browserReply{ok(jsvalue.Object{{Key: "passkeyId", Value: reg.PasskeyID}, {Key: "identityId", Value: reg.IdentityID}, {Key: "signedIn", Value: reg.Session != nil}})}, nil
}

// SignOut is POST /auth/sign-out.
func (o *browserOps) SignOut(ctx context.Context, _ browser.SignOutRequestObject) (browser.SignOutResponseObject, error) {
	r := httpRequestOf(ctx)
	if err := o.auth().EndSession(ctx, cookieValue(r, o.s.cookieName(sessionCookie))); err != nil {
		return nil, err
	}
	http.SetCookie(writerOf(ctx), o.s.cookie(sessionCookie, "", -1, true))
	return browserReply{reply{status: http.StatusNoContent}}, nil
}

// MintBrowserBearer is POST /auth/varlatch-token.
func (o *browserOps) MintBrowserBearer(ctx context.Context, _ browser.MintBrowserBearerRequestObject) (browser.MintBrowserBearerResponseObject, error) {
	session, err := o.session(ctx)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, domainerr.New("AUTHENTICATION_REQUIRED", "No authenticated session")
	}
	bearer, err := o.auth().MintBearer(ctx, session, auth.ClientLabel(userAgentOf(ctx)))
	if err != nil {
		return nil, err
	}
	return browserReply{ok(jsvalue.Object{{Key: "token", Value: bearer.Token}, {Key: "identityId", Value: bearer.IdentityID}, {Key: "expiresAt", Value: iso(bearer.ExpiresAt)}})}, nil
}
