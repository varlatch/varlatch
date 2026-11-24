// SPDX-License-Identifier: AGPL-3.0-or-later

package oauth

import (
	"cmp"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/varlatch/varlatch/go/server/oauth/oauthparams"
	"github.com/varlatch/varlatch/go/server/outbound"
)

// What is asked of a provider: its documents, its token endpoint, its
// revocation endpoint and its userinfo endpoint. Every request goes through
// the outbound policy (ADR-0057: the address decided when the connection
// opens, TLS verified, no proxy), follows no redirect, and is bounded in
// time and in what it reads. Nothing of an answer but fixed words, and what
// is checked to be a token or plain text, is kept: no error holds a URL's
// query, a body or an error_description, since any of them may hold a code
// or a token.

const (
	// CallTimeout bounds one request, its answer included.
	CallTimeout = 15 * time.Second
	// maxAnswer bounds what is read of an answer.
	maxAnswer = 128 << 10
	maxToken  = 16 << 10
)

// failure is a request that gave nothing.
type failure struct {
	// reason is a fixed word, or the server's error code (a short token).
	reason string
	// unsent is whether the request certainly did not reach the server, and
	// answered whether the server refused it.
	unsent, answered bool
	// status is the answer's, 0 for none.
	status     int
	retryAfter time.Duration
	refusal    *outbound.RefusedError
}

func (f *failure) Error() string { return "oauth: " + f.reason }

// answer is an answer read whole.
type answer struct {
	status int
	header http.Header
	body   []byte
}

func (s *Service) do(ctx context.Context, req *http.Request) (*answer, *failure) {
	var sent atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteHeaderField: func(string, []string) { sent.Store(true) }, WroteHeaders: func() { sent.Store(true) }})
	ctx, cancel := context.WithTimeout(ctx, cmp.Or(s.Timeout, CallTimeout))
	defer cancel()
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "application/json")
	// Nothing to unpack: what is read is what was sent.
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "varlatchd")
	client := s.Policy.Client(outbound.OAuth)
	// A redirect is an answer like any other, and no token's.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		f := &failure{reason: "unreachable", unsent: !sent.Load()}
		switch refusal := outbound.RefusalOf(err); {
		case refusal != nil:
			f.reason, f.refusal = "outbound-refused", refusal
		case ctx.Err() != nil:
			f.reason = "timeout"
		}
		return nil, f
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxAnswer+1))
	switch {
	case err != nil && ctx.Err() != nil:
		return nil, &failure{reason: "timeout", status: res.StatusCode}
	case err != nil:
		return nil, &failure{reason: "unreachable", status: res.StatusCode}
	case len(body) > maxAnswer:
		return nil, &failure{reason: "answer-too-large", status: res.StatusCode}
	}
	return &answer{status: res.StatusCode, header: res.Header, body: body}, nil
}

// object reads an answer's body as a JSON object, by its members' exact
// names.
func (a *answer) object() (map[string]json.RawMessage, bool) {
	var o map[string]json.RawMessage
	if err := json.Unmarshal(a.body, &o); err != nil || o == nil {
		return nil, false
	}
	return o, true
}

func text(o map[string]json.RawMessage, k string) string {
	var s string
	if json.Unmarshal(o[k], &s) != nil {
		return ""
	}
	return s
}

// after is the Retry-After of an answer, an hour at most.
func (a *answer) after(now time.Time) time.Duration {
	v := a.header.Get("Retry-After")
	if v == "" {
		return 0
	}
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, 0), time.Hour)
}

// errorCodes are the error codes that are repeated: OAuth's and OpenID
// Connect's own, and a few providers'. Any other is "provider-error": what a
// server writes there may be anything, a token it was sent included.
var errorCodes = map[string]bool{
	"invalid_request": true, "invalid_client": true, "invalid_grant": true, "unauthorized_client": true, "unsupported_grant_type": true, "invalid_scope": true,
	"access_denied": true, "unsupported_response_type": true, "server_error": true, "temporarily_unavailable": true, "unsupported_token_type": true,
	"interaction_required": true, "login_required": true, "consent_required": true, "account_selection_required": true, "invalid_target": true,
	"invalid_token": true, "insufficient_scope": true, "slow_down": true, "redirect_uri_mismatch": true, "admin_policy_enforced": true,
	"org_internal": true, "disabled_client": true, "deleted_client": true, "invalid_resource": true, "use_dpop_nonce": true, "invalid_dpop_proof": true,
}

// errorCode is a code as it is repeated; "" for none.
func errorCode(code string) string {
	if code == "" || errorCodes[code] {
		return code
	}
	return "provider-error"
}

// refusedAnswer is the failure of an answer that is no success.
func (s *Service) refusedAnswer(a *answer) *failure {
	f := &failure{status: a.status, retryAfter: a.after(s.now())}
	switch {
	case a.status >= 300 && a.status < 400:
		f.reason = "redirect"
	case a.status == http.StatusTooManyRequests:
		f.reason, f.answered = "rate-limited", true
	case a.status >= 500:
		f.reason = "server-error"
	default:
		f.reason = "bad-answer"
		if o, ok := a.object(); ok {
			if code := errorCode(text(o, "error")); code != "" {
				f.reason, f.answered = code, true
			}
		}
	}
	return f
}

// tokens is a token endpoint's answer.
type tokens struct {
	access, refresh, idToken string
	// lifetime and refreshLifetime are in seconds, 0 when the server says
	// nothing. unusable is why the access token is of no use, though the
	// server answered with success.
	lifetime, refreshLifetime int64
	scopes                    string
	scopesGiven               bool
	unusable                  string
	// at is when the request was sent: what expires counts from there.
	at time.Time
}

// tokenText is whether s is a token (RFC 6749 appendix A.12, without the
// space): text a header takes as it is.
func tokenText(s string) bool {
	if s == "" || len(s) > maxToken {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// seconds reads a number of seconds, also one written as text; ok is false
// when there is none.
func seconds(o map[string]json.RawMessage, k string) (n int64, ok bool) {
	raw, has := o[k]
	if !has || string(raw) == "null" {
		return 0, false
	}
	var f float64
	if json.Unmarshal(raw, &f) != nil {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return 0, true
		}
		var err error
		if f, err = strconv.ParseFloat(s, 64); err != nil {
			return 0, true
		}
	}
	if math.IsNaN(f) || f <= 0 {
		return 0, true
	}
	return int64(math.Min(f, oauthparams.MaxLifetimeSeconds)), true
}

// clientOf is who asks: the parameters, and the client secret.
type clientOf struct {
	p      oauthparams.Params
	secret string
}

// form posts a form to an endpoint as the client.
func (s *Service) form(ctx context.Context, c clientOf, endpoint string, v url.Values) (*answer, *failure) {
	if c.p.AuthMethod != oauthparams.AuthBasic {
		v.Set("client_id", c.p.ClientID)
	}
	if c.p.AuthMethod == oauthparams.AuthPost {
		v.Set("client_secret", c.secret)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, &failure{reason: "bad-endpoint", unsent: true}
	}
	if req.URL.Scheme != "https" {
		return nil, &failure{reason: "bad-endpoint", unsent: true}
	}
	// A POST with a body is never sent again by the transport itself.
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.p.AuthMethod == oauthparams.AuthBasic {
		// RFC 6749 section 2.3.1: both form-encoded first.
		req.SetBasicAuth(url.QueryEscape(c.p.ClientID), url.QueryEscape(c.secret))
	}
	return s.do(ctx, req)
}

// token asks the pinned token endpoint.
func (s *Service) token(ctx context.Context, c clientOf, v url.Values) (tokens, *failure) {
	at := s.now()
	a, f := s.form(ctx, c, c.p.TokenEndpoint, v)
	if f != nil {
		return tokens{}, f
	}
	if a.status != http.StatusOK {
		return tokens{}, s.refusedAnswer(a)
	}
	o, ok := a.object()
	if !ok {
		return tokens{}, &failure{reason: "bad-answer", status: a.status}
	}
	// Some servers refuse with 200.
	if code := errorCode(text(o, "error")); code != "" && text(o, "access_token") == "" {
		return tokens{}, &failure{reason: code, answered: true, status: a.status}
	}
	t := tokens{access: text(o, "access_token"), refresh: text(o, "refresh_token"), idToken: text(o, "id_token"), at: at}
	if !tokenText(t.refresh) {
		t.refresh = ""
	}
	if len(t.idToken) > maxToken {
		t.idToken = ""
	}
	if raw, has := o["scope"]; has {
		t.scopes, t.scopesGiven = text(o, "scope"), true
		var list []string
		if json.Unmarshal(raw, &list) == nil {
			t.scopes = strings.Join(list, " ")
		}
		if len(t.scopes) > 8192 || strings.ContainsFunc(t.scopes, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			t.scopes, t.scopesGiven = "", false
		}
	}
	// Nothing that was sent, and no refresh token, comes back as something
	// that is shown or handed out.
	sent := []string{t.refresh, c.secret, v.Get("refresh_token"), v.Get("code"), v.Get("code_verifier")}
	for _, x := range append(sent, t.access) {
		if x != "" && strings.Contains(t.scopes, x) {
			t.scopes, t.scopesGiven = "", false
		}
	}
	said := false
	if t.lifetime, said = seconds(o, "expires_in"); !said {
		t.lifetime = c.p.LifetimeSeconds
	}
	for _, k := range []string{"refresh_token_expires_in", "refresh_expires_in"} {
		if n, ok := seconds(o, k); ok && n > 0 {
			t.refreshLifetime = n
		}
	}
	switch kind := text(o, "token_type"); {
	case !tokenText(t.access):
		t.unusable = "no-access-token"
	case slices.ContainsFunc(sent, func(x string) bool { return len(x) > 3 && strings.Contains(t.access, x) }):
		t.unusable = "not-an-access-token"
	case kind != "" && !strings.EqualFold(kind, "bearer"):
		t.unusable = "token-type"
	case said && t.lifetime == 0:
		t.unusable = "already-expired"
	}
	return t, nil
}

// revoke asks the revocation endpoint (RFC 7009) to revoke a token.
func (s *Service) revoke(ctx context.Context, c clientOf, token, hint string) *failure {
	a, f := s.form(ctx, c, c.p.RevocationEndpoint, url.Values{"token": {token}, "token_type_hint": {hint}})
	if f != nil {
		return f
	}
	if a.status != http.StatusOK && a.status != http.StatusNoContent {
		return s.refusedAnswer(a)
	}
	return nil
}

// document gets a JSON document.
func (s *Service) document(ctx context.Context, raw, bearer string) (map[string]json.RawMessage, *failure) {
	a, f := s.get(ctx, raw, bearer)
	if f != nil {
		return nil, f
	}
	if a.status != http.StatusOK {
		return nil, s.refusedAnswer(a)
	}
	o, ok := a.object()
	if !ok {
		return nil, &failure{reason: "bad-answer", status: a.status}
	}
	return o, nil
}

func (s *Service) get(ctx context.Context, raw, bearer string) (*answer, *failure) {
	if oauthparams.CheckEndpoint(raw) != nil {
		return nil, &failure{reason: "bad-endpoint", unsent: true}
	}
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return nil, &failure{reason: "bad-endpoint", unsent: true}
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return s.do(ctx, req)
}

// discover reads an issuer's metadata: OpenID Connect's document, or RFC
// 8414's. The issuer in it has to be the one asked.
func (s *Service) discover(ctx context.Context, issuer string) (map[string]json.RawMessage, *failure) {
	o, f := s.document(ctx, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", "")
	if f != nil && f.status == http.StatusNotFound {
		u, err := url.Parse(issuer)
		if err != nil {
			return nil, f
		}
		u.Path, u.RawPath = "/.well-known/oauth-authorization-server"+strings.TrimSuffix(u.Path, "/"), ""
		o, f = s.document(ctx, u.String(), "")
	}
	if f != nil {
		return nil, f
	}
	if text(o, "issuer") != issuer {
		return nil, &failure{reason: "issuer-mismatch"}
	}
	return o, nil
}
