// SPDX-License-Identifier: AGPL-3.0-or-later

package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/oauth/oauthparams"
	"github.com/varlatch/varlatch/go/server/oidc"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// Connecting in the browser: the authorization code grant with PKCE (RFC
// 7636, S256 only), as RFC 9700 asks for it.
//
//  1. Start: a person, in their browser session, gets the URL of the
//     provider's authorization endpoint. The state (its hash), the nonce
//     (its hash), the PKCE verifier (sealed) and the redirect URI are kept
//     for ten minutes, for this person in this session and this connection.
//  2. The provider sends the browser to the dashboard's page for that
//     provider's token endpoint. The page takes the code out of its address
//     and sends it on (Complete), with the URI it was sent to.
//  3. Complete: the state is taken (once, whatever becomes of it), the
//     redirect URI and the issuer (RFC 9207) are checked, and then the code
//     is exchanged at the connection's pinned token endpoint, the ID token
//     verified, and the account compared with the one before.

// AuthorizationTTL is how long an authorization may take, and maxPending how
// many a person may have begun.
const (
	AuthorizationTTL = 10 * time.Minute
	maxPending       = 20
)

// session is the browser session of who asks; only one connects.
func session(p *auth.Principal) (string, error) {
	if p.Identity.Kind != "human" || p.Credential.Kind != auth.KindBrowser || p.Credential.AuthSessionID == nil {
		return "", &domainerr.Error{Code: "PERMISSION_DENIED", Message: "An OAuth connection is connected by a person, in their dashboard session",
			Details: jsvalue.Object{{Key: "reason", Value: "browser-session-required"}}}
	}
	return *p.Credential.AuthSessionID, nil
}

// Start begins an authorization: the URL to send the browser to.
func (s *Service) Start(ctx context.Context, req Request, item string, accountChange bool, base *url.URL) (jsvalue.Object, []auth.PendingReport, error) {
	sid, err := session(req.Principal)
	if err != nil {
		return nil, nil, err
	}
	state, nonce, verifier := random(), random(), random()
	stateHash := hash(state)
	var out jsvalue.Object
	var reports []auth.PendingReport
	err = s.Writer.Job(ctx, req.gates(), func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, req.scope("")); err != nil {
			return err
		}
		r, err := find(ctx, tx, req.Target.Env.ID, item)
		if err != nil {
			return err
		}
		if reports, err = write.Checkpoint(ctx, tx, req.Principal, req.Target.OrganizationID); err != nil {
			return err
		}
		if r.params.Grant != oauthparams.AuthorizationCode {
			return &domainerr.Error{Code: "VALIDATION_FAILED", Message: "This OAuth connection is the client's own: nobody consents to it",
				Details: jsvalue.Object{{Key: "reason", Value: "client-credentials"}}}
		}
		now, q := s.now(), query.New(tx)
		if err := q.PruneOAuthAuthorizations(ctx, now.UnixMicro()); err != nil {
			return err
		}
		n, err := q.CountOAuthAuthorizations(ctx, query.CountOAuthAuthorizationsParams{IdentityID: req.Principal.Identity.ID, ExpiresAt: now.UnixMicro()})
		if err != nil {
			return err
		}
		if n >= maxPending {
			return domainerr.New("RATE_LIMITED", "Too many authorizations are in progress: finish one, or wait ten minutes")
		}
		kek, err := values.OrgKEK(ctx, tx, s.RootKEK, r.OrganizationID)
		if err != nil {
			return err
		}
		defer clear(kek)
		kept, err := seal(kek, envelope.OAuthVerifierContext(r.OrganizationID, stateHash), verifier)
		if err != nil {
			return err
		}
		redirect := RedirectURI(base, r.params)
		expires := now.Add(AuthorizationTTL)
		change := int64(0)
		if accountChange {
			change = 1
		}
		if err := q.InsertOAuthAuthorization(ctx, query.InsertOAuthAuthorizationParams{
			StateHash: stateHash, OrganizationID: r.OrganizationID, ValueID: r.ValueID, VersionID: r.VersionID,
			IdentityID: req.Principal.Identity.ID, AuthSessionID: sid, NonceHash: hash(nonce), Verifier: kept.String,
			RedirectUri: redirect, AccountChange: change, CreatedAt: now.UnixMicro(), ExpiresAt: expires.UnixMicro(),
		}); err != nil {
			return err
		}
		to, err := url.Parse(r.params.AuthorizationEndpoint)
		if err != nil {
			return err
		}
		v := to.Query()
		for _, x := range r.params.AuthorizationParams {
			v.Set(x.Name, x.Value)
		}
		v.Set("response_type", "code")
		v.Set("client_id", r.params.ClientID)
		v.Set("redirect_uri", redirect)
		if len(r.params.Scopes) > 0 {
			v.Set("scope", strings.Join(r.params.Scopes, " "))
		}
		v.Set("state", state)
		if r.params.OpenID() {
			v.Set("nonce", nonce)
		}
		sum := sha256.Sum256([]byte(verifier))
		v.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
		v.Set("code_challenge_method", "S256")
		// The same parameter is never sent twice, whatever the endpoint had.
		to.RawQuery = v.Encode()
		out = jsvalue.Object{{Key: "authorizationUrl", Value: to.String()}, {Key: "state", Value: state}, {Key: "redirectUri", Value: redirect},
			{Key: "expiresAt", Value: audit.ISOTime(expires.UnixMicro())}}
		return nil
	})
	return out, reports, err
}

// Answer is what the provider sent the browser back with.
type Answer struct{ State, Code, Error, Issuer, RedirectURI string }

// outcome is what became of an authorization.
type outcome struct {
	// kind is "connected", "refused" (the answer does not fit what was asked
	// for) or "failed" (the provider said no, or nothing).
	kind, reason string
	account      *account
	before       *account
	tokens       tokens
}

var outcomeMessages = map[string]string{
	"redirect-uri-mismatch":   "The browser came back to another address than the one it was sent to: nothing was exchanged.",
	"issuer-missing":          "The provider says it names itself when it sends the browser back, and this answer did not: nothing was exchanged.",
	"issuer-mismatch":         "The answer is another provider's than the one asked: nothing was exchanged.",
	"no-code":                 "The answer holds no authorization code.",
	"access-denied":           "Access was not given at the provider.",
	"no-id-token":             "The provider gave no ID token, so whose account it is cannot be known. Nothing was kept.",
	"id-token":                "The provider's ID token is not valid. Nothing was kept.",
	"nonce-mismatch":          "The provider's ID token is another authorization's. Nothing was kept.",
	"audience-mismatch":       "The provider's ID token is for another client. Nothing was kept.",
	"userinfo":                "The provider's userinfo endpoint gave no account. Nothing was kept.",
	"account-mismatch":        "This is another account than the one the connection was connected to. Nothing was kept: connect with that account, or confirm the change.",
	"account-unknown":         "The provider does not say whose account it is, and the connection was connected to one that is known. Nothing was kept: confirm the change to connect it anyway.",
	"no-access-token":         "The provider gave no access token.",
	"token-type":              "The provider gave a token of a type other than Bearer, which Varlatch does not use. Nothing was kept.",
	"not-an-access-token":     "The provider gave back something it was sent, or the refresh token, as the access token. Nothing was kept.",
	"provider-error":          "The provider answered with an error of its own.",
	"already-expired":         "The provider gave an access token that had expired. Nothing was kept.",
	"invalid_client":          "The provider does not accept the client ID and secret.",
	"invalid_grant":           "The provider does not accept the authorization code: it was used or had expired. Connect again.",
	"outbound-refused":        "This installation's outbound policy refuses the provider's endpoint.",
	"timeout":                 "The provider did not answer in time. Connect again.",
	"unreachable":             "The provider could not be reached. Connect again.",
	"answer-too-large":        "The provider's answer was larger than Varlatch reads.",
	"redirect":                "The provider's token endpoint answered with a redirect, which is not followed.",
	"bad-answer":              "The provider's answer could not be read.",
	"unauthorized_client":     "The provider does not let this client use this grant.",
	"invalid_scope":           "The provider does not know a scope that was asked for.",
	"redirect_uri_mismatch":   "The provider does not know this redirect URI: register it there.",
	"invalid_request":         "The provider did not accept the request.",
	"temporarily_unavailable": "The provider is temporarily unavailable. Connect again later.",
}

func messageOf(reason string) string {
	if m, ok := outcomeMessages[reason]; ok {
		return m
	}
	return "The provider answered with an error (" + reason + ")."
}

// Complete takes the provider's answer.
func (s *Service) Complete(ctx context.Context, req Request, item string, in Answer, base *url.URL) (jsvalue.Object, []auth.PendingReport, error) {
	sid, err := session(req.Principal)
	if err != nil {
		return nil, nil, err
	}
	seen, err := find(ctx, s.store().Reader(), req.Target.Env.ID, item)
	if err != nil {
		return nil, nil, err
	}
	// The state, once: gone before anything is asked of the provider, and for
	// nobody but the person and the session that began it.
	var begun query.OauthAuthorization
	stateHash := hash(in.State)
	err = s.Writer.Job(ctx, req.gates(), func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, req.scope("")); err != nil {
			return err
		}
		if _, err := write.Checkpoint(ctx, tx, req.Principal, req.Target.OrganizationID); err != nil {
			return err
		}
		var err error
		begun, err = query.New(tx).TakeOAuthAuthorization(ctx, query.TakeOAuthAuthorizationParams{
			StateHash: stateHash, OrganizationID: req.Target.OrganizationID, IdentityID: req.Principal.Identity.ID, AuthSessionID: sid})
		if errors.Is(err, sql.ErrNoRows) {
			return domainerr.New("RESOURCE_NOT_FOUND", "No authorization you began in this session has this state")
		}
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	if begun.ExpiresAt <= s.now().UnixMicro() {
		return nil, nil, domainerr.New("EXPIRED", "This authorization expired. Connect again.")
	}
	if begun.ValueID != seen.ValueID || begun.VersionID != seen.VersionID {
		return nil, nil, domainerr.New("STATE_CHANGED", "The OAuth connection changed since this authorization began. Connect again.")
	}
	if o := checkAnswer(seen.params, begun, in); o != nil {
		return s.notConnected(ctx, req, seen, *o, base)
	}
	var connected jsvalue.Object
	var r *row
	var c clientOf
	var verifier string
	out, reports, err := write.RunEffect(ctx, s.Writer, write.Effect[outcome, outcome]{
		OrganizationID: req.Target.OrganizationID, People: []write.Gate{write.Person(req.Principal.Identity.ID, write.Shared)},
		Resources: []write.Gate{gate(seen.ValueID)}, Principal: req.Principal,
		Check: func(ctx context.Context, tx *sql.Tx) error {
			var err error
			if err = write.CheckLive(ctx, tx, req.scope("")); err != nil {
				return err
			}
			if r, err = find(ctx, tx, req.Target.Env.ID, item); err != nil {
				return err
			}
			if r.ValueID != begun.ValueID || r.VersionID != begun.VersionID {
				return domainerr.New("STATE_CHANGED", "The OAuth connection changed since this authorization began. Connect again.")
			}
			kek, err := values.OrgKEK(ctx, tx, s.RootKEK, r.OrganizationID)
			if err != nil {
				return err
			}
			defer clear(kek)
			if c, err = r.client(kek); err != nil {
				return err
			}
			verifier, err = open(kek, envelope.OAuthVerifierContext(r.OrganizationID, stateHash), nullStr(begun.Verifier))
			return err
		},
		Call: func(ctx context.Context) (outcome, error) {
			return s.exchange(ctx, req, r, c, begun, in.Code, verifier), write.EffectAlive(ctx)
		},
		Final: func(ctx context.Context, tx *storage.Tx, o outcome) (outcome, error) {
			if o.kind != "connected" {
				return o, s.recordNotConnected(ctx, tx, req, r, o)
			}
			now, err := find(ctx, tx, req.Target.Env.ID, item)
			if err != nil {
				return o, err
			}
			if now.VersionID != r.VersionID || now.OauthConnection.Generation != r.OauthConnection.Generation {
				return o, domainerr.New("STATE_CHANGED", "The OAuth connection changed since this authorization began. Connect again.")
			}
			if err := s.storeConsent(ctx, tx, req, now, o); err != nil {
				return o, err
			}
			if now, err = find(ctx, tx, req.Target.Env.ID, item); err != nil {
				return o, err
			}
			connected = s.js(now, base)
			return o, nil
		},
	})
	if err != nil {
		return nil, nil, err
	}
	return outcomeJS(out, connected), reports, nil
}

// checkAnswer is what is wrong with an answer before anything is exchanged.
func checkAnswer(p oauthparams.Params, begun query.OauthAuthorization, in Answer) *outcome {
	refuse := func(reason string) *outcome { return &outcome{kind: "refused", reason: reason} }
	switch {
	case in.RedirectURI != begun.RedirectUri:
		return refuse("redirect-uri-mismatch")
	case in.Issuer == "" && p.IssParameter:
		return refuse("issuer-missing")
	case in.Issuer != "" && p.Issuer != "" && in.Issuer != p.Issuer:
		return refuse("issuer-mismatch")
	case in.Error != "":
		reason := errorCode(in.Error)
		if reason == "access_denied" {
			reason = "access-denied"
		}
		return &outcome{kind: "failed", reason: reason}
	case in.Code == "":
		return refuse("no-code")
	}
	return nil
}

// exchange exchanges the code and finds out whose account it is.
func (s *Service) exchange(ctx context.Context, req Request, r *row, c clientOf, begun query.OauthAuthorization, code, verifier string) outcome {
	t, f := s.token(ctx, c, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {begun.RedirectUri}, "code_verifier": {verifier}})
	if f != nil {
		s.noteRefusal(ctx, r, req, f)
		return outcome{kind: "failed", reason: f.reason}
	}
	if t.unusable != "" {
		return outcome{kind: "refused", reason: t.unusable}
	}
	o := outcome{kind: "connected", tokens: t}
	acct, reason := s.accountOf(ctx, r, req, t, begun.NonceHash)
	if reason != "" {
		return outcome{kind: "refused", reason: reason}
	}
	// Nor is a token somebody's name.
	if acct != nil {
		for _, x := range []string{t.access, t.refresh, c.secret, code, verifier} {
			if x != "" && (strings.Contains(acct.id, x) || strings.Contains(acct.label, x)) {
				return outcome{kind: "refused", reason: "bad-answer"}
			}
		}
	}
	o.account = acct
	if before := r.OauthConnection; before.Account != "" {
		o.before = &account{before.Account, before.AccountLabel}
		switch {
		case begun.AccountChange == 1:
		case acct == nil:
			return outcome{kind: "refused", reason: "account-unknown", before: o.before}
		case acct.id != before.Account:
			return outcome{kind: "refused", reason: "account-mismatch", account: acct, before: o.before}
		}
	}
	return o
}

// accountOf is whose account the tokens are for: the verified ID token's
// subject, else the userinfo endpoint's; nil when the provider has neither.
func (s *Service) accountOf(ctx context.Context, r *row, req Request, t tokens, nonceHash string) (*account, string) {
	var acct *account
	if r.params.OpenID() {
		if t.idToken == "" {
			return nil, "no-id-token"
		}
		claims, reason := s.idToken(ctx, r, req, t.idToken, nonceHash)
		if reason != "" {
			return nil, reason
		}
		acct = accountIn(claims, "sub")
	}
	if r.params.UserinfoEndpoint == "" || acct != nil && acct.label != acct.id {
		return acct, ""
	}
	o, f := s.document(ctx, r.params.UserinfoEndpoint, t.access)
	if f != nil {
		s.noteRefusal(ctx, r, req, f)
		if acct != nil {
			return acct, "" // known by its ID: only its name is missing
		}
		return nil, "userinfo"
	}
	claims := jsvalue.Object{}
	for _, k := range []string{"sub", "id", "email", "preferred_username", "login", "name"} {
		if raw, ok := o[k]; ok {
			var v any
			if json.Unmarshal(raw, &v) == nil {
				claims = append(claims, jsvalue.Member{Key: k, Value: v})
			}
		}
	}
	told := accountIn(claims, "sub", "id")
	switch {
	case acct == nil && told == nil:
		return nil, "userinfo"
	case acct == nil:
		return told, ""
	case told == nil || told.id != acct.id:
		return acct, "" // OpenID Connect section 5.3.2: not this account's
	}
	return told, ""
}

// shown is text a provider gave, as people see it.
func shown(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 320 || !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool {
		return r < 0x20 || r >= 0x7f && r < 0xa0 || r >= 0x200b && r <= 0x200f || r >= 0x2028 && r <= 0x202e || r >= 0x2066 && r <= 0x2069 || r == 0xfeff
	}) {
		return ""
	}
	return s
}

// accountIn reads an account from claims: the first of idClaims as its ID.
func accountIn(claims jsvalue.Object, idClaims ...string) *account {
	get := func(k string) string {
		v, _ := claims.Get(k)
		switch x := v.(type) {
		case string:
			return shown(x)
		case float64:
			if x == float64(int64(x)) {
				b, _ := json.Marshal(int64(x))
				return string(b)
			}
		}
		return ""
	}
	a := &account{}
	for _, k := range idClaims {
		if a.id = get(k); a.id != "" {
			break
		}
	}
	if a.id == "" {
		return nil
	}
	for _, k := range []string{"email", "preferred_username", "login", "name"} {
		if a.label = get(k); a.label != "" {
			return a
		}
	}
	a.label = a.id
	return a
}

// idToken verifies an ID token (OpenID Connect section 3.1.3.7) against the
// issuer's keys, at the pinned address: its signature, issuer and times, then
// that it is for this client and this authorization.
func (s *Service) idToken(ctx context.Context, r *row, req Request, raw, nonceHash string) (jsvalue.Object, string) {
	var refusal *failure
	v := &oidc.Verifier{Now: s.Now, Fetch: func(_ context.Context, what string) (*oidc.Response, error) {
		if what == strings.TrimSuffix(r.params.Issuer, "/")+"/.well-known/openid-configuration" {
			// What was read when the connection was made, not what the issuer
			// would say now.
			doc, err := json.Marshal(map[string]string{"issuer": r.params.Issuer, "jwks_uri": r.params.JWKSURI})
			return &oidc.Response{Status: 200, Body: doc}, err
		}
		a, f := s.get(ctx, what, "")
		if f != nil {
			refusal = f
			return nil, f
		}
		return &oidc.Response{Status: a.status, Body: a.body}, nil
	}}
	claims, err := v.Verify(raw, r.params.Issuer)
	s.noteRefusal(ctx, r, req, refusal)
	if err != nil {
		return nil, "id-token"
	}
	if !audienceIs(claims, r.params.ClientID) {
		return nil, "audience-mismatch"
	}
	nonce, _ := claims.Get("nonce")
	n, _ := nonce.(string)
	if subtle.ConstantTimeCompare([]byte(hash(n)), []byte(nonceHash)) != 1 {
		return nil, "nonce-mismatch"
	}
	return claims, ""
}

// audienceIs is whether an ID token is for a client, and for it alone or
// made for it (azp).
func audienceIs(claims jsvalue.Object, clientID string) bool {
	aud, _ := claims.Get("aud")
	azp, hasAzp := claims.Get("azp")
	if hasAzp && azp != any(clientID) {
		return false
	}
	switch a := aud.(type) {
	case string:
		return a == clientID
	case []any:
		for _, x := range a {
			if x == any(clientID) {
				return len(a) == 1 || hasAzp
			}
		}
	}
	return false
}

// storeConsent stores the tokens of a consent, in its job, with what came before
// gone in the same one.
func (s *Service) storeConsent(ctx context.Context, tx *storage.Tx, req Request, r *row, o outcome) error {
	kek, err := values.OrgKEK(ctx, tx, s.RootKEK, r.OrganizationID)
	if err != nil {
		return err
	}
	defer clear(kek)
	var acct account
	if o.account != nil {
		acct = *o.account
	}
	c := r.OauthConnection
	sl, err := r.sealTokens(kek, o.tokens, o.tokens.refresh, c.Generation+1, acct.id)
	if err != nil {
		return err
	}
	granted := sql.NullString{String: o.tokens.scopes, Valid: o.tokens.scopesGiven}
	n, err := query.New(tx).ConnectOAuth(ctx, query.ConnectOAuthParams{
		AccessToken: sl.access, AccessExpiresAt: sl.expiresAt, AccessLifetime: sl.lifetime,
		RefreshToken: sl.refresh, RefreshExpiresAt: sl.refreshExpires, KeepaliveAt: sl.keptTo, GrantedScopes: granted,
		Account: acct.id, AccountLabel: acct.label, ConnectedBy: nullStr(req.Principal.Identity.ID), Now: nullInt(s.now().UnixMicro()),
		ValueID: r.ValueID, VersionID: r.VersionID, Generation: c.Generation,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return domainerr.New("STATE_CHANGED", "The OAuth connection changed since this authorization began. Connect again.")
	}
	typ, what := "sync.connection_created", "connected"
	if c.ConnectedAt.Valid {
		typ, what = "sync.connection_credential_replaced", "reconnected"
	}
	md := jsvalue.Object{{Key: "account", Value: acct.label}, {Key: "refreshToken", Value: sl.refresh.Valid}}
	if o.before != nil && o.before.id != acct.id {
		md = append(md, jsvalue.Member{Key: "accountChanged", Value: true}, jsvalue.Member{Key: "previousAccount", Value: o.before.label})
	}
	if m := missing(r.params.Scopes, granted); len(m) > 0 {
		md = append(md, jsvalue.Member{Key: "missingScopes", Value: strings.Join(m, " ")})
	}
	return s.record(ctx, tx, r, typ, audit.Info, req, what, md)
}

// notConnected answers an authorization that ended before an exchange.
func (s *Service) notConnected(ctx context.Context, req Request, r *row, o outcome, _ *url.URL) (jsvalue.Object, []auth.PendingReport, error) {
	if err := s.store().Write(ctx, func(tx *storage.Tx) error { return s.recordNotConnected(ctx, tx, req, r, o) }); err != nil {
		return nil, nil, err
	}
	return outcomeJS(o, nil), nil, nil
}

func (s *Service) recordNotConnected(ctx context.Context, tx query.DBTX, req Request, r *row, o outcome) error {
	md := jsvalue.Object{{Key: "reason", Value: o.reason}}
	if o.account != nil {
		md = append(md, jsvalue.Member{Key: "account", Value: o.account.label})
	}
	if o.before != nil {
		md = append(md, jsvalue.Member{Key: "previousAccount", Value: o.before.label})
	}
	return s.record(ctx, tx, r, "sync.connection_checked", audit.Deny, req, "not-connected", md)
}

func outcomeJS(o outcome, connection jsvalue.Object) jsvalue.Object {
	out := jsvalue.Object{{Key: "outcome", Value: o.kind}}
	if o.kind == "connected" {
		return append(out, jsvalue.Member{Key: "connection", Value: connection})
	}
	out = append(out, jsvalue.Member{Key: "reason", Value: o.reason}, jsvalue.Member{Key: "message", Value: messageOf(o.reason)})
	show := func(k string, a *account) {
		if a != nil {
			out = append(out, jsvalue.Member{Key: k, Value: jsvalue.Object{{Key: "id", Value: a.id}, {Key: "label", Value: a.label}}})
		}
	}
	show("account", o.account)
	show("previousAccount", o.before)
	return out
}
