// SPDX-License-Identifier: AGPL-3.0-or-later

// Package oauth is OAuth connections (ADR-0062): Varlatch holds the client
// and the tokens of a connection to somebody else's API, and gives a Broker
// the access token. Only the access token, and only in the exercise of a
// Capability (go/server/values): the refresh token and the client secret
// leave for the connection's own provider and for nowhere else.
//
// A connection is an item of an environment. What it is (endpoints, client,
// scopes, hosts) is a value version, with the client secret sealed in it;
// the endpoints are pinned when it is made, on one host or on hosts the
// request names, all of which are in its redirect URI. Its tokens are in
// oauth_connections, sealed with those parameters: changed ones open
// nothing.
//
//   - Connecting (connect.go): a person's consent in the browser, with PKCE,
//     a state and a nonce bound to their session; or the client's own
//     credentials.
//   - Refreshing (refresh.go): in one place, one at a time, its claim in the
//     database before anything is sent, the new refresh token stored with
//     the access token before anyone gets either.
//   - Disconnecting: revoked at the provider where it can be, and forgotten
//     here whatever the provider says.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/oauth/oauthparams"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// Service is what the operations, the exercise and the worker work with: one
// in a process.
type Service struct {
	Writer  *write.Writer
	RootKEK []byte
	Policy  *outbound.Policy
	Now     func() time.Time
	Log     *slog.Logger
	// Admit is the maintenance admission (nil for none): a refresh outlives
	// the request that asked for it, so it enters on its own.
	Admit func() (leave func(), ok bool)
	// Timeout bounds one request to a provider (0: CallTimeout), Wait how long
	// who asks for a refresh waits (0: refreshWait), and GateWait how long the
	// refresh itself waits for its turn (0: gateWait).
	Timeout, Wait, GateWait time.Duration

	mu      sync.Mutex
	closed  bool
	flights map[string]*flight
	running sync.WaitGroup
	// crash, in tests, ends a refresh at a named point as the end of the
	// process would: nothing after it happens.
	crash func(point string) bool
}

func (s *Service) store() *storage.DB { return s.Writer.Store }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Close waits for the refreshes in progress, so no answer is lost to a stop,
// and starts no other.
func (s *Service) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.running.Wait()
}

// gate is a connection's: connecting, refreshing, changing and disconnecting
// it, one at a time.
func gate(valueID string) write.Gate { return write.Resource("oauth_connection", valueID) }

// Request is who asks.
type Request struct {
	Principal *auth.Principal
	RequestID string
	Target    values.Target
}

func (r Request) gates(more ...write.Gate) []write.Gate {
	return append([]write.Gate{write.Organization(r.Target.OrganizationID, write.Shared), write.Person(r.Principal.Identity.ID, write.Shared)}, more...)
}

func (r Request) scope(exception string) write.Scope {
	return write.Scope{OrganizationID: r.Target.OrganizationID, ProjectID: r.Target.Project.ID, EnvironmentIDs: []string{r.Target.Env.ID}, DuringFreeze: exception}
}

func random() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
func nullInt(n int64) sql.NullInt64   { return sql.NullInt64{Int64: n, Valid: n != 0} }

// ---------------------------------------------------------------------------
// A connection as stored.

// row is a live connection.
type row struct {
	query.OAuthConnectionByIDRow
	params oauthparams.Params
	text   string
}

func rowOf(r query.OAuthConnectionByIDRow) (*row, error) {
	p, ok := oauthparams.Parse(r.Params)
	if !ok {
		return nil, domainerr.New("STATE_CHANGED", "This OAuth connection was made by a newer Varlatch")
	}
	text, err := p.Text()
	if err != nil {
		return nil, err
	}
	return &row{r, p, text}, nil
}

func notFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "OAuth connection not found") }

// find is an environment's own connection.
func find(ctx context.Context, db query.DBTX, environmentID, item string) (*row, error) {
	r, err := query.New(db).OAuthConnectionOf(ctx, query.OAuthConnectionOfParams{EnvironmentID: environmentID, ItemName: item})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notFound()
	}
	if err != nil {
		return nil, err
	}
	return rowOf(query.OAuthConnectionByIDRow(r))
}

// byID is a connection by its value row, nil when there is none any more.
func byID(ctx context.Context, db query.DBTX, valueID string) (*row, error) {
	r, err := query.New(db).OAuthConnectionByID(ctx, valueID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rowOf(r)
}

func (r *row) resource() jsvalue.Object {
	return jsvalue.Object{{Key: "projectId", Value: r.ProjectID}, {Key: "environmentId", Value: r.EnvironmentID},
		{Key: "itemName", Value: r.ItemName}, {Key: "versionId", Value: r.VersionID}}
}

// client opens the client secret, to be sent to the endpoints it is sealed
// with.
func (r *row) client(orgKEK []byte) (clientOf, error) {
	secret, err := values.ConnectionSecret(orgKEK, r.OrganizationID, r.ValueID, r.VersionID, r.text, r.Payload.String, r.WrappedDek.String)
	if err != nil {
		return clientOf{}, err
	}
	return clientOf{p: r.params, secret: secret}, nil
}

// context is what a token of the connection is sealed with.
func (r *row) context(purpose string, generation, expiresAt int64, account string) envelope.Context {
	if purpose == envelope.PurposeOAuthRefreshToken {
		expiresAt = 0
	}
	return envelope.OAuthTokenContext(purpose, r.OrganizationID, r.ValueID, r.VersionID, r.text, account, generation, expiresAt)
}

// seal seals a token; "" is no token.
func seal(orgKEK []byte, c envelope.Context, token string) (sql.NullString, error) {
	if token == "" {
		return sql.NullString{}, nil
	}
	plain := []byte(token)
	defer clear(plain)
	env, err := envelope.Seal(orgKEK, plain, c)
	if err != nil {
		return sql.NullString{}, err
	}
	b, err := json.Marshal(env)
	return sql.NullString{String: string(b), Valid: true}, err
}

// open opens a token; none is "".
func open(orgKEK []byte, c envelope.Context, stored sql.NullString) (string, error) {
	if !stored.Valid {
		return "", nil
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(stored.String), &env); err != nil {
		return "", fmt.Errorf("oauth: a stored token is not an envelope: %w", err)
	}
	plain, err := envelope.Open(orgKEK, env, c)
	if err != nil {
		return "", err
	}
	defer clear(plain)
	return string(plain), nil
}

func (r *row) openAccess(orgKEK []byte) (string, error) {
	c := r.OauthConnection
	return open(orgKEK, r.context(envelope.PurposeOAuthAccessToken, c.Generation, c.AccessExpiresAt.Int64, c.Account), c.AccessToken)
}

func (r *row) openRefresh(orgKEK []byte) (string, error) {
	c := r.OauthConnection
	return open(orgKEK, r.context(envelope.PurposeOAuthRefreshToken, c.Generation, 0, c.Account), c.RefreshToken)
}

// account is whose the connection is, as the provider says: a stable ID, and
// what people call it.
type account struct{ id, label string }

// minKeepalive is how often, at most, a connection nobody uses is kept.
const minKeepalive = 10 * time.Minute

// keepalive is when a refresh token would have to be used to stay one, 0 for
// never: after two thirds of the time the provider keeps it without use, or
// of the time it lasts when it says.
func keepalive(p oauthparams.Params, t tokens, hasRefresh bool) int64 {
	if !hasRefresh {
		return 0
	}
	var after time.Duration
	if p.IdleDays > 0 {
		after = time.Duration(p.IdleDays) * 24 * time.Hour * 2 / 3
	}
	if t.refreshLifetime > 0 {
		if d := time.Duration(t.refreshLifetime) * time.Second * 2 / 3; after == 0 || d < after {
			after = d
		}
	}
	if after == 0 {
		return 0
	}
	return t.at.Add(max(after, minKeepalive)).UnixMicro()
}

// sealed are a token set's columns.
type sealed struct {
	access, refresh                             sql.NullString
	expiresAt, lifetime, refreshExpires, keptTo sql.NullInt64
}

// sealTokens seals a token set for a generation of r.
func (r *row) sealTokens(orgKEK []byte, t tokens, refresh string, generation int64, acct string) (sealed, error) {
	var out sealed
	if t.lifetime > 0 {
		out.expiresAt, out.lifetime = nullInt(t.at.Add(time.Duration(t.lifetime)*time.Second).UnixMicro()), nullInt(t.lifetime)
	}
	if t.refreshLifetime > 0 && refresh != "" {
		out.refreshExpires = nullInt(t.at.Add(time.Duration(t.refreshLifetime) * time.Second).UnixMicro())
	}
	out.keptTo = nullInt(keepalive(r.params, t, refresh != ""))
	var err error
	if out.access, err = seal(orgKEK, r.context(envelope.PurposeOAuthAccessToken, generation, out.expiresAt.Int64, acct), t.access); err != nil {
		return sealed{}, err
	}
	out.refresh, err = seal(orgKEK, r.context(envelope.PurposeOAuthRefreshToken, generation, 0, acct), refresh)
	return out, err
}

// ---------------------------------------------------------------------------
// The provider of a connection to make.

// Provider is a provider as a request gives it.
type Provider struct {
	Preset, Tenant, Issuer                                                             string
	AuthorizationEndpoint, TokenEndpoint, RevocationEndpoint, UserinfoEndpoint, Method string
	// EndpointHosts are hosts its endpoints may be on, beside the issuer's,
	// or the token endpoint's where that was given.
	EndpointHosts      []string
	Lifetime, IdleDays int64
	Params             []oauthparams.Param
}

func invalid(err error) error { return domainerr.New("VALIDATION_FAILED", err.Error()) }

// Discover is what Resolve makes of a provider, whether or not the hosts of
// its endpoints were named: to show them.
func (s *Service) Discover(ctx context.Context, req Request, in Provider, grant string, withSecret bool) (oauthparams.Params, error) {
	return s.endpoints(ctx, req, in, grant, nil, withSecret, false)
}

// Resolve makes the parameters of a provider's: a preset's or an issuer's
// from its metadata, or the endpoints given. Nothing is asked of anything
// but the issuer, and every endpoint is one the outbound policy lets be
// asked. Every address is on the host that was given (the issuer's, or the
// token endpoint's) or on one the request names: whoever names them sees
// them, and they are in the redirect URI (oauthparams.RedirectName).
// withSecret is whether the client has a secret.
func (s *Service) Resolve(ctx context.Context, req Request, in Provider, grant string, scopes []string, withSecret bool) (oauthparams.Params, error) {
	return s.endpoints(ctx, req, in, grant, scopes, withSecret, true)
}

func (s *Service) endpoints(ctx context.Context, req Request, in Provider, grant string, scopes []string, withSecret, named bool) (oauthparams.Params, error) {
	p := oauthparams.Params{V: oauthparams.Version, Provider: in.Preset, Grant: grant, Scopes: slices.Clone(scopes),
		AuthMethod: in.Method, LifetimeSeconds: in.Lifetime, IdleDays: in.IdleDays, AuthorizationParams: oauthparams.SortParams(in.Params)}
	given := in.AuthorizationEndpoint != "" || in.TokenEndpoint != "" || in.RevocationEndpoint != "" || in.UserinfoEndpoint != ""
	preset, known := oauthparams.Presets[in.Preset]
	more, err := oauthparams.CanonicalEndpointHosts(in.EndpointHosts)
	if err != nil {
		return p, invalid(err)
	}
	switch {
	case len(more) > 0 && known:
		return p, invalid(errors.New("endpointHosts: a preset has its own hosts"))
	case len(more) > 0 && grant == oauthparams.ClientCredentials:
		return p, invalid(errors.New("endpointHosts: the endpoints of a client's own connection are all on one host"))
	case known:
		if given || in.Issuer != "" {
			return p, invalid(errors.New("provider: a preset has its own issuer and endpoints; use the preset generic to give them"))
		}
		if preset.Tenant == nil && in.Tenant != "" {
			return p, invalid(errors.New("tenant: this provider has none"))
		}
		if preset.Tenant != nil && !preset.Tenant.MatchString(strings.ToLower(in.Tenant)) {
			return p, invalid(errors.New("tenant: the tenant's own ID (a UUID) is needed: common, organizations and consumers let in accounts of any tenant, and name none to check"))
		}
		if !slices.Contains(preset.Grants, grant) {
			return p, invalid(errors.New("grant: this provider does not have it"))
		}
		p.Tenant = strings.ToLower(in.Tenant)
		p.Issuer = preset.Issuer(p.Tenant)
		if p.IdleDays == 0 {
			p.IdleDays = preset.IdleDays
		}
		if grant == oauthparams.AuthorizationCode {
			p.Scopes = preset.WithScopes(scopes)
			if len(p.AuthorizationParams) == 0 {
				p.AuthorizationParams = oauthparams.SortParams(preset.Params)
			}
		}
	case in.Preset != oauthparams.Generic:
		return p, invalid(errors.New("provider: no such preset"))
	case in.Tenant != "":
		return p, invalid(errors.New("tenant: only for the preset microsoft"))
	case in.Issuer != "" && given:
		return p, invalid(errors.New("provider: an issuer, whose metadata names the endpoints, or the endpoints; not both"))
	case in.Issuer != "":
		p.Issuer = in.Issuer
	default:
		p.AuthorizationEndpoint, p.TokenEndpoint, p.RevocationEndpoint, p.UserinfoEndpoint = in.AuthorizationEndpoint, in.TokenEndpoint, in.RevocationEndpoint, in.UserinfoEndpoint
		if grant == oauthparams.ClientCredentials {
			p.AuthorizationEndpoint = ""
		}
	}
	var methods []string
	if p.Issuer != "" {
		if err := oauthparams.CheckEndpoint(p.Issuer); err != nil {
			return p, invalid(errors.New("issuer: " + err.Error()))
		}
		if err := s.allowed(ctx, req, p.Issuer); err != nil {
			return p, err
		}
		doc, f := s.discover(ctx, p.Issuer)
		if f != nil {
			if f.refusal != nil {
				if err := s.recordRefusal(ctx, req, f.refusal, "connection"); err != nil {
					return p, err
				}
				return p, refused(f.refusal)
			}
			return p, &domainerr.Error{Code: "VALIDATION_FAILED", Message: "issuer: its metadata could not be read (" + f.reason + ")",
				Details: jsvalue.Object{{Key: "reason", Value: f.reason}}}
		}
		p.TokenEndpoint, p.RevocationEndpoint = text(doc, "token_endpoint"), text(doc, "revocation_endpoint")
		if grant == oauthparams.AuthorizationCode {
			p.AuthorizationEndpoint, p.UserinfoEndpoint, p.JWKSURI = text(doc, "authorization_endpoint"), text(doc, "userinfo_endpoint"), text(doc, "jwks_uri")
			_ = json.Unmarshal(doc["authorization_response_iss_parameter_supported"], &p.IssParameter)
			var pkce []string
			if json.Unmarshal(doc["code_challenge_methods_supported"], &pkce) == nil && len(pkce) > 0 && !slices.Contains(pkce, "S256") {
				return p, invalid(errors.New("issuer: it does not support PKCE with S256, which Varlatch connects with"))
			}
		}
		_ = json.Unmarshal(doc["token_endpoint_auth_methods_supported"], &methods)
	}
	if p.AuthMethod == "" {
		switch {
		case !withSecret:
			p.AuthMethod = oauthparams.AuthNone
		case len(methods) == 0 || slices.Contains(methods, oauthparams.AuthBasic):
			p.AuthMethod = oauthparams.AuthBasic
		default:
			p.AuthMethod = oauthparams.AuthPost
		}
	}
	if (p.AuthMethod == oauthparams.AuthNone) == withSecret {
		return p, invalid(errors.New("clientSecret: needed, unless tokenEndpointAuthMethod is none"))
	}
	endpoints := []struct{ name, url string }{{"authorizationEndpoint", p.AuthorizationEndpoint}, {"tokenEndpoint", p.TokenEndpoint},
		{"revocationEndpoint", p.RevocationEndpoint}, {"userinfoEndpoint", p.UserinfoEndpoint}, {"jwksUri", p.JWKSURI}}
	for _, e := range endpoints {
		if e.url == "" {
			continue
		}
		if err := oauthparams.CheckEndpoint(e.url); err != nil {
			return p, invalid(errors.New(e.name + ": " + err.Error()))
		}
	}
	if known {
		if err := preset.CheckHosts(p); err != nil {
			return p, invalid(err)
		}
	} else if named {
		if err := checkHosts(p, more); err != nil {
			return p, err
		}
	}
	for _, e := range endpoints {
		if e.url == "" {
			continue
		}
		// The browser asks the authorization endpoint, not this server.
		if e.name != "authorizationEndpoint" {
			if err := s.allowed(ctx, req, e.url); err != nil {
				return p, err
			}
		}
	}
	return p, nil
}

// checkHosts refuses addresses on hosts nobody named.
func checkHosts(p oauthparams.Params, named []string) error {
	given := p.Server()
	if p.Issuer != "" {
		given = oauthparams.Host(p.Issuer)
	}
	var others []string
	for _, h := range p.EndpointHosts() {
		if h != given && h != "" && !slices.Contains(named, h) {
			others = append(others, h)
		}
	}
	if len(others) == 0 {
		return nil
	}
	message := "The provider has addresses on other hosts than " + given + ": " + strings.Join(others, ", ") + ". If they are the provider's own, name them in endpointHosts"
	if p.Grant == oauthparams.ClientCredentials {
		message = "The endpoints of a client's own connection are all on one host, and " + strings.Join(others, ", ") + " is not " + given +
			": give the token endpoint itself, and a revocation endpoint on its host or none"
	}
	return &domainerr.Error{Code: "VALIDATION_FAILED", Message: message,
		Details: jsvalue.Object{{Key: "reason", Value: "endpoint-hosts"}, {Key: "endpointHosts", Value: list(others)}}}
}

// allowed is the outbound policy's verdict on a URL before it is saved
// (ADR-0057 Decision 6).
func (s *Service) allowed(ctx context.Context, req Request, raw string) error {
	refusal, err := s.Policy.RefusalFor(ctx, raw, outbound.OAuth)
	if err != nil || refusal == nil {
		return err
	}
	if err := s.recordRefusal(ctx, req, refusal, "configuration"); err != nil {
		return err
	}
	return refused(refusal)
}

func (s *Service) recordRefusal(ctx context.Context, req Request, refusal *outbound.RefusedError, phase string) error {
	return s.Policy.RecordRefusal(ctx, s.store(), outbound.RefusalRecord{
		OrganizationID: req.Target.OrganizationID, Purpose: outbound.OAuth, Phase: phase, Refusal: refusal,
		Resource:        jsvalue.Object{{Key: "projectId", Value: req.Target.Project.ID}, {Key: "environmentId", Value: req.Target.Env.ID}},
		ActorIdentityID: &req.Principal.Identity.ID, RequestID: &req.RequestID,
	})
}

func refused(r *outbound.RefusedError) error {
	return &domainerr.Error{Code: "VALIDATION_FAILED", Message: r.Error(), Details: jsvalue.Object{{Key: "outbound", Value: string(r.Reason)}}}
}

// ---------------------------------------------------------------------------
// Making, changing, reading.

// Input is a connection to make.
type Input struct {
	Item         string
	Provider     Provider
	Grant        string
	ClientID     string
	ClientSecret string
	Scopes       []string
	Hosts        []string
}

// checkSecret is whether s may be a client secret.
func checkSecret(s string) error {
	if len(s) > 2048 || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		return invalid(errors.New("clientSecret: printable ASCII, at most 2048 characters"))
	}
	return nil
}

// Create makes a connection, not connected yet.
func (s *Service) Create(ctx context.Context, req Request, in Input, base *url.URL) (jsvalue.Object, []auth.PendingReport, error) {
	if err := checkSecret(in.ClientSecret); err != nil {
		return nil, nil, err
	}
	hosts, err := oauthparams.CanonicalHosts(in.Hosts)
	if err != nil {
		return nil, nil, invalid(err)
	}
	// Whose account is used, and where its tokens go, is a person's decision
	// from the start.
	if in.Grant == oauthparams.AuthorizationCode {
		if err := person(req.Principal, "An OAuth connection to a person's account is made by a person"); err != nil {
			return nil, nil, err
		}
	}
	// Nothing is asked of a provider for an Organization that may not write.
	if err := write.CheckLive(ctx, s.store().Reader(), req.scope("")); err != nil {
		return nil, nil, err
	}
	p, err := s.Resolve(ctx, req, in.Provider, in.Grant, in.Scopes, in.ClientSecret != "")
	if err != nil {
		return nil, nil, err
	}
	p.ClientID, p.Hosts = in.ClientID, hosts
	if err := p.Check(); err != nil {
		return nil, nil, invalid(err)
	}
	var out jsvalue.Object
	var reports []auth.PendingReport
	err = s.Writer.Job(ctx, req.gates(), func(ctx context.Context, tx *storage.Tx) error {
		_, _, r, err := values.CreateConnection(ctx, tx, s.RootKEK, req.Principal, req.Target, in.Item,
			values.ConnectionInput{Params: p, ClientSecret: in.ClientSecret}, req.RequestID, s.now().UnixMicro())
		if err != nil {
			return err
		}
		reports = r
		made, err := find(ctx, tx, req.Target.Env.ID, in.Item)
		if err != nil {
			return err
		}
		out = s.js(made, base)
		return nil
	})
	return out, reports, err
}

// Change is what to change of a connection; nil leaves a member.
type Change struct {
	Provider          *Provider
	ClientID          *string
	ClientSecret      *string
	Scopes, Hosts     *[]string
	Paused            *bool
	ExpectedVersionID *string
}

// person refuses whoever is none: what a connection's tokens can reach is
// decided by people.
func person(p *auth.Principal, message string) error {
	if p.Identity.Kind == "human" {
		return nil
	}
	return &domainerr.Error{Code: "PERMISSION_DENIED", Message: message,
		Details: jsvalue.Object{{Key: "reason", Value: "person-required"}}}
}

// Update changes a connection. Its provider and client can change only while
// it holds no tokens (it is disconnected first, which revokes them), so a
// token is never sent to a server it was not given by; its hosts, scopes,
// provider and client only by a person. A new client secret or new hosts
// leave it connected.
func (s *Service) Update(ctx context.Context, req Request, item string, in Change, base *url.URL) (jsvalue.Object, []auth.PendingReport, error) {
	for _, c := range []struct {
		has  bool
		what string
	}{{in.Provider != nil, "The provider"}, {in.ClientID != nil, "The client"}, {in.Scopes != nil, "The scopes"}, {in.Hosts != nil, "The hosts"}} {
		if c.has {
			if err := person(req.Principal, c.what+" of an OAuth connection is changed by a person"); err != nil {
				return nil, nil, err
			}
		}
	}
	seen, err := find(ctx, s.store().Reader(), req.Target.Env.ID, item)
	if err != nil {
		return nil, nil, err
	}
	if in.ClientSecret != nil {
		if err := checkSecret(*in.ClientSecret); err != nil {
			return nil, nil, err
		}
	}
	next := seen.params
	rewrite := in.Provider != nil || in.ClientID != nil || in.ClientSecret != nil || in.Scopes != nil || in.Hosts != nil
	if in.Scopes != nil {
		next.Scopes = slices.Clone(*in.Scopes)
		if preset, ok := oauthparams.Presets[next.Provider]; ok && next.Grant == oauthparams.AuthorizationCode {
			next.Scopes = preset.WithScopes(next.Scopes)
		}
	}
	if in.Hosts != nil {
		if next.Hosts, err = oauthparams.CanonicalHosts(*in.Hosts); err != nil {
			return nil, nil, invalid(err)
		}
	}
	withSecret := next.AuthMethod != oauthparams.AuthNone
	if in.ClientSecret != nil {
		withSecret = *in.ClientSecret != ""
	}
	if in.Provider != nil {
		if err := write.CheckLive(ctx, s.store().Reader(), req.scope("")); err != nil {
			return nil, nil, err
		}
		clientID, hosts := next.ClientID, next.Hosts
		if next, err = s.Resolve(ctx, req, *in.Provider, next.Grant, next.Scopes, withSecret); err != nil {
			return nil, nil, err
		}
		next.ClientID, next.Hosts = clientID, hosts
	}
	if in.ClientID != nil {
		next.ClientID = *in.ClientID
	}
	if (next.AuthMethod == oauthparams.AuthNone) == withSecret {
		return nil, nil, invalid(errors.New("clientSecret: needed, unless tokenEndpointAuthMethod is none"))
	}
	if err := next.Check(); err != nil {
		return nil, nil, invalid(err)
	}
	// Whoever sends another server's parameters sends the secret anew: the
	// stored one is for the server it was given for.
	if !next.SameServer(seen.params) && in.ClientSecret == nil && next.AuthMethod != oauthparams.AuthNone {
		return nil, nil, invalid(errors.New("clientSecret: needed when the provider or the client changes"))
	}
	// Pausing does not wait for a refresh in progress.
	var gates []write.Gate
	if rewrite {
		gates = append(gates, gate(seen.ValueID))
	}
	var out jsvalue.Object
	var reports []auth.PendingReport
	err = s.Writer.Job(ctx, req.gates(gates...), func(ctx context.Context, tx *storage.Tx) error {
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
		if r.VersionID != seen.VersionID || in.ExpectedVersionID != nil && r.VersionID != *in.ExpectedVersionID {
			return &domainerr.Error{Code: "VERSION_CONFLICT", Message: "The OAuth connection changed since the expected version",
				Details: jsvalue.Object{{Key: "currentVersionId", Value: r.VersionID}}}
		}
		at, q := s.now().UnixMicro(), query.New(tx)
		if rewrite {
			if err := s.rewrite(ctx, tx, req, r, item, next, in.ClientSecret, at); err != nil {
				return err
			}
		}
		if in.Paused != nil && *in.Paused != r.OauthConnection.PausedAt.Valid {
			var since sql.NullInt64
			if *in.Paused {
				since = nullInt(at)
			}
			if err := q.PauseOAuthConnection(ctx, query.PauseOAuthConnectionParams{PausedAt: since, ValueID: r.ValueID}); err != nil {
				return err
			}
			outcome := "resumed"
			if *in.Paused {
				outcome = "paused"
			}
			if err := s.record(ctx, tx, r, "sync.connection_checked", audit.Info, req, outcome, nil); err != nil {
				return err
			}
		}
		if r, err = find(ctx, tx, req.Target.Env.ID, item); err != nil {
			return err
		}
		out = s.js(r, base)
		return nil
	})
	return out, reports, err
}

// rewrite writes new parameters (or a new client secret) as a new version,
// and seals the tokens again for it; another server's or client's hold no
// token of the old one's.
func (s *Service) rewrite(ctx context.Context, tx *storage.Tx, req Request, r *row, item string, next oauthparams.Params, secret *string, at int64) error {
	q, c := query.New(tx), r.OauthConnection
	same := next.SameServer(r.params)
	if !same && (c.AccessToken.Valid || c.RefreshToken.Valid) {
		return &domainerr.Error{Code: "VALIDATION_FAILED", Message: "The provider and the client of a connected OAuth connection stay: disconnect it first",
			Details: jsvalue.Object{{Key: "reason", Value: "connected"}}}
	}
	kek, err := values.OrgKEK(ctx, tx, s.RootKEK, r.OrganizationID)
	if err != nil {
		return err
	}
	defer clear(kek)
	var access, refresh string
	if same {
		if access, err = r.openAccess(kek); err != nil {
			return err
		}
		if refresh, err = r.openRefresh(kek); err != nil {
			return err
		}
	}
	if secret == nil {
		old, err := r.client(kek)
		if err != nil {
			return err
		}
		secret = &old.secret
	}
	versionID, err := values.UpdateConnection(ctx, tx, kek, req.Principal, req.Target, r.ValueID, item, r.VersionID,
		values.ConnectionInput{Params: next, ClientSecret: *secret}, req.RequestID, at)
	if err != nil {
		return err
	}
	// An authorization in progress was asked for with the old parameters.
	if err := q.EndOAuthAuthorizations(ctx, r.ValueID); err != nil {
		return err
	}
	if !same {
		// Whose account it was stays: another one is still another one.
		return q.ChangeOAuthServer(ctx, query.ChangeOAuthServerParams{ValueID: r.ValueID, VersionID: versionID})
	}
	text, err := next.Text()
	if err != nil {
		return err
	}
	moved := *r
	moved.VersionID, moved.params, moved.text = versionID, next, text
	generation := c.Generation + 1
	p := query.MoveOAuthConnectionParams{ValueID: r.ValueID, VersionID: versionID, KeepaliveAt: c.KeepaliveAt}
	if p.AccessToken, err = seal(kek, moved.context(envelope.PurposeOAuthAccessToken, generation, c.AccessExpiresAt.Int64, c.Account), access); err != nil {
		return err
	}
	if p.RefreshToken, err = seal(kek, moved.context(envelope.PurposeOAuthRefreshToken, generation, 0, c.Account), refresh); err != nil {
		return err
	}
	return q.MoveOAuthConnection(ctx, p)
}

// List is an environment's own connections.
func (s *Service) List(ctx context.Context, db query.DBTX, t values.Target, base *url.URL) ([]any, error) {
	rows, err := query.New(db).OAuthConnectionsOfEnvironment(ctx, t.Env.ID)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, r := range rows {
		one, err := rowOf(query.OAuthConnectionByIDRow{ValueID: r.ValueID, ItemName: r.ItemName, VersionID: r.VersionID, Params: r.Params,
			CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, EnvironmentID: t.Env.ID, ProjectID: t.Project.ID, OrganizationID: t.OrganizationID, OauthConnection: r.OauthConnection})
		if err != nil {
			continue // a newer Varlatch's
		}
		out = append(out, s.js(one, base))
	}
	return out, nil
}

// Get is one of them.
func (s *Service) Get(ctx context.Context, db query.DBTX, t values.Target, item string, base *url.URL) (jsvalue.Object, error) {
	r, err := find(ctx, db, t.Env.ID, item)
	if err != nil {
		return nil, err
	}
	return s.js(r, base), nil
}

// RedirectURI is where a server sends the browser back to: the dashboard's
// page for that server and its hosts.
func RedirectURI(base *url.URL, p oauthparams.Params) string {
	return base.Scheme + "://" + base.Host + strings.TrimRight(base.EscapedPath(), "/") + "/oauth/callback/" + url.PathEscape(p.RedirectName())
}

func isoOrNil(n sql.NullInt64) any {
	if !n.Valid {
		return nil
	}
	return audit.ISOTime(n.Int64)
}

func list(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// implied are scopes a server need not name among the ones it granted.
var implied = []string{"openid", "profile", "email", "offline_access"}

// missing are the scopes asked for that the server did not grant, as far as
// it says: none when it does not say.
func missing(asked []string, granted sql.NullString) []string {
	out := []string{}
	if !granted.Valid {
		return out
	}
	have := strings.Fields(granted.String)
	for _, s := range asked {
		if slices.Contains(have, s) || slices.Contains(implied, s) {
			continue
		}
		// Microsoft names the resource before its own scopes.
		if slices.ContainsFunc(have, func(h string) bool { return strings.HasSuffix(h, "/"+s) }) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// js is a connection as the API shows it: no secret, no token, nothing
// derived from one.
func (s *Service) js(r *row, base *url.URL) jsvalue.Object {
	c, now := r.OauthConnection, s.now().UnixMicro()
	shown := &values.Connection{Status: c.Status, Refreshing: c.ClaimUntil.Valid && c.ClaimUntil.Int64 > now}
	opt := func(v sql.NullString) any {
		if !v.Valid {
			return nil
		}
		return v.String
	}
	var acct any
	if c.Account != "" {
		acct = jsvalue.Object{{Key: "id", Value: c.Account}, {Key: "label", Value: c.AccountLabel}}
	}
	granted := any(nil)
	if c.GrantedScopes.Valid {
		granted = list(strings.Fields(c.GrantedScopes.String))
	}
	out := jsvalue.Object{
		{Key: "item", Value: r.ItemName}, {Key: "environmentId", Value: r.EnvironmentID}, {Key: "versionId", Value: r.VersionID},
		{Key: "provider", Value: r.params.JS()}, {Key: "grant", Value: r.params.Grant}, {Key: "clientId", Value: r.params.ClientID},
		{Key: "hasClientSecret", Value: r.params.AuthMethod != oauthparams.AuthNone},
		{Key: "scopes", Value: list(r.params.Scopes)}, {Key: "hosts", Value: list(r.params.Hosts)},
		{Key: "status", Value: shown.State()}, {Key: "reason", Value: opt(c.Reason)}, {Key: "paused", Value: c.PausedAt.Valid},
		{Key: "account", Value: acct}, {Key: "grantedScopes", Value: granted}, {Key: "missingScopes", Value: list(missing(r.params.Scopes, c.GrantedScopes))},
		{Key: "hasRefreshToken", Value: c.RefreshToken.Valid},
		{Key: "accessTokenExpiresAt", Value: isoOrNil(c.AccessExpiresAt)}, {Key: "refreshTokenExpiresAt", Value: isoOrNil(c.RefreshExpiresAt)},
		{Key: "connectedBy", Value: opt(c.ConnectedBy)}, {Key: "connectedAt", Value: isoOrNil(c.ConnectedAt)}, {Key: "refreshedAt", Value: isoOrNil(c.RefreshedAt)},
		{Key: "retryAt", Value: isoOrNil(c.RetryAt)},
		{Key: "createdBy", Value: opt(r.CreatedBy)}, {Key: "createdAt", Value: audit.ISOTime(r.CreatedAt)},
	}
	if base != nil && r.params.Grant == oauthparams.AuthorizationCode {
		out = append(out, jsvalue.Member{Key: "redirectUri", Value: RedirectURI(base, r.params)})
	}
	return out
}

// record records an event of a connection, under the event types a Platform
// Connection has (a reverse migration carries only types the TypeScript
// server knows): the resource names the item, and connection says which
// kind it is.
func (s *Service) record(ctx context.Context, tx query.DBTX, r *row, typ, decision string, req Request, outcome string, md jsvalue.Object) error {
	e := audit.Event{Type: typ, Decision: decision, OrganizationID: &r.OrganizationID, Resource: r.resource(),
		Metadata: append(jsvalue.Object{{Key: "connection", Value: "oauth"}, {Key: "outcome", Value: outcome}, {Key: "server", Value: r.params.Server()},
			{Key: "endpointHosts", Value: strings.Join(r.params.EndpointHosts(), ",")}}, md...)}
	if req.Principal != nil {
		action := "config.value.write"
		e.ActorIdentityID, e.Action = &req.Principal.Identity.ID, &action
	}
	if req.RequestID != "" {
		e.RequestID = &req.RequestID
	}
	_, err := audit.Record(ctx, tx, e)
	return err
}

// refusalEvent is an outbound refusal's event, within the policy's bound.
func (s *Service) refusalEvent(r *row, req Request, f *failure) (audit.Event, bool) {
	rec := outbound.RefusalRecord{OrganizationID: r.OrganizationID, Purpose: outbound.OAuth, Phase: "connection", Refusal: f.refusal,
		Resource: jsvalue.Object{{Key: "projectId", Value: r.ProjectID}, {Key: "environmentId", Value: r.EnvironmentID}, {Key: "itemName", Value: r.ItemName}}}
	if req.Principal != nil {
		rec.ActorIdentityID = &req.Principal.Identity.ID
	}
	return s.Policy.RefusalEvent(rec)
}

// noteRefusal records an outbound refusal of a call: with the final job of
// the effect it is in, or alone.
func (s *Service) noteRefusal(ctx context.Context, r *row, req Request, f *failure) {
	if f == nil || f.refusal == nil {
		return
	}
	if e, ok := s.refusalEvent(r, req, f); ok && !write.NoteRefusal(ctx, e) {
		if err := s.store().Write(ctx, func(tx *storage.Tx) error { _, err := audit.Record(ctx, tx, e); return err }); err != nil {
			s.log().Error("could not audit a refused OAuth request", "error", err)
		}
	}
}

// Disconnected is a disconnection's outcome at the provider.
const (
	revokedThere = "revoked"
	notSupported = "not-supported"
	revokeFailed = "failed"
	nothingThere = "nothing-to-revoke"
	leftThere    = "left"
)

// Disconnect revokes a connection's tokens at its provider, when that has an
// endpoint for it and revoke says so, and forgets them here whatever it
// answered. While the Organization is frozen too: it only takes away.
func (s *Service) Disconnect(ctx context.Context, req Request, item string, revoke bool, base *url.URL) (jsvalue.Object, []auth.PendingReport, error) {
	seen, err := find(ctx, s.store().Reader(), req.Target.Env.ID, item)
	if err != nil {
		return nil, nil, err
	}
	gctx, release, err := s.Writer.Gates.Acquire(ctx, req.gates(gate(seen.ValueID))...)
	if err != nil {
		return nil, nil, err
	}
	defer release()
	// The checks, and the tokens as they are while no refresh runs.
	var reports []auth.PendingReport
	var c clientOf
	var access, refresh string
	var r *row
	err = func() error {
		tx, err := s.store().Reader().BeginTx(gctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if err := write.CheckLive(gctx, tx, req.scope(authz.DuringFreezeRecovery)); err != nil {
			return err
		}
		if r, err = find(gctx, tx, req.Target.Env.ID, item); err != nil {
			return err
		}
		if reports, err = write.Checkpoint(gctx, tx, req.Principal, req.Target.OrganizationID); err != nil {
			return err
		}
		if !revoke {
			return nil
		}
		kek, err := values.OrgKEK(gctx, tx, s.RootKEK, r.OrganizationID)
		if err != nil {
			return err
		}
		defer clear(kek)
		// Tokens that do not open (changed rows) are forgotten all the same.
		if c, err = r.client(kek); err == nil {
			if access, err = r.openAccess(kek); err == nil {
				refresh, err = r.openRefresh(kek)
			}
		}
		if err != nil {
			s.log().Error("an OAuth connection's tokens do not open: forgotten without revoking them", "item", item, "error", err)
			access, refresh = "", ""
		}
		return nil
	}()
	if err != nil {
		return nil, nil, err
	}
	// From here on it ends, whoever asked is still there or not.
	dctx := context.WithoutCancel(gctx)
	there, reason := leftThere, ""
	if revoke {
		switch {
		case access == "" && refresh == "":
			there = nothingThere
		case r.params.RevocationEndpoint == "":
			there = notSupported
		default:
			there = revokedThere
			var f *failure
			if refresh != "" {
				f = s.revoke(dctx, c, refresh, "refresh_token")
			}
			// The access token too: a server need not end it with the refresh
			// token (RFC 7009 section 2.1), and need not know the one it ended.
			if access != "" && (f == nil || refresh == "") {
				if g := s.revoke(dctx, c, access, "access_token"); refresh == "" {
					f = g
				}
			}
			if f != nil {
				there, reason = revokeFailed, f.reason
				s.noteRefusal(dctx, r, req, f)
			}
		}
	}
	var out jsvalue.Object
	err = s.store().Write(dctx, func(tx *storage.Tx) error {
		q := query.New(tx)
		if _, err := q.RevokeOAuthConnection(dctx, r.ValueID); err != nil {
			return err
		}
		if err := q.EndOAuthAuthorizations(dctx, r.ValueID); err != nil {
			return err
		}
		md := jsvalue.Object{{Key: "atProvider", Value: there}}
		if reason != "" {
			md = append(md, jsvalue.Member{Key: "reason", Value: reason})
		}
		if r.OauthConnection.Account != "" {
			md = append(md, jsvalue.Member{Key: "account", Value: r.OauthConnection.AccountLabel})
		}
		if err := s.record(dctx, tx, r, "sync.connection_revoked", audit.Info, req, "disconnected", md); err != nil {
			return err
		}
		now, err := find(dctx, tx, req.Target.Env.ID, item)
		if err != nil {
			return err
		}
		out = jsvalue.Object{{Key: "atProvider", Value: there}, {Key: "connection", Value: s.js(now, base)}}
		if reason != "" {
			out = append(out, jsvalue.Member{Key: "reason", Value: reason})
		}
		return nil
	})
	return out, reports, err
}

// CrashAt ends every refresh of s at a point crash names, as the end of the
// process would: nothing that comes after happens (tests only). The points
// are "claimed" (nothing sent yet), "answered" (nothing stored yet) and
// "stored".
func CrashAt(s *Service, crash func(point string) bool) { s.crash = crash }
