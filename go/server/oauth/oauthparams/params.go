// SPDX-License-Identifier: AGPL-3.0-or-later

// Package oauthparams is what may be read of an OAuth connection (ADR-0062):
// the provider's endpoints as they were pinned when the connection was
// made, the client, the scopes, and the hosts its access token may go to.
// It is stored in plaintext beside the sealed client secret, and is part of
// what that secret and every token are sealed with: a changed one opens
// nothing.
package oauthparams

import (
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Version is the version of Params this server writes and knows. A row of
// another one (a later release's, after a rollback) is an item without a
// value here.
const Version = 1

// How a connection gets its tokens.
const (
	// AuthorizationCode is a person's consent, in the browser.
	AuthorizationCode = "authorization_code"
	// ClientCredentials is the client's own, no person.
	ClientCredentials = "client_credentials"
)

// How the client authenticates at the token endpoint.
const (
	AuthBasic = "client_secret_basic"
	AuthPost  = "client_secret_post"
	AuthNone  = "none"
)

// Bounds.
const (
	maxText   = 512
	maxURL    = 2000
	maxScopes = 100
	maxHosts  = 50
	maxExtra  = 10
	// MaxLifetimeSeconds bounds what an access token is taken to last (a
	// year), and MaxIdleDays what an unused refresh token is.
	MaxLifetimeSeconds = 366 * 24 * 60 * 60
	MaxIdleDays        = 3650
)

// Param is one more parameter of the authorization request.
type Param struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Params are a connection's readable parameters. The order of its members
// is the order they are sealed in (Text): jsonb, which a migration goes
// through, keeps none.
type Params struct {
	V int `json:"v"`
	// Provider is the preset's name, for people and the redirect URI
	// (RedirectName): nothing else depends on it once the connection is made.
	// Tenant is Microsoft's.
	Provider string `json:"provider"`
	Tenant   string `json:"tenant,omitempty"`
	// Issuer is the OpenID Provider (or authorization server) the endpoints
	// were discovered from; "" when they were given.
	Issuer                string `json:"issuer,omitempty"`
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string `json:"tokenEndpoint"`
	RevocationEndpoint    string `json:"revocationEndpoint,omitempty"`
	UserinfoEndpoint      string `json:"userinfoEndpoint,omitempty"`
	JWKSURI               string `json:"jwksUri,omitempty"`
	// IssParameter is whether the server said it names itself in its
	// authorization responses (RFC 9207): then one that does not is refused.
	IssParameter bool   `json:"issParameter,omitempty"`
	AuthMethod   string `json:"tokenEndpointAuthMethod"`
	Grant        string `json:"grant"`
	ClientID     string `json:"clientId"`
	// Scopes as asked for, in order.
	Scopes              []string `json:"scopes,omitempty"`
	AuthorizationParams []Param  `json:"authorizationParams,omitempty"`
	// Hosts are the destinations its access token may go to, canonical;
	// none: whatever the Capability names.
	Hosts []string `json:"hosts,omitempty"`
	// LifetimeSeconds is how long an access token lasts where the server
	// does not say; 0: unknown.
	LifetimeSeconds int64 `json:"accessTokenLifetimeSeconds,omitempty"`
	// IdleDays is after how many days without use the provider drops a
	// refresh token; 0: unknown.
	IdleDays int64 `json:"refreshTokenIdleDays,omitempty"`
}

// Text is the parameters as stored and sealed.
func (p Params) Text() (string, error) {
	b, err := json.Marshal(p)
	return string(b), err
}

// Parse reads stored parameters; false for what this server does not know.
func Parse(text string) (Params, bool) {
	var p Params
	if json.Unmarshal([]byte(text), &p) != nil || p.V != Version || p.Check() != nil {
		return Params{}, false
	}
	return p, true
}

// An Error is a refused parameter: a fixed text that holds no value given.
type Error struct{ Field, Message string }

func (e *Error) Error() string { return e.Field + ": " + e.Message }

func bad(field, message string) error { return &Error{field, message} }

// plain is whether s is text that shows as it is: no control or format
// characters, valid UTF-8.
func plain(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r >= 0x7f && r < 0xa0 || r == 0x2028 || r == 0x2029 || r >= 0x200b && r <= 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 || r == 0xfeff {
			return false
		}
	}
	return true
}

// CheckEndpoint is whether raw is a URL tokens may be sent to: https, no
// credentials, no fragment, written as it is parsed, so that what is shown
// is what is asked.
func CheckEndpoint(raw string) error {
	if !plain(raw, maxURL) || strings.ContainsFunc(raw, func(r rune) bool { return r > 0x7e || r == ' ' || r == '\\' }) {
		return errors.New("not a URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return errors.New("not a URL")
	}
	if u.Scheme != "https" {
		return errors.New("only https")
	}
	if u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("no credentials and no fragment")
	}
	// A host is shown to people, and part of the redirect URI
	// (RedirectName): nothing that could be read as another.
	if !plainHost(u.Hostname()) {
		return errors.New("a host of letters, digits, dots and hyphens, or an address")
	}
	// Both parsers (net/url's, and the WHATWG one the outbound policy
	// reads with) name the same host.
	w, ok := whatwg.ParseURL(raw)
	if !ok || w.Protocol != "https:" || !strings.EqualFold(w.Host, strings.TrimSuffix(strings.ToLower(u.Host), ":443")) {
		return errors.New("not a URL that reads one way")
	}
	return nil
}

// plainHost is whether h is a host name of letters, digits, hyphens,
// underscores and dots, or an IP address.
func plainHost(h string) bool {
	if whatwg.IsIP(h) != 0 {
		return true
	}
	return h != "" && !strings.ContainsFunc(h, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.'
	})
}

// Host is the host of an endpoint, with its port when that is not 443, as
// people and the redirect URI see it.
func Host(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" && port != "443" {
		host += ":" + port
	}
	return host
}

// CanonicalEndpointHosts reads the hosts a request names for a provider's
// endpoints (host, or host:port), each once.
func CanonicalEndpointHosts(in []string) ([]string, error) {
	var out []string
	for _, raw := range in {
		if strings.ContainsAny(raw, "/?#@\\") || CheckEndpoint("https://"+raw+"/") != nil {
			return nil, bad("endpointHosts", "hosts, with a port when it is not 443")
		}
		if h := Host("https://" + raw); !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out, nil
}

// Scope tokens (RFC 6749 section 3.3).
func scopeToken(s string) bool {
	if s == "" || len(s) > maxText {
		return false
	}
	for i := range len(s) {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// reservedParams are the authorization request's own parameters, and those
// that would replace them.
var reservedParams = []string{"response_type", "response_mode", "client_id", "client_secret", "redirect_uri", "scope", "state", "nonce",
	"code_challenge", "code_challenge_method", "request", "request_uri", "registration", "code", "id_token_hint", "grant_type", "dpop_jkt"}

// Check is whether the parameters are whole and well-formed.
func (p Params) Check() error {
	if !plain(p.Provider, 40) {
		return bad("provider", "a short name")
	}
	if p.Tenant != "" && !plain(p.Tenant, 100) {
		return bad("tenant", "not a tenant")
	}
	for _, e := range []struct {
		name, url string
		need      bool
	}{
		{"issuer", p.Issuer, false},
		{"authorizationEndpoint", p.AuthorizationEndpoint, p.Grant == AuthorizationCode},
		{"tokenEndpoint", p.TokenEndpoint, true},
		{"revocationEndpoint", p.RevocationEndpoint, false},
		{"userinfoEndpoint", p.UserinfoEndpoint, false},
		{"jwksUri", p.JWKSURI, false},
	} {
		if e.url == "" {
			if e.need {
				return bad(e.name, "needed")
			}
			continue
		}
		if err := CheckEndpoint(e.url); err != nil {
			return bad(e.name, err.Error())
		}
	}
	if p.Issuer != "" && strings.Contains(p.Issuer, "?") {
		return bad("issuer", "no query")
	}
	// Nothing at the provider says which hosts a client's own connection may
	// have: a person's has its redirect URI.
	if p.Grant == ClientCredentials && len(p.EndpointHosts()) > 1 {
		return bad("provider", "the endpoints of a client's own connection are all on one host: give the token endpoint, and a revocation endpoint on its host or none")
	}
	if !slices.Contains([]string{AuthBasic, AuthPost, AuthNone}, p.AuthMethod) {
		return bad("tokenEndpointAuthMethod", "one of client_secret_basic, client_secret_post, none")
	}
	if p.Grant != AuthorizationCode && p.Grant != ClientCredentials {
		return bad("grant", "one of authorization_code, client_credentials")
	}
	if p.Grant == ClientCredentials && p.AuthMethod == AuthNone {
		return bad("grant", "client_credentials needs a client secret")
	}
	if !plain(p.ClientID, maxText) {
		return bad("clientId", "a client ID of at most 512 characters")
	}
	if len(p.Scopes) > maxScopes {
		return bad("scopes", "at most 100")
	}
	for i, s := range p.Scopes {
		if !scopeToken(s) || slices.Contains(p.Scopes[:i], s) {
			return bad("scopes", "scope tokens, without blanks, each once")
		}
	}
	if len(p.AuthorizationParams) > maxExtra {
		return bad("authorizationParams", "at most 10")
	}
	for i, x := range p.AuthorizationParams {
		if !scopeToken(x.Name) || !plain(x.Value, maxText) || slices.Contains(reservedParams, strings.ToLower(x.Name)) || i > 0 && p.AuthorizationParams[i-1].Name >= x.Name {
			return bad("authorizationParams", "a name of this request's own, a repeated one, or a text that is not plain")
		}
	}
	if len(p.Hosts) > maxHosts {
		return bad("hosts", "at most 50")
	}
	for _, h := range p.Hosts {
		if sel, ok := authz.ParseDestinationSelector(h); !ok || sel.String() != h {
			return bad("hosts", "destination selectors, as a Capability's: host, host:port or *.domain")
		}
	}
	if p.LifetimeSeconds < 0 || p.LifetimeSeconds > MaxLifetimeSeconds {
		return bad("accessTokenLifetimeSeconds", "at most a year")
	}
	if p.IdleDays < 0 || p.IdleDays > MaxIdleDays {
		return bad("refreshTokenIdleDays", "at most 3650")
	}
	return nil
}

// CanonicalHosts reads hosts as a Capability's destinations are.
func CanonicalHosts(in []string) ([]string, error) {
	var out []string
	for _, raw := range in {
		sel, ok := authz.ParseDestinationSelector(raw)
		if !ok {
			return nil, bad("hosts", "destination selectors, as a Capability's: host, host:port or *.domain")
		}
		if s := sel.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// SortParams puts the authorization request's parameters in their order.
func SortParams(in []Param) []Param {
	out := slices.Clone(in)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SameServer is whether p's tokens, client and endpoints are q's too: what
// tokens were obtained with. Changing any of it voids them. The client
// secret, the scopes asked for the next time, the hosts and what is assumed
// about lifetimes are not part of it.
func (p Params) SameServer(q Params) bool {
	p.Scopes, q.Scopes, p.Hosts, q.Hosts = nil, nil, nil, nil
	p.LifetimeSeconds, q.LifetimeSeconds, p.IdleDays, q.IdleDays = 0, 0, 0, 0
	p.AuthorizationParams, q.AuthorizationParams = nil, nil
	p.AuthMethod, q.AuthMethod = "", ""
	a, _ := p.Text()
	b, _ := q.Text()
	return a == b
}

// Reaches is whether the access token may go to d: its hosts name it, or
// it names none.
func (p Params) Reaches(d authz.Destination) bool {
	if len(p.Hosts) == 0 {
		return true
	}
	for _, h := range p.Hosts {
		if sel, ok := authz.ParseDestinationSelector(h); ok && sel.Matches(d) {
			return true
		}
	}
	return false
}

// Covers is whether every destination sel matches is one of the hosts.
func (p Params) Covers(sel authz.DestinationSelector) bool {
	if len(p.Hosts) == 0 {
		return true
	}
	for _, h := range p.Hosts {
		host, ok := authz.ParseDestinationSelector(h)
		if ok && covers(host, sel) {
			return true
		}
	}
	return false
}

func covers(outer, inner authz.DestinationSelector) bool {
	if outer.Port != inner.Port {
		return false
	}
	if !outer.Wildcard {
		return !inner.Wildcard && inner.Host == outer.Host
	}
	if inner.Wildcard && inner.Host == outer.Host {
		return true
	}
	return whatwg.IsIP(inner.Host) == 0 && strings.HasSuffix(inner.Host, "."+outer.Host)
}

// OpenID is whether the connection asks for an ID token it can verify.
func (p Params) OpenID() bool {
	return p.Issuer != "" && p.JWKSURI != "" && slices.Contains(p.Scopes, "openid")
}

// Server is the token endpoint's host and port.
func (p Params) Server() string { return Host(p.TokenEndpoint) }

// EndpointHosts are the hosts of every address of the connection's, the
// token endpoint's first: all that its client secret, a code or a token is
// ever sent to, that its identity is learned from, and that the browser is
// sent to.
func (p Params) EndpointHosts() []string {
	out := []string{p.Server()}
	for _, e := range []string{p.Issuer, p.AuthorizationEndpoint, p.RevocationEndpoint, p.UserinfoEndpoint, p.JWKSURI} {
		if e == "" {
			continue
		}
		if h := Host(e); !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	slices.Sort(out[1:])
	return out
}

// RedirectName is the last segment of the redirect URI. Each server has its
// own, so a code another server was asked for is never sent to this one (RFC
// 9700 section 4.4.2); and each set of hosts has its own, so a connection
// with another host among them than the ones its owner registered it with
// connects at no provider. A preset's hosts are fixed. No host holds a "~".
func (p Params) RedirectName() string {
	if _, ok := Presets[p.Provider]; ok {
		return p.Server()
	}
	return strings.Join(p.EndpointHosts(), "~")
}

// JS is what answers carry of the parameters.
func (p Params) JS() jsvalue.Object {
	opt := func(o jsvalue.Object, k, v string) jsvalue.Object {
		if v == "" {
			return o
		}
		return append(o, jsvalue.Member{Key: k, Value: v})
	}
	o := jsvalue.Object{{Key: "preset", Value: p.Provider}}
	o = opt(o, "tenant", p.Tenant)
	o = opt(o, "issuer", p.Issuer)
	o = opt(o, "authorizationEndpoint", p.AuthorizationEndpoint)
	o = append(o, jsvalue.Member{Key: "tokenEndpoint", Value: p.TokenEndpoint})
	o = opt(o, "revocationEndpoint", p.RevocationEndpoint)
	o = opt(o, "userinfoEndpoint", p.UserinfoEndpoint)
	o = opt(o, "jwksUri", p.JWKSURI)
	hosts := []any{}
	for _, h := range p.EndpointHosts() {
		hosts = append(hosts, h)
	}
	o = append(o, jsvalue.Member{Key: "endpointHosts", Value: hosts})
	o = append(o, jsvalue.Member{Key: "tokenEndpointAuthMethod", Value: p.AuthMethod})
	if len(p.AuthorizationParams) > 0 {
		x := jsvalue.Object{}
		for _, a := range p.AuthorizationParams {
			x = append(x, jsvalue.Member{Key: a.Name, Value: a.Value})
		}
		o = append(o, jsvalue.Member{Key: "authorizationParams", Value: x})
	}
	if p.LifetimeSeconds > 0 {
		o = append(o, jsvalue.Member{Key: "accessTokenLifetimeSeconds", Value: p.LifetimeSeconds})
	}
	if p.IdleDays > 0 {
		o = append(o, jsvalue.Member{Key: "refreshTokenIdleDays", Value: p.IdleDays})
	}
	return o
}

// Seconds is n seconds in words.
func Seconds(n int64) string {
	if n == 1 {
		return "1 second"
	}
	return strconv.FormatInt(n, 10) + " seconds"
}
