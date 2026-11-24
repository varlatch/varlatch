// SPDX-License-Identifier: AGPL-3.0-or-later

// Package oauthtest is a fake OAuth 2 and OpenID Connect provider for tests
// (ADR-0062): one that does what a provider should, refresh token rotation
// with reuse detection included, and everything it should not. Never
// shipped, and it contacts nothing.
package oauthtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Issuer, ClientID and Secret are the provider's and its one client's.
const (
	Issuer   = "https://idp.example"
	ClientID = "client-1"
	Secret   = "made-up client secret/+="
	// PublicIP is what the test's resolver answers for every public name.
	PublicIP = "93.184.215.14"
)

// Account is whose consent a provider gives.
type Account struct{ Sub, Email string }

// Request is one request to the token or revocation endpoint.
type Request struct {
	Path, Host string
	Form       url.Values
	User, Pass string
	Basic      bool
}

type grant struct {
	account                            Account
	challenge, redirect, nonce, client string
	scope                              string
	family                             int
	used                               bool
}

// Provider is the fake. Its knobs are set under Set.
type Provider struct {
	// The knobs.
	Account Account
	// Rotate: a refresh gives another refresh token and ends the one used; a
	// second use of one ends the family, but within Grace of the first.
	Rotate bool
	Grace  time.Duration
	// ExpiresIn is expires_in as JSON ("" leaves it out).
	ExpiresIn        string
	RefreshExpiresIn string
	NoRefresh        bool
	NoIDToken        bool
	// Scope is the answer's scope; "-" leaves it out, "" is what was asked.
	Scope     string
	TokenType string
	// What the ID token says instead.
	ClaimIssuer, ClaimNonce, ClaimSub string
	ClaimAud                          any
	ClaimAzp                          string
	ClaimExp                          time.Duration
	BadSignature                      bool
	// Status, Body and Header replace the token endpoint's answer, before
	// anything is done for it.
	Status int
	Body   string
	Header http.Header
	// Answer makes the token endpoint's answer, in the place of Body.
	Answer func(Request) string
	// Lose does what was asked and closes the connection without an answer.
	Lose bool
	// Delay is waited before an answer, and Hold, when set, is waited for.
	Delay time.Duration
	Hold  chan struct{}
	// Issuing is Iss of the authorization response ("" leaves it out).
	Iss string
	// IssParameter is what the metadata says of it; Metadata replaces members
	// of the metadata.
	IssParameter bool
	Metadata     map[string]any
	// Userinfo replaces userinfo's answer.
	Userinfo string
	// RevokeStatus is the revocation endpoint's (200 when 0).
	RevokeStatus int
	Now          func() time.Time

	// Registered, when it is set, are the client's redirect URIs: the
	// authorization endpoint sends the browser to no other.
	Registered []string

	// What happened: the requests to the token and revocation endpoints, and
	// every host that was sent a credential of any kind.
	Requests []Request
	Refused  []string
	Trusted  map[string]bool

	mu       sync.Mutex
	server   *httptest.Server
	ca       *x509.CertPool
	caPEM    []byte
	key      *ecdsa.PrivateKey
	codes    map[string]*grant
	refresh  map[string]*refreshToken
	access   map[string]*grant
	families map[int]bool // ended
	seq      int
}

type refreshToken struct {
	grant
	usedAt time.Time
}

// New starts a provider that answers for every name.
func New() *Provider {
	p := &Provider{Account: Account{"sub-alice", "alice@example.com"}, ExpiresIn: "3600", Rotate: true, TokenType: "Bearer", Now: time.Now,
		codes: map[string]*grant{}, refresh: map[string]*refreshToken{}, access: map[string]*grant{}, families: map[int]bool{}, Trusted: map[string]bool{}}
	var err error
	if p.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		panic(err)
	}
	cert, pool := certificate("idp.example", "evil.example", "other.example", "localhost", "accounts.google.com", "login.microsoftonline.com")
	p.ca, p.caPEM = pool, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	p.server = httptest.NewUnstartedServer(http.HandlerFunc(p.serve))
	p.server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	p.server.StartTLS()
	return p
}

// Close stops it.
func (p *Provider) Close() { p.server.CloseClientConnections(); p.server.Close() }

// Addr is where it listens.
func (p *Provider) Addr() string { return p.server.Listener.Addr().String() }

// Dial connects to the provider whatever the address, for the outbound
// policy's options; the policy has decided the address before.
func (p *Provider) Dial(ctx context.Context, network, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, p.Addr())
}

// TLS trusts the provider's certificate, and nothing else.
func (p *Provider) TLS() *tls.Config { return &tls.Config{RootCAs: p.ca} }

// PEM is its certificate authority, for a varlatchd of its own to trust
// (SSL_CERT_FILE).
func (p *Provider) PEM() []byte { return p.caPEM }

// Set changes knobs.
func (p *Provider) Set(f func(p *Provider)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(p)
}

// Count is how many requests of a grant type (or to "/revoke") there were.
func (p *Provider) Count(what string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, r := range p.Requests {
		if r.Form.Get("grant_type") == what || r.Path == what {
			n++
		}
	}
	return n
}

// Last is the last request.
func (p *Provider) Last() Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.Requests) == 0 {
		return Request{}
	}
	return p.Requests[len(p.Requests)-1]
}

// Secrets are every token the provider ever gave out, and the client secret:
// what may be nowhere but in a Broker's answer (access tokens).
func (p *Provider) Secrets() (access, others []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for t := range p.access {
		access = append(access, t)
	}
	for t := range p.refresh {
		others = append(others, t)
	}
	for c := range p.codes {
		others = append(others, c)
	}
	return access, append(others, Secret, url.QueryEscape(Secret))
}

// Live is whether an access token is the provider's, and its grant is not
// ended.
func (p *Provider) Live(token string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	g := p.access[token]
	return g != nil && !p.families[g.family]
}

// End ends every grant, as a person revoking consent does.
func (p *Provider) End() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, t := range p.refresh {
		p.families[t.family] = true
	}
}

func (p *Provider) token(kind string) string {
	p.seq++
	var b [18]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s.%d.%s", kind, p.seq, base64.RawURLEncoding.EncodeToString(b[:]))
}

// Consent is the browser at the authorization endpoint, and a person who says
// yes: where the browser is sent back to.
func (p *Provider) Consent(authorizationURL string) (*url.URL, error) {
	u, err := url.Parse(authorizationURL)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	v := u.Query()
	for k, all := range v {
		if len(all) != 1 {
			return nil, fmt.Errorf("the parameter %s is there %d times", k, len(all))
		}
	}
	if v.Get("response_type") != "code" || v.Get("client_id") != ClientID || v.Get("code_challenge_method") != "S256" || v.Get("state") == "" {
		return nil, fmt.Errorf("not an authorization request with PKCE: %s", u.RawQuery)
	}
	if len(p.Registered) > 0 && !slices.Contains(p.Registered, v.Get("redirect_uri")) {
		return nil, fmt.Errorf("redirect_uri_mismatch: %s is not registered", v.Get("redirect_uri"))
	}
	p.seq++
	code := p.token("code")
	p.codes[code] = &grant{account: p.Account, challenge: v.Get("code_challenge"), redirect: v.Get("redirect_uri"), nonce: v.Get("nonce"), client: ClientID, scope: v.Get("scope"), family: p.seq}
	back, err := url.Parse(v.Get("redirect_uri"))
	if err != nil {
		return nil, err
	}
	q := url.Values{"code": {code}, "state": {v.Get("state")}}
	if p.Iss != "" {
		q.Set("iss", p.Iss)
	}
	back.RawQuery = q.Encode()
	return back, nil
}

// TrustedHosts are the hosts that were sent a credential, in order.
func (p *Provider) TrustedHosts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Sorted(maps.Keys(p.Trusted))
}

func (p *Provider) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost || r.Header.Get("Authorization") != "" {
		p.mu.Lock()
		p.Trusted[r.Host] = true
		p.mu.Unlock()
	}
	const wellKnown = "/.well-known/openid-configuration"
	path := r.URL.Path
	if strings.HasSuffix(path, wellKnown) {
		path = wellKnown // an issuer with a path
	}
	switch path {
	case wellKnown:
		p.mu.Lock()
		iss := "https://" + r.Host
		m := map[string]any{"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token", "userinfo_endpoint": iss + "/userinfo",
			"revocation_endpoint": iss + "/revoke", "jwks_uri": iss + "/jwks", "code_challenge_methods_supported": []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"}, "authorization_response_iss_parameter_supported": p.IssParameter}
		for k, v := range p.Metadata {
			m[k] = v
			if v == nil {
				delete(m, k)
			}
		}
		p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(m)
	case "/jwks":
		pub, _ := p.key.PublicKey.Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1", "x": b64(pub[1:33]), "y": b64(pub[33:])}}})
	case "/userinfo":
		p.mu.Lock()
		g, body := p.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")], p.Userinfo
		p.mu.Unlock()
		switch {
		case g == nil:
			w.WriteHeader(401)
		case body != "":
			_, _ = w.Write([]byte(body))
		default:
			_ = json.NewEncoder(w).Encode(map[string]string{"sub": g.account.Sub, "email": g.account.Email})
		}
	case "/token":
		p.serveToken(w, r)
	case "/revoke":
		p.mu.Lock()
		defer p.mu.Unlock()
		p.note(r)
		if p.RevokeStatus != 0 {
			w.WriteHeader(p.RevokeStatus)
			return
		}
		t := r.PostForm.Get("token")
		if g := p.refresh[t]; g != nil {
			p.families[g.family] = true
		} else if g := p.access[t]; g != nil {
			p.families[g.family] = true
		}
	default:
		w.WriteHeader(404)
	}
}

func (p *Provider) note(r *http.Request) Request {
	_ = r.ParseForm()
	q := Request{Path: r.URL.Path, Host: r.Host, Form: r.PostForm}
	q.User, q.Pass, q.Basic = r.BasicAuth()
	p.Requests = append(p.Requests, q)
	return q
}

func (p *Provider) serveToken(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	q := p.note(r)
	delay, hold := p.Delay, p.Hold
	p.mu.Unlock()
	if hold != nil {
		<-hold
	}
	time.Sleep(delay)
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.Header {
		w.Header()[k] = v
	}
	if p.Answer != nil {
		_, _ = w.Write([]byte(p.Answer(q)))
		return
	}
	if p.Status != 0 || p.Body != "" {
		if p.Status != 0 {
			w.WriteHeader(p.Status)
		}
		_, _ = w.Write([]byte(p.Body))
		return
	}
	refuse := func(status int, code string) {
		p.Refused = append(p.Refused, code)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "echo: " + r.PostForm.Encode()})
	}
	id, _ := url.QueryUnescape(q.User)
	secret, _ := url.QueryUnescape(q.Pass)
	if !q.Basic {
		id, secret = q.Form.Get("client_id"), q.Form.Get("client_secret")
	}
	if id != ClientID || secret != Secret {
		refuse(401, "invalid_client")
		return
	}
	var g grant
	switch q.Form.Get("grant_type") {
	case "authorization_code":
		c := p.codes[q.Form.Get("code")]
		sum := sha256.Sum256([]byte(q.Form.Get("code_verifier")))
		if c == nil || c.used || c.redirect != q.Form.Get("redirect_uri") || c.challenge != b64(sum[:]) {
			if c != nil && c.used {
				p.families[c.family] = true
			}
			refuse(400, "invalid_grant")
			return
		}
		c.used = true
		g = *c
	case "refresh_token":
		t := p.refresh[q.Form.Get("refresh_token")]
		if t == nil || p.families[t.family] {
			refuse(400, "invalid_grant")
			return
		}
		if p.Rotate {
			if !t.usedAt.IsZero() && p.Now().Sub(t.usedAt) > p.Grace {
				// Used before: somebody else has it. All of it ends.
				p.families[t.family] = true
				refuse(400, "invalid_grant")
				return
			}
			if t.usedAt.IsZero() {
				t.usedAt = p.Now()
			}
		}
		g = t.grant
	case "client_credentials":
		p.seq++
		g = grant{client: id, scope: q.Form.Get("scope"), family: p.seq}
	default:
		refuse(400, "unsupported_grant_type")
		return
	}
	out := map[string]any{"token_type": p.TokenType, "access_token": p.token("at")}
	p.access[out["access_token"].(string)] = &g
	if p.TokenType == "" {
		delete(out, "token_type")
	}
	if p.ExpiresIn != "" {
		out["expires_in"] = json.RawMessage(p.ExpiresIn)
	}
	if kind := q.Form.Get("grant_type"); kind != "client_credentials" && !p.NoRefresh && (kind == "authorization_code" || p.Rotate) {
		t := p.token("rt")
		p.refresh[t] = &refreshToken{grant: g}
		out["refresh_token"] = t
		if p.RefreshExpiresIn != "" {
			out["refresh_token_expires_in"] = json.RawMessage(p.RefreshExpiresIn)
		}
	}
	switch p.Scope {
	case "-":
	case "":
		out["scope"] = g.scope
	default:
		out["scope"] = p.Scope
	}
	if strings.Contains(" "+g.scope+" ", " openid ") && !p.NoIDToken {
		out["id_token"] = p.idToken(g, r.Host)
	}
	if p.Lose {
		if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
			_ = c.Close()
		}
		return
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (p *Provider) idToken(g grant, host string) string {
	or := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	exp := p.ClaimExp
	if exp == 0 {
		exp = 10 * time.Minute
	}
	claims := map[string]any{"iss": or(p.ClaimIssuer, "https://"+host), "sub": or(p.ClaimSub, g.account.Sub), "aud": ClientID, "email": g.account.Email,
		"iat": p.Now().Unix(), "exp": p.Now().Add(exp).Unix(), "nonce": or(p.ClaimNonce, g.nonce)}
	if p.ClaimAud != nil {
		claims["aud"] = p.ClaimAud
	}
	if p.ClaimAzp != "" {
		claims["azp"] = p.ClaimAzp
	}
	body, _ := json.Marshal(claims)
	signed := b64([]byte(`{"alg":"ES256","kid":"k1"}`)) + "." + b64(body)
	sum := sha256.Sum256([]byte(signed))
	a, b, err := ecdsa.Sign(rand.Reader, p.key, sum[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	a.FillBytes(sig[:32])
	b.FillBytes(sig[32:])
	if p.BadSignature {
		sig[5] ^= 1
	}
	return signed + "." + b64(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// certificate makes a certificate for names, and the pool that trusts it.
func certificate(names ...string) (tls.Certificate, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	t := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "oauthtest"}, DNSNames: names, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}
