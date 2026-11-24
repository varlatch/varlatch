// SPDX-License-Identifier: AGPL-3.0-or-later

package oauthparams

import (
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/authz"
)

func valid() Params {
	return Params{V: Version, Provider: "generic", Issuer: "https://idp.example", AuthorizationEndpoint: "https://idp.example/authorize", TokenEndpoint: "https://idp.example:8443/token",
		RevocationEndpoint: "https://idp.example/revoke", UserinfoEndpoint: "https://idp.example/me", JWKSURI: "https://idp.example/jwks", AuthMethod: AuthPost, Grant: AuthorizationCode,
		ClientID: "client-1", Scopes: []string{"openid", "a:b/c"}, AuthorizationParams: []Param{{"access_type", "offline"}, {"prompt", "consent"}},
		Hosts: []string{"*.api.example:443", "api.example:8443"}, LifetimeSeconds: 60, IdleDays: 90}
}

func TestTextIsOneForm(t *testing.T) {
	p := valid()
	text, err := p.Text()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := Parse(text)
	again, _ := got.Text()
	if !ok || again != text {
		t.Errorf("%v %s", ok, again)
	}
	// In another order, as jsonb gives it back.
	moved := `{"grant":"authorization_code",` + strings.Replace(text[1:], `"grant":"authorization_code",`, "", 1)
	if got, ok := Parse(moved); !ok {
		t.Error("another order")
	} else if again, _ := got.Text(); again != text {
		t.Errorf("%s", again)
	}
	for _, bad := range []string{"", "{}", "[]", `{"v":1}`, strings.Replace(text, `"v":1`, `"v":2`, 1), strings.Replace(text, "https://idp.example:8443/token", "http://idp.example/token", 1)} {
		if _, ok := Parse(bad); ok {
			t.Errorf("%s", bad)
		}
	}
}

func TestCheck(t *testing.T) {
	if err := valid().Check(); err != nil {
		t.Fatal(err)
	}
	for what, change := range map[string]func(*Params){
		"provider":                 func(p *Params) { p.Provider = "" },
		"a token endpoint":         func(p *Params) { p.TokenEndpoint = "" },
		"an authorization one":     func(p *Params) { p.AuthorizationEndpoint = "" },
		"issuer with a query":      func(p *Params) { p.Issuer = "https://idp.example?x" },
		"method":                   func(p *Params) { p.AuthMethod = "private_key_jwt" },
		"grant":                    func(p *Params) { p.Grant = "password" },
		"public client, no person": func(p *Params) { p.Grant, p.AuthMethod = ClientCredentials, AuthNone },
		"client":                   func(p *Params) { p.ClientID = "a\nb" },
		"bidi in the client":       func(p *Params) { p.ClientID = "a‮b" },
		"a scope with a blank":     func(p *Params) { p.Scopes = []string{"a b"} },
		"a scope twice":            func(p *Params) { p.Scopes = []string{"a", "a"} },
		"a parameter twice":        func(p *Params) { p.AuthorizationParams = []Param{{"a", "1"}, {"a", "2"}} },
		"not in order":             func(p *Params) { p.AuthorizationParams = []Param{{"b", "1"}, {"a", "2"}} },
		"state":                    func(p *Params) { p.AuthorizationParams = []Param{{"State", "1"}} },
		"code_challenge_method":    func(p *Params) { p.AuthorizationParams = []Param{{"code_challenge_method", "plain"}} },
		"request_uri":              func(p *Params) { p.AuthorizationParams = []Param{{"request_uri", "https://x.example"}} },
		"hosts":                    func(p *Params) { p.Hosts = []string{"api.example"} }, // not canonical
		"lifetime":                 func(p *Params) { p.LifetimeSeconds = MaxLifetimeSeconds + 1 },
		"idle":                     func(p *Params) { p.IdleDays = -1 },
	} {
		p := valid()
		change(&p)
		if err := p.Check(); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
}

func TestCheckEndpoint(t *testing.T) {
	for _, ok := range []string{"https://idp.example", "https://idp.example/a/b?tenant=x", "https://idp.example:8443/", "https://xn--bcher-kva.example/", "https://[2001:db8::1]/t"} {
		if err := CheckEndpoint(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "idp.example", "http://idp.example", "HTTPS://idp.example#x", "https://idp.example#", "https://u@idp.example", "https://u:p@idp.example", "https:idp.example", "https:///x",
		"https://idp.example\\@evil.example", "https://idp.example /", "https://idp.example/\n", "https://bücher.example/", "javascript:alert(1)", "https://idp%2eexample/", "https://0x7f.1/", "ftp://idp.example"} {
		if err := CheckEndpoint(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

func TestSameServer(t *testing.T) {
	p := valid()
	for what, x := range map[string]struct {
		change func(*Params)
		same   bool
	}{
		"nothing":       {func(*Params) {}, true},
		"scopes":        {func(q *Params) { q.Scopes = nil }, true},
		"hosts":         {func(q *Params) { q.Hosts = nil }, true},
		"method":        {func(q *Params) { q.AuthMethod = AuthBasic }, true},
		"lifetimes":     {func(q *Params) { q.LifetimeSeconds, q.IdleDays = 1, 1 }, true},
		"token":         {func(q *Params) { q.TokenEndpoint += "2" }, false},
		"revocation":    {func(q *Params) { q.RevocationEndpoint = "" }, false},
		"userinfo":      {func(q *Params) { q.UserinfoEndpoint += "2" }, false},
		"keys":          {func(q *Params) { q.JWKSURI += "2" }, false},
		"authorization": {func(q *Params) { q.AuthorizationEndpoint += "2" }, false},
		"issuer":        {func(q *Params) { q.Issuer += "/x" }, false},
		"client":        {func(q *Params) { q.ClientID += "2" }, false},
		"grant":         {func(q *Params) { q.Grant = ClientCredentials }, false},
	} {
		q := valid()
		x.change(&q)
		if p.SameServer(q) != x.same {
			t.Errorf("%s: %v", what, !x.same)
		}
	}
	if len(p.Scopes) == 0 || len(p.Hosts) == 0 {
		t.Error("it changed them")
	}
}

func TestServerAndHosts(t *testing.T) {
	for url, want := range map[string]string{"https://idp.example/token": "idp.example", "https://idp.example:443/": "idp.example", "https://IDP.example:8443/x": "idp.example:8443", "https://[2001:db8::1]:444/": "[2001:db8::1]:444"} {
		if got := (Params{TokenEndpoint: url}).Server(); got != want {
			t.Errorf("%s: %s", url, got)
		}
	}
	p := valid()
	for d, want := range map[authz.Destination]bool{{Host: "x.api.example", Port: 443}: true, {Host: "api.example", Port: 443}: false, {Host: "api.example", Port: 8443}: true, {Host: "evil.example", Port: 443}: false, {Host: "API.example.", Port: 8443}: true} {
		if p.Reaches(d) != want {
			t.Errorf("%v: %v", d, !want)
		}
	}
	p.Hosts = nil
	if !p.Reaches(authz.Destination{Host: "any.example", Port: 1}) {
		t.Error("no hosts")
	}
}

// A preset is data: what it makes is whole, and the tenant is one.
func TestPresets(t *testing.T) {
	for name, p := range Presets {
		if name != p.Name || CheckEndpoint(p.Issuer("9188040d-6c67-4c5b-b112-36a304b66dad")) != nil {
			t.Errorf("%s", name)
		}
	}
	ms := Presets["microsoft"]
	for tenant, ok := range map[string]bool{"9188040d-6c67-4c5b-b112-36a304b66dad": true, "common": false, "organizations": false, "consumers": false, "contoso.onmicrosoft.com": false, "": false, "9188040d-6c67-4c5b-b112-36a304b66dad/../common": false} {
		if ms.Tenant.MatchString(tenant) != ok {
			t.Errorf("%q", tenant)
		}
	}
	if got := strings.Join(Presets["google"].WithScopes([]string{"email", "https://www.googleapis.com/auth/gmail.send"}), " "); got != "openid email https://www.googleapis.com/auth/gmail.send" {
		t.Error(got)
	}
}
