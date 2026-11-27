// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/oauth/oauthtest"
	"github.com/varlatch/varlatch/go/server/write"
)

// What bounds an OAuth connection (ADR-0062): the hosts its secrets go to,
// who makes and deletes one, how often it is refreshed, and what is kept of
// an answer that took long.

const redirectBase = "http://127.0.0.1:8686/oauth/callback/"

// provided is a provider by its endpoints, at idp.example but for more.
func provided(more with) map[string]any {
	p := map[string]any{"preset": "generic", "authorizationEndpoint": "https://idp.example/authorize", "tokenEndpoint": "https://idp.example/token",
		"userinfoEndpoint": "https://idp.example/userinfo", "revocationEndpoint": "https://idp.example/revoke"}
	for k, v := range more {
		p[k] = v
		if v == nil {
			delete(p, k)
		}
	}
	return p
}

// Every address of a provider's is on the host that was given, or on one the
// request names: at making, at changing, and whatever the metadata says.
func TestEveryAddressIsOnANamedHost(t *testing.T) {
	w := newOAuthWorld(t)
	w.idp.Set(func(p *oauthtest.Provider) { p.Registered = []string{redirectBase + "idp.example"} })
	make1 := func(provider map[string]any, more with) answer {
		b := connection(with{"provider": provider, "scopes": []string{"mail.read"}, "clientSecret": "placeholder"})
		for k, v := range more {
			b[k] = v
		}
		return w.call("POST", oauthPath, "alice", b)
	}
	refused := func(what string, a answer) {
		t.Helper()
		w.wantReason(what, a, 422, "VALIDATION_FAILED", "endpoint-hosts")
		if d := a.body["error"].(map[string]any)["details"].(map[string]any); fmt.Sprint(d["endpointHosts"]) != "[evil.example]" {
			t.Errorf("%s: %s", what, a.raw)
		}
	}
	foreign := map[string]string{"userinfoEndpoint": "userinfo_endpoint", "revocationEndpoint": "revocation_endpoint", "authorizationEndpoint": "authorization_endpoint", "": "jwks_uri"}
	for member, metadata := range foreign {
		if member != "" {
			refused(member, make1(provided(with{member: "https://evil.example/x"}), nil))
			refused(member+", another port", make1(provided(with{member: "https://evil.example/x", "endpointHosts": []string{"evil.example:8443", "idp.example"}}), nil))
		}
		w.idp.Set(func(p *oauthtest.Provider) { p.Metadata = map[string]any{metadata: "https://evil.example/x"} })
		refused(metadata, make1(map[string]any{"preset": "generic", "issuer": oauthtest.Issuer}, nil))
	}
	// An issuer whose metadata names an honest server's endpoints.
	w.idp.Set(func(p *oauthtest.Provider) {
		p.Metadata = map[string]any{"authorization_endpoint": "https://idp.example/authorize", "token_endpoint": "https://idp.example/token"}
	})
	a := make1(map[string]any{"preset": "generic", "issuer": "https://evil.example"}, nil)
	w.wantReason("another's issuer", a, 422, "VALIDATION_FAILED", "endpoint-hosts")
	w.idp.Set(func(p *oauthtest.Provider) { p.Metadata = nil })
	// Other names of one.
	for _, h := range []string{"idp.example.evil.example", "xidp.example", "idp.example."} {
		w.wantReason(h, make1(provided(with{"revocationEndpoint": "https://" + h + "/x"}), nil), 422, "VALIDATION_FAILED", "endpoint-hosts")
	}
	for what, p := range map[string]map[string]any{
		"a host with more": provided(with{"endpointHosts": []string{"evil.example/x"}}),
		"a wildcard":       provided(with{"endpointHosts": []string{"*.example"}}),
		"a preset's":       {"preset": "google", "endpointHosts": []string{"evil.example"}},
	} {
		w.want(what, make1(p, nil), 422, "VALIDATION_FAILED")
	}
	if w.idp.TrustedHosts() != nil {
		t.Errorf("a credential went to %v", w.idp.TrustedHosts())
	}

	// Named, it is in the redirect URI, what is answered, and the event; and at
	// an honest provider that URI is nobody's.
	named := w.want("named", make1(provided(with{"revocationEndpoint": "https://evil.example/revoke", "userinfoEndpoint": "https://evil.example/userinfo",
		"endpointHosts": []string{"EVIL.example:443"}}), with{"hosts": []string{"api.idp.example"}}), 201, "")
	if named.body["redirectUri"] != redirectBase+"idp.example~evil.example" || fmt.Sprint(named.body["provider"].(map[string]any)["endpointHosts"]) != "[idp.example evil.example]" {
		t.Errorf("%s", named.raw)
	}
	w.wantEvent("value.written", "Alice", nil, map[string]any{"server": "idp.example", "endpointHosts": "idp.example,evil.example"})
	w.grantWrite("bob")
	w.want("bob's secret", w.call("PATCH", mailPath, "bobweb", map[string]any{"clientSecret": oauthtest.Secret}), 200, "")
	start := w.want("start", w.call("POST", mailPath+"/authorizations", "bobweb", nil), 201, "")
	if _, err := w.idp.Consent(start.body["authorizationUrl"].(string)); err == nil || !strings.Contains(err.Error(), "redirect_uri_mismatch") {
		t.Errorf("%v", err)
	}
	// Sent on with the registered URI, the code is not exchanged here.
	u := strings.Replace(start.body["authorizationUrl"].(string), "idp.example~evil.example", "idp.example", 1)
	back, err := w.idp.Consent(u)
	if err != nil {
		t.Fatal(err)
	}
	if a := w.complete("bobweb", answerOf(back)); a.body["reason"] != "redirect-uri-mismatch" {
		t.Errorf("%s", a.raw)
	}
	w.want("disconnect", w.call("POST", mailPath+"/disconnect", "alice", nil), 200, "")
	if w.idp.TrustedHosts() != nil {
		t.Errorf("a credential went to %v", w.idp.TrustedHosts())
	}
	// A change is held to the same.
	refused("a change", w.call("PATCH", mailPath, "alice", map[string]any{"clientSecret": "x", "provider": provided(with{"revocationEndpoint": "https://evil.example/revoke"})}))

	// The honest one: every secret goes to its one host, and the events say so.
	w.want("delete", w.call("DELETE", envPath+"/values/"+mailItem, "alice", nil), 204, "")
	w.want("made", make1(provided(nil), with{"clientSecret": oauthtest.Secret}), 201, "")
	w.connect()
	w.wantEvent("sync.connection_created", "Alice", nil, map[string]any{"endpointHosts": "idp.example"})
	w.later(2 * time.Hour)
	w.token1("refreshed", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
	w.want("disconnect", w.call("POST", mailPath+"/disconnect", "alice", nil), 200, "")
	w.wantEvent("sync.connection_revoked", "Alice", nil, map[string]any{"endpointHosts": "idp.example"})
	if got := w.idp.TrustedHosts(); !slices.Equal(got, []string{"idp.example"}) {
		t.Errorf("credentials went to %v", got)
	}
}

// Named hosts work, and nothing but they do.
func TestAProviderOnSeveralHosts(t *testing.T) {
	w := newOAuthWorld(t)
	uri := redirectBase + "idp.example~other.example"
	w.idp.Set(func(p *oauthtest.Provider) {
		p.Registered = []string{uri}
		p.Metadata = map[string]any{"userinfo_endpoint": "https://other.example/userinfo"}
	})
	issuer := map[string]any{"preset": "generic", "issuer": oauthtest.Issuer}
	found := w.want("discovery shows them", w.call("POST", oauthPath+"/discovery", "alice", map[string]any{"provider": issuer}), 200, "")
	if found.body["redirectUri"] != uri || fmt.Sprint(found.body["provider"].(map[string]any)["endpointHosts"]) != "[idp.example other.example]" {
		t.Errorf("%s", found.raw)
	}
	issuer["endpointHosts"] = []string{"idp.example", "other.example"}
	made := w.create(with{"provider": issuer, "scopes": []string{"mail.read"}})
	if made.body["redirectUri"] != uri {
		t.Errorf("%s", made.raw)
	}
	w.connect()
	if got := w.idp.TrustedHosts(); !slices.Equal(got, []string{"idp.example", "other.example"}) {
		t.Errorf("%v", got)
	}
	// What was shown is what is connected.
	w.want("another version", w.call("POST", mailPath+"/authorizations", "web", map[string]any{"expectedVersionId": "ver_other"}), 409, "VERSION_CONFLICT")
	w.want("this one", w.call("POST", mailPath+"/authorizations", "web", map[string]any{"expectedVersionId": made.body["versionId"]}), 201, "")
	// A client's own connection is on one host.
	own := connection(with{"item": "OWN_TOKEN", "grant": "client_credentials", "scopes": []string{"x"}, "provider": map[string]any{"preset": "generic", "tokenEndpoint": "https://idp.example/token", "revocationEndpoint": "https://other.example/revoke"}})
	w.wantReason("two hosts", w.call("POST", oauthPath, "alice", own), 422, "VALIDATION_FAILED", "endpoint-hosts")
	own["provider"].(map[string]any)["endpointHosts"] = []string{"other.example"}
	w.want("named all the same", w.call("POST", oauthPath, "alice", own), 422, "VALIDATION_FAILED")
}

// A preset's hosts are its own, whatever its metadata says, and its redirect
// URI names its token endpoint's alone.
func TestAPresetsHosts(t *testing.T) {
	const tenant = "9188040d-6c67-4c5b-b112-36a304b66dad"
	for name, p := range map[string]map[string]any{"google": {"preset": "google"}, "microsoft": {"preset": "microsoft", "tenant": tenant}} {
		t.Run(name, func(t *testing.T) {
			w := newOAuthWorld(t)
			host, issuer := "accounts.google.com", "https://accounts.google.com"
			if name == "microsoft" {
				host, issuer = "login.microsoftonline.com", "https://login.microsoftonline.com/"+tenant+"/v2.0"
			}
			metadata := func(more map[string]any) {
				m := map[string]any{"issuer": issuer}
				for k, v := range more {
					m[k] = v
				}
				w.idp.Set(func(p *oauthtest.Provider) { p.Metadata = m })
			}
			for _, k := range []string{"authorization_endpoint", "token_endpoint", "revocation_endpoint", "userinfo_endpoint", "jwks_uri"} {
				for _, at := range []string{"https://evil.example/x", "https://" + host + ".evil.example/x", "https://" + host + ":8443/x"} {
					metadata(map[string]any{k: at})
					a := w.want(k, w.call("POST", oauthPath, "alice", connection(with{"provider": p})), 422, "VALIDATION_FAILED")
					if !strings.Contains(a.raw, "none of this preset's") {
						t.Errorf("%s: %s", k, a.raw)
					}
				}
			}
			metadata(map[string]any{"userinfo_endpoint": "https://" + map[string]string{"google": "openidconnect.googleapis.com", "microsoft": "graph.microsoft.com"}[name] + "/userinfo"})
			a := w.want("its own", w.call("POST", oauthPath, "alice", connection(with{"provider": p})), 201, "")
			if a.body["redirectUri"] != redirectBase+host {
				t.Errorf("%s", a.raw)
			}
			if w.idp.TrustedHosts() != nil {
				t.Errorf("%v", w.idp.TrustedHosts())
			}
		})
	}
}

// A machine makes and deletes no connection of a person's; a client's own is
// its to make.
func TestWhatAMachineMayDoToAConnection(t *testing.T) {
	w := newOAuthWorld(t)
	w.grantWrite("svc")
	del := func(as string) answer { return w.call("DELETE", envPath+"/values/"+mailItem, as, nil) }
	set := func(as string) answer {
		return w.call("POST", envPath+"/changes", as, map[string]any{"changes": []any{map[string]any{"op": "delete", "item": mailItem}}})
	}
	w.wantReason("make", w.call("POST", oauthPath, "svc", connection(nil)), 403, "PERMISSION_DENIED", "person-required")
	w.create(nil)
	w.want("one nobody connected", del("svc"), 204, "")
	w.create(nil)
	w.connect()
	gone := func(what string) {
		t.Helper()
		w.wantReason(what, del("svc"), 403, "PERMISSION_DENIED", "person-required")
		w.wantReason(what+", a change set", set("svc"), 403, "PERMISSION_DENIED", "person-required")
	}
	gone("connected")
	w.want("disconnect", w.call("POST", mailPath+"/disconnect", "svc", nil), 200, "")
	gone("disconnected")
	w.want("another client", w.call("PATCH", mailPath, "alice", map[string]any{"clientId": "other", "clientSecret": "x"}), 200, "")
	gone("changed")
	w.want("by a person", set("alice"), 200, "")
	w.want("a client's own", w.call("POST", oauthPath, "svc", connection(with{"grant": "client_credentials", "scopes": []string{"mail.send"}})), 201, "")
	w.token1("works", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
	w.want("and is deleted", del("svc"), 204, "")
}

// A secret given for one server is sent to no other, whoever changes what.
func TestAClientSecretIsForItsServer(t *testing.T) {
	w := newOAuthWorld(t)
	w.create(with{"provider": provided(nil), "scopes": []string{"mail.read"}})
	for what, p := range map[string]map[string]any{
		"token": provided(with{"tokenEndpoint": "https://idp.example/other"}), "revocation": provided(with{"revocationEndpoint": "https://idp.example/other"}),
		"userinfo": provided(with{"userinfoEndpoint": nil}), "authorization": provided(with{"authorizationEndpoint": "https://idp.example/other"}),
	} {
		a := w.want(what, w.call("PATCH", mailPath, "alice", map[string]any{"provider": p}), 422, "VALIDATION_FAILED")
		if !strings.Contains(a.raw, "clientSecret: needed") {
			t.Errorf("%s: %s", what, a.raw)
		}
	}
	// Given before somebody else changed the server: refused, with the version
	// it was given for.
	seen := w.status()["versionId"]
	w.want("a change", w.call("PATCH", mailPath, "alice", map[string]any{"clientSecret": "x", "provider": provided(with{"tokenEndpoint": "https://evil.example/token", "endpointHosts": []string{"idp.example"}})}), 200, "")
	w.want("the secret", w.call("PATCH", mailPath, "web", map[string]any{"clientSecret": oauthtest.Secret, "expectedVersionId": seen}), 409, "VERSION_CONFLICT")
	// Moved in the database, it opens for nothing else.
	w.exec("UPDATE value_versions SET payload = json_set(payload, '$.oauth.revocationEndpoint', 'https://evil.example/revoke') WHERE json_type(payload, '$.oauth') = 'object'")
	w.want("start", w.call("POST", mailPath+"/authorizations", "web", nil), 201, "")
	if w.idp.TrustedHosts() != nil {
		t.Errorf("%v", w.idp.TrustedHosts())
	}
}

// The metadata is not asked when connecting, nor when refreshing or
// disconnecting.
func TestDiscoveryIsOnceAtTheStart(t *testing.T) {
	w := newOAuthWorld(t)
	w.create(nil)
	w.idp.Set(func(p *oauthtest.Provider) {
		p.Metadata = map[string]any{}
		for _, k := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "revocation_endpoint", "jwks_uri"} {
			p.Metadata[k] = "https://evil.example/x"
		}
	})
	w.connect()
	w.later(2 * time.Hour)
	w.want("refresh", w.call("POST", mailPath+"/refresh", "alice", nil), 200, "")
	w.want("secret", w.call("PATCH", mailPath, "alice", map[string]any{"clientSecret": oauthtest.Secret, "scopes": []string{"openid"}}), 200, "")
	w.connect()
	if a := w.want("disconnect", w.call("POST", mailPath+"/disconnect", "alice", nil), 200, ""); a.body["atProvider"] != "revoked" {
		t.Errorf("%s", a.raw)
	}
	if got := w.idp.TrustedHosts(); !slices.Equal(got, []string{"idp.example"}) {
		t.Errorf("%v", got)
	}
}

// Whose account it was stays through a change of the client or the provider.
func TestAnotherAccountAfterAChange(t *testing.T) {
	w := connected(t, nil)
	w.want("pause", w.call("PATCH", mailPath, "web", map[string]any{"paused": true}), 200, "")
	w.want("disconnect", w.call("POST", mailPath+"/disconnect", "web", nil), 200, "")
	w.want("away", w.call("PATCH", mailPath, "web", map[string]any{"clientId": "other", "clientSecret": "x"}), 200, "")
	back1 := w.want("back", w.call("PATCH", mailPath, "web", map[string]any{"clientId": oauthtest.ClientID, "clientSecret": oauthtest.Secret}), 200, "")
	if back1.body["paused"] != true || fmt.Sprint(back1.body["account"]) != "map[id:sub-alice label:alice@example.com]" || back1.body["hasRefreshToken"] != false {
		t.Errorf("%s", back1.raw)
	}
	w.want("resume", w.call("PATCH", mailPath, "web", map[string]any{"paused": false}), 200, "")
	w.idp.Set(func(p *oauthtest.Provider) {
		p.Account = oauthtest.Account{Sub: "sub-mallory", Email: "mallory@example.com"}
	})
	_, back := w.begin("web", nil)
	if a := w.complete("web", answerOf(back)); a.body["reason"] != "account-mismatch" {
		t.Errorf("%s", a.raw)
	}
	_, back = w.begin("web", map[string]any{"confirmAccountChange": true})
	if a := w.complete("web", answerOf(back)); a.body["outcome"] != "connected" {
		t.Errorf("%s", a.raw)
	}
	w.wantEvent("sync.connection_credential_replaced", "Alice", nil, map[string]any{"accountChanged": true, "previousAccount": "alice@example.com", "account": "mallory@example.com"})
}

// For a longer validity, the provider is asked once a minute at most.
func TestMinValidityAsksOnceAMinute(t *testing.T) {
	for _, mv := range []int{3600, 3599, 86_400} {
		w := connected(t, nil)
		c := w.mailCapability("broker", nil)
		events := func() string { return w.events("sync.connection_credential_replaced") }
		n, e := w.idp.Count("refresh_token"), events()
		w.later(2 * time.Second)
		for range 10 {
			a := w.exerciseMail("broker", c, with{"minValiditySeconds": mv})
			if mv >= 3600 {
				w.wantReason("never", a, 422, "VALIDATION_FAILED", "min-validity-too-long")
			} else {
				w.wantReason("not now", a, 429, "RATE_LIMITED", "connection-unavailable")
				if after := a.body["error"].(map[string]any)["details"].(map[string]any)["retryAfterSeconds"].(float64); after < 50 || after > 60 || !strings.Contains(a.raw, "just-refreshed") {
					t.Errorf("%s", a.raw)
				}
			}
			w.later(100 * time.Millisecond)
		}
		if got := w.idp.Count("refresh_token") - n; got != 0 || events() != e {
			t.Errorf("%d: %d refreshes", mv, got)
		}
		// Ten minutes of it, every second.
		for range 600 {
			w.later(time.Second)
			w.exerciseMail("broker", c, with{"minValiditySeconds": mv})
		}
		if got := w.idp.Count("refresh_token") - n; got < 1 || got > 10 {
			t.Errorf("%d: %d refreshes in ten minutes", mv, got)
		}
		// What lasts as long is given, whoever asks for more.
		w.token1("an ordinary one", w.exerciseMail("broker", c, with{"minValiditySeconds": 600}))
	}
	// A short life is asked for in its own measure.
	w := connected(t, nil)
	w.idp.Set(func(p *oauthtest.Provider) { p.ExpiresIn = "90" })
	w.want("refresh", w.call("POST", mailPath+"/refresh", "alice", nil), 200, "")
	c := w.mailCapability("broker", nil)
	w.later(31 * time.Second)
	if got := w.token1("a minute of 90 seconds", w.exerciseMail("broker", c, with{"minValiditySeconds": 60})); got["expiresInSeconds"].(float64) < 88 {
		t.Errorf("%v", got)
	}
}

// Keeping a refresh token ends with the life it was said to have, and is not
// done for one that a use does not keep.
func TestKeepaliveEndsWithTheToken(t *testing.T) {
	hour := func(w *world) int {
		n := w.idp.Count("refresh_token")
		for range 60 {
			w.later(time.Minute)
			if err := w.oauth.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		return w.idp.Count("refresh_token") - n
	}
	// Said once, not replaced, and accepted ever after.
	w := newOAuthWorld(t)
	w.idp.Set(func(p *oauthtest.Provider) { p.RefreshExpiresIn, p.Rotate = "86400", false })
	w.create(nil)
	w.connect()
	total := 0
	for range 48 {
		total += hour(w)
	}
	if total != 1 {
		t.Errorf("%d refreshes nobody asked for, of one whose end does not move", total)
	}
	w.token1("it still works when it is asked for", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
	// Every use gives it another while: kept.
	w = newOAuthWorld(t)
	w.idp.Set(func(p *oauthtest.Provider) { p.RefreshExpiresIn = "3600" })
	w.create(nil)
	w.connect()
	if n := hour(w) + hour(w); n != 3 && n != 2 {
		t.Errorf("%d refreshes in two hours of one that lasts one", n)
	}
	// One that says what is left of a day, replaced at each use or not.
	w = newOAuthWorld(t)
	end := w.now().Add(24 * time.Hour)
	left := func(p *oauthtest.Provider) {
		p.RefreshExpiresIn = fmt.Sprint(max(1, int64(end.Sub(w.now())/time.Second)))
	}
	w.idp.Set(left)
	w.create(nil)
	w.connect()
	n := w.idp.Count("refresh_token")
	for range 25 * 6 {
		w.later(10 * time.Minute)
		w.idp.Set(left)
		if err := w.oauth.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.idp.Count("refresh_token") - n; got != 1 {
		t.Errorf("%d refreshes of one that ends in a day whatever it is used for", got)
	}
	// One that says a second each time, or a minute.
	for _, life := range []string{"1", "60"} {
		w = newOAuthWorld(t)
		w.idp.Set(func(p *oauthtest.Provider) { p.RefreshExpiresIn = life })
		w.create(nil)
		w.connect()
		if n := hour(w); n != 0 {
			t.Errorf("%d refreshes in an hour of one that lasts %s s", n, life)
		}
	}
}

// copies puts n rows beside the connection, due long ago, in an environment
// that is made as how says: ones that cannot be refreshed.
func (w *world) copies(n int, env, name string) {
	w.t.Helper()
	v := w.text("SELECT value_id FROM oauth_connections ORDER BY connected_at IS NULL LIMIT 1")
	for i := range n {
		x := fmt.Sprintf("%s%03d", name, i)
		w.exec("INSERT INTO env_values (id, environment_id, item_name, deleted_at) VALUES (?, ?, ?, 1)", "val_"+x, env, strings.ToUpper(x))
		w.exec("INSERT INTO value_versions (id, value_id, payload, wrapped_dek) SELECT ?, ?, s.payload, s.wrapped_dek FROM value_versions s JOIN env_values e ON e.current_version_id = s.id WHERE e.id = ?", "ver_"+x, "val_"+x, v)
		w.exec("UPDATE env_values SET current_version_id = ? WHERE id = ?", "ver_"+x, "val_"+x)
		w.exec("INSERT INTO oauth_connections (value_id, version_id, status, keepalive_at, refresh_token) SELECT ?, ?, 'connected', 1, refresh_token FROM oauth_connections WHERE value_id = ?", "val_"+x, "ver_"+x, v)
	}
}

// otherOrg makes an Organization with an environment of its own, and answers
// both.
func (w *world) otherOrg(name string) (org, env string) {
	w.exec("INSERT INTO organizations (id, slug, name, wrapped_org_kek) SELECT ?, ?, name, wrapped_org_kek FROM organizations WHERE slug = 'cap'", "org_"+name, name)
	w.exec("INSERT INTO projects (id, organization_id, slug, name, contract_authority) VALUES (?, ?, 'p', 'p', 'managed')", "prj_"+name, "org_"+name)
	w.exec("INSERT INTO environments (id, project_id, name, kind, tier) VALUES (?, ?, 'e', 'shared', 'development')", "env_"+name, "prj_"+name)
	return "org_" + name, "env_" + name
}

// What cannot be refreshed, and what is slow, holds up nobody else's.
func TestKeepaliveIsNotHeldUp(t *testing.T) {
	newDue := func(t *testing.T) *world {
		w := connected(t, with{"provider": map[string]any{"preset": "generic", "issuer": oauthtest.Issuer, "refreshTokenIdleDays": 90}})
		return w
	}
	due := func(w *world) { w.later(61 * 24 * time.Hour) }
	for what, dead := range map[string]func(w *world, org, env string){
		"an expired environment": func(w *world, _, env string) { w.exec("UPDATE environments SET expires_at = 5 WHERE id = ?", env) },
		"a deleted environment":  func(w *world, _, env string) { w.exec("UPDATE environments SET deleted_at = 5 WHERE id = ?", env) },
		"a frozen Organization": func(w *world, org, _ string) {
			w.exec("INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ('ofz_x', ?, ?, 1, 'drill')", org, w.idn("Alice"))
		},
		"a newer Varlatch's": func(w *world, _, _ string) {
			w.exec("UPDATE value_versions SET payload = json_set(payload, '$.oauth.v', 2) WHERE id LIKE 'ver_dead%'")
		},
		// Not seen by the query: refused when it is tried.
		"rows that open nothing": func(*world, string, string) {},
		"ones being refreshed": func(w *world, _, _ string) {
			w.exec("UPDATE oauth_connections SET claim_id = 'ocl_x', claim_until = 9000000000000000 WHERE value_id LIKE 'val_dead%'")
		},
	} {
		t.Run(what, func(t *testing.T) {
			w := newDue(t)
			org, env := w.otherOrg("dead")
			w.copies(510, env, "dead")
			dead(w, org, env)
			due(w)
			if err := w.oauth.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if n := w.idp.Count("refresh_token"); n != 1 {
				t.Errorf("%d refreshes of the live one in the first pass", n)
			}
			w.wantStatus("connected", nil)
		})
	}
	// In its own Organization it has its turn too: what was refused is later
	// in line.
	w := newDue(t)
	w.copies(50, w.env("development"), "dead")
	due(w)
	for range 3 {
		if err := w.oauth.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := w.idp.Count("refresh_token"); n != 1 {
		t.Errorf("%d refreshes after three passes", n)
	}
	// Another Organization's that take their time.
	w = newDue(t)
	w.oauth.Wait = 3 * time.Second
	org, env := w.otherOrg("slow")
	w.copies(40, env, "slow")
	due(w)
	_, release, err := w.oauth.Writer.Gates.Acquire(context.Background(), write.Organization(org, write.Exclusive))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() { _ = w.oauth.RunOnce(ctx) })
	for i := 0; w.idp.Count("refresh_token") == 0; i++ {
		if i > 200 {
			t.Fatal("not refreshed while another Organization's wait")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	release()
	wg.Wait()
}

// A refresh that waited for its turn has its whole time for the answer, and
// keeps it.
func TestAnAnswerAfterALongWaitIsKept(t *testing.T) {
	w := connected(t, nil)
	w.oauth.GateWait = time.Second
	v := w.text("SELECT value_id FROM oauth_connections")
	w.later(2 * time.Hour)
	_, release, err := w.oauth.Writer.Gates.Acquire(context.Background(), write.Resource("oauth_connection", v))
	if err != nil {
		t.Fatal(err)
	}
	w.idp.Set(func(p *oauthtest.Provider) { p.Delay = 1200 * time.Millisecond })
	ctx, gone := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() { _ = w.oauth.Refresh(ctx, v, 1) })
	}
	time.Sleep(700 * time.Millisecond)
	release()
	time.Sleep(200 * time.Millisecond)
	gone() // whoever asked
	wg.Wait()
	w.oauth.Close()
	w.restart()
	if n := w.idp.Count("refresh_token"); n != 1 {
		t.Errorf("%d refreshes", n)
	}
	if st := w.text("SELECT status || ' ' || generation || ' ' || unanswered FROM oauth_connections"); st != "connected 2 0" {
		t.Error(st)
	}
	w.idp.Set(func(p *oauthtest.Provider) { p.Delay = 0 })
	w.token1("its token", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
	// One that never had its turn sent nothing.
	w.later(2 * time.Hour)
	w.oauth.GateWait = 200 * time.Millisecond
	_, release, err = w.oauth.Writer.Gates.Acquire(context.Background(), write.Resource("oauth_connection", v))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.oauth.Refresh(context.Background(), v, 2); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Errorf("%v", err)
	}
	release()
	if n := w.idp.Count("refresh_token"); n != 1 {
		t.Errorf("%d refreshes", n)
	}
}

// A connection that is connected again, or changed, between an exercise's
// decision and its job: what is given is what is there then, and recorded.
func TestATokenReplacedWhileItIsGiven(t *testing.T) {
	const columns = "version_id, generation, access_token, access_expires_at, access_lifetime, refresh_token, account, account_label, status"
	row := func(w *world) string {
		return w.text("SELECT json_array(" + columns + ") FROM oauth_connections")
	}
	put := "UPDATE oauth_connections SET (" + columns + ") = (SELECT "
	for i := range strings.Split(columns, ", ") {
		put += fmt.Sprintf("json_extract(?1, '$[%d]'), ", i)
	}
	put = strings.TrimSuffix(put, ", ") + ")"
	for what, change := range map[string]func(w *world){
		"another account": func(w *world) {
			w.idp.Set(func(p *oauthtest.Provider) { p.Account = oauthtest.Account{Sub: "sub-bob", Email: "bob@example.com"} })
			_, back := w.begin("web", map[string]any{"confirmAccountChange": true})
			w.want("complete", w.complete("web", answerOf(back)), 200, "")
		},
		"refreshed": func(w *world) { w.want("refresh", w.call("POST", mailPath+"/refresh", "alice", nil), 200, "") },
		"changed": func(w *world) {
			w.want("change", w.call("PATCH", mailPath, "alice", map[string]any{"scopes": []string{"openid"}}), 200, "")
		},
	} {
		t.Run(what, func(t *testing.T) {
			w := connected(t, nil)
			c := w.mailCapability("broker", with{"singleUse": true})
			value := "SELECT current_version_id FROM env_values WHERE item_name = '" + mailItem + "' AND environment_id = '" + w.env("development") + "'"
			old, oldVersion := row(w), w.text(value)
			change(w)
			next, nextVersion := row(w), w.text(value)
			want := w.token1("what is there", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))["value"]
			w.exec(put, old)
			w.exec("UPDATE env_values SET current_version_id = ? WHERE item_name = ? AND environment_id = ?", oldVersion, mailItem, w.env("development"))
			was := w.token1("what was", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))["value"]
			if what != "changed" && was == want {
				t.Fatal("no other token")
			}
			// The writer is held while the exercise decides.
			held, free := make(chan struct{}), make(chan struct{})
			var wg sync.WaitGroup
			wg.Go(func() {
				if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
					close(held)
					<-free
					if _, err := tx.ExecContext(context.Background(), put, next); err != nil {
						return err
					}
					_, err := tx.ExecContext(context.Background(), "UPDATE env_values SET current_version_id = ? WHERE item_name = ? AND environment_id = ?", nextVersion, mailItem, w.env("development"))
					return err
				}); err != nil {
					t.Error(err)
				}
			})
			<-held
			var got answer
			wg.Go(func() { got = w.exerciseMail("broker", c, nil) })
			time.Sleep(300 * time.Millisecond)
			close(free)
			wg.Wait()
			tok := w.token1("given", got)
			if tok["value"] != want || tok["versionId"] != nextVersion {
				t.Errorf("another token was given than is there: version %v, want %s", tok["versionId"], nextVersion)
			}
			w.wantEvent("capability.exercised", "broker", map[string]any{"capabilityId": c.id}, map[string]any{"items": mailItem + "@" + nextVersion})
		})
	}
}
