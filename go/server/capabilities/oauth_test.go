// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/oauth"
	"github.com/varlatch/varlatch/go/server/oauth/oauthtest"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/write"
)

// OAuth connections (ADR-0062), over HTTP, on the parity fixture's rows,
// against a fake provider (server/oauth/oauthtest).

const (
	mailItem  = "MAIL_TOKEN"
	mailPlace = "header:authorization"
	oauthPath = envPath + "/oauth-connections"
	mailPath  = oauthPath + "/" + mailItem
)

// newOAuthWorld is a world with a provider, and two browser sessions: web
// (Alice's), web2 (Alice's other one) and bobweb.
func newOAuthWorld(t *testing.T) *world {
	t.Helper()
	idp := oauthtest.New()
	t.Cleanup(idp.Close)
	w := newWorld(t)
	w.stop()
	w.idp, w.names = idp, map[string]string{}
	idp.Now = w.now
	w.start()
	for name, who := range map[string][2]string{"web": {"Alice", "ses_alice"}, "web2": {"Alice", "ses_alice2"}, "bobweb": {"bob", "ses_bob"}} {
		token := "vlt_web_" + name + strings.Repeat("x", 40)
		w.exec("INSERT INTO credentials (id, identity_id, kind, token_hash, auth_session_id) VALUES (?, ?, 'browser', ?, ?)",
			"crd_"+name, w.idn(who[0]), auth.HashToken(token), who[1])
		w.f.Tokens[name] = token
	}
	return w
}

// connection is a body that makes the connection at the fake provider.
func connection(more with) map[string]any {
	b := map[string]any{"item": mailItem, "provider": map[string]any{"preset": "generic", "issuer": oauthtest.Issuer}, "clientId": oauthtest.ClientID,
		"clientSecret": oauthtest.Secret, "scopes": []string{"openid", "mail.read"}}
	for k, v := range more {
		b[k] = v
		if v == nil {
			delete(b, k)
		}
	}
	return b
}

func (w *world) create(more with) answer {
	w.t.Helper()
	return w.want("create", w.call("POST", oauthPath, "alice", connection(more)), 201, "")
}

// begin begins an authorization, and consents to it at the provider.
func (w *world) begin(as string, body any) (answer, *url.URL) {
	w.t.Helper()
	a := w.want("start", w.call("POST", mailPath+"/authorizations", as, body), 201, "")
	back, err := w.idp.Consent(a.body["authorizationUrl"].(string))
	if err != nil {
		w.t.Fatal(err)
	}
	return a, back
}

// answerOf is what the dashboard's page sends on from its address.
func answerOf(back *url.URL) map[string]any {
	v, at := back.Query(), *back
	at.RawQuery = ""
	out := map[string]any{"redirectUri": at.String()}
	for _, k := range []string{"state", "code", "error", "iss"} {
		if v.Has(k) {
			out[k] = v.Get(k)
		}
	}
	return out
}

func (w *world) complete(as string, body map[string]any) answer {
	return w.call("POST", mailPath+"/authorizations/complete", as, body)
}

// connect connects the connection, as Alice in her session.
func (w *world) connect() answer {
	w.t.Helper()
	_, back := w.begin("web", nil)
	a := w.want("complete", w.complete("web", answerOf(back)), 200, "")
	if a.body["outcome"] != "connected" {
		w.t.Fatalf("%s", a.raw)
	}
	return a
}

// connected is a world with the connection connected.
func connected(t *testing.T, more with) *world {
	t.Helper()
	w := newOAuthWorld(t)
	w.create(more)
	w.connect()
	return w
}

func (w *world) status() map[string]any {
	w.t.Helper()
	return w.want("get", w.call("GET", mailPath, "alice", nil), 200, "").body
}

func (w *world) wantStatus(status string, reason any) map[string]any {
	w.t.Helper()
	got := w.status()
	if got["status"] != status || reason != any("*") && got["reason"] != reason {
		w.t.Fatalf("status %v, reason %v; want %s, %v", got["status"], got["reason"], status, reason)
	}
	return got
}

func (w *world) mailCapability(as string, more with) capability {
	w.t.Helper()
	b := with{"items": []string{mailItem}, "targets": map[string]any{mailItem: []string{mailPlace}}, "ttlSeconds": 86_400}
	for k, v := range more {
		b[k] = v
	}
	return w.issue(as, b)
}

func (w *world) exerciseMail(as string, c capability, more with) answer {
	b := with{"placements": []any{map[string]any{"item": mailItem, "target": mailPlace}}}
	for k, v := range more {
		b[k] = v
	}
	return w.exercise(as, c, b)
}

// token1 is the one item of an exercise's answer.
func (w *world) token1(what string, a answer) map[string]any {
	w.t.Helper()
	w.want(what, a, 200, "")
	items, _ := a.body["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["kind"] != "oauth" {
		w.t.Fatalf("%s: %s", what, a.raw)
	}
	return items[0].(map[string]any)
}

func (w *world) wantReason(what string, a answer, status int, code, reason string) answer {
	w.t.Helper()
	w.want(what, a, status, code)
	if !strings.Contains(a.raw, `"reason":"`+reason+`"`) {
		w.t.Fatalf("%s: %s, want %s", what, a.raw, reason)
	}
	return a
}

// later moves the clock.
func (w *world) later(d time.Duration) { w.ahead.Add(int64(d)) }

// noSecrets fails when text holds anything the provider ever gave out, or
// the client secret; access tokens too, unless they are allowed there.
func (w *world) noSecrets(what, text string, accessAllowed bool) {
	w.t.Helper()
	access, others := w.idp.Secrets()
	if !accessAllowed {
		others = append(others, access...)
	}
	for _, s := range others {
		if strings.Contains(text, s) {
			w.t.Errorf("%s holds %s", what, s)
		}
	}
}

// noSecretsKept looks through every audit event, and every column of the
// database there is, for one in clear.
func (w *world) noSecretsKept() {
	w.t.Helper()
	tables := paritytest.Rows(w.t, w.store, "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
	for _, r := range tables {
		for _, row := range paritytest.Rows(w.t, w.store, "SELECT * FROM "+r["name"].(string)) {
			w.noSecrets("the table "+r["name"].(string), fmt.Sprint(row), false)
		}
	}
}

// ---------------------------------------------------------------------------

func TestConnectAndExercise(t *testing.T) {
	w := newOAuthWorld(t)
	var log syncBuffer
	w.stop()
	w.log = &log
	w.start()
	made := w.create(with{"hosts": []string{"api.example.com"}})
	w.noSecrets("the answer to a creation", made.raw, false)
	if made.body["status"] != "not_connected" || made.body["hasClientSecret"] != true || made.body["redirectUri"] != "http://127.0.0.1:8686/oauth/callback/idp.example" {
		t.Errorf("%s", made.raw)
	}
	pr := made.body["provider"].(map[string]any)
	if pr["tokenEndpoint"] != "https://idp.example/token" || pr["tokenEndpointAuthMethod"] != "client_secret_basic" {
		t.Errorf("%s", made.raw)
	}
	w.wantEvent("value.written", "Alice", map[string]any{"itemName": mailItem, "versionId": made.body["versionId"]},
		map[string]any{"oauth": true, "server": "idp.example", "clientId": oauthtest.ClientID, "sensitive": true})
	c := w.mailCapability("broker", nil)
	w.wantReason("not connected", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED", "connection-not-connected")
	got := w.connect().body["connection"].(map[string]any)
	if got["status"] != "connected" || fmt.Sprint(got["account"]) != "map[id:sub-alice label:alice@example.com]" || got["connectedBy"] != w.idn("Alice") ||
		got["hasRefreshToken"] != true || fmt.Sprint(got["missingScopes"]) != "[]" {
		t.Errorf("%v", got)
	}
	w.wantEvent("sync.connection_created", "Alice", map[string]any{"itemName": mailItem}, map[string]any{"connection": "oauth", "outcome": "connected", "account": "alice@example.com"})
	if r := w.idp.Last(); !r.Basic || r.Form.Get("code_verifier") == "" || r.Form.Get("client_secret") != "" || r.Form.Get("client_id") != "" {
		t.Errorf("the code's exchange: %+v", r)
	}
	a := w.exerciseMail("broker", c, nil)
	tok := w.token1("exercise", a)
	if !w.idp.Live(tok["value"].(string)) || tok["versionId"] != made.body["versionId"] || tok["expiresAt"] != got["accessTokenExpiresAt"] {
		t.Errorf("%v", tok)
	}
	if left := tok["expiresInSeconds"].(float64); left < 3590 || left > 3600 {
		t.Errorf("%v seconds", left)
	}
	w.noSecrets("an exercise", a.raw, true)
	w.wantEvent("capability.exercised", "broker", map[string]any{"capabilityId": c.id}, map[string]any{
		"items": mailItem + "@" + made.body["versionId"].(string), "oauthTokens": mailItem + "@" + made.body["versionId"].(string) + "#1=" + got["accessTokenExpiresAt"].(string)})
	// Again: the same token, nothing asked of the provider.
	if again := w.token1("again", w.exerciseMail("broker", c, nil)); again["value"] != tok["value"] || w.idp.Count("refresh_token") != 0 {
		t.Errorf("%v", again)
	}
	// Its last minute: another one.
	w.later(59*time.Minute + 5*time.Second)
	next := w.token1("in its last minute", w.exerciseMail("broker", c, nil))
	if next["value"] == tok["value"] || w.idp.Count("refresh_token") != 1 || !w.idp.Live(next["value"].(string)) {
		t.Errorf("%v", next)
	}
	// A use by Varlatch of its own: no actor.
	e := w.event("sync.connection_credential_replaced")
	if e["actor_identity_id"] != nil || !strings.Contains(fmt.Sprint(e["metadata"]), "refreshed") {
		t.Errorf("%v", e)
	}
	// Placed beside a value.
	both := w.issue("broker", with{"items": []string{mailItem, "SECRET_A"}, "targets": map[string]any{mailItem: []string{mailPlace}, "SECRET_A": []string{"header:x-a"}}})
	b := w.want("both", w.exercise("broker", both, with{"placements": []any{map[string]any{"item": mailItem, "target": mailPlace}, map[string]any{"item": "SECRET_A", "target": "header:x-a"}}}), 200, "")
	if items := b.body["items"].([]any); len(items) != 2 || items[0].(map[string]any)["value"] != "a-secret" || items[1].(map[string]any)["value"] != next["value"] {
		t.Errorf("%s", b.raw)
	}
	w.noSecrets("the log", log.String(), false)
	w.noSecretsKept()
}

func TestMinValidityRefreshesFirst(t *testing.T) {
	w := connected(t, nil)
	c := w.mailCapability("broker", with{"singleUse": true})
	first := w.token1("another", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
	w.later(40 * time.Minute)
	got := w.token1("30 minutes", w.exerciseMail("broker", c, with{"minValiditySeconds": 1800}))
	if got["value"] == first["value"] || got["expiresInSeconds"].(float64) < 3500 {
		t.Errorf("%v", got)
	}
	w.wantEvent("capability.exercised", "broker", nil, map[string]any{"minValiditySeconds": 1800, "singleUse": true})
	// More than the provider's tokens last: refused, the single use not
	// spent, and not asked of the provider each time.
	c = w.mailCapability("broker", with{"singleUse": true})
	n := w.idp.Count("refresh_token")
	for range 3 {
		w.wantReason("two hours", w.exerciseMail("broker", c, with{"minValiditySeconds": 7200}), 422, "VALIDATION_FAILED", "min-validity-too-long")
	}
	if got := w.idp.Count("refresh_token") - n; got > 1 {
		t.Errorf("refreshed %d times for it", got)
	}
	w.token1("the single use", w.exerciseMail("broker", c, nil))
	w.wantReason("twice", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED", "already-used")
	// A provider that says nothing of it, and one that says how long in text.
	w.idp.Set(func(p *oauthtest.Provider) { p.ExpiresIn = "" })
	w.later(2 * time.Hour)
	if got := w.token1("no expiry", w.exerciseMail("broker", w.mailCapability("broker", nil), with{"minValiditySeconds": 600})); got["expiresAt"] != nil || got["expiresInSeconds"] != nil {
		t.Errorf("%v", got)
	}
	w.later(1000 * time.Hour)
	n = w.idp.Count("refresh_token")
	w.token1("still", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
	if w.idp.Count("refresh_token") != n {
		t.Error("refreshed a token without an expiry")
	}
	w.idp.Set(func(p *oauthtest.Provider) { p.ExpiresIn = `"120"` })
	w.want("refresh", w.call("POST", mailPath+"/refresh", "alice", nil), 200, "")
	if got := w.token1("in text", w.exerciseMail("broker", w.mailCapability("broker", nil), nil)); got["expiresInSeconds"].(float64) > 120 {
		t.Errorf("%v", got)
	}
}

// Many at once while the token has ended: one refresh, and everyone gets its
// token.
func TestOneRefreshServesAll(t *testing.T) {
	w := connected(t, nil)
	w.check = false
	caps := []capability{w.mailCapability("broker", nil), w.mailCapability("broker2", nil)}
	w.later(2 * time.Hour)
	hold := make(chan struct{})
	w.idp.Set(func(p *oauthtest.Provider) { p.Hold = hold })
	const n = 40
	got := make([]answer, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { got[i] = w.exerciseMail([]string{"broker", "broker2"}[i%2], caps[i%2], nil) })
	}
	for w.idp.Count("refresh_token") == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	if s := w.status()["status"]; s != "refreshing" {
		t.Errorf("%v while it refreshes", s)
	}
	close(hold)
	wg.Wait()
	first := ""
	for i, a := range got {
		v := w.token1(fmt.Sprint(i), a)["value"].(string)
		if first == "" {
			first = v
		}
		if v != first {
			t.Errorf("another token: %s, %s", v, first)
		}
	}
	if c := w.idp.Count("refresh_token"); c != 1 {
		t.Errorf("%d refreshes", c)
	}
	if w.events("sync.connection_credential_replaced") != "1" {
		t.Error("more than one event")
	}
}

// Two processes on one database: one refresh, the other waits for it.
func TestTwoProcessesRefreshOnce(t *testing.T) {
	w := connected(t, nil)
	w.later(2 * time.Hour)
	store, err := storage.Open(context.Background(), storage.Options{Path: w.db})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	other := &oauth.Service{Writer: &write.Writer{Store: store, Gates: write.NewGates()}, RootKEK: w.rootKEK, Policy: w.policy, Now: w.now}
	defer other.Close()
	w.idp.Set(func(p *oauthtest.Provider) { p.Delay = 300 * time.Millisecond })
	id := w.text("SELECT value_id FROM oauth_connections")
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			s := w.oauth
			if i%2 == 1 {
				s = other
			}
			errs[i] = s.Refresh(context.Background(), id, 1)
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("%d: %v", i, err)
		}
	}
	if c := w.idp.Count("refresh_token"); c != 1 {
		t.Errorf("%d refreshes", c)
	}
	w.token1("after", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
	w.wantStatus("connected", nil)
}

// The points a process may end at around a refresh. What is stored is always
// a refresh token that may still be good: the one used until the job that
// stores the answer, the answer's from then on.
func TestAProcessThatEndsDuringARefresh(t *testing.T) {
	for _, point := range []string{"claimed", "answered", "stored"} {
		for _, grace := range []time.Duration{0, 10 * time.Minute} {
			t.Run(fmt.Sprint(point, grace), func(t *testing.T) {
				w := connected(t, nil)
				w.idp.Set(func(p *oauthtest.Provider) { p.Grace = grace })
				c := w.mailCapability("broker", nil)
				w.later(2 * time.Hour)
				oauth.CrashAt(w.oauth, func(p string) bool { return p == point })
				w.check = false
				w.exerciseMail("broker", c, nil)
				w.check = true
				w.restart()
				if point == "stored" {
					w.token1("after it", w.exerciseMail("broker", c, nil))
					if n := w.idp.Count("refresh_token"); n != 1 {
						t.Errorf("%d refreshes", n)
					}
					return
				}
				// Its claim is still there: nobody else asks, until it is over.
				n := w.idp.Count("refresh_token")
				claim := w.wantReason("while it is claimed", w.refusedSoon(c), 429, "RATE_LIMITED", "connection-unavailable")
				if !strings.Contains(claim.raw, `"cause":"refreshing"`) || w.idp.Count("refresh_token") != n {
					t.Errorf("%s", claim.raw)
				}
				w.later(31 * time.Second)
				a := w.exerciseMail("broker", c, nil)
				switch {
				case point == "claimed" || grace > 0:
					w.token1("again", a)
					w.wantStatus("connected", nil)
					if !strings.Contains(fmt.Sprint(w.event("sync.connection_credential_replaced")["metadata"]), "afterLostAnswer") {
						t.Error("the lost answer is not in the event")
					}
				default:
					// The provider replaced the refresh token, and takes a second use
					// of it for a theft: nothing but a person helps.
					w.wantReason("reused", a, 403, "PERMISSION_DENIED", "connection-needs-reconnect")
					w.wantStatus("needs_reconnect", "refresh-answer-lost")
					w.connect()
					w.token1("connected again", w.exerciseMail("broker", c, nil))
				}
				w.noSecretsKept()
			})
		}
	}
}

// refusedSoon is an exercise that does not wait long for a claim of another
// process: its clock does not move while it waits.
func (w *world) refusedSoon(c capability) answer {
	w.oauth.Wait = time.Second
	return w.exerciseMail("broker", c, nil)
}

func TestALostAnswer(t *testing.T) {
	for _, grace := range []time.Duration{0, time.Minute} {
		w := connected(t, nil)
		w.idp.Set(func(p *oauthtest.Provider) { p.Lose, p.Grace = true, grace })
		c := w.mailCapability("broker", with{"singleUse": true})
		w.later(2 * time.Hour)
		a := w.wantReason("lost", w.exerciseMail("broker", c, nil), 429, "RATE_LIMITED", "connection-unavailable")
		after := a.body["error"].(map[string]any)["details"].(map[string]any)["retryAfterSeconds"].(float64)
		if after < 1 || after > 6 {
			t.Errorf("retry after %v s: a provider's leeway is short", after)
		}
		w.wantStatus("failing", "unreachable")
		w.idp.Set(func(p *oauthtest.Provider) { p.Lose = false })
		w.wantReason("before its time", w.exerciseMail("broker", c, nil), 429, "RATE_LIMITED", "connection-unavailable")
		w.later(6 * time.Second)
		a = w.exerciseMail("broker", c, nil)
		if grace > 0 {
			w.token1("the retry", a)
			w.wantStatus("connected", nil)
			continue
		}
		w.wantReason("reuse detected", a, 403, "PERMISSION_DENIED", "connection-needs-reconnect")
		w.wantStatus("needs_reconnect", "refresh-answer-lost")
		w.wantEvent1("sync.connection_checked", map[string]any{"outcome": "needs-reconnect", "reason": "refresh-answer-lost"})
		// The single use is not spent by any of it.
		w.connect()
		w.token1("after it was connected again", w.exerciseMail("broker", c, nil))
	}
}

// wantEvent1 is wantEvent for an event of Varlatch's own.
func (w *world) wantEvent1(typ string, metadata map[string]any) {
	w.t.Helper()
	e := w.event(typ)
	got, _ := e["metadata"].(map[string]any)
	if got == nil {
		_ = json.Unmarshal([]byte(fmt.Sprint(e["metadata"])), &got)
	}
	for k, v := range metadata {
		if fmt.Sprint(got[k]) != fmt.Sprint(v) {
			w.t.Errorf("%s: %s is %v, want %v", typ, k, got[k], v)
		}
	}
}

// What a provider may do wrong at a refresh: nothing of it is kept, the
// tokens stay, and it is tried again later, with the token there is while it
// lasts.
func TestARefreshThatFails(t *testing.T) {
	for reason, set := range map[string]func(*oauthtest.Provider){
		"server-error": func(p *oauthtest.Provider) { p.Status, p.Body = 502, "echo at.1.secret" },
		"rate-limited": func(p *oauthtest.Provider) { p.Status, p.Header = 429, http.Header{"Retry-After": {"90"}} },
		"redirect": func(p *oauthtest.Provider) {
			p.Status, p.Header = 307, http.Header{"Location": {"https://evil.example/token"}}
		},
		"bad-answer":              func(p *oauthtest.Provider) { p.Body = "<html>" },
		"answer-too-large":        func(p *oauthtest.Provider) { p.Body = `{"access_token":"` + strings.Repeat("x", 300<<10) + `"}` },
		"invalid_client":          func(p *oauthtest.Provider) { p.Status, p.Body = 401, `{"error":"invalid_client"}` },
		"temporarily_unavailable": func(p *oauthtest.Provider) { p.Status, p.Body = 400, `{"error":"temporarily_unavailable"}` },
	} {
		t.Run(reason, func(t *testing.T) {
			w := connected(t, nil)
			c := w.mailCapability("broker", nil)
			before := w.token1("before", w.exerciseMail("broker", c, nil))
			w.idp.Set(set)
			// Half an hour left: good enough for what asks for nothing, served
			// from what there is when the refresh it asks for fails.
			w.later(30 * time.Minute)
			w.wantReason("45 minutes", w.exerciseMail("broker", c, with{"minValiditySeconds": 2700}), 429, "RATE_LIMITED", "connection-unavailable")
			st := w.wantStatus("failing", reason)
			if st["retryAt"] == nil || st["hasRefreshToken"] != true {
				t.Errorf("%v", st)
			}
			if got := w.token1("what there is", w.exerciseMail("broker", c, nil)); got["value"] != before["value"] {
				t.Errorf("%v", got)
			}
			w.wantEvent1("sync.connection_checked", map[string]any{"outcome": "failing", "reason": reason})
			// Not asked again before its time, and the event not repeated.
			n := w.idp.Count("refresh_token")
			w.want("at once", w.exerciseMail("broker", c, with{"minValiditySeconds": 2700}), 429, "RATE_LIMITED")
			if w.idp.Count("refresh_token") != n {
				t.Error("asked again at once")
			}
			w.later(2 * time.Minute)
			a := w.want("later", w.exerciseMail("broker", c, with{"minValiditySeconds": 2700}), 429, "RATE_LIMITED")
			if w.idp.Count("refresh_token") != n+1 || w.events("sync.connection_checked") != "1" {
				t.Errorf("%d refreshes, %s events", w.idp.Count("refresh_token")-n, w.events("sync.connection_checked"))
			}
			w.noSecrets("a refusal", a.raw, false)
			// It recovers.
			w.idp.Set(func(p *oauthtest.Provider) { p.Status, p.Body, p.Header = 0, "", nil })
			w.later(15 * time.Minute)
			if got := w.token1("recovered", w.exerciseMail("broker", c, with{"minValiditySeconds": 2700})); got["value"] == before["value"] {
				t.Errorf("%v", got)
			}
			w.wantStatus("connected", nil)
			for _, r := range w.idp.Requests {
				if r.Host != "idp.example" {
					t.Errorf("a request to %s", r.Host)
				}
			}
			w.noSecretsKept()
		})
	}
}

func TestASlowProvider(t *testing.T) {
	w := connected(t, nil)
	w.oauth.Timeout = time.Second
	hold := make(chan struct{})
	defer close(hold)
	w.idp.Set(func(p *oauthtest.Provider) { p.Hold = hold })
	w.later(2 * time.Hour)
	c := w.mailCapability("broker", nil)
	start := time.Now()
	w.wantReason("slow", w.exerciseMail("broker", c, nil), 429, "RATE_LIMITED", "connection-unavailable")
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("waited %s", d)
	}
	w.wantStatus("failing", "timeout")
}

// The provider says no for good, or a person there did.
func TestNeedsReconnecting(t *testing.T) {
	w := connected(t, nil)
	c := w.mailCapability("broker", nil)
	w.idp.End()
	w.later(2 * time.Hour)
	w.wantReason("revoked there", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED", "connection-needs-reconnect")
	st := w.wantStatus("needs_reconnect", "refused-by-provider")
	if st["hasRefreshToken"] != false || st["accessTokenExpiresAt"] != nil || st["account"] == nil {
		t.Errorf("%v", st)
	}
	n := w.idp.Count("refresh_token")
	w.wantReason("again", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED", "connection-needs-reconnect")
	w.want("asked for", w.call("POST", mailPath+"/refresh", "alice", nil), 200, "")
	if w.idp.Count("refresh_token") != n {
		t.Error("asked again")
	}
	w.connect()
	w.wantEvent("sync.connection_credential_replaced", "Alice", nil, map[string]any{"outcome": "reconnected", "account": "alice@example.com"})
	w.token1("connected again", w.exerciseMail("broker", c, nil))
	// No refresh token at all: good until its access token ends.
	w.idp.Set(func(p *oauthtest.Provider) { p.NoRefresh = true })
	if got := w.connect().body["connection"].(map[string]any); got["hasRefreshToken"] != false {
		t.Errorf("%v", got)
	}
	w.token1("while it lasts", w.exerciseMail("broker", c, nil))
	w.later(2 * time.Hour)
	w.wantReason("after", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED", "connection-needs-reconnect")
	w.wantStatus("needs_reconnect", "no-refresh-token")
}

// A provider that does not replace refresh tokens, one whose answer holds an
// unusable access token with a new refresh token, and one that answers for
// somebody else.
func TestWhatARefreshAnswers(t *testing.T) {
	w := connected(t, nil)
	c := w.mailCapability("broker", nil)
	w.idp.Set(func(p *oauthtest.Provider) { p.Rotate = false })
	for range 3 {
		w.later(2 * time.Hour)
		w.token1("not replaced", w.exerciseMail("broker", c, nil))
	}
	w.idp.Set(func(p *oauthtest.Provider) { p.Rotate, p.TokenType = true, "DPoP" })
	w.later(2 * time.Hour)
	w.wantReason("another type", w.exerciseMail("broker", c, nil), 429, "RATE_LIMITED", "connection-unavailable")
	w.wantStatus("failing", "token-type")
	// The refresh token that came with it is the one that is used next: the
	// other would be a second use, which ends everything.
	w.idp.Set(func(p *oauthtest.Provider) { p.TokenType = "bearer" })
	w.later(time.Hour)
	w.token1("with the new one", w.exerciseMail("broker", c, nil))
	w.idp.Set(func(p *oauthtest.Provider) { p.ExpiresIn = "0" })
	w.later(2 * time.Hour)
	w.want("expired when given", w.exerciseMail("broker", c, nil), 429, "RATE_LIMITED")
	w.wantStatus("failing", "already-expired")
	w.idp.Set(func(p *oauthtest.Provider) { p.ExpiresIn, p.Scope = "3600", "openid" })
	w.later(time.Hour)
	w.token1("fewer scopes", w.exerciseMail("broker", c, nil))
	if st := w.status(); fmt.Sprint(st["missingScopes"]) != "[mail.read]" || fmt.Sprint(st["grantedScopes"]) != "[openid]" {
		t.Errorf("%v", st)
	}
	w.wantEvent1("sync.connection_credential_replaced", map[string]any{"missingScopes": "mail.read"})
	w.idp.Set(func(p *oauthtest.Provider) { p.ClaimSub = "sub-mallory" })
	w.later(2 * time.Hour)
	w.wantReason("another account", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED", "connection-needs-reconnect")
	w.wantStatus("needs_reconnect", "account-mismatch")
}

// A provider that gives back what it was sent, where it may be shown or
// handed out.
func TestAnEchoingProvider(t *testing.T) {
	w := connected(t, nil)
	c := w.mailCapability("broker", nil)
	echo := func(f func(url.Values) string) func(*oauthtest.Provider) {
		return func(p *oauthtest.Provider) { p.Answer = func(r oauthtest.Request) string { return f(r.Form) } }
	}
	for what, x := range map[string]struct {
		set    func(*oauthtest.Provider)
		reason string
	}{
		"as an error":            {echo(func(v url.Values) string { return `{"error":"` + v.Get("refresh_token") + `"}` }), "provider-error"},
		"as a lower-case error":  {echo(func(url.Values) string { return `{"error":"rt_secret_0123456789"}` }), "provider-error"},
		"as the access token":    {echo(func(v url.Values) string { return `{"access_token":"` + v.Get("refresh_token") + `"}` }), "not-an-access-token"},
		"the new refresh token":  {echo(func(url.Values) string { return `{"access_token":"rt.x.1","refresh_token":"rt.x.1"}` }), "not-an-access-token"},
		"in the access token":    {echo(func(v url.Values) string { return `{"access_token":"x` + v.Get("refresh_token") + `x"}` }), "not-an-access-token"},
		"with a line break":      {echo(func(url.Values) string { return `{"access_token":"a\r\nX-Evil: 1"}` }), "no-access-token"},
		"a number as the token":  {echo(func(url.Values) string { return `{"access_token":1}` }), "no-access-token"},
		"in another case":        {echo(func(url.Values) string { return `{"ACCESS_TOKEN":"x"}` }), "no-access-token"},
		"nothing that is a JSON": {echo(func(url.Values) string { return `{"access_token":"x"}{"a":1}` }), "bad-answer"},
	} {
		w = connected(t, nil)
		c = w.mailCapability("broker", nil)
		w.later(2 * time.Hour)
		w.idp.Set(x.set)
		a := w.exerciseMail("broker", c, nil)
		if a.status != 429 || !strings.Contains(a.raw, x.reason) {
			t.Errorf("%s: %s", what, a.raw)
		}
		w.noSecrets(what, a.raw, false)
		w.wantStatus("failing", x.reason)
		w.noSecretsKept()
	}
	// In the scopes: shown to nobody.
	w = connected(t, nil)
	c = w.mailCapability("broker", nil)
	w.later(2 * time.Hour)
	w.idp.Set(echo(func(v url.Values) string {
		return `{"access_token":"fresh-1","expires_in":60,"scope":"mail.read ` + v.Get("refresh_token") + `"}`
	}))
	if got := w.token1("in the scopes", w.exerciseMail("broker", c, nil)); got["value"] != "fresh-1" {
		t.Errorf("%v", got)
	}
	w.noSecretsKept()
	// As somebody's name.
	w.idp.Set(func(p *oauthtest.Provider) { p.Answer = nil; p.Account.Email = oauthtest.Secret })
	_, back := w.begin("web", nil)
	if a := w.complete("web", answerOf(back)); a.body["reason"] != "bad-answer" {
		t.Errorf("%s", a.raw)
	}
	w.noSecretsKept()
}

// ---------------------------------------------------------------------------
// Connecting.

func TestWhatIsWrongWithAnAnswer(t *testing.T) {
	for reason, x := range map[string]struct {
		set    func(*oauthtest.Provider)
		change func(map[string]any)
		kind   string
	}{
		"redirect-uri-mismatch": {change: func(b map[string]any) { b["redirectUri"] = "http://127.0.0.1:8686/oauth/callback/evil.example" }, kind: "refused"},
		"issuer-mismatch":       {change: func(b map[string]any) { b["iss"] = "https://evil.example" }, kind: "refused"},
		"no-code":               {change: func(b map[string]any) { delete(b, "code") }, kind: "refused"},
		"access-denied":         {change: func(b map[string]any) { delete(b, "code"); b["error"] = "access_denied" }, kind: "failed"},
		"provider-error":        {change: func(b map[string]any) { delete(b, "code"); b["error"] = "a_made_up_code" }, kind: "failed"},
		"invalid_grant":         {change: func(b map[string]any) { b["code"] = "code.another" }, kind: "failed"},
		"nonce-mismatch":        {set: func(p *oauthtest.Provider) { p.ClaimNonce = "another" }, kind: "refused"},
		"audience-mismatch":     {set: func(p *oauthtest.Provider) { p.ClaimAud = []string{oauthtest.ClientID, "another"} }, kind: "refused"},
		"id-token":              {set: func(p *oauthtest.Provider) { p.ClaimIssuer = "https://evil.example" }, kind: "refused"},
		"no-id-token":           {set: func(p *oauthtest.Provider) { p.NoIDToken = true }, kind: "refused"},
		"token-type":            {set: func(p *oauthtest.Provider) { p.TokenType = "mac" }, kind: "refused"},
		"no-access-token":       {set: func(p *oauthtest.Provider) { p.Body = `{"token_type":"Bearer"}` }, kind: "refused"},
		"redirect": {set: func(p *oauthtest.Provider) {
			p.Status, p.Header = 302, http.Header{"Location": {"https://evil.example/"}}
		}, kind: "failed"},
		"answer-too-large": {set: func(p *oauthtest.Provider) { p.Body = strings.Repeat(" ", 200<<10) }, kind: "failed"},
	} {
		t.Run(reason, func(t *testing.T) {
			w := newOAuthWorld(t)
			w.create(nil)
			if x.set != nil {
				w.idp.Set(x.set)
			}
			_, back := w.begin("web", nil)
			body := answerOf(back)
			if x.change != nil {
				x.change(body)
			}
			a := w.want(reason, w.complete("web", body), 200, "")
			if a.body["outcome"] != x.kind || a.body["reason"] != reason || a.body["message"] == "" {
				t.Errorf("%s", a.raw)
			}
			w.noSecrets("the answer", a.raw, false)
			w.wantStatus("not_connected", nil)
			w.wantEvent("sync.connection_checked", "Alice", map[string]any{"itemName": mailItem}, map[string]any{"outcome": "not-connected", "reason": reason})
			if x.change != nil && reason != "invalid_grant" && len(w.idp.Requests) != 0 {
				t.Error("the code was sent")
			}
			// Used up, whatever became of it.
			w.want("again", w.complete("web", answerOf(back)), 404, "RESOURCE_NOT_FOUND")
			w.noSecretsKept()
		})
	}
	// More of what is wrong with an ID token.
	for what, set := range map[string]func(*oauthtest.Provider){
		"signature": func(p *oauthtest.Provider) { p.BadSignature = true },
		"expired":   func(p *oauthtest.Provider) { p.ClaimExp = -10 * time.Minute },
		"azp":       func(p *oauthtest.Provider) { p.ClaimAzp = "another" },
		"aud":       func(p *oauthtest.Provider) { p.ClaimAud = "another" },
	} {
		w := newOAuthWorld(t)
		w.create(nil)
		w.idp.Set(set)
		_, back := w.begin("web", nil)
		if a := w.want(what, w.complete("web", answerOf(back)), 200, ""); a.body["outcome"] != "refused" {
			t.Errorf("%s: %s", what, a.raw)
		}
	}
	// Within the leeway of the clocks.
	w := newOAuthWorld(t)
	w.create(nil)
	w.idp.Set(func(p *oauthtest.Provider) { p.ClaimExp = -30 * time.Second })
	w.connect()
}

func TestTheStateIsOneSessionsAndOnce(t *testing.T) {
	w := newOAuthWorld(t)
	w.create(nil)
	begun, back := w.begin("web", nil)
	body := answerOf(back)
	for what, as := range map[string]string{"another session of hers": "web2", "another person": "bobweb", "a credential of hers without a session": "alice"} {
		a := w.complete(as, body)
		if a.status == 200 {
			t.Fatalf("%s: %s", what, a.raw)
		}
	}
	wrong := answerOf(back)
	wrong["state"] = "made-up"
	w.want("another state", w.complete("web", wrong), 404, "RESOURCE_NOT_FOUND")
	if len(w.idp.Requests) != 0 {
		t.Error("the code was sent")
	}
	// None of that used it up.
	if a := w.want("hers", w.complete("web", body), 200, ""); a.body["outcome"] != "connected" {
		t.Fatalf("%s", a.raw)
	}
	w.want("twice", w.complete("web", body), 404, "RESOURCE_NOT_FOUND")
	// Ten minutes.
	_, back = w.begin("web", nil)
	w.later(10*time.Minute + time.Second)
	w.want("late", w.complete("web", answerOf(back)), 410, "EXPIRED")
	// The state is not in the database, nor the verifier, nor the nonce.
	u, _ := url.Parse(begun.body["authorizationUrl"].(string))
	_, _ = w.begin("web", nil)
	for _, r := range paritytest.Rows(t, w.store, "SELECT * FROM oauth_authorizations") {
		if strings.Contains(fmt.Sprint(r), u.Query().Get("state")) || strings.Contains(fmt.Sprint(r), u.Query().Get("nonce")) {
			t.Errorf("%v", r)
		}
	}
	// At once: one of them.
	_, back = w.begin("web", nil)
	body = answerOf(back)
	w.check = false
	var wg sync.WaitGroup
	got := make([]answer, 8)
	for i := range got {
		wg.Go(func() { got[i] = w.complete("web", body) })
	}
	wg.Wait()
	ok := 0
	for _, a := range got {
		if a.status == 200 {
			ok++
		}
	}
	if ok != 1 {
		t.Errorf("%d of them", ok)
	}
	// Machines and people without a session begin none, and not forever many.
	w.check = true
	w.wantReason("cli", w.call("POST", mailPath+"/authorizations", "alice", nil), 403, "PERMISSION_DENIED", "browser-session-required")
	w.check = false
	limited := false
	for range 25 {
		if a := w.call("POST", mailPath+"/authorizations", "web", nil); a.status == 429 {
			limited = true
		}
	}
	if !limited {
		t.Error("no end to authorizations in progress")
	}
}

// The server a code is for is the one it is sent to, whatever a malicious one
// makes of it (RFC 9700 section 4.4).
func TestMixUp(t *testing.T) {
	w := newOAuthWorld(t)
	// A server that names itself when it sends the browser back.
	w.idp.Set(func(p *oauthtest.Provider) { p.IssParameter = true })
	w.create(nil)
	_, back := w.begin("web", nil)
	if a := w.complete("web", answerOf(back)); a.body["reason"] != "issuer-missing" {
		t.Errorf("%s", a.raw)
	}
	w.idp.Set(func(p *oauthtest.Provider) { p.Iss = oauthtest.Issuer })
	w.connect()
	// Another server whose metadata names the honest one's authorization
	// endpoint: the code would go to its own token endpoint. The redirect URI
	// is another one, which the honest server does not know.
	evil := w.want("create", w.call("POST", oauthPath, "alice", connection(with{"item": "EVIL_TOKEN",
		"provider": map[string]any{"preset": "generic", "issuer": "https://evil.example"}})), 201, "")
	if !strings.HasSuffix(evil.body["redirectUri"].(string), "/oauth/callback/evil.example") {
		t.Errorf("%s", evil.raw)
	}
	w.idp.Set(func(p *oauthtest.Provider) {
		p.Metadata = map[string]any{"authorization_endpoint": "https://idp.example/authorize"}
	})
	mixed := connection(with{"item": "MIXED_TOKEN", "provider": map[string]any{"preset": "generic", "issuer": "https://evil.example"}})
	w.wantReason("not named", w.call("POST", oauthPath, "alice", mixed), 422, "VALIDATION_FAILED", "endpoint-hosts")
	mixed["provider"].(map[string]any)["endpointHosts"] = []string{"idp.example"}
	if a := w.want("named", w.call("POST", oauthPath, "alice", mixed), 201, ""); !strings.HasSuffix(a.body["redirectUri"].(string), "/oauth/callback/evil.example~idp.example") {
		t.Errorf("%s", a.raw)
	}
	// A state of one connection at another one's address.
	a := w.want("start", w.call("POST", oauthPath+"/EVIL_TOKEN/authorizations", "web", nil), 201, "")
	body := map[string]any{"state": a.body["state"], "code": "stolen", "redirectUri": "http://127.0.0.1:8686/oauth/callback/idp.example"}
	n := len(w.idp.Requests)
	w.want("another connection", w.complete("web", body), 409, "STATE_CHANGED")
	if len(w.idp.Requests) != n {
		t.Error("the code was sent")
	}
}

func TestAnotherAccount(t *testing.T) {
	w := connected(t, nil)
	c := w.mailCapability("broker", nil)
	before := w.token1("alice's", w.exerciseMail("broker", c, nil))
	mallory := oauthtest.Account{Sub: "sub-mallory", Email: "mallory@example.com"}
	w.idp.Set(func(p *oauthtest.Provider) { p.Account = mallory })
	_, back := w.begin("web", nil)
	a := w.want("another account", w.complete("web", answerOf(back)), 200, "")
	if a.body["reason"] != "account-mismatch" || fmt.Sprint(a.body["account"]) != "map[id:sub-mallory label:mallory@example.com]" || fmt.Sprint(a.body["previousAccount"]) != "map[id:sub-alice label:alice@example.com]" {
		t.Errorf("%s", a.raw)
	}
	// What it was stays.
	if got := w.token1("still alice's", w.exerciseMail("broker", c, nil)); got["value"] != before["value"] {
		t.Errorf("%v", got)
	}
	w.wantEvent("sync.connection_checked", "Alice", nil, map[string]any{"reason": "account-mismatch", "account": "mallory@example.com", "previousAccount": "alice@example.com"})
	// Disconnected, it is still alice's.
	w.want("disconnect", w.call("POST", mailPath+"/disconnect", "alice", nil), 200, "")
	_, back = w.begin("web", nil)
	if a := w.complete("web", answerOf(back)); a.body["reason"] != "account-mismatch" {
		t.Errorf("%s", a.raw)
	}
	// A provider that does not say whose it is.
	w.idp.Set(func(p *oauthtest.Provider) {
		p.Account = oauthtest.Account{Sub: "sub-alice", Email: "alice@example.com"}
	})
	_, back = w.begin("web", nil)
	// Confirmed, and it is in the event.
	w.idp.Set(func(p *oauthtest.Provider) { p.Account = mallory })
	_, back = w.begin("web", map[string]any{"confirmAccountChange": true})
	if a := w.want("confirmed", w.complete("web", answerOf(back)), 200, ""); a.body["outcome"] != "connected" {
		t.Errorf("%s", a.raw)
	}
	w.wantEvent("sync.connection_credential_replaced", "Alice", nil, map[string]any{"accountChanged": true, "account": "mallory@example.com", "previousAccount": "alice@example.com"})
	if st := w.status(); fmt.Sprint(st["account"]) != "map[id:sub-mallory label:mallory@example.com]" {
		t.Errorf("%v", st)
	}
	// By its userinfo endpoint, without an ID token.
	w = newOAuthWorld(t)
	w.create(with{"scopes": []string{"mail.read"}, "provider": map[string]any{"preset": "generic", "authorizationEndpoint": "https://idp.example/authorize",
		"tokenEndpoint": "https://idp.example/token", "userinfoEndpoint": "https://idp.example/userinfo"}})
	if got := w.connect().body["connection"].(map[string]any); fmt.Sprint(got["account"]) != "map[id:sub-alice label:alice@example.com]" {
		t.Errorf("%v", got)
	}
	w.idp.Set(func(p *oauthtest.Provider) { p.Userinfo = `{"id": 42, "login": "mallory‮"}` })
	_, back = w.begin("web", nil)
	if a := w.complete("web", answerOf(back)); a.body["reason"] != "account-mismatch" || fmt.Sprint(a.body["account"]) != "map[id:42 label:42]" {
		t.Errorf("%s", a.raw)
	}
	w.idp.Set(func(p *oauthtest.Provider) { p.Userinfo = `[]` })
	_, back = w.begin("web", nil)
	if a := w.complete("web", answerOf(back)); a.body["reason"] != "userinfo" {
		t.Errorf("%s", a.raw)
	}
}

// Who may do what.
func TestWhoMayConnect(t *testing.T) {
	w := newOAuthWorld(t)
	for _, as := range []string{"broker", "agent", "carol", "svc", "off"} {
		for _, x := range [][2]string{{"POST", oauthPath}, {"POST", oauthPath + "/discovery"}, {"GET", oauthPath}} {
			var body any
			if x[0] == "POST" {
				body = connection(nil)
			}
			if a := w.call(x[0], x[1], as, body); a.status < 400 {
				t.Errorf("%s %s as %s: %s", x[0], x[1], as, a.raw)
			}
		}
	}
	w.create(nil)
	w.connect()
	for _, as := range []string{"broker", "agent", "carol", "svc"} {
		for _, x := range [][2]string{{"GET", mailPath}, {"PATCH", mailPath}, {"POST", mailPath + "/authorizations"}, {"POST", mailPath + "/refresh"}, {"POST", mailPath + "/disconnect"}} {
			a := w.call(x[0], x[1], as, map[string]any{})
			if a.status < 400 {
				t.Errorf("%s %s as %s: %s", x[0], x[1], as, a.raw)
			}
		}
	}
	w.wantStatus("connected", nil)
	// The item is what it is: no value or seed over it, no rotation.
	for what, a := range map[string]answer{
		"a value":  w.call("PUT", envPath+"/values/"+mailItem, "alice", map[string]any{"value": "x"}),
		"a seed":   w.setSeed(mailItem, uriA),
		"rotation": w.call("POST", envPath+"/values/"+mailItem+"/rotations", "alice", map[string]any{"value": "x"}),
		"changes":  w.call("POST", envPath+"/changes", "alice", map[string]any{"changes": []any{map[string]any{"op": "set", "item": mailItem, "value": "x"}}}),
	} {
		w.wantReason(what, a, 422, "VALIDATION_FAILED", "oauth-connection")
	}
	w.want("again", w.call("POST", oauthPath, "alice", connection(nil)), 409, "VERSION_CONFLICT")
	w.want("over a value", w.call("POST", oauthPath, "alice", connection(with{"item": "SECRET_A"})), 409, "VERSION_CONFLICT")
	w.want("a name", w.call("POST", oauthPath, "alice", connection(with{"item": "lower"})), 422, "VALIDATION_FAILED")
	// Deleted as any item, with its tokens.
	w.want("delete", w.call("DELETE", envPath+"/values/"+mailItem, "alice", nil), 204, "")
	if n := w.text("SELECT count(*) FROM oauth_connections"); n != "0" {
		t.Errorf("%s rows of tokens", n)
	}
	w.want("gone", w.call("GET", mailPath, "alice", nil), 404, "RESOURCE_NOT_FOUND")
	w.create(nil)
	w.wantStatus("not_connected", nil)
	if st := w.status(); st["account"] != nil {
		t.Errorf("a new one knows the old one's account: %v", st)
	}
}

// ---------------------------------------------------------------------------
// Where things go.

// What may not be a provider's: addresses inside, plain http, and names that
// resolve inside, at the issuer and in what it answers.
func TestProvidersInside(t *testing.T) {
	w := newOAuthWorld(t)
	w.names["inside.example"] = "10.0.0.5"
	w.names["meta.example"] = "169.254.169.254"
	w.names["loop.example"] = "127.0.0.1"
	provider := func(more with) map[string]any {
		p := map[string]any{"preset": "generic", "authorizationEndpoint": "https://idp.example/authorize", "tokenEndpoint": "https://idp.example/token"}
		for k, v := range more {
			p[k] = v
		}
		return connection(with{"provider": p})
	}
	for what, body := range map[string]map[string]any{
		"an issuer inside":         connection(with{"provider": map[string]any{"preset": "generic", "issuer": "https://inside.example"}}),
		"an issuer at metadata":    connection(with{"provider": map[string]any{"preset": "generic", "issuer": "https://meta.example"}}),
		"an issuer on loopback":    connection(with{"provider": map[string]any{"preset": "generic", "issuer": "https://127.0.0.1:8200"}}),
		"a token endpoint inside":  provider(with{"tokenEndpoint": "https://inside.example/token"}),
		"a literal":                provider(with{"tokenEndpoint": "https://192.168.1.1/token"}),
		"in another form":          provider(with{"tokenEndpoint": "https://0x7f.1/token"}),
		"a revocation endpoint":    provider(with{"revocationEndpoint": "https://loop.example/revoke"}),
		"a userinfo endpoint":      provider(with{"userinfoEndpoint": "https://[::1]/me"}),
		"plain http":               provider(with{"tokenEndpoint": "http://idp.example/token"}),
		"http, the browser's":      provider(with{"authorizationEndpoint": "http://idp.example/authorize"}),
		"a script, the browser's":  provider(with{"authorizationEndpoint": "javascript:alert(1)//https://x"}),
		"credentials":              provider(with{"tokenEndpoint": "https://user:pw@idp.example/token"}),
		"a fragment":               provider(with{"tokenEndpoint": "https://idp.example/token#x"}),
		"a backslash":              provider(with{"tokenEndpoint": `https://idp.example\@inside.example/token`}),
		"an issuer and endpoints":  connection(with{"provider": map[string]any{"preset": "generic", "issuer": oauthtest.Issuer, "tokenEndpoint": "https://evil.example/token"}}),
		"a preset's own endpoints": connection(with{"provider": map[string]any{"preset": "google", "tokenEndpoint": "https://evil.example/token"}}),
		"common":                   connection(with{"provider": map[string]any{"preset": "microsoft", "tenant": "common"}}),
		"no tenant":                connection(with{"provider": map[string]any{"preset": "microsoft"}}),
		"a tenant's path":          connection(with{"provider": map[string]any{"preset": "microsoft", "tenant": "../evil"}}),
		"google, no person":        connection(with{"provider": map[string]any{"preset": "google"}, "grant": "client_credentials"}),
		"its own state":            provider(with{"authorizationParams": map[string]any{"state": "x"}}),
		"its own redirect":         provider(with{"authorizationParams": map[string]any{"Redirect_URI": "https://evil.example"}}),
		"no secret":                connection(with{"clientSecret": nil, "provider": map[string]any{"preset": "generic", "issuer": oauthtest.Issuer, "tokenEndpointAuthMethod": "client_secret_post"}}),
		"a host that is none":      connection(with{"hosts": []string{"https://api.example.com/x"}}),
	} {
		a := w.want(what, w.call("POST", oauthPath, "alice", body), 422, "VALIDATION_FAILED")
		w.noSecrets(what, a.raw, false)
	}
	if w.events("outbound.refused") == "0" {
		t.Error("no refusal is recorded")
	}
	// What the metadata names.
	for what, m := range map[string]map[string]any{
		"token endpoint inside":   {"token_endpoint": "https://inside.example/token"},
		"jwks inside":             {"jwks_uri": "https://meta.example/latest/meta-data"},
		"userinfo inside":         {"userinfo_endpoint": "https://10.1.2.3/"},
		"revocation, plain http":  {"revocation_endpoint": "http://idp.example/revoke"},
		"another issuer":          {"issuer": "https://evil.example"},
		"no token endpoint":       {"token_endpoint": nil},
		"a script":                {"authorization_endpoint": "javascript:alert(1)"},
		"no PKCE":                 {"code_challenge_methods_supported": []string{"plain"}},
		"no authorization at all": {"authorization_endpoint": nil},
	} {
		w.idp.Set(func(p *oauthtest.Provider) { p.Metadata = m })
		a := w.want(what, w.call("POST", oauthPath, "alice", connection(nil)), 422, "VALIDATION_FAILED")
		w.noSecrets(what, a.raw, false)
	}
	w.idp.Set(func(p *oauthtest.Provider) { p.Metadata = nil })
	if len(w.idp.Requests) != 0 {
		t.Errorf("%+v", w.idp.Requests)
	}
	// A name that points inside afterwards: refused when it connects, the
	// tokens kept, and it is in the audit log.
	w.create(nil)
	w.connect()
	w.later(2 * time.Hour)
	w.restart() // no connection is kept open
	w.names["idp.example"] = "10.0.0.5"
	n := len(w.idp.Requests)
	w.wantReason("rebound", w.exerciseMail("broker", w.mailCapability("broker", nil), nil), 429, "RATE_LIMITED", "connection-unavailable")
	w.wantStatus("failing", "outbound-refused")
	if len(w.idp.Requests) != n {
		t.Error("the refresh token was sent inside")
	}
	e := w.event("outbound.refused")
	if !strings.Contains(fmt.Sprint(e["metadata"]), "connection") || !strings.Contains(fmt.Sprint(e["resource"]), mailItem) {
		t.Errorf("%v", e)
	}
	w.want("disconnected all the same", w.call("POST", mailPath+"/disconnect", "alice", nil), 200, "")
	w.wantStatus("revoked", nil)
	// The certificate is another one's.
	w.names["wrong.example"] = ""
	w.want("a certificate for another name", w.call("POST", oauthPath, "alice", connection(with{"item": "WRONG_CERT", "provider": map[string]any{"preset": "generic", "issuer": "https://wrong.example"}})), 422, "VALIDATION_FAILED")
}

// The endpoints are the ones pinned: whatever the metadata says later, and
// whatever is written into the rows.
func TestEndpointsArePinned(t *testing.T) {
	w := connected(t, nil)
	c := w.mailCapability("broker", nil)
	w.idp.Set(func(p *oauthtest.Provider) {
		p.Metadata = map[string]any{"token_endpoint": "https://evil.example/token", "jwks_uri": "https://evil.example/jwks"}
	})
	w.later(2 * time.Hour)
	w.token1("after the metadata changed", w.exerciseMail("broker", c, nil))
	for _, r := range w.idp.Requests {
		if r.Host != "idp.example" {
			t.Errorf("a request to %s", r.Host)
		}
	}
	// By a person, with the secret, while nothing is connected.
	evil := map[string]any{"preset": "generic", "issuer": "https://evil.example"}
	w.idp.Set(func(p *oauthtest.Provider) { p.Metadata = nil })
	w.wantReason("connected", w.call("PATCH", mailPath, "alice", map[string]any{"provider": evil, "clientSecret": "another"}), 422, "VALIDATION_FAILED", "connected")
	w.want("another client", w.call("PATCH", mailPath, "alice", map[string]any{"clientId": "client-2", "clientSecret": "x"}), 422, "VALIDATION_FAILED")
	w.want("disconnect", w.call("POST", mailPath+"/disconnect", "alice", nil), 200, "")
	w.want("without the secret", w.call("PATCH", mailPath, "alice", map[string]any{"provider": evil}), 422, "VALIDATION_FAILED")
	w.grantWrite("svc")
	for _, body := range []map[string]any{{"provider": evil, "clientSecret": "x"}, {"clientId": "client-2", "clientSecret": "x"}, {"hosts": []string{"evil.example"}}, {"scopes": []string{"everything"}}} {
		w.wantReason(fmt.Sprint(body), w.call("PATCH", mailPath, "svc", body), 403, "PERMISSION_DENIED", "person-required")
	}
	changed := w.want("another server", w.call("PATCH", mailPath, "alice", map[string]any{"provider": evil, "clientSecret": "another"}), 200, "")
	if fmt.Sprint(changed.body["account"]) != "map[id:sub-alice label:alice@example.com]" || changed.body["status"] != "not_connected" {
		t.Errorf("%s", changed.raw)
	}
	// The rows.
	w = connected(t, nil)
	c = w.mailCapability("broker", nil)
	set := func(q string) { w.exec(q) }
	for what, q := range map[string]string{
		"the token endpoint": "UPDATE value_versions SET payload = json_set(payload, '$.oauth.tokenEndpoint', 'https://evil.example/token') WHERE json_type(payload, '$.oauth') = 'object'",
		"the hosts":          "UPDATE value_versions SET payload = json_set(payload, '$.oauth.hosts', json('[\"evil.example:443\"]')) WHERE json_type(payload, '$.oauth') = 'object'",
		"the client":         "UPDATE value_versions SET payload = json_set(payload, '$.oauth.clientId', 'client-2') WHERE json_type(payload, '$.oauth') = 'object'",
	} {
		old := w.text("SELECT payload FROM value_versions WHERE json_type(payload, '$.oauth') = 'object'")
		set(q)
		w.check = false
		a := w.exerciseMail("broker", c, with{"destination": map[string]any{"host": "api.example.com", "port": 443}})
		if a.status == 200 {
			t.Errorf("%s: %s", what, a.raw)
		}
		w.later(2 * time.Hour)
		n := len(w.idp.Requests)
		if a := w.exerciseMail("broker", c, nil); a.status == 200 || len(w.idp.Requests) != n {
			t.Errorf("%s: %s, %d requests", what, a.raw, len(w.idp.Requests)-n)
		}
		w.later(-2 * time.Hour)
		w.check = true
		w.exec("UPDATE value_versions SET payload = ? WHERE json_type(payload, '$.oauth') = 'object'", old)
		w.exec("UPDATE oauth_connections SET claim_id = NULL, claim_until = NULL")
	}
	w.token1("as it was", w.exerciseMail("broker", c, nil))
	// The expiry, the account, the generation, another connection's token.
	for what, q := range map[string]string{
		"expires":    "UPDATE oauth_connections SET access_expires_at = access_expires_at + 1000000",
		"account":    "UPDATE oauth_connections SET account = 'sub-mallory'",
		"generation": "UPDATE oauth_connections SET generation = generation + 1",
		"swapped":    "UPDATE oauth_connections SET access_token = refresh_token",
	} {
		row := paritytest.Rows(t, w.store, "SELECT * FROM oauth_connections")[0]
		set(q)
		w.check = false
		if a := w.exerciseMail("broker", c, nil); a.status == 200 {
			t.Errorf("%s: %s", what, a.raw)
		}
		w.check = true
		w.exec("UPDATE oauth_connections SET access_expires_at = ?, account = ?, generation = ?, access_token = ?", row["access_expires_at"], row["account"], row["generation"], w.jsonText(row["access_token"]))
	}
}

func (w *world) jsonText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// grantWrite gives a machine config.value.write in development.
func (w *world) grantWrite(subject string) {
	w.t.Helper()
	w.want("grant", w.call("POST", "/v1/organizations/cap/grants", "alice", map[string]any{
		"subjectIdentityId": w.idn(subject), "actions": []string{"config.value.write", "config.metadata.read"},
		"scope": map[string]any{"kind": "environments", "projectId": w.project(), "selector": map[string]any{"kind": "environments", "environmentIds": []string{w.env("development")}}},
	}), 201, "")
}

// A connection's hosts bound where its token goes, at issuing and at use.
func TestHosts(t *testing.T) {
	w := connected(t, with{"hosts": []string{"api.example.com", "*.mail.example", "other.example:8443"}})
	issue := func(dest ...string) answer {
		return w.call("POST", capsPath, "broker", w.issueBody(with{"items": []string{mailItem}, "targets": map[string]any{mailItem: []string{mailPlace}}, "destinations": dest}))
	}
	for _, ok := range [][]string{{"api.example.com"}, {"a.mail.example", "*.b.mail.example"}, {"*.mail.example"}, {"other.example:8443", "API.example.com"}} {
		w.want(fmt.Sprint(ok), issue(ok...), 201, "")
	}
	for _, no := range [][]string{{"evil.example"}, {"api.example.com", "evil.example"}, {"*.example.com"}, {"mail.example"}, {"*.example"}, {"other.example"}, {"api.example.com:8443"}, {"10.0.0.1"}} {
		w.wantReason(fmt.Sprint(no), issue(no...), 422, "VALIDATION_FAILED", "connection-host")
	}
	// Other items are not affected, and the orchestrator's issuing is bound as
	// the Broker's is.
	w.want("another item", w.call("POST", capsPath, "broker", w.issueBody(with{"destinations": []string{"evil.example"}})), 201, "")
	w.grant("svc", "development")
	w.want("delegated", w.call("POST", capsPath, "svc", w.issueBody(with{"items": []string{mailItem}, "targets": map[string]any{mailItem: []string{mailPlace}},
		"destinations": []string{"evil.example"}, "brokerIdentityId": w.idn("broker")})), 422, "VALIDATION_FAILED")
	// At use: hosts that became fewer bind a Capability issued before.
	c := w.mailCapability("broker", with{"destinations": []string{"api.example.com", "*.mail.example"}})
	w.token1("api", w.exerciseMail("broker", c, nil))
	w.want("fewer", w.call("PATCH", mailPath, "alice", map[string]any{"hosts": []string{"*.mail.example"}}), 200, "")
	w.wantReason("api, after", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED", "destination-mismatch")
	w.token1("mail", w.exerciseMail("broker", c, with{"destination": map[string]any{"host": "imap.mail.example", "port": 443}}))
	w.wantEvent("capability.exercised", "broker", nil, map[string]any{"destination": "imap.mail.example:443"})
	// New hosts and a new client secret left it connected.
	w.wantStatus("connected", nil)
	w.later(2 * time.Hour)
	w.token1("and refreshing", w.exerciseMail("broker", c, with{"destination": map[string]any{"host": "imap.mail.example", "port": 443}}))
}

// Every path but the exercise.
func TestNoOtherPathDeliversAToken(t *testing.T) {
	w := newOAuthWorld(t)
	var log syncBuffer
	w.stop()
	w.log = &log
	w.start()
	w.create(nil)
	w.connect()
	w.want("refers to it", w.call("PUT", envPath+"/values/SECRET_USES", "alice", map[string]any{"value": "Bearer ${" + mailItem + "}"}), 200, "")
	named := func(a answer) map[string]any {
		items, _ := a.body["items"].([]any)
		for _, i := range items {
			if m := i.(map[string]any); m["name"] == mailItem {
				return m
			}
		}
		return nil
	}
	for _, q := range []string{"", "?include=metadata", "?include=values", "?include=values&purpose=export", "?include=values&purpose=scan"} {
		a := w.want(q, w.call("GET", envPath+"/effective-configuration"+q, "alice", nil), 200, "")
		w.noSecrets("effective configuration"+q, a.raw, false)
		if m := named(a); m == nil || m["value"] != nil || fmt.Sprint(m["oauth"]) != "map[account:alice@example.com grant:authorization_code paused:false preset:generic status:connected]" || m["sensitive"] != true {
			t.Errorf("%s: %v", q, m)
		}
	}
	for _, body := range []map[string]any{{"scope": "all-authorized-secrets"}, {"scope": "all-authorized-secrets", "purpose": "export"}, {"items": []string{mailItem}}, {"items": []string{mailItem, "SECRET_A"}, "totpSeeds": true},
		{"items": []string{mailItem}, "purpose": "export"}, {"items": []string{mailItem}, "purpose": "scan"}} {
		a := w.want(fmt.Sprint(body), w.call("POST", envPath+"/disclosures", "alice", body), 200, "")
		w.noSecrets(fmt.Sprintf("the disclosure %v", body), a.raw, false)
		if named(a) != nil {
			t.Errorf("%v: disclosed", body)
		}
		if body["items"] != nil && !slices.Contains(a.body["withheld"].([]any), any(mailItem)) {
			t.Errorf("%v: withheld %v", body, a.body["withheld"])
		}
	}
	for _, mode := range []string{"strict", "preflight"} {
		a := w.want(mode, w.call("POST", envPath+"/retrievals", "alice", map[string]any{"mode": mode}), 200, "")
		w.noSecrets("a retrieval", a.raw, false)
		if m := named(a); m == nil || m["value"] != nil || m["oauth"] == nil {
			t.Errorf("%s: %v", mode, m)
		}
		if strings.Contains(a.raw, `{"name":"MAIL_TOKEN","reason":"oauth-connection","requires":"secret.use"}`) != (mode == "strict") {
			t.Errorf("%s: %s", mode, a.raw)
		}
		if !strings.Contains(a.raw, `{"name":"SECRET_USES","references":["MAIL_TOKEN"]}`) {
			t.Errorf("%s: a reference: %s", mode, a.raw)
		}
	}
	w.noSecrets("a validation", w.want("validate", w.call("POST", envPath+"/validate", "alice", map[string]any{}), 200, "").raw, false)
	if found := w.want("search", w.call("GET", "/v1/organizations/cap/config-items?q=mail", "alice", nil), 200, ""); !strings.Contains(found.raw, mailItem) {
		t.Errorf("%s", found.raw)
	}
	c := w.issue("broker", with{"items": []string{"SECRET_USES", mailItem}, "targets": map[string]any{"SECRET_USES": []string{"header:x-u"}, mailItem: []string{mailPlace}}})
	a := w.want("a reference", w.exercise("broker", c, with{"placements": []any{map[string]any{"item": "SECRET_USES", "target": "header:x-u"}}}), 403, "PERMISSION_DENIED")
	if !strings.Contains(a.raw, `"cause":"oauth-connection"`) {
		t.Errorf("%s", a.raw)
	}
	// What the API says of it, to whoever may ask.
	for _, x := range []answer{w.call("GET", oauthPath, "alice", nil), w.call("GET", mailPath, "alice", nil), w.call("PATCH", mailPath, "alice", map[string]any{"paused": false}),
		w.call("POST", mailPath+"/refresh", "alice", nil), w.call("GET", "/v1/organizations/cap/audit-events", "alice", nil), w.call("GET", "/v1/organizations/cap/audit-events/export", "alice", nil)} {
		w.want("read", x, 200, "")
		w.noSecrets("an answer", x.raw, false)
	}
	// The row made to look like a value's: no path opens it.
	w.exec("UPDATE env_values SET deleted_at = NULL WHERE item_name = ?", mailItem)
	w.check = false
	for what, a := range map[string]answer{
		"disclosed": w.call("POST", envPath+"/disclosures", "alice", map[string]any{"items": []string{mailItem}}),
		"all":       w.call("POST", envPath+"/disclosures", "alice", map[string]any{"scope": "all-authorized-secrets"}),
		"strict":    w.call("POST", envPath+"/retrievals", "alice", map[string]any{"mode": "strict"}),
		"exercised": w.exerciseMail("broker", w.mailCapability("broker", nil), nil),
	} {
		w.noSecrets(what, a.raw, false)
		if a.status == 200 {
			t.Errorf("%s: %s", what, a.raw)
		}
	}
	// Without its mark it opens to an envelope.
	w.exec("UPDATE value_versions SET payload = json_remove(payload, '$.oauth') WHERE json_type(payload, '$.oauth') = 'object'")
	if a := w.call("POST", envPath+"/disclosures", "alice", map[string]any{"items": []string{mailItem}}); a.status != 200 || !strings.Contains(a.raw, "ciphertext") {
		t.Errorf("%s", a.raw)
	} else {
		w.noSecrets("the opened envelope", a.raw, false)
	}
	w.noSecrets("the log", log.String(), false)
	w.noSecretsKept()
}

// Every GET and POST there is, asked by an Organization Admin and by the
// Broker.
func TestNoOperationAnswersWithAToken(t *testing.T) {
	w := newOAuthWorld(t)
	w.create(nil)
	w.connect()
	c := w.mailCapability("broker", nil)
	w.token1("exercise", w.exerciseMail("broker", c, nil))
	w.check = false
	param := regexp.MustCompile(`\{[^}]+\}`)
	names := map[string]string{"{org}": "cap", "{project}": "api", "{environment}": "development", "{identity}": w.idn("broker"), "{item}": mailItem, "{capability}": c.id}
	tried := 0
	for _, as := range []string{"web", "broker"} {
		for _, pattern := range httpserver.BuiltOperations {
			method, route, _ := strings.Cut(pattern, " ")
			if method != http.MethodGet && method != http.MethodPost || strings.Contains(route, "/organizations/{org}/deletion") || strings.Contains(route, "incident") {
				continue
			}
			path := param.ReplaceAllStringFunc(route, func(p string) string {
				if v, ok := names[p]; ok {
					return v
				}
				return "x"
			})
			for _, body := range []any{nil, map[string]any{"scope": "all-authorized-secrets", "mode": "strict", "items": []string{mailItem}}} {
				if method == http.MethodGet && body != nil {
					continue
				}
				w.noSecrets(as+": "+pattern, w.call(method, path, as, body).raw, false)
				tried++
			}
		}
	}
	if tried < 200 {
		t.Errorf("%d requests", tried)
	}
}

// ---------------------------------------------------------------------------
// Not now, and not any more.

func TestFrozenPausedAndDeleted(t *testing.T) {
	w := connected(t, nil)
	c := w.mailCapability("broker", nil)
	n := w.idp.Count("refresh_token")
	asked := func(what string) {
		t.Helper()
		if got := w.idp.Count("refresh_token"); got != n {
			t.Errorf("%s: asked the provider", what)
		}
	}
	w.later(2 * time.Hour)
	// Paused.
	w.want("pause", w.call("PATCH", mailPath, "alice", map[string]any{"paused": true}), 200, "")
	w.wantReason("paused", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED", "connection-paused")
	if a := w.want("refresh", w.call("POST", mailPath+"/refresh", "alice", nil), 200, ""); a.body["refreshed"] != false || a.body["reason"] != "paused" {
		t.Errorf("%s", a.raw)
	}
	asked("paused")
	w.want("resume", w.call("PATCH", mailPath, "alice", map[string]any{"paused": false}), 200, "")
	// Frozen: neither used nor refreshed, by the worker neither.
	w.exec("UPDATE oauth_connections SET keepalive_at = 1")
	w.exec("INSERT INTO organization_freezes (id, organization_id, frozen_by, reason, frozen_at) SELECT 'ofz_t', id, ?, 'x', 1 FROM organizations WHERE slug = 'cap'", w.idn("Alice"))
	w.want("frozen", w.exerciseMail("broker", c, nil), 409, "ORGANIZATION_FROZEN")
	w.want("frozen", w.call("POST", mailPath+"/refresh", "alice", nil), 409, "ORGANIZATION_FROZEN")
	w.want("frozen", w.call("POST", mailPath+"/authorizations", "web", nil), 409, "ORGANIZATION_FROZEN")
	w.want("frozen", w.call("POST", oauthPath, "alice", connection(with{"item": "OTHER"})), 409, "ORGANIZATION_FROZEN")
	if err := w.oauth.RunOnce(context.Background()); err != nil {
		t.Error(err)
	}
	asked("frozen")
	// Revoking still works.
	if a := w.want("disconnect", w.call("POST", mailPath+"/disconnect", "alice", nil), 200, ""); a.body["atProvider"] != "revoked" {
		t.Errorf("%s", a.raw)
	}
	w.exec("UPDATE organization_freezes SET lifted_at = 2, lifted_by = frozen_by, lift_method = 'approval' WHERE id = 'ofz_t'")
	w.connect()
	n = w.idp.Count("refresh_token")
	w.later(2 * time.Hour)
	// Its environment's end, and the Organization's.
	w.exec("UPDATE environments SET expires_at = 5 WHERE id = ?", w.env("development"))
	w.check = false
	w.exerciseMail("broker", c, nil)
	asked("expired")
	w.check = true
	w.exec("UPDATE environments SET expires_at = NULL WHERE id = ?", w.env("development"))
	w.want("delete", w.call("DELETE", envPath+"/values/"+mailItem, "alice", nil), 204, "")
	if err := w.oauth.Refresh(context.Background(), w.text("SELECT id FROM env_values WHERE item_name = ?", mailItem), 1); err == nil {
		t.Error("a deleted connection is refreshed")
	}
	asked("deleted")
	// Deleted with its environment.
	w.create(nil)
	w.connect()
	w.exec("UPDATE oauth_connections SET keepalive_at = 1")
	w.want("the environment", w.call("DELETE", envPath, "alice", nil), 204, "")
	if got := w.text("SELECT count(*) FROM oauth_connections"); got != "0" {
		t.Errorf("%s rows of tokens", got)
	}
	if err := w.oauth.RunOnce(context.Background()); err != nil {
		t.Error(err)
	}
	asked("deleted with its environment")
}

// What happens to a connection while a refresh of it is away.
func TestRacesWithARefresh(t *testing.T) {
	during := func(t *testing.T, w *world, what func()) answer {
		t.Helper()
		hold := make(chan struct{})
		w.idp.Set(func(p *oauthtest.Provider) { p.Hold = hold })
		w.later(2 * time.Hour)
		n := w.idp.Count("refresh_token")
		c := w.mailCapability("broker", nil)
		got := make(chan answer)
		w.check = false
		go func() { got <- w.exerciseMail("broker", c, nil) }()
		for w.idp.Count("refresh_token") == n {
			time.Sleep(5 * time.Millisecond)
		}
		done := make(chan struct{})
		go func() { what(); close(done) }()
		select {
		case <-done:
		case <-time.After(300 * time.Millisecond): // it waits for the refresh
		}
		w.idp.Set(func(p *oauthtest.Provider) { p.Hold = nil })
		close(hold)
		<-done
		a := <-got
		w.check = true
		return a
	}
	t.Run("deleted", func(t *testing.T) {
		w := connected(t, nil)
		a := during(t, w, func() { w.call("DELETE", envPath+"/values/"+mailItem, "alice", nil) })
		if a.status == 200 && len(a.body["items"].([]any)) != 0 {
			t.Errorf("%s", a.raw)
		}
		if n := w.text("SELECT count(*) FROM oauth_connections"); n != "0" {
			t.Errorf("%s rows", n)
		}
	})
	t.Run("paused", func(t *testing.T) {
		w := connected(t, nil)
		a := during(t, w, func() { w.call("PATCH", mailPath, "alice", map[string]any{"paused": true}) })
		w.wantReason("paused", a, 403, "PERMISSION_DENIED", "connection-paused")
		// The answer was stored all the same: the refresh token in it is the
		// only one there is.
		w.want("resume", w.call("PATCH", mailPath, "alice", map[string]any{"paused": false}), 200, "")
		w.token1("resumed", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
	})
	t.Run("disconnected", func(t *testing.T) {
		w := connected(t, nil)
		during(t, w, func() { w.call("POST", mailPath+"/disconnect", "alice", nil) })
		w.wantStatus("revoked", nil)
		if n := w.text("SELECT count(*) FROM oauth_connections WHERE access_token IS NOT NULL OR refresh_token IS NOT NULL"); n != "0" {
			t.Error("tokens are left")
		}
		// What it revoked is the refresh token the answer gave.
		if r := w.idp.Last(); r.Path != "/revoke" {
			t.Errorf("%+v", r)
		}
		access, _ := w.idp.Secrets()
		for _, s := range access {
			if w.idp.Live(s) {
				t.Error("an access token is live")
			}
		}
	})
	t.Run("a new client secret", func(t *testing.T) {
		w := connected(t, nil)
		during(t, w, func() { w.call("PATCH", mailPath, "alice", map[string]any{"clientSecret": oauthtest.Secret}) })
		w.token1("after", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
		w.later(2 * time.Hour)
		w.token1("and refreshing", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
	})
	t.Run("the grant is removed", func(t *testing.T) {
		w := connected(t, nil)
		a := during(t, w, func() {
			w.exec("UPDATE grants SET revoked_at = 1 WHERE subject_identity_id = ?", w.idn("agent"))
		})
		w.want("decided again", a, 403, "PERMISSION_DENIED")
		w.noSecrets("the refusal", a.raw, false)
	})
	t.Run("frozen", func(t *testing.T) {
		w := connected(t, nil)
		a := during(t, w, func() {
			w.exec("INSERT INTO organization_freezes (id, organization_id, frozen_by, reason, frozen_at) SELECT 'ofz_t', id, ?, 'x', 1 FROM organizations WHERE slug = 'cap'", w.idn("Alice"))
		})
		w.want("frozen", a, 409, "ORGANIZATION_FROZEN")
		w.exec("UPDATE organization_freezes SET lifted_at = 2, lifted_by = frozen_by, lift_method = 'approval' WHERE id = 'ofz_t'")
		w.token1("after it", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
	})
	t.Run("who asked is gone", func(t *testing.T) {
		w := connected(t, nil)
		w.later(2 * time.Hour)
		w.idp.Set(func(p *oauthtest.Provider) { p.Delay = 200 * time.Millisecond })
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if err := w.oauth.Refresh(ctx, w.text("SELECT value_id FROM oauth_connections"), 1); err == nil {
			t.Error("it waited")
		}
		w.oauth.Close() // a stop waits for it
		w.restart()
		if n := w.idp.Count("refresh_token"); n != 1 {
			t.Errorf("%d", n)
		}
		w.token1("its answer is kept", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))
		if n := w.idp.Count("refresh_token"); n != 1 {
			t.Errorf("%d", n)
		}
	})
}

func TestDisconnect(t *testing.T) {
	for what, x := range map[string]struct {
		set   func(*oauthtest.Provider)
		body  any
		there string
		live  bool
	}{
		"revoked":       {there: "revoked"},
		"failed":        {set: func(p *oauthtest.Provider) { p.RevokeStatus = 503 }, there: "failed", live: true},
		"left":          {body: map[string]any{"revokeAtProvider": false}, there: "left", live: true},
		"not-supported": {set: func(p *oauthtest.Provider) { p.Metadata = map[string]any{"revocation_endpoint": nil} }, there: "not-supported", live: true},
	} {
		t.Run(what, func(t *testing.T) {
			w := newOAuthWorld(t)
			if x.set != nil {
				w.idp.Set(x.set)
			}
			w.create(nil)
			w.connect()
			c := w.mailCapability("broker", with{"singleUse": true})
			tok := w.token1("before", w.exerciseMail("broker", w.mailCapability("broker", nil), nil))["value"].(string)
			a := w.want("disconnect", w.call("POST", mailPath+"/disconnect", "alice", x.body), 200, "")
			if a.body["atProvider"] != x.there || w.idp.Live(tok) != x.live {
				t.Errorf("%s, live %v", a.raw, w.idp.Live(tok))
			}
			w.noSecrets("the answer", a.raw, false)
			w.wantEvent("sync.connection_revoked", "Alice", map[string]any{"itemName": mailItem}, map[string]any{"connection": "oauth", "atProvider": x.there, "account": "alice@example.com"})
			if n := w.text("SELECT count(*) FROM oauth_connections WHERE access_token IS NOT NULL OR refresh_token IS NOT NULL"); n != "0" {
				t.Error("tokens are left")
			}
			w.wantReason("after", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED", "connection-revoked")
			if a := w.want("again", w.call("POST", mailPath+"/disconnect", "alice", x.body), 200, ""); x.there == "revoked" && a.body["atProvider"] != "nothing-to-revoke" {
				t.Errorf("%s", a.raw)
			}
			w.connect()
			w.token1("connected again, the single use not spent", w.exerciseMail("broker", c, nil))
		})
	}
}

// The client's own access, nobody's account.
func TestClientCredentials(t *testing.T) {
	w := newOAuthWorld(t)
	made := w.create(with{"grant": "client_credentials", "scopes": []string{"mail.send"}})
	if made.body["redirectUri"] != nil {
		t.Errorf("%s", made.raw)
	}
	w.wantReason("nobody consents", w.call("POST", mailPath+"/authorizations", "web", nil), 422, "VALIDATION_FAILED", "client-credentials")
	c := w.mailCapability("broker", nil)
	first := w.token1("the first use gets one", w.exerciseMail("broker", c, nil))
	if r := w.idp.Last(); r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("scope") != "mail.send" {
		t.Errorf("%+v", r)
	}
	w.wantStatus("connected", nil)
	w.later(2 * time.Hour)
	if got := w.token1("another", w.exerciseMail("broker", c, nil)); got["value"] == first["value"] {
		t.Errorf("%v", got)
	}
	// A refused client is no reason to forget it: its secret may be replaced.
	w.want("another secret", w.call("PATCH", mailPath, "alice", map[string]any{"clientSecret": "wrong"}), 200, "")
	w.later(2 * time.Hour)
	w.wantReason("refused", w.exerciseMail("broker", c, nil), 429, "RATE_LIMITED", "connection-unavailable")
	w.wantStatus("failing", "invalid_client")
	w.grantWrite("svc")
	w.want("by a machine", w.call("PATCH", mailPath, "svc", map[string]any{"clientSecret": oauthtest.Secret}), 200, "")
	w.token1("at once", w.exerciseMail("broker", c, nil))
	w.want("disconnect", w.call("POST", mailPath+"/disconnect", "alice", nil), 200, "")
	w.wantReason("after", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED", "connection-revoked")
	w.wantReason("by a machine", w.call("POST", mailPath+"/refresh", "svc", nil), 403, "PERMISSION_DENIED", "person-required")
	if a := w.want("by a person", w.call("POST", mailPath+"/refresh", "alice", nil), 200, ""); a.body["refreshed"] != true {
		t.Errorf("%s", a.raw)
	}
	w.token1("again", w.exerciseMail("broker", c, nil))
}

// A refresh token nobody uses is used before the provider drops it, and not
// otherwise.
func TestKeepalive(t *testing.T) {
	w := connected(t, with{"provider": map[string]any{"preset": "generic", "issuer": oauthtest.Issuer, "refreshTokenIdleDays": 90}})
	ctx := context.Background()
	run := func() {
		t.Helper()
		if err := w.oauth.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	w.later(59 * 24 * time.Hour)
	run()
	if n := w.idp.Count("refresh_token"); n != 0 {
		t.Errorf("%d refreshes before it is due", n)
	}
	w.later(2 * 24 * time.Hour)
	run()
	run()
	if n := w.idp.Count("refresh_token"); n != 1 {
		t.Errorf("%d refreshes", n)
	}
	w.want("pause", w.call("PATCH", mailPath, "alice", map[string]any{"paused": true}), 200, "")
	w.later(100 * 24 * time.Hour)
	run()
	if n := w.idp.Count("refresh_token"); n != 1 {
		t.Errorf("%d refreshes while paused", n)
	}
	// One whose provider says when it ends.
	w = newOAuthWorld(t)
	w.idp.Set(func(p *oauthtest.Provider) { p.RefreshExpiresIn = "86400" })
	w.create(nil)
	if got := w.connect().body["connection"].(map[string]any); got["refreshTokenExpiresAt"] == nil {
		t.Errorf("%v", got)
	}
	w.later(17 * time.Hour)
	run()
	if n := w.idp.Count("refresh_token"); n != 1 {
		t.Errorf("%d refreshes", n)
	}
	// None otherwise.
	w = connected(t, nil)
	w.later(1000 * 24 * time.Hour)
	run()
	if n := w.idp.Count("refresh_token"); n != 0 {
		t.Errorf("%d refreshes of one that says nothing", n)
	}
	// What is no connection any more is forgotten, however it went.
	w.exec("UPDATE env_values SET current_version_id = (SELECT current_version_id FROM env_values WHERE item_name = 'SECRET_B' AND environment_id = ?1), deleted_at = NULL WHERE environment_id = ?1 AND item_name = ?2", w.env("development"), mailItem)
	run()
	if n := w.text("SELECT count(*) FROM oauth_connections"); n != "0" {
		t.Errorf("%s rows", n)
	}
}

// For another Broker, with an exercise-only credential of a run, once
// (ADR-0060).
func TestADelegatedToken(t *testing.T) {
	w := connected(t, nil)
	w.grant("svc", "development")
	w.want("bind", w.bind("broker", with{"exerciseOnly": true, "runIdClaim": "job"}), 201, "")
	machine := w.exchanged(w.token(map[string]any{"job": "run-1"}))
	c := w.mailCapability("svc", with{"brokerIdentityId": w.idn("broker"), "singleUse": true, "runId": "run-1"})
	w.want("the issuer", w.exerciseMail("svc", c, nil), 404, "RESOURCE_NOT_FOUND")
	for _, x := range [][2]string{{"GET", oauthPath}, {"GET", mailPath}, {"POST", mailPath + "/refresh"}, {"POST", mailPath + "/disconnect"}} {
		if a := w.call(x[0], x[1], machine, nil); a.status != 403 {
			t.Errorf("%v: %s", x, a.raw)
		}
	}
	w.later(2 * time.Hour)
	machine = w.exchanged(w.token(map[string]any{"job": "run-1"}))
	w.token1("the machine", w.exerciseMail(machine, c, with{"minValiditySeconds": 1800}))
	w.wantEvent("capability.exercised", "broker", map[string]any{"capabilityId": c.id}, map[string]any{"issuedByIdentityId": w.idn("svc"), "singleUse": true, "runId": "run-1"})
	w.want("twice", w.exerciseMail(machine, c, nil), 403, "PERMISSION_DENIED")
	w.want("an Agent without a Grant", w.exerciseMail("broker", w.mailCapability("broker", with{"agentIdentityId": w.idn("nogrant")}), nil), 403, "PERMISSION_DENIED")
	// Refused before the provider is asked: no secret, no Grant, no refresh.
	w.later(2 * time.Hour)
	n := w.idp.Count("refresh_token")
	c = w.mailCapability("broker", with{"agentIdentityId": w.idn("nogrant")})
	w.want("no Grant", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED")
	w.want("no secret", w.exerciseMail("broker", capability{c.id, "wrong"}, nil), 404, "RESOURCE_NOT_FOUND")
	w.want("another destination", w.exerciseMail("broker", w.mailCapability("broker", nil), with{"destination": map[string]any{"host": "evil.example", "port": 443}}), 403, "PERMISSION_DENIED")
	if w.idp.Count("refresh_token") != n {
		t.Error("refreshed for a refused exercise")
	}
}

// A Capability's token from the environment above.
func TestAnInheritedConnection(t *testing.T) {
	w := connected(t, with{"hosts": []string{"api.example.com"}})
	w.want("derive", w.call("POST", "/v1/organizations/cap/projects/api/environments", "alice", map[string]any{"name": "development/alice", "kind": "personal", "parentEnvironmentId": w.env("development")}), 201, "")
	path := "/v1/organizations/cap/projects/api/environments/development%2Falice"
	a := w.want("listed", w.call("GET", path+"/effective-configuration", "alice", nil), 200, "")
	if !strings.Contains(a.raw, `"source":"parent"`) || !strings.Contains(a.raw, `"oauth":`) {
		t.Errorf("%s", a.raw)
	}
	body := w.issueBody(with{"items": []string{mailItem}, "targets": map[string]any{mailItem: []string{mailPlace}}, "destinations": []string{"evil.example"}})
	w.wantReason("its hosts bind there too", w.call("POST", path+"/capabilities", "broker", body), 422, "VALIDATION_FAILED", "connection-host")
	w.want("its own connections", w.call("GET", path+"/oauth-connections/"+mailItem, "alice", nil), 404, "RESOURCE_NOT_FOUND")
}

// What an older varlatchd, and the TypeScript server, read.
func TestAnOlderServerReadsNoConnection(t *testing.T) {
	w := connected(t, nil)
	env := w.env("development")
	for what, q := range map[string]string{
		"resolveItems": "SELECT count(*) FROM env_values WHERE environment_id = ? AND deleted_at IS NULL AND current_version_id IS NOT NULL AND item_name = '" + mailItem + "'",
		"deleteValue":  "SELECT count(*) FROM env_values WHERE environment_id = ? AND item_name = '" + mailItem + "' AND deleted_at IS NULL",
		"the search":   "SELECT count(*) FROM env_values WHERE environment_id IN (?) AND deleted_at IS NULL AND current_version_id IS NOT NULL AND item_name = '" + mailItem + "'",
	} {
		if n := w.text(q, env); n != "0" {
			t.Errorf("%s finds it", what)
		}
	}
	// #453's server has no seed of it either.
	if n := w.text("SELECT count(*) FROM value_versions WHERE json_type(payload, '$.totp') = 'object'"); n != "0" {
		t.Error("a seed")
	}
	// After a migration there and back its tokens are gone and it is not
	// connected; what it is stayed.
	w.exec("DELETE FROM oauth_connections")
	a := w.want("listed", w.call("GET", envPath+"/effective-configuration", "alice", nil), 200, "")
	if !strings.Contains(a.raw, `"oauth":{"preset":"generic","grant":"authorization_code","status":"not_connected","paused":false}`) {
		t.Errorf("%s", a.raw)
	}
	c := w.mailCapability("broker", nil)
	w.wantReason("not connected", w.exerciseMail("broker", c, nil), 403, "PERMISSION_DENIED", "connection-not-connected")
	if err := w.oauth.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := w.wantStatus("not_connected", nil); st["account"] != nil {
		t.Errorf("%v", st)
	}
	w.connect()
	w.token1("connected again", w.exerciseMail("broker", c, nil))
}

// The host's check of what Organizations configured lists a connection's
// endpoints, one row a host; the API's report keeps the kinds it documents.
func TestTheAdminCheckListsEndpoints(t *testing.T) {
	w := newOAuthWorld(t)
	w.names["private.example"] = "10.0.0.9"
	w.create(nil)
	r, err := w.policy.RunAdminCheck(context.Background(), w.store.Reader(), "cap", w.now)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, d := range r.Destinations {
		got = append(got, fmt.Sprint(d.Kind, " ", d.Host, " ", d.Verdict))
	}
	if !slices.Equal(got, []string{"oauth-connection idp.example public"}) {
		t.Errorf("%q", got)
	}
	if r, err := w.policy.RunCheck(context.Background(), w.store.Reader(), "cap", w.now); err != nil || len(r.Destinations) != 0 {
		t.Errorf("%v, %v", r.Destinations, err)
	}
}
