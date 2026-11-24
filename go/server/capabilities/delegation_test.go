// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/oidc"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// Capabilities issued for another Broker, exercise-only credentials, tokens
// exchanged once and single use (ADR-0060), over HTTP, on the parity
// fixture's rows: its people, machines, Agents and Secrets.

const (
	testIssuer = "https://issuer.example"
	capsPath   = "/v1/organizations/cap/projects/api/environments/development/capabilities"
	prodPath   = "/v1/organizations/cap/projects/api/environments/production/capabilities"
)

type world struct {
	t       *testing.T
	db      string
	rootKEK []byte
	f       paritytest.Fixture
	store   *storage.DB
	handler http.Handler
	values  *values.Service
	key     *ecdsa.PrivateKey
	// ahead is how far the clock is ahead of the wall's, in nanoseconds.
	ahead atomic.Int64
	check bool
}

func newWorld(t *testing.T) *world {
	t.Helper()
	f, err := paritytest.Read(paritytest.Path("capabilities-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, f: f, db: filepath.Join(t.TempDir(), "varlatch.db"), check: true}
	if err := paritytest.Prepare(w.db, f.Rows, capabilitiesTables); err != nil {
		t.Fatal(err)
	}
	if w.rootKEK, err = hex.DecodeString(f.RootKEK); err != nil {
		t.Fatal(err)
	}
	if w.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	w.start()
	t.Cleanup(w.stop)
	return w
}

func (w *world) now() time.Time { return time.Now().Add(time.Duration(w.ahead.Load())) }

// start opens the database and serves it, as a new process would.
func (w *world) start() {
	w.t.Helper()
	store, err := storage.Open(context.Background(), storage.Options{Path: w.db})
	if err != nil {
		w.t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := outbound.New(nil, outbound.Options{Log: log, Resolve: func(context.Context, string) ([]outbound.Answer, error) {
		return []outbound.Answer{{Address: "93.184.215.14", Family: 4}}, nil
	}})
	public, _ := url.Parse("http://127.0.0.1:8686")
	wr := &write.Writer{Store: store, Gates: write.NewGates()}
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: w.rootKEK, PublicURL: public, PersonGate: wr.Gates.PersonGate, Now: w.now})
	vs := values.New(store, w.rootKEK, values.Options{Log: log, Approvals: approvals, Gates: wr.Gates, Now: w.now})
	h, err := httpserver.New(httpserver.Options{
		Version: "0.50.0-test", Backend: daemon.NewBackend(store, w.rootKEK), Log: log, PublicURL: public,
		Auth: approvals, Values: vs, Writer: wr, RootKEK: w.rootKEK, Now: w.now, Outbound: policy, OIDCFetch: w.fetch,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	w.store, w.handler, w.values = store, h, vs
}

func (w *world) stop() {
	w.values.Settled()
	_ = w.store.Close()
}

func (w *world) restart() { w.t.Helper(); w.stop(); w.start() }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (w *world) fetch(_ context.Context, raw string) (*oidc.Response, error) {
	switch raw {
	case testIssuer + "/.well-known/openid-configuration":
		return &oidc.Response{Status: 200, Body: []byte(`{"issuer":"` + testIssuer + `","jwks_uri":"` + testIssuer + `/jwks"}`)}, nil
	case testIssuer + "/jwks":
		pub, err := w.key.PublicKey.Bytes()
		if err != nil {
			return nil, err
		}
		return &oidc.Response{Status: 200, Body: []byte(`{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":"k1","x":"` +
			b64(pub[1:33]) + `","y":"` + b64(pub[33:]) + `"}]}`)}, nil
	}
	return &oidc.Response{Status: 404}, nil
}

// token is a token of the test's issuer, valid for ten minutes unless
// claims say otherwise; a nil claim is left out.
func (w *world) token(claims map[string]any) string {
	w.t.Helper()
	all := map[string]any{"iss": testIssuer, "aud": "varlatch", "sub": "machine:m1", "exp": w.now().Unix() + 600, "jti": fmt.Sprint(time.Now().UnixNano())}
	for k, v := range claims {
		all[k] = v
		if v == nil {
			delete(all, k)
		}
	}
	payload, err := json.Marshal(all)
	if err != nil {
		w.t.Fatal(err)
	}
	signed := b64([]byte(`{"alg":"ES256","kid":"k1"}`)) + "." + b64(payload)
	return signed + "." + b64(w.sign(signed))
}

func (w *world) sign(text string) []byte {
	sum := sha256.Sum256([]byte(text))
	r, s, err := ecdsa.Sign(rand.Reader, w.key, sum[:])
	if err != nil {
		w.t.Fatal(err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

type answer struct {
	status int
	body   map[string]any
	raw    string
}

// call sends a request with a credential by name (the fixture's) or as it
// is, and checks the exchange against the OpenAPI document.
func (w *world) call(method, path, credential string, body any) answer {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if t, ok := w.f.Tokens[credential]; ok {
		credential = t
	}
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, req)
	if w.check {
		openapicheck.Recorder{T: w.t}.Exchange(req, b, rec)
	}
	a := answer{status: rec.Code, raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &a.body)
	return a
}

func (a answer) err() string {
	e, _ := a.body["error"].(map[string]any)
	code, _ := e["code"].(string)
	msg, _ := e["message"].(string)
	return code + ": " + msg
}

// want fails unless the answer has the status and, for a refusal, the
// error's code.
func (w *world) want(what string, a answer, status int, code string) answer {
	w.t.Helper()
	if a.status != status || code != "" && !strings.HasPrefix(a.err(), code+":") {
		w.t.Fatalf("%s: %d %s; want %d %s", what, a.status, a.raw, status, code)
	}
	return a
}

func (w *world) idn(name string) string {
	for _, r := range w.f.Rows["identities"] {
		if r["name"] == name {
			return r["id"].(string)
		}
	}
	w.t.Fatalf("no identity %q", name)
	return ""
}

func (w *world) env(name string) string {
	for _, r := range w.f.Rows["environments"] {
		if r["name"] == name && r["project_id"] == w.project() {
			return r["id"].(string)
		}
	}
	w.t.Fatalf("no environment %q", name)
	return ""
}

func (w *world) project() string {
	for _, r := range w.f.Rows["projects"] {
		if r["active_contract_revision_id"] != nil {
			return r["id"].(string)
		}
	}
	w.t.Fatal("no project")
	return ""
}

func (w *world) exec(q string, args ...any) {
	w.t.Helper()
	if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), q, args...)
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) text(q string, args ...any) string {
	w.t.Helper()
	var s string
	if err := w.store.Reader().QueryRow(q, args...).Scan(&s); err != nil {
		w.t.Fatalf("%s: %v", q, err)
	}
	return s
}

// grant gives subject capability.issue in an environment of the Project,
// and returns the Grant.
func (w *world) grant(subject, environment string) string {
	w.t.Helper()
	a := w.want("grant", w.call("POST", "/v1/organizations/cap/grants", "alice", map[string]any{
		"subjectIdentityId": w.idn(subject), "actions": []string{"capability.issue"},
		"scope": map[string]any{"kind": "environments", "projectId": w.project(), "selector": map[string]any{"kind": "environments", "environmentIds": []string{w.env(environment)}}},
	}), 201, "")
	return a.body["id"].(string)
}

type with map[string]any

// issueBody is an issuance of SECRET_A for agent, with more members.
func (w *world) issueBody(more with) map[string]any {
	b := map[string]any{
		"agentIdentityId": w.idn("agent"), "items": []string{"SECRET_A"}, "destinations": []string{"api.example.com"},
		"targets": map[string]any{"SECRET_A": []string{"header:authorization"}}, "ttlSeconds": 600,
	}
	for k, v := range more {
		b[k] = v
	}
	return b
}

type capability struct{ id, secret string }

func (w *world) issue(as string, more with) capability {
	w.t.Helper()
	a := w.want("issue as "+as, w.call("POST", capsPath, as, w.issueBody(more)), 201, "")
	return capability{a.body["id"].(string), a.body["secret"].(string)}
}

// exercise asks for SECRET_A; more replaces members of the body.
func (w *world) exercise(as string, c capability, more with) answer {
	b := map[string]any{
		"capabilitySecret": c.secret, "destination": map[string]any{"host": "api.example.com", "port": 443},
		"placements": []any{map[string]any{"item": "SECRET_A", "target": "header:authorization"}},
	}
	for k, v := range more {
		b[k] = v
	}
	return w.call("POST", capsPath+"/"+c.id+"/exercises", as, b)
}

func (w *world) wantValue(what string, a answer) {
	w.t.Helper()
	w.want(what, a, 200, "")
	items, _ := a.body["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["value"] != "a-secret" {
		w.t.Fatalf("%s: %s", what, a.raw)
	}
}

// event is the newest audit event of a type: its row.
func (w *world) event(typ string) paritytest.Row {
	w.t.Helper()
	rows := paritytest.Rows(w.t, w.store, "SELECT * FROM audit_events WHERE event_type = ? ORDER BY event_order DESC LIMIT 1", typ)
	if len(rows) != 1 {
		w.t.Fatalf("no %s event", typ)
	}
	return rows[0]
}

func (w *world) wantEvent(typ, actor string, resource, metadata map[string]any) {
	w.t.Helper()
	e := w.event(typ)
	if e["actor_identity_id"] != w.idn(actor) {
		w.t.Errorf("%s: actor %v, want %s", typ, e["actor_identity_id"], actor)
	}
	for column, want := range map[string]map[string]any{"resource": resource, "metadata": metadata} {
		got, _ := e[column].(map[string]any)
		if got == nil {
			_ = json.Unmarshal([]byte(fmt.Sprint(e[column])), &got)
		}
		for k, v := range want {
			if fmt.Sprint(got[k]) != fmt.Sprint(v) {
				w.t.Errorf("%s: %s.%s is %v, want %v", typ, column, k, got[k], v)
			}
		}
	}
}

func (w *world) events(typ string) string {
	return w.text("SELECT count(*) FROM audit_events WHERE event_type = ?", typ)
}

// bind creates an OIDC binding of an identity, with more members.
func (w *world) bind(identity string, more with) answer {
	b := map[string]any{"issuer": testIssuer, "audience": "varlatch", "subject": "machine:m1"}
	for k, v := range more {
		b[k] = v
	}
	return w.call("POST", "/v1/organizations/cap/identities/"+w.idn(identity)+"/oidc-bindings", "alice", b)
}

func (w *world) exchange(token string) answer {
	return w.call("POST", "/v1/oidc/token", "", map[string]any{"token": token, "organization": "cap"})
}

func (w *world) exchanged(token string) string {
	w.t.Helper()
	return w.want("exchange", w.exchange(token), 201, "").body["token"].(string)
}

func TestIssueForAnotherBroker(t *testing.T) {
	w := newWorld(t)
	w.grant("svc", "development")
	a := w.want("issue", w.call("POST", capsPath, "svc", w.issueBody(with{"brokerIdentityId": w.idn("broker"), "runId": "job-1"})), 201, "")
	if a.body["brokerIdentityId"] != w.idn("broker") || a.body["preflight"] != "ok" {
		t.Errorf("issued: %s", a.raw)
	}
	c := capability{a.body["id"].(string), a.body["secret"].(string)}
	w.wantEvent("capability.issued", "svc", map[string]any{"capabilityId": c.id, "brokerIdentityId": w.idn("broker"), "agentIdentityId": w.idn("agent")},
		map[string]any{"runId": "job-1", "items": "SECRET_A"})
	if e := w.event("capability.issued"); e["action"] != "capability.issue" || !strings.Contains(fmt.Sprint(e["authz"]), "grt_") {
		t.Errorf("issued's action %v, authz %v", e["action"], e["authz"])
	}

	// Only the Broker it names exercises it: not its issuer, not another.
	w.want("the issuer", w.exercise("svc", c, nil), 404, "RESOURCE_NOT_FOUND")
	w.want("another Broker", w.exercise("broker2", c, nil), 404, "RESOURCE_NOT_FOUND")
	w.wantEvent("capability.denied", "broker2", map[string]any{"capabilityId": c.id}, map[string]any{"reason": "wrong-broker", "issuedByIdentityId": w.idn("svc")})
	w.want("another Organization's Broker", w.exercise("obroker", c, nil), 404, "RESOURCE_NOT_FOUND")
	w.want("a person", w.exercise("alice", c, nil), 404, "RESOURCE_NOT_FOUND")
	w.want("a guessed secret", w.exercise("broker", capability{c.id, "vlt_cap_guess"}, nil), 404, "RESOURCE_NOT_FOUND")
	w.wantValue("its Broker", w.exercise("broker", c, nil))
	w.wantEvent("capability.exercised", "broker", map[string]any{"capabilityId": c.id, "agentIdentityId": w.idn("agent")},
		map[string]any{"issuedByIdentityId": w.idn("svc"), "runId": "job-1"})

	// An issuer that is a Broker: another's with capability.issue only.
	w.want("a Broker for another, without the Grant", w.call("POST", capsPath, "broker2", w.issueBody(with{"brokerIdentityId": w.idn("broker")})), 404, "RESOURCE_NOT_FOUND")
	w.grant("broker2", "development")
	c = w.issue("broker2", with{"brokerIdentityId": w.idn("broker")})
	w.want("the issuing Broker", w.exercise("broker2", c, nil), 404, "RESOURCE_NOT_FOUND")
	w.wantValue("the named Broker", w.exercise("broker", c, nil))
	// Naming itself is what it always did: no Grant needed, no new member
	// but the one asked for.
	c = w.issue("broker", with{"brokerIdentityId": w.idn("broker")})
	w.wantValue("issued for itself", w.exercise("broker", c, nil))
}

// Issuing never widens: the Agent's secret.use is what an exercise needs,
// whoever issued.
func TestIssuingForAnotherWidensNothing(t *testing.T) {
	w := newWorld(t)
	w.grant("svc", "development")
	a := w.want("issue", w.call("POST", capsPath, "svc", w.issueBody(with{"brokerIdentityId": w.idn("broker"), "agentIdentityId": w.idn("nogrant")})), 201, "")
	if a.body["preflight"] != "agent-lacks-secret-use" {
		t.Errorf("preflight: %s", a.raw)
	}
	c := capability{a.body["id"].(string), a.body["secret"].(string)}
	w.want("an Agent without secret.use", w.exercise("broker", c, nil), 403, "PERMISSION_DENIED")
	// Of capability.issue, nothing is readable.
	for _, path := range []string{"/v1/organizations/cap/projects/api/environments/development/effective-configuration", "/v1/organizations/cap/audit-events"} {
		if a := w.call("GET", path, "svc", nil); a.status < 400 {
			t.Errorf("capability.issue reads %s: %d", path, a.status)
		}
	}
	// Within its lifetime and destinations, as any Capability.
	c = w.issue("svc", with{"brokerIdentityId": w.idn("broker"), "ttlSeconds": 60})
	w.want("another destination", w.exercise("broker", c, with{"destination": map[string]any{"host": "evil.example", "port": 443}}), 403, "PERMISSION_DENIED")
	w.want("another placement", w.exercise("broker", c, with{"placements": []any{map[string]any{"item": "SECRET_B", "target": "header:x-key"}}}), 403, "PERMISSION_DENIED")
	w.ahead.Add(int64(2 * time.Minute))
	w.want("expired", w.exercise("broker", c, nil), 403, "PERMISSION_DENIED")
}

// Who may not issue for another learns nothing, and is told what anyone
// but a Broker always was; a denial that named a Broker is recorded.
func TestWhoMayNotIssueForAnother(t *testing.T) {
	w := newWorld(t)
	body := w.issueBody(with{"brokerIdentityId": w.idn("broker")})
	denied := w.events("authorization.denied")
	for _, as := range []string{"svc", "bob", "carol", "alice"} {
		plain := w.call("POST", capsPath, as, w.issueBody(nil))
		w.want(as, plain, 404, "RESOURCE_NOT_FOUND")
		if got := w.events("authorization.denied"); as == "svc" && got != denied {
			t.Errorf("a caller that names no Broker: %s denials, had %s", got, denied)
		}
		named := w.want(as, w.call("POST", capsPath, as, body), 404, "RESOURCE_NOT_FOUND")
		if as != "carol" && named.err() != plain.err() {
			t.Errorf("%s: %s, without a Broker %s", as, named.err(), plain.err())
		}
		// Nothing of the body is judged first.
		w.want(as+", a bad body", w.call("POST", capsPath, as, map[string]any{"brokerIdentityId": 1}), 404, "RESOURCE_NOT_FOUND")
	}
	w.wantEvent("authorization.denied", "Alice", map[string]any{"environmentId": w.env("development")}, nil)
	if e := w.event("authorization.denied"); e["action"] != "capability.issue" {
		t.Errorf("the denial's action is %v", e["action"])
	}
	w.want("another Organization's machine", w.call("POST", capsPath, "obroker", body), 404, "RESOURCE_NOT_FOUND")

	// A Grant to a person or an Agent has no effect.
	for _, subject := range []string{"Alice", "agent"} {
		w.grant(subject, "development")
	}
	w.want("a person with the Grant", w.call("POST", capsPath, "alice", body), 404, "RESOURCE_NOT_FOUND")
	run := w.want("an agent-run credential", w.call("POST", "/v1/organizations/cap/identities/"+w.idn("agent")+"/credentials", "broker", map[string]any{"ttlSeconds": 60}), 201, "")
	w.want("an Agent with the Grant", w.call("POST", capsPath, run.body["token"].(string), body), 403, "PERMISSION_DENIED")
	// Were its credentials not read-only, its kind would refuse it.
	for kind, may := range map[string]bool{"agent": false, "human": false, "": false, "service": true, "workload": true, "ci": true, "broker": true} {
		if authz.MayIssueCapabilities(kind) != may {
			t.Errorf("a %q identity may issue: %v", kind, !may)
		}
	}
	w.exec("UPDATE identities SET kind = 'agent' WHERE id = ?", w.idn("svc"))
	w.grant("svc", "development")
	w.want("a machine turned Agent, with the Grant", w.call("POST", capsPath, "svc", body), 404, "RESOURCE_NOT_FOUND")
	w.exec("UPDATE grants SET revoked_at = 1 WHERE subject_identity_id = ?", w.idn("svc"))
	w.exec("UPDATE identities SET kind = 'service' WHERE id = ?", w.idn("svc"))

	// A Grant holds in its scope only.
	w.grant("svc", "production")
	w.want("another Environment", w.call("POST", capsPath, "svc", body), 404, "RESOURCE_NOT_FOUND")
	w.want("the Environment of the Grant", w.call("POST", prodPath, "svc", body), 201, "")

	// The Broker named is a live Broker of the Organization, or the answer
	// is one and the same.
	w.exec("UPDATE identities SET disabled = 1 WHERE id = ?", w.idn("broker2"))
	for name, id := range map[string]string{
		"unknown": "idn_nobody", "another Organization's": w.idn("obroker"), "a retired": w.idn("broker2"),
		"a service": w.idn("svc"), "an Agent": w.idn("agent"), "a person": w.idn("Alice"),
	} {
		a := w.want(name, w.call("POST", prodPath, "svc", w.issueBody(with{"brokerIdentityId": id})), 422, "VALIDATION_FAILED")
		if a.err() != "VALIDATION_FAILED: brokerIdentityId must name an active broker identity in this organization" {
			t.Errorf("%s: %s", name, a.err())
		}
	}
	w.want("no Broker named", w.call("POST", prodPath, "svc", w.issueBody(nil)), 422, "VALIDATION_FAILED")
	w.want("not a string", w.call("POST", prodPath, "svc", w.issueBody(with{"brokerIdentityId": 1})), 422, "VALIDATION_FAILED")
	w.want("U+0000", w.call("POST", prodPath, "svc", w.issueBody(with{"brokerIdentityId": "idn_\x00"})), 500, "INTERNAL")
}

// The Organization Admin bundle does not hold capability.issue.
func TestCapabilityIssueIsNoBuiltInRoles(t *testing.T) {
	if slices.Contains(authz.Actions, authz.CapabilityIssue) {
		t.Fatal("capability.issue is in the Admin bundle")
	}
	res := authz.Resource{OrganizationID: "org_a", ProjectID: "prj_a", Environment: &authz.Environment{ID: "env_a", RootID: "env_a", Tier: "development"}}
	for _, role := range []string{authz.Admin, authz.Member} {
		if authz.Evaluate(authz.Input{Action: authz.CapabilityIssue, Resource: res, OrgRole: role}).Allowed {
			t.Errorf("%s holds capability.issue", role)
		}
	}
}

// A Capability lives as long as its issuer may issue: its Grant removed or
// its identity retired, the next exercise is refused.
func TestTheIssuersRightIsEvaluatedAtExercise(t *testing.T) {
	w := newWorld(t)
	grant := w.grant("svc", "development")
	c := w.issue("svc", with{"brokerIdentityId": w.idn("broker")})
	w.wantValue("while it may", w.exercise("broker", c, nil))
	w.want("remove the Grant", w.call("DELETE", "/v1/organizations/cap/grants/"+grant, "alice", nil), 204, "")
	a := w.want("without the Grant", w.exercise("broker", c, nil), 403, "PERMISSION_DENIED")
	if !strings.Contains(a.raw, `"reason":"issuer-not-allowed"`) {
		t.Errorf("%s", a.raw)
	}
	w.grant("svc", "development")
	w.wantValue("granted again", w.exercise("broker", c, nil))
	w.want("retire", w.call("POST", "/v1/organizations/cap/identities/"+w.idn("svc")+"/retire", "alice", nil), 200, "")
	w.want("retired", w.exercise("broker", c, nil), 403, "PERMISSION_DENIED")
	// A Capability a Broker issued for itself depends on no one's Grant.
	w.wantValue("a Broker's own", w.exercise("broker", w.issue("broker", nil), nil))
}

func TestListAndRevokeWhatWasIssued(t *testing.T) {
	w := newWorld(t)
	w.want("no Grant, no list", w.call("GET", capsPath, "svc", nil), 403, "PERMISSION_DENIED")
	grant := w.grant("svc", "development")
	mine := w.issue("svc", with{"brokerIdentityId": w.idn("broker")})
	theirs := w.issue("broker", nil)
	ids := func(a answer) (out []string) {
		w.want("list", a, 200, "")
		for _, i := range a.body["items"].([]any) {
			out = append(out, i.(map[string]any)["id"].(string))
		}
		return out
	}
	if got := ids(w.call("GET", capsPath, "svc", nil)); !slices.Equal(got, []string{mine.id}) {
		t.Errorf("the issuer sees %v", got)
	}
	if got := ids(w.call("GET", capsPath, "broker", nil)); !slices.Contains(got, mine.id) || !slices.Contains(got, theirs.id) {
		t.Errorf("the Broker sees %v", got)
	}
	if got := ids(w.call("GET", capsPath, "broker2", nil)); slices.Contains(got, mine.id) {
		t.Errorf("another Broker sees %v", got)
	}
	all := w.call("GET", capsPath, "alice", nil)
	if got := ids(all); !slices.Contains(got, mine.id) || !strings.Contains(all.raw, `"issuedByIdentityId":"`+w.idn("svc")+`"`) {
		t.Errorf("policy.read sees %s", all.raw)
	}
	for _, i := range all.body["items"].([]any) {
		if m := i.(map[string]any); m["id"] == theirs.id && (m["issuedByIdentityId"] != nil || m["singleUse"] != nil) {
			t.Errorf("a Broker's own reads otherwise: %v", m)
		}
	}
	w.want("another Environment's list", w.call("GET", prodPath, "svc", nil), 403, "PERMISSION_DENIED")

	// Its own, with the Grant or without it (a revocation only takes away);
	// no one else's.
	w.want("another's", w.call("DELETE", capsPath+"/"+theirs.id, "svc", nil), 403, "PERMISSION_DENIED")
	w.want("an unknown one", w.call("DELETE", capsPath+"/cap_unknown", "svc", nil), 403, "PERMISSION_DENIED")
	w.want("another Broker", w.call("DELETE", capsPath+"/"+mine.id, "broker2", nil), 404, "RESOURCE_NOT_FOUND")
	w.want("remove the Grant", w.call("DELETE", "/v1/organizations/cap/grants/"+grant, "alice", nil), 204, "")
	w.want("its own", w.call("DELETE", capsPath+"/"+mine.id, "svc", nil), 204, "")
	w.wantEvent("capability.revoked", "svc", map[string]any{"capabilityId": mine.id, "brokerIdentityId": w.idn("broker"), "issuedByIdentityId": w.idn("svc")}, nil)
	w.want("again", w.call("DELETE", capsPath+"/"+mine.id, "svc", nil), 404, "RESOURCE_NOT_FOUND")
	w.want("revoked", w.exercise("broker", mine, nil), 403, "PERMISSION_DENIED")
	// Its Broker may too.
	w.grant("svc", "development")
	c := w.issue("svc", with{"brokerIdentityId": w.idn("broker")})
	w.want("its Broker", w.call("DELETE", capsPath+"/"+c.id, "broker", nil), 204, "")
}

// While the Organization is frozen for an incident nothing is issued or
// exercised; what was issued is still revoked.
func TestFrozen(t *testing.T) {
	w := newWorld(t)
	w.grant("svc", "development")
	w.want("bind", w.bind("broker", with{"exerciseOnly": true}), 201, "")
	cred := w.exchanged(w.token(nil))
	c := w.issue("svc", with{"brokerIdentityId": w.idn("broker"), "singleUse": true})
	token := w.token(nil)
	w.exec("INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) SELECT 'ofz_test', id, ?, ?, 'drill' FROM organizations WHERE slug = 'cap'",
		w.idn("Alice"), w.now().UnixMicro())
	w.want("issue", w.call("POST", capsPath, "svc", w.issueBody(with{"brokerIdentityId": w.idn("broker")})), 409, "ORGANIZATION_FROZEN")
	w.want("exercise", w.exercise(cred, c, nil), 409, "ORGANIZATION_FROZEN")
	w.want("exchange", w.exchange(token), 409, "ORGANIZATION_FROZEN")
	w.want("list", w.call("GET", capsPath, "svc", nil), 200, "")
	w.exec("UPDATE organization_freezes SET lifted_at = ?, lift_method = 'operator' WHERE id = 'ofz_test'", w.now().UnixMicro())
	// Neither the token nor the single use was spent.
	w.exchanged(token)
	w.wantValue("exercise, lifted", w.exercise(cred, c, nil))
	w.exec("UPDATE organization_freezes SET lifted_at = NULL, lift_method = NULL WHERE id = 'ofz_test'")
	w.want("revoke", w.call("DELETE", capsPath+"/"+c.id, "svc", nil), 204, "")
}

func TestSingleUse(t *testing.T) {
	w := newWorld(t)
	a := w.want("issue", w.call("POST", capsPath, "broker", w.issueBody(with{"singleUse": true,
		"items": []string{"SECRET_A", "SECRET_MISS"}, "targets": map[string]any{"SECRET_A": []string{"header:authorization"}, "SECRET_MISS": []string{"header:x-miss"}}})), 201, "")
	if a.body["singleUse"] != true {
		t.Errorf("issued: %s", a.raw)
	}
	w.wantEvent("capability.issued", "broker", nil, map[string]any{"singleUse": true})
	c := capability{a.body["id"].(string), a.body["secret"].(string)}
	listed := func(used bool) {
		t.Helper()
		for _, i := range w.call("GET", capsPath, "alice", nil).body["items"].([]any) {
			if m := i.(map[string]any); m["id"] == c.id && (m["singleUse"] != true || m["used"] != used) {
				t.Errorf("listed: %v, want used %v", m, used)
			}
		}
	}
	listed(false)
	// A refused exercise does not use it up, not even one refused after
	// capability.exercised, for a reference in what was decrypted.
	w.want("another destination", w.exercise("broker", c, with{"destination": map[string]any{"host": "evil.example", "port": 443}}), 403, "PERMISSION_DENIED")
	w.want("a bad secret", w.exercise("broker", capability{c.id, "vlt_cap_x"}, nil), 404, "RESOURCE_NOT_FOUND")
	w.want("another Broker", w.exercise("broker2", c, nil), 404, "RESOURCE_NOT_FOUND")
	missing := w.want("an unresolved reference", w.exercise("broker", c, with{"placements": []any{map[string]any{"item": "SECRET_MISS", "target": "header:x-miss"}}}), 403, "PERMISSION_DENIED")
	if !strings.Contains(missing.raw, "unresolved-reference") {
		t.Fatalf("%s", missing.raw)
	}
	listed(false)
	w.wantValue("the first", w.exercise("broker", c, nil))
	w.wantEvent("capability.exercised", "broker", map[string]any{"capabilityId": c.id}, map[string]any{"singleUse": true})
	listed(true)
	second := w.want("the second", w.exercise("broker", c, nil), 403, "PERMISSION_DENIED")
	if !strings.Contains(second.raw, `"reason":"already-used"`) {
		t.Errorf("%s", second.raw)
	}
	w.restart()
	w.want("after a restart", w.exercise("broker", c, nil), 403, "PERMISSION_DENIED")
	// A used one is still revocable, and no other Capability is single-use.
	w.want("revoke", w.call("DELETE", capsPath+"/"+c.id, "broker", nil), 204, "")
	again := w.issue("broker", with{"singleUse": false})
	w.wantValue("not single-use", w.exercise("broker", again, nil))
	w.wantValue("not single-use, again", w.exercise("broker", again, nil))
	w.want("singleUse is a boolean", w.call("POST", capsPath, "broker", w.issueBody(with{"singleUse": "yes"})), 422, "VALIDATION_FAILED")
}

// Many at once: one is granted, every other refused, and the audit log says
// so.
func TestSingleUseUnderConcurrency(t *testing.T) {
	w := newWorld(t)
	w.grant("svc", "development")
	for round := range 5 {
		c := w.issue("svc", with{"brokerIdentityId": w.idn("broker"), "singleUse": true})
		var granted, refused atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 12 {
			wg.Go(func() {
				<-start
				switch a := w.exercise("broker", c, nil); a.status {
				case 200:
					granted.Add(1)
				case 403:
					refused.Add(1)
				default:
					t.Errorf("%d %s", a.status, a.raw)
				}
			})
		}
		close(start)
		wg.Wait()
		if granted.Load() != 1 || refused.Load() != 11 {
			t.Fatalf("round %d: %d granted, %d refused", round, granted.Load(), refused.Load())
		}
		if n := w.text("SELECT count(*) FROM audit_events WHERE event_type = 'capability.exercised' AND json_extract(resource, '$.capabilityId') = ?", c.id); n != "1" {
			t.Fatalf("round %d: %s capability.exercised", round, n)
		}
	}
}

// A revocation while an exercise holds the use is never undone by that
// exercise's refusal.
func TestARevocationHoldsThroughARefusedSingleUse(t *testing.T) {
	w := newWorld(t)
	body := w.issueBody(with{"singleUse": true, "items": []string{"SECRET_A", "SECRET_MISS"},
		"targets": map[string]any{"SECRET_A": []string{"header:authorization"}, "SECRET_MISS": []string{"header:x-miss"}}})
	for range 20 {
		a := w.want("issue", w.call("POST", capsPath, "broker", body), 201, "")
		c := capability{a.body["id"].(string), a.body["secret"].(string)}
		var wg sync.WaitGroup
		wg.Go(func() {
			w.exercise("broker", c, with{"placements": []any{map[string]any{"item": "SECRET_MISS", "target": "header:x-miss"}}})
		})
		wg.Go(func() {
			if a := w.call("DELETE", capsPath+"/"+c.id, "broker", nil); a.status != 204 {
				t.Errorf("revoke: %d %s", a.status, a.raw)
			}
		})
		wg.Wait()
		w.want("revoked", w.exercise("broker", c, nil), 403, "PERMISSION_DENIED")
	}
}

func TestExerciseOnlyBindings(t *testing.T) {
	w := newWorld(t)
	for what, c := range map[string]struct {
		identity string
		more     with
	}{
		"a service":                        {"svc", with{"exerciseOnly": true}},
		"an Agent":                         {"agent", with{"exerciseOnly": true}},
		"runIdClaim alone":                 {"broker", with{"runIdClaim": "job"}},
		"runIdClaim with a singleExchange": {"broker", with{"runIdClaim": "job", "singleExchange": true}},
		"more than once":                   {"broker", with{"exerciseOnly": true, "singleExchange": false}},
		"an empty claim":                   {"broker", with{"exerciseOnly": true, "runIdClaim": ""}},
		"not a boolean":                    {"broker", with{"exerciseOnly": "yes"}},
		"a reserved claim":                 {"broker", with{"claims": map[string]string{"varlatch:limits": `{"v":1,"singleExchange":true}`}}},
		"another reserved claim":           {"broker", with{"claims": map[string]string{"varlatch:x": "y"}}},
	} {
		w.want(what, w.bind(c.identity, c.more), 422, "VALIDATION_FAILED")
	}
	a := w.want("bind", w.bind("broker", with{"exerciseOnly": true, "runIdClaim": "job", "claims": map[string]string{"team": "a"}}), 201, "")
	for k, want := range map[string]any{"exerciseOnly": true, "runIdClaim": "job", "singleExchange": true} {
		if a.body[k] != want {
			t.Errorf("%s is %v", k, a.body[k])
		}
	}
	if fmt.Sprint(a.body["claims"]) != "map[team:a]" {
		t.Errorf("claims: %v", a.body["claims"])
	}
	w.wantEvent("oidc_binding.created", "Alice", nil, map[string]any{"exerciseOnly": true, "runIdClaim": "job", "singleExchange": true})
	// Listed the same; a binding without limits reads as it always did.
	w.want("plain", w.bind("broker", with{"subject": "machine:m2"}), 201, "")
	list := w.want("list", w.call("GET", "/v1/organizations/cap/identities/"+w.idn("broker")+"/oidc-bindings", "alice", nil), 200, "")
	items := list.body["items"].([]any)
	first, _ := json.Marshal(items[0])
	created, _ := json.Marshal(a.body)
	if !bytes.Equal(first, created) {
		t.Errorf("listed %s, created %s", first, created)
	}
	if m := items[1].(map[string]any); len(m) != 7 || m["claims"] != nil {
		t.Errorf("a binding without limits: %v", m)
	}
	// It is revoked as any other.
	w.want("revoke", w.call("DELETE", "/v1/organizations/cap/identities/"+w.idn("broker")+"/oidc-bindings/"+a.body["id"].(string), "alice", nil), 204, "")
	w.want("revoked", w.exchange(w.token(map[string]any{"team": "a", "job": "j"})), 401, "INVALID_CREDENTIAL")
}

func TestExerciseOnlyCredential(t *testing.T) {
	w := newWorld(t)
	w.grant("svc", "development")
	// The Broker holds far more than its exercise-only credential may use.
	w.want("grant", w.call("POST", "/v1/organizations/cap/grants", "alice", map[string]any{
		"subjectIdentityId": w.idn("broker"), "scope": map[string]any{"kind": "organization"}, "actions": authz.Actions}), 201, "")
	w.grant("broker", "development")
	w.want("bind", w.bind("broker", with{"exerciseOnly": true, "runIdClaim": "job"}), 201, "")
	ex := w.want("exchange", w.exchange(w.token(map[string]any{"job": "job-1"})), 201, "")
	if ex.body["exerciseOnly"] != true || ex.body["runId"] != "job-1" || ex.body["identityId"] != w.idn("broker") {
		t.Errorf("exchanged: %s", ex.raw)
	}
	cred := ex.body["token"].(string)
	w.wantEvent("credential.issued", "broker", map[string]any{"identityId": w.idn("broker")}, map[string]any{"exerciseOnly": true, "runId": "job-1", "kind": "oidc"})

	mine := w.issue("svc", with{"brokerIdentityId": w.idn("broker"), "runId": "job-1"})
	other := w.issue("svc", with{"brokerIdentityId": w.idn("broker"), "runId": "job-2"})
	none := w.issue("svc", with{"brokerIdentityId": w.idn("broker")})
	others := w.issue("svc", with{"brokerIdentityId": w.idn("broker2"), "runId": "job-1"})
	w.wantValue("its run's", w.exercise(cred, mine, nil))
	w.want("another run's", w.exercise(cred, other, nil), 404, "RESOURCE_NOT_FOUND")
	w.wantEvent("capability.denied", "broker", map[string]any{"capabilityId": other.id}, map[string]any{"reason": "wrong-run"})
	w.want("one of no run", w.exercise(cred, none, nil), 404, "RESOURCE_NOT_FOUND")
	w.want("another Broker's", w.exercise(cred, others, nil), 404, "RESOURCE_NOT_FOUND")
	// The Broker's full credential is not tied to a run.
	w.wantValue("the full credential", w.exercise("broker", other, nil))

	// Every other operation is refused, reads included, whatever the
	// Broker's Grants allow.
	issuance := w.call("POST", capsPath, cred, w.issueBody(nil))
	w.want("issuing", issuance, 403, "PERMISSION_DENIED")
	w.wantEvent("authorization.denied", "broker", nil, map[string]any{"reason": "exercise_only_credential", "method": "POST",
		"route": "/v1/organizations/{org}/projects/{project}/environments/{environment}/capabilities"})
	if e := w.event("authorization.denied"); e["credential_id"] != ex.body["id"] || e["organization_id"] == nil {
		t.Errorf("the refusal's event: %v", e)
	}
	w.want("listing", w.call("GET", capsPath, cred, nil), 403, "PERMISSION_DENIED")
	w.want("revoking", w.call("DELETE", capsPath+"/"+mine.id, cred, nil), 403, "PERMISSION_DENIED")
	w.want("whoami", w.call("GET", "/v1/me", cred, nil), 403, "PERMISSION_DENIED")
	w.want("an agent-run credential", w.call("POST", "/v1/organizations/cap/identities/"+w.idn("agent")+"/credentials", cred, map[string]any{"ttlSeconds": 60}), 403, "PERMISSION_DENIED")

	// Its metadata says so, and an admin revokes it as any other.
	list := w.want("credentials", w.call("GET", "/v1/organizations/cap/identities/"+w.idn("broker")+"/credentials", "alice", nil), 200, "")
	if !strings.Contains(list.raw, `"exerciseOnly":true,"runId":"job-1"`) {
		t.Errorf("credentials: %s", list.raw)
	}
	w.restart()
	w.wantValue("after a restart", w.exercise(cred, mine, nil))
	w.want("revoke", w.call("DELETE", "/v1/organizations/cap/identities/"+w.idn("broker")+"/credentials/"+ex.body["id"].(string), "alice", nil), 204, "")
	w.want("revoked", w.exercise(cred, mine, nil), 401, "INVALID_CREDENTIAL")
	w.want("revoked, listing", w.call("GET", capsPath, cred, nil), 401, "INVALID_CREDENTIAL")

	// Expired, and without its limits' row, it authenticates nothing.
	cred = w.exchanged(w.token(map[string]any{"job": "job-1"}))
	w.wantValue("a new one", w.exercise(cred, mine, nil))
	w.exec("DELETE FROM exercise_credentials")
	w.want("its limits lost", w.exercise(cred, mine, nil), 401, "INVALID_CREDENTIAL")
	cred = w.exchanged(w.token(map[string]any{"job": "job-1"}))
	w.ahead.Add(int64(11 * time.Minute))
	w.want("expired", w.exercise(cred, mine, nil), 401, "INVALID_CREDENTIAL")
}

// Every operation of the API but the exercise, and a path that is none,
// refuses an exercise-only credential before anything else: one added
// later does too, since only the exercise's own pattern is let through.
func TestEveryOtherOperationRefusesAnExerciseOnlyCredential(t *testing.T) {
	w := newWorld(t)
	w.want("bind", w.bind("broker", with{"exerciseOnly": true}), 201, "")
	cred := w.exchanged(w.token(nil))
	w.check = false // synthetic paths
	open := []string{"GET /v1/meta", "POST /v1/oidc/token", "POST /v1/auth/device", "POST /v1/auth/device/token"}
	const exercisePattern = "POST /v1/organizations/{org}/projects/{project}/environments/{environment}/capabilities/{capability}/exercises"
	param := regexp.MustCompile(`\{[^}]+\}`)
	names := map[string]string{"{org}": "cap", "{project}": "api", "{environment}": "development", "{identity}": w.idn("broker")}
	refused := 0
	for _, pattern := range httpserver.BuiltOperations {
		if slices.Contains(open, pattern) {
			continue
		}
		method, route, _ := strings.Cut(pattern, " ")
		path := param.ReplaceAllStringFunc(route, func(p string) string {
			if v, ok := names[p]; ok {
				return v
			}
			return "x"
		})
		a := w.call(method, path, cred, map[string]any{})
		if pattern == exercisePattern {
			w.want(pattern, a, 422, "VALIDATION_FAILED") // let through, to its own checks
			continue
		}
		if a.status != 403 || a.err() != "PERMISSION_DENIED: Exercise-only credentials exercise Capabilities and nothing else" {
			t.Errorf("%s: %d %s", pattern, a.status, a.raw)
		}
		refused++
	}
	if refused < 150 {
		t.Errorf("%d operations refused it; BuiltOperations has %d", refused, len(httpserver.BuiltOperations))
	}
	for _, c := range [][2]string{{"GET", "/v1/unknown"}, {"HEAD", "/v1/me"}, {"OPTIONS", "/v1/me"}, {"PUT", capsPath}, {"GET", capsPath + "/x/exercises"},
		{"POST", capsPath + "/x/exercises/"}, {"POST", "/v1/me/../organizations"}} {
		if a := w.call(c[0], c[1], cred, nil); a.status == 200 || a.status == 201 || a.status == 204 && c[0] != "OPTIONS" {
			t.Errorf("%s %s: %d %s", c[0], c[1], a.status, a.raw)
		}
	}
}

func TestRunIDClaim(t *testing.T) {
	w := newWorld(t)
	w.want("bind", w.bind("broker", with{"exerciseOnly": true, "runIdClaim": "job"}), 201, "")
	for what, v := range map[string]any{"no claim": nil, "an empty one": "", "a number": 7, "a list": []string{"job-1"}, "too long": strings.Repeat("j", 201), "U+0000": "a\x00"} {
		w.want(what, w.exchange(w.token(map[string]any{"job": v})), 401, "INVALID_CREDENTIAL")
		if e := w.event("authentication.failed"); !strings.Contains(fmt.Sprint(e["metadata"]), "run-id-claim") {
			t.Errorf("%s: %v", what, e["metadata"])
		}
	}
	w.want("200 characters", w.exchange(w.token(map[string]any{"job": strings.Repeat("é", 200)})), 201, "")
}

func TestATokenIsExchangedOnce(t *testing.T) {
	w := newWorld(t)
	w.want("bind", w.bind("svc", with{"singleExchange": true}), 201, "")
	token := w.token(nil)
	w.exchanged(token)
	again := w.want("again", w.exchange(token), 401, "INVALID_CREDENTIAL")
	if again.err() != w.exchange("a.b.c").err() {
		t.Errorf("a replay is answered otherwise than any refusal: %s", again.err())
	}
	replays := func() string {
		return w.text(`SELECT count(*) FROM audit_events WHERE event_type = 'authentication.failed' AND json_extract(metadata, '$.reason') = 'token-already-exchanged'
			AND organization_id IS NOT NULL AND json_extract(resource, '$.identityId') = ?`, w.idn("svc"))
	}
	if replays() != "1" {
		t.Errorf("%s replays recorded for the Organization", replays())
	}
	// Across a restart.
	w.restart()
	w.want("after a restart", w.exchange(token), 401, "INVALID_CREDENTIAL")
	// Another token with the same jti is the same token; another jti is not.
	w.exchanged(w.token(map[string]any{"jti": "one"}))
	w.want("the same jti", w.exchange(w.token(map[string]any{"jti": "one", "extra": "x"})), 401, "INVALID_CREDENTIAL")
	w.exchanged(w.token(map[string]any{"jti": "two"}))
	// Without a jti (or with one that is none), the token itself is the key,
	// however its signature is written.
	for _, jti := range []any{nil, "", 5} {
		bare := w.token(map[string]any{"jti": jti, "n": fmt.Sprint(jti)})
		w.exchanged(bare)
		w.want("no jti, again", w.exchange(bare), 401, "INVALID_CREDENTIAL")
		signed := bare[:strings.LastIndexByte(bare, '.')]
		w.want("no jti, signed again", w.exchange(signed+"."+b64(w.sign(signed))), 401, "INVALID_CREDENTIAL")
	}
	w.exchanged(w.token(map[string]any{"jti": nil, "n": "another"}))
	// A token valid for longer than a day would be kept as long.
	w.want("valid for two days", w.exchange(w.token(map[string]any{"exp": w.now().Add(48 * time.Hour).Unix()})), 401, "INVALID_CREDENTIAL")
	// A refused exchange spends nothing.
	spare := w.token(map[string]any{"jti": "spare"})
	w.exec("UPDATE identities SET disabled = 1 WHERE id = ?", w.idn("svc"))
	w.want("retired", w.exchange(spare), 401, "INVALID_CREDENTIAL")
	w.exec("UPDATE identities SET disabled = 0 WHERE id = ?", w.idn("svc"))
	w.want("a bad ttl", w.call("POST", "/v1/oidc/token", "", map[string]any{"token": spare, "organization": "cap", "ttlSeconds": 0}), 422, "VALIDATION_FAILED")
	w.exchanged(spare)
}

// What is kept of exchanged tokens is bounded: gone once they are no longer
// accepted.
func TestTokenUsesArePruned(t *testing.T) {
	w := newWorld(t)
	w.want("bind", w.bind("svc", with{"singleExchange": true}), 201, "")
	token := w.token(nil)
	w.exchanged(token)
	for range 3 {
		w.exchanged(w.token(nil))
	}
	count := func() string { return w.text("SELECT count(*) FROM oidc_token_uses") }
	if count() != "4" {
		t.Fatalf("%s uses", count())
	}
	// Kept for as long as the token is accepted, and an hour more.
	w.ahead.Store(int64(10*time.Minute + 30*time.Second))
	w.want("within the leeway", w.exchange(token), 401, "INVALID_CREDENTIAL")
	if e := w.event("authentication.failed"); !strings.Contains(fmt.Sprint(e["metadata"]), "token-already-exchanged") {
		t.Errorf("within the leeway: %v", e["metadata"])
	}
	w.ahead.Store(int64(2 * time.Hour))
	w.want("long after", w.exchange(token), 401, "INVALID_CREDENTIAL")
	w.exchanged(w.token(nil))
	if count() != "1" {
		t.Errorf("%s uses kept", count())
	}
}

func TestATokenIsExchangedOnceUnderConcurrency(t *testing.T) {
	w := newWorld(t)
	w.want("bind", w.bind("broker", with{"exerciseOnly": true}), 201, "")
	for round := range 5 {
		token := w.token(nil)
		before := w.text("SELECT count(*) FROM credentials")
		var issued, refused atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 12 {
			wg.Go(func() {
				<-start
				switch a := w.exchange(token); a.status {
				case 201:
					issued.Add(1)
				case 401:
					refused.Add(1)
				default:
					t.Errorf("%d %s", a.status, a.raw)
				}
			})
		}
		close(start)
		wg.Wait()
		if issued.Load() != 1 || refused.Load() != 11 {
			t.Fatalf("round %d: %d issued, %d refused", round, issued.Load(), refused.Load())
		}
		if n := w.text("SELECT count(*) - ? FROM credentials", before); n != "1" {
			t.Fatalf("round %d: %s credentials", round, n)
		}
	}
}

// A binding made without limits exchanges a token as often as before; one
// beside it that limits the same token limits it.
func TestLimitsOfSeveralBindings(t *testing.T) {
	w := newWorld(t)
	w.want("plain", w.bind("broker", nil), 201, "")
	token := w.token(map[string]any{"job": "job-1"})
	for range 3 {
		cred := w.exchanged(token)
		w.want("a full credential", w.call("GET", "/v1/me", cred, nil), 200, "")
	}
	b := w.want("limited", w.bind("broker", with{"exerciseOnly": true, "subject": "machine:*"}), 201, "")
	ex := w.want("exchange", w.exchange(token), 201, "")
	if ex.body["exerciseOnly"] != true {
		t.Errorf("a token two bindings match: %s", ex.raw)
	}
	w.wantEvent("credential.issued", "broker", nil, map[string]any{"oidcBindingId": b.body["id"]})
	w.want("listing", w.call("GET", capsPath, ex.body["token"].(string), nil), 403, "PERMISSION_DENIED")
	w.want("again", w.exchange(token), 401, "INVALID_CREDENTIAL")
	w.want("a run claim", w.bind("broker", with{"exerciseOnly": true, "runIdClaim": "job", "subject": "machine:m*"}), 201, "")
	if ex = w.want("exchange", w.exchange(w.token(map[string]any{"job": "job-1"})), 201, ""); ex.body["runId"] != "job-1" {
		t.Errorf("a token three bindings match: %s", ex.raw)
	}
	w.want("another run claim", w.bind("broker", with{"exerciseOnly": true, "runIdClaim": "run", "subject": "machine:m1*"}), 201, "")
	w.want("two run claims", w.exchange(w.token(map[string]any{"job": "job-1", "run": "job-1"})), 401, "INVALID_CREDENTIAL")
}

// A server that does not know the limits (an earlier varlatchd after a
// rollback, the TypeScript server after a reverse migration) reads the same
// rows: what is limited is inert there, never unlimited.
func TestLimitsFailClosedOnAnOlderServer(t *testing.T) {
	w := newWorld(t)
	w.want("bind", w.bind("broker", with{"exerciseOnly": true, "claims": map[string]string{"team": "a"}}), 201, "")
	token := w.token(map[string]any{"team": "a"})
	cred := w.exchanged(token)
	// Its lookup is by the token's hash alone.
	if n := w.text("SELECT count(*) FROM credentials WHERE token_hash = ?", auth.HashToken(cred)); n != "0" {
		t.Error("an older server authenticates an exercise-only credential")
	}
	if n := w.text("SELECT count(*) FROM credentials WHERE token_hash = ?", auth.ExercisePrefix+auth.HashToken(cred)); n != "1" {
		t.Error("the credential is not there")
	}
	// Its match of a binding is every claim of the row.
	row, err := jsvalue.Parse([]byte(w.text("SELECT claims FROM oidc_bindings")))
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := jsvalue.Parse([]byte(`{"iss":"` + testIssuer + `","aud":"varlatch","sub":"machine:m1","team":"a"}`))
	if oidc.Matches(claims.(jsvalue.Object), "varlatch", "machine:m1", row.(jsvalue.Object)) {
		t.Error("an older server exchanges a limited binding's token")
	}
	// Its comparison is of the secret's hash with the row's.
	c := w.issue("broker", with{"singleUse": true})
	stored := func() string { return w.text("SELECT secret_hash FROM capabilities WHERE id = ?", c.id) }
	if stored() == values.HashSecret(c.secret) {
		t.Error("an older server exercises a single-use Capability")
	}
	w.wantValue("here", w.exercise("broker", c, nil))
	if stored() == values.HashSecret(c.secret) {
		t.Error("an older server exercises a used Capability")
	}
}
