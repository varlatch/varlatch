// SPDX-License-Identifier: AGPL-3.0-or-later

package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/write"
)

// receiver is a local webhook endpoint: it records every request and
// answers each path with the next status of its script (200 once the
// script is used up).
type receiver struct {
	mu       sync.Mutex
	got      []received
	statuses map[string][]int
	block    chan struct{} // when set, every request waits on it
	srv      *httptest.Server
}

type received struct {
	method, target, contentType, signature string
	body                                   []byte
}

func newReceiver(t *testing.T) *receiver {
	r := &receiver{statuses: map[string][]int{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, received{req.Method, req.RequestURI, req.Header.Get("Content-Type"), req.Header.Get(SignatureHeader), body})
		status := http.StatusOK
		if s := r.statuses[req.URL.Path]; len(s) > 0 {
			status, r.statuses[req.URL.Path] = s[0], s[1:]
		}
		block := r.block
		r.mu.Unlock()
		if block != nil {
			<-block
		}
		if status == http.StatusFound {
			w.Header().Set("Location", "/elsewhere")
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) requests() []received {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]received(nil), r.got...)
}

func (r *receiver) url(path string) string { return r.srv.URL + path }

func (r *receiver) port() string {
	_, p, _ := net.SplitHostPort(r.srv.Listener.Addr().String())
	return p
}

// dns is a resolver the test changes.
type dns struct {
	mu      sync.Mutex
	answers map[string][]outbound.Answer
}

func (d *dns) resolve(_ context.Context, name string) ([]outbound.Answer, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a, ok := d.answers[name]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (d *dns) set(name string, a ...outbound.Answer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.answers[name] = a
}

type world struct {
	t     *testing.T
	store *storage.DB
	s     *Service
	dns   *dns
	org   authz.Organization
}

func newWorld(t *testing.T, allow string) *world {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := db.Init(ctx, store, "test"); err != nil {
		t.Fatal(err)
	}
	wd := &world{t: t, store: store, dns: &dns{answers: map[string][]outbound.Answer{}}}
	wd.exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
	wd.exec(`INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_a', 'idn_a', 'cli', 'h_a')`)
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	rootKEK := envelope.GenerateKey()
	org, err := orgs.Create(ctx, w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	wd.org = authz.Organization{ID: org.ID, Slug: "acme", Name: "Acme"}
	entries, err := outbound.ParseAllow(allow)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := outbound.New(entries, outbound.Options{Resolve: wd.dns.resolve, Log: log})
	t.Cleanup(policy.Close)
	public, _ := url.Parse("http://127.0.0.1:8686")
	approvals := auth.New(store, auth.Options{PublicURL: public, RootKEK: rootKEK, PersonGate: w.Gates.PersonGate})
	wd.s = &Service{Writer: w, Approvals: approvals, RootKEK: rootKEK, Policy: policy, Log: log}
	return wd
}

func (wd *world) exec(q string, args ...any) {
	wd.t.Helper()
	if err := wd.store.Write(context.Background(), func(tx *storage.Tx) error { _, err := tx.ExecContext(context.Background(), q, args...); return err }); err != nil {
		wd.t.Fatal(err)
	}
}

func (wd *world) count(q string, args ...any) int {
	wd.t.Helper()
	var n int
	if err := wd.store.Reader().QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		wd.t.Fatal(err)
	}
	return n
}

type row struct {
	failures int64
	status   *string
	cursor   int64
}

func (wd *world) row(id string) row {
	wd.t.Helper()
	var r row
	if err := wd.store.Reader().QueryRowContext(context.Background(), `SELECT failure_count, last_status, cursor_order FROM webhooks WHERE id = ?`, id).Scan(&r.failures, &r.status, &r.cursor); err != nil {
		wd.t.Fatal(err)
	}
	return r
}

func alice() *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: "idn_a", Kind: "human"}, Credential: auth.Credential{ID: "crd_a", Kind: auth.KindCLI}}
}

func (wd *world) create(url string, eventTypes ...string) Created {
	wd.t.Helper()
	var types []string
	if len(eventTypes) > 0 {
		types = eventTypes
	}
	out, _, err := wd.s.Create(context.Background(), Request{Principal: alice()}, wd.org, url, types)
	if err != nil {
		wd.t.Fatal(err)
	}
	return out
}

// event records an audit event of the Organization.
func (wd *world) event(typ string, resource jsvalue.Object) {
	wd.t.Helper()
	org := wd.org.ID
	if err := wd.s.Writer.Job(context.Background(), nil, func(ctx context.Context, tx *storage.Tx) error {
		_, err := audit.Record(ctx, tx, audit.Event{Type: typ, Decision: audit.Info, OrganizationID: &org, Resource: resource})
		return err
	}); err != nil {
		wd.t.Fatal(err)
	}
}

func (wd *world) deliver() {
	wd.t.Helper()
	if err := wd.s.DeliverOnce(context.Background()); err != nil {
		wd.t.Fatal(err)
	}
}

func code(err error) (string, jsvalue.Object) {
	var de *domainerr.Error
	if errors.As(err, &de) {
		return de.Code, de.Details
	}
	return "", nil
}

type payload struct {
	WebhookID      string           `json:"webhookId"`
	OrganizationID string           `json:"organizationId"`
	Events         []map[string]any `json:"events"`
}

func decode(t *testing.T, body []byte) payload {
	t.Helper()
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func types(p payload) []string {
	var out []string
	for _, e := range p.Events {
		out = append(out, e["eventType"].(string))
	}
	return out
}

// verify checks a delivery's signature as a receiver does.
func verify(t *testing.T, secret string, r received) {
	t.Helper()
	ts, sig, ok := strings.Cut(r.signature, ",v1=")
	seconds, err := strconv.ParseInt(strings.TrimPrefix(ts, "t="), 10, 64)
	if !ok || !strings.HasPrefix(ts, "t=") || err != nil || Sign(secret, seconds, r.body) != sig {
		t.Errorf("signature %q does not verify", r.signature)
	}
	if d := time.Since(time.Unix(seconds, 0)); d < -time.Minute || d > time.Minute {
		t.Errorf("signature time %d is %v away", seconds, d)
	}
}

// A webhook receives only what follows its registration, signed, as one
// JSON batch; the cursor moves only on a 2xx, so a failure sends the same
// batch again, and a delivered batch is never sent twice.
func TestDeliverySignedOrderedAtLeastOnce(t *testing.T) {
	rc := newReceiver(t)
	wd := newWorld(t, "127.0.0.1/32:*")
	wd.event("project.created", nil) // before: never delivered
	hook := wd.create(rc.url("/hook?token=abc"))
	if !strings.HasPrefix(hook.Secret, "vlt_whsec_") || len(hook.Secret) != len("vlt_whsec_")+43 {
		t.Fatalf("secret %q", hook.Secret)
	}
	wd.deliver()
	if n := len(rc.requests()); n != 0 {
		t.Fatalf("%d deliveries with nothing after the registration (its own event included)", n)
	}
	rc.statuses["/hook"] = []int{http.StatusInternalServerError}
	wd.event("project.created", jsvalue.Object{{Key: "projectId", Value: "prj_a"}})
	wd.event("environment.created", nil)
	wd.deliver()
	if r := wd.row(hook.Webhook.ID); r.failures != 1 || *r.status != "500" {
		t.Errorf("after a 500: %+v", r)
	}
	wd.deliver()
	got := rc.requests()
	if len(got) != 2 || string(got[0].body) != string(got[1].body) {
		t.Fatalf("want the same batch twice, got %d", len(got))
	}
	r := got[1]
	if r.method != http.MethodPost || r.target != "/hook?token=abc" || r.contentType != "application/json" {
		t.Errorf("%s %s %s", r.method, r.target, r.contentType)
	}
	verify(t, hook.Secret, r)
	p := decode(t, r.body)
	if p.WebhookID != hook.Webhook.ID || p.OrganizationID != wd.org.ID || strings.Join(types(p), " ") != "project.created environment.created" {
		t.Errorf("%+v", p)
	}
	if row := wd.row(hook.Webhook.ID); row.failures != 0 || *row.status != "200" {
		t.Errorf("after a 200: %+v", row)
	}
	wd.deliver()
	if n := len(rc.requests()); n != 2 {
		t.Errorf("delivered again: %d requests", n)
	}
}

// The event-type filter selects what is sent; a batch with nothing to
// send (the deletion lifecycle's events, events of a deleted Project or
// of one of its environments) moves the cursor past it, sending nothing.
func TestFilterAndSkippedEvents(t *testing.T) {
	rc := newReceiver(t)
	wd := newWorld(t, "127.0.0.1/32:*")
	filtered := wd.create(rc.url("/filtered"), "environment.created")
	all := wd.create(rc.url("/all"))
	wd.exec(`INSERT INTO projects (id, organization_id, slug, name, contract_authority, deleted_at) VALUES ('prj_gone', ?, 'gone', 'Gone', 'managed', 1)`, wd.org.ID)
	wd.exec(`INSERT INTO environments (id, project_id, name, kind, tier) VALUES ('env_gone', 'prj_gone', 'dev', 'shared', 'development')`)
	wd.event("organization.deletion_cancelled", nil)
	wd.event("project.created", jsvalue.Object{{Key: "projectId", Value: "prj_gone"}})
	wd.event("environment.created", jsvalue.Object{{Key: "environmentId", Value: "env_gone"}})
	wd.deliver()
	if n := len(rc.requests()); n != 0 {
		t.Fatalf("%d deliveries of skipped events", n)
	}
	before := wd.row(all.Webhook.ID)
	wd.event("project.created", jsvalue.Object{{Key: "projectId", Value: "prj_live"}})
	wd.event("environment.created", jsvalue.Object{{Key: "environmentId", Value: "env_live"}})
	wd.deliver()
	byPath := map[string][]string{}
	for _, r := range rc.requests() {
		byPath[r.target] = types(decode(t, r.body))
	}
	if strings.Join(byPath["/filtered"], " ") != "environment.created" || strings.Join(byPath["/all"], " ") != "project.created environment.created" {
		t.Errorf("%v", byPath)
	}
	if before.cursor <= 0 || wd.row(filtered.Webhook.ID).cursor <= before.cursor {
		t.Errorf("cursors %d, %d", before.cursor, wd.row(filtered.Webhook.ID).cursor)
	}
}

// Nothing goes to a revoked webhook, nor while its Organization is being
// deleted or the webhook is suspended by a deletion (ADR-0051 Decision
// 9); the events wait, and go out once the deletion is cancelled.
func TestRevokedAndSuspended(t *testing.T) {
	rc := newReceiver(t)
	wd := newWorld(t, "127.0.0.1/32:*")
	revoked := wd.create(rc.url("/revoked"))
	if _, err := wd.s.Revoke(context.Background(), Request{Principal: alice()}, wd.org.ID, revoked.Webhook.ID); err != nil {
		t.Fatal(err)
	}
	live := wd.create(rc.url("/live"))
	wd.exec(`INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required)
		VALUES ('odl_openaaaaaaaaaaaaaaaaaaaaa', ?, 'idn_a', 0, 1, 0)`, wd.org.ID)
	wd.event("project.created", nil)
	wd.deliver()
	wd.exec(`UPDATE webhooks SET suspended_by_deletion = 'odl_openaaaaaaaaaaaaaaaaaaaaa' WHERE id = ?`, live.Webhook.ID)
	wd.deliver()
	if n := len(rc.requests()); n != 0 {
		t.Fatalf("%d deliveries while being deleted", n)
	}
	if r := wd.row(live.Webhook.ID); r.failures != 0 || r.status != nil {
		t.Errorf("row changed: %+v", r)
	}
	wd.exec(`UPDATE organization_deletions SET cancelled_by = 'idn_a', cancelled_at = 2`)
	wd.exec(`UPDATE webhooks SET suspended_by_deletion = NULL`)
	wd.deliver()
	got := rc.requests()
	if len(got) != 1 || got[0].target != "/live" || strings.Join(types(decode(t, got[0].body)), " ") != "project.created" {
		t.Errorf("%d deliveries", len(got))
	}
}

// Redirects are never followed (fetch's redirect: "error"), and a
// delivery is bounded by its timeout; each is a failure the row records,
// as the TypeScript server names it.
func TestRedirectAndTimeout(t *testing.T) {
	rc := newReceiver(t)
	wd := newWorld(t, "127.0.0.1/32:*")
	hook := wd.create(rc.url("/moved"))
	rc.statuses["/moved"] = []int{http.StatusFound}
	wd.event("project.created", nil)
	wd.deliver()
	if r := wd.row(hook.Webhook.ID); *r.status != "TypeError" || r.failures != 1 || len(rc.requests()) != 1 {
		t.Errorf("redirect: %+v, %d requests", r, len(rc.requests()))
	}
	old := deliveryTimeout
	deliveryTimeout = 200 * time.Millisecond
	t.Cleanup(func() { deliveryTimeout = old })
	rc.block = make(chan struct{})
	defer close(rc.block)
	wd.deliver()
	if r := wd.row(hook.Webhook.ID); *r.status != "TimeoutError" || r.failures != 2 {
		t.Errorf("timeout: %+v", r)
	}
}

// A delivery cut short by a stop records nothing: the next start sends it.
func TestStopRecordsNothing(t *testing.T) {
	rc := newReceiver(t)
	wd := newWorld(t, "127.0.0.1/32:*")
	hook := wd.create(rc.url("/slow"))
	wd.event("project.created", nil)
	rc.block = make(chan struct{})
	defer close(rc.block)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- wd.s.DeliverOnce(ctx) }()
	for len(rc.requests()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("%v", err)
	}
	if r := wd.row(hook.Webhook.ID); r.failures != 0 || r.status != nil {
		t.Errorf("recorded: %+v", r)
	}
}

// The loop skips its pass while the maintenance admission is closed.
func TestLoopPausesUnderMaintenance(t *testing.T) {
	rc := newReceiver(t)
	wd := newWorld(t, "127.0.0.1/32:*")
	wd.create(rc.url("/m"))
	wd.event("project.created", nil)
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	open, admitted := false, 0
	admit := func() (func(), bool) {
		mu.Lock()
		defer mu.Unlock()
		if !open {
			return nil, false
		}
		admitted++
		return func() {}, true
	}
	done := make(chan struct{})
	go func() { defer close(done); wd.s.RunLoop(ctx, 20*time.Millisecond, admit) }()
	time.Sleep(100 * time.Millisecond)
	if n := len(rc.requests()); n != 0 {
		t.Fatalf("%d deliveries under maintenance", n)
	}
	mu.Lock()
	open = true
	mu.Unlock()
	for deadline := time.Now().Add(5 * time.Second); len(rc.requests()) == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if len(rc.requests()) != 1 {
		t.Errorf("%d deliveries once admitted", len(rc.requests()))
	}
}

// The request is built from the URL as `new URL` reads it: the host the
// outbound check decided (0x7f.1 is 127.0.0.1, never a name Go would
// look up), the path and query percent-encoded as fetch sends them.
func TestRequestFromTheWHATWGURL(t *testing.T) {
	rc := newReceiver(t)
	wd := newWorld(t, "127.0.0.1/32:*")
	origin := "http://0x7f.1:" + rc.port()
	// A path that starts with "//" goes out as a path, never as an
	// absolute URL (net/url's Opaque form would send "http://x/y").
	cases := map[string]string{
		"/a b/é?x y=\"1\"#frag": "/a%20b/%C3%A9?x%20y=%221%22",
		"//x/y?z=1":             "//x/y?z=1",
		"//hooks/a b/%41?q=%2F": "//hooks/a%20b/%41?q=%2F",
		"///triple":             "///triple",
	}
	for path := range cases {
		wd.create(origin + path)
	}
	wd.event("project.created", nil)
	wd.deliver()
	var got []string
	for _, r := range rc.requests() {
		got = append(got, r.target)
	}
	slices.Sort(got)
	var want []string
	for _, target := range cases {
		want = append(want, target)
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("targets %q, want %q", got, want)
	}
	for _, target := range want {
		u, ok := requestURL(origin + target)
		if !ok || u.Host != "127.0.0.1:"+rc.port() || u.RequestURI() != target {
			t.Errorf("%s: %v %q", target, ok, u.RequestURI())
		}
	}
}

// A connection that never completes ends at the dialer's connect timeout,
// a network error (undici's ConnectTimeoutError in fetch's TypeError), not
// the delivery's own deadline (fetch's TimeoutError).
func TestConnectTimeoutIsTypeError(t *testing.T) {
	wd := newWorld(t, "127.0.0.1/32:*")
	hook := wd.create("http://127.0.0.1:9/blackhole")
	wd.event("project.created", nil)
	blackhole := func(ctx context.Context, _, _ string) (net.Conn, error) {
		// The dialer's own deadline, shorter than the delivery's.
		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	wd.s.client = &http.Client{Transport: &http.Transport{DialContext: blackhole}}
	wd.deliver()
	if r := wd.row(hook.Webhook.ID); r.status == nil || *r.status != "TypeError" || r.failures != 1 {
		t.Errorf("connect timeout: %+v", r)
	}
}

// A URL the policy refuses is refused at registration, before any
// approval, with its class and never its address, and the refusal is
// recorded although nothing else is; a name that resolves to a refused
// address only later is refused at delivery: the cursor stays, and the
// refusal is recorded once within the rate bound.
func TestOutboundRefusals(t *testing.T) {
	wd := newWorld(t, "127.0.0.1/32:*")
	ctx := context.Background()
	_, _, err := wd.s.Create(ctx, Request{Principal: alice()}, wd.org, "https://10.0.0.7/hook", nil)
	c, details := code(err)
	if reason, _ := details.Get("outbound"); c != "VALIDATION_FAILED" || reason != "private_address" || strings.Contains(err.Error(), "10.0.0.7") {
		t.Errorf("%v %v", err, details)
	}
	if n := wd.count(`SELECT count(*) FROM audit_events WHERE event_type = 'outbound.refused' AND json_extract(metadata, '$.phase') = 'configuration'`); n != 1 {
		t.Errorf("%d configuration refusals recorded", n)
	}
	if n := wd.count(`SELECT count(*) FROM webhooks`); n != 0 {
		t.Errorf("%d webhooks", n)
	}
	for _, bad := range []string{"ftp://h/x", "https://u:p@h/x", "https://u@h/x", "not a url"} {
		if _, _, err := wd.s.Create(ctx, Request{Principal: alice()}, wd.org, bad, nil); func() string { c, _ := code(err); return c }() != "VALIDATION_FAILED" {
			t.Errorf("%s: %v", bad, err)
		}
	}
	hook := wd.create("https://later.test/hook") // does not resolve: saved
	wd.dns.set("later.test", outbound.Answer{Address: "192.168.1.9", Family: 4})
	wd.event("project.created", nil)
	wd.deliver()
	wd.deliver()
	r := wd.row(hook.Webhook.ID)
	if *r.status != outbound.LastStatusRefused || r.failures != 2 {
		t.Errorf("%+v", r)
	}
	if n := wd.count(`SELECT count(*) FROM audit_events WHERE event_type = 'outbound.refused' AND json_extract(metadata, '$.phase') = 'connection'
		AND json_extract(resource, '$.webhookId') = ?`, hook.Webhook.ID); n != 1 {
		t.Errorf("%d connection refusals recorded", n)
	}
	// A filter change keeps working on a refused URL; a URL change is checked.
	if _, _, err := wd.s.Update(ctx, Request{Principal: alice()}, wd.org.ID, hook.Webhook.ID, Patch{ExpectedVersion: 1, SetEventTypes: true, EventTypes: []string{"project.created"}}); err != nil {
		t.Errorf("filter change: %v", err)
	}
	bad := "https://10.0.0.8/x"
	if _, _, err := wd.s.Update(ctx, Request{Principal: alice()}, wd.org.ID, hook.Webhook.ID, Patch{ExpectedVersion: 2, URL: &bad}); func() string { c, _ := code(err); return c }() != "VALIDATION_FAILED" {
		t.Errorf("URL change: %v", err)
	}
}

// Updates keep the secret and the cursor, check the version, and answer
// an unchanged webhook as it is; a reordering is written without an
// approval; revoking is refused for an unknown webhook.
func TestUpdateAndRevoke(t *testing.T) {
	rc := newReceiver(t)
	wd := newWorld(t, "127.0.0.1/32:*")
	ctx := context.Background()
	hook := wd.create(rc.url("/one"), "a.b", "c.d")
	up := func(p Patch) (map[string]any, error) {
		resp, _, err := wd.s.Update(ctx, Request{Principal: alice()}, wd.org.ID, hook.Webhook.ID, p)
		if err != nil {
			return nil, err
		}
		var out map[string]any
		_ = json.Unmarshal(jsvalue.Stringify(resp.Payload), &out)
		return out, nil
	}
	if out, err := up(Patch{ExpectedVersion: 1}); err != nil || out["version"] != float64(1) {
		t.Errorf("unchanged: %v %v", out, err)
	}
	if out, err := up(Patch{ExpectedVersion: 1, SetEventTypes: true, EventTypes: []string{"c.d", "a.b"}}); err != nil || out["version"] != float64(2) {
		t.Errorf("reordered: %v %v", out, err)
	}
	if _, err := up(Patch{ExpectedVersion: 1, SetEventTypes: true}); func() string { c, _ := code(err); return c }() != "VERSION_CONFLICT" {
		t.Errorf("stale version: %v", err)
	}
	two := rc.url("/two")
	out, err := up(Patch{ExpectedVersion: 2, URL: &two, SetEventTypes: true})
	if err != nil || out["url"] != two || out["eventTypes"] != nil || out["version"] != float64(3) {
		t.Errorf("changed: %v %v", out, err)
	}
	if n := wd.count(`SELECT count(*) FROM audit_events WHERE event_type = 'webhook.updated'`); n != 2 {
		t.Errorf("%d webhook.updated events", n)
	}
	wd.event("project.created", nil)
	wd.deliver()
	got := rc.requests()
	if len(got) != 1 || got[0].target != "/two" {
		t.Fatalf("%+v", got)
	}
	verify(t, hook.Secret, got[0])
	if _, err := wd.s.Revoke(ctx, Request{Principal: alice()}, wd.org.ID, "whk_nope"); func() string { c, _ := code(err); return c }() != "RESOURCE_NOT_FOUND" {
		t.Errorf("unknown: %v", err)
	}
}
