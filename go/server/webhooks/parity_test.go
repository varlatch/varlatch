// SPDX-License-Identifier: AGPL-3.0-or-later

package webhooks_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/webhooks"
	"github.com/varlatch/varlatch/go/server/write"
)

var writeGoSealed = flag.String("write-go-sealed", "", "write the v0.22.0 webhooks fixture with the canary, every Organization KEK and every webhook secret sealed again by Go to this path")

// webhooksTables are the tables of webhooks-v0.22.0.json
// (go-webhooks-fixture.test.ts).
var webhooksTables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "projects", "environments",
	"security_controls", "approval_intents", "organization_freezes", "organization_deletions", "webhooks", "audit_events"}

// The fixture's public URL, allow list, resolver and delivery clock
// (PUBLIC_URL, ALLOW, RESOLVE and DELIVERY_AT there).
const (
	publicURL = "http://127.0.0.1:8686"
	allow     = "hooks.internal,127.0.0.1/32:*"
)

var deliveryAt = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

var answers = map[string][]outbound.Answer{
	"hooks.public.example": {{Address: "93.184.216.34", Family: 4}},
	"hooks.internal":       {{Address: "10.1.2.3", Family: 4}},
	"intranet.example":     {{Address: "192.168.1.20", Family: 4}},
}

func resolve(_ context.Context, name string) ([]outbound.Answer, error) {
	if a, ok := answers[name]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func policy(t *testing.T) *outbound.Policy {
	entries, err := outbound.ParseAllow(allow)
	if err != nil {
		t.Fatal(err)
	}
	return outbound.New(entries, outbound.Options{Resolve: resolve, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
}

// delivery is one recorded delivery request (Delivery there).
type delivery struct {
	WebhookID   string `json:"webhookId"`
	Target      string `json:"target"`
	ContentType string `json:"contentType"`
	Signature   string `json:"signature"`
	Body        string `json:"body"`
}

// extra is what the webhooks fixture holds beyond the kit's members.
type extra struct {
	Secrets    map[string]string `json:"secrets"`
	Deliveries []delivery        `json:"deliveries"`
	Delivered  []map[string]any  `json:"delivered"`
}

func read(t *testing.T, path string) (paritytest.Fixture, extra) {
	t.Helper()
	f, err := paritytest.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var x extra
	if err := json.Unmarshal(b, &x); err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 80 || len(x.Deliveries) < 6 || len(x.Secrets) < 15 {
		t.Fatalf("%s: %d requests, %d deliveries, %d secrets: the fixture is incomplete", path, len(f.Requests), len(x.Deliveries), len(x.Secrets))
	}
	return f, x
}

// fillPath is go-webhooks-fixture.test.ts's: acme's id and the named
// webhooks, by Organization and URL.
func fillPath(f paritytest.Fixture) func(string) string {
	orgID := func(slug string) string {
		for _, o := range f.Rows["organizations"] {
			if o["slug"] == slug {
				return o["id"].(string)
			}
		}
		return ""
	}
	hook := func(slug, url string) string {
		for _, w := range f.Rows["webhooks"] {
			if w["organization_id"] == orgID(slug) && w["url"] == url {
				return w["id"].(string)
			}
		}
		return ""
	}
	pub := "https://hooks.public.example"
	return strings.NewReplacer(
		"{acmeId}", orgID("acme"),
		"{updId}", hook("acme", pub+"/upd"), "{delId}", hook("acme", pub+"/del"), "{oldId}", hook("acme", pub+"/old"),
		"{refusedId}", hook("acme", "https://intranet.example/refused"), "{betaId}", hook("beta", pub+"/beta"),
		"{frozenId}", hook("frozen", pub+"/frozen"), "{deletingId}", hook("deleting", pub+"/deleting"), "{repId}", hook("rep", pub+"/rep"),
		"{enfId}", hook("enf", pub+"/enf"), "{enfSetId}", hook("enf", pub+"/enf-set"), "{enfDelId}", hook("enf", pub+"/enf-del"),
	).Replace
}

func open(t *testing.T, f paritytest.Fixture) (*storage.DB, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, webhooksTables); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	return store, rootKEK
}

// replayRequests runs the table against varlatchd on the file's rows.
func replayRequests(t *testing.T, f paritytest.Fixture) {
	store, rootKEK := open(t, f)
	public, _ := url.Parse(publicURL)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	now := paritytest.HourClock()
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PublicURL: public, PersonGate: w.Gates.PersonGate, Now: now})
	vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates, Now: now})
	p := policy(t)
	t.Cleanup(p.Close)
	h, err := httpserver.New(httpserver.Options{
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: public,
		Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Now: now, Outbound: p,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vs.Settled)
	paritytest.Replay(t, paritytest.Target{
		Handler: h, Store: store, Settled: vs.Settled, Path: fillPath(f), Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}, f)
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// replayDeliveries runs one delivery pass on a copy of the file's rows
// with the clock at DELIVERY_AT, through a recording client that answers
// 500 for /fail, and compares the requests (the target as sent, the
// Content-Type, the signature and the body, byte for byte) and each
// webhook's delivery state afterwards with the TypeScript server's.
func replayDeliveries(t *testing.T, f paritytest.Fixture, x extra) {
	store, rootKEK := open(t, f)
	var sent []delivery
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		var p struct {
			WebhookID string `json:"webhookId"`
		}
		_ = json.Unmarshal(body, &p)
		sent = append(sent, delivery{
			WebhookID: p.WebhookID, Target: r.URL.Scheme + "://" + r.URL.Host + r.URL.RequestURI(),
			ContentType: r.Header.Get("Content-Type"), Signature: r.Header.Get(webhooks.SignatureHeader), Body: string(body),
		})
		status := http.StatusOK
		if strings.HasPrefix(r.URL.RequestURI(), "/fail") {
			status = http.StatusInternalServerError
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}, Request: r}, nil
	})}
	p := policy(t)
	t.Cleanup(p.Close)
	s := &webhooks.Service{Writer: &write.Writer{Store: store, Gates: write.NewGates()}, RootKEK: rootKEK, Policy: p,
		Now: func() time.Time { return deliveryAt }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s.SetClient(client)
	if err := s.DeliverOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	sort.Slice(sent, func(i, j int) bool { return sent[i].WebhookID < sent[j].WebhookID })
	if len(sent) != len(x.Deliveries) {
		t.Errorf("%d deliveries, the TypeScript server sent %d", len(sent), len(x.Deliveries))
	}
	for i := range min(len(sent), len(x.Deliveries)) {
		if sent[i] != x.Deliveries[i] {
			t.Errorf("delivery %d:\n got %+v\nwant %+v", i, sent[i], x.Deliveries[i])
		}
	}
	rows, err := store.Reader().Query(`SELECT id, failure_count, last_status, CAST(cursor_order AS TEXT), cursor_event_id FROM webhooks ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id, cursor, event string
		var failures int64
		var status *string
		if err := rows.Scan(&id, &failures, &status, &cursor, &event); err != nil {
			t.Fatal(err)
		}
		got = append(got, fmt.Sprintf("%s %d %v %s %s", id, failures, deref(status), cursor, event))
	}
	var want []string
	for _, r := range x.Delivered {
		failures, _ := r["failure_count"].(float64)
		want = append(want, fmt.Sprintf("%s %d %v %s %s", r["id"], int64(failures), r["last_status"], r["cursor_order"], r["cursor_event_id"]))
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("delivery state:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func deref(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// The webhooks fixtures give the TypeScript server's answers and
// deliveries (step 4.7b): listWebhooks, createWebhook (every zod issue,
// the outbound policy's refusals and their records, frozen, deleting, at
// report and at enforce with its approval), updateWebhook (versions,
// a reordering, the token, a refused URL, an Idempotency-Key's replay and
// conflict) and revokeWebhook, with their audit events and side rows;
// then one delivery pass whose requests match byte for byte. The
// signatures over the same bodies at the same second show that varlatchd
// opened every secret the TypeScript code sealed, this release's and
// v0.21.0's (G3 at the database level, webhook secrets, ts-to-go).
func TestTypeScriptFixtures(t *testing.T) {
	for _, name := range []string{"webhooks-v0.22.0.json", "webhooks-v0.21.0.json"} {
		t.Run(name, func(t *testing.T) {
			f, x := read(t, paritytest.Path(name))
			replayRequests(t, f)
			replayDeliveries(t, f, x)
		})
	}
}

func envelopeValue(t *testing.T, e envelope.Envelope) map[string]any {
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// goSealed is the v0.22.0 fixture with the Root KEK canary, every
// Organization KEK and every webhook secret sealed again by Go.
func goSealed(t *testing.T) (paritytest.Fixture, extra) {
	f, x := read(t, paritytest.Path("webhooks-v0.22.0.json"))
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	for _, inst := range f.Rows["installation"] {
		canary, err := envelope.NewCanary(rootKEK, inst["id"].(string))
		if err != nil {
			t.Fatal(err)
		}
		inst["kek_canary"] = envelopeValue(t, canary)
	}
	kekOf := map[string][]byte{}
	for _, o := range f.Rows["organizations"] {
		id := o["id"].(string)
		kek, wrapped, err := envelope.WrapOrgKEK(rootKEK, id)
		if err != nil {
			t.Fatal(err)
		}
		kekOf[id] = kek
		o["wrapped_org_kek"] = envelopeValue(t, wrapped)
	}
	sealedOf := map[string]map[string]any{}
	for _, w := range f.Rows["webhooks"] {
		id, org := w["id"].(string), w["organization_id"].(string)
		secret, ok := x.Secrets[id]
		if !ok {
			t.Fatalf("no secret for %s", id)
		}
		sealed, err := envelope.Seal(kekOf[org], []byte(secret), envelope.WebhookSecretContext(org, id))
		if err != nil {
			t.Fatal(err)
		}
		sealedOf[id] = envelopeValue(t, sealed)
		w["secret_envelope"] = sealedOf[id]
	}
	// The side rows a request changed show the envelope as the rows hold it.
	for _, r := range f.Requests {
		for _, rows := range r.Side["webhooks"] {
			resealSide(rows, sealedOf)
		}
	}
	f.Comment = "Written by the Go tests (go test ./server/webhooks -run TestGoSealedFixture -args -write-go-sealed=<file>): the v0.22.0 webhooks fixture with the Root KEK canary, every Organization KEK and every webhook secret sealed again by Go; services/varlatchd/test/go-webhooks-fixture.test.ts opens it with the TypeScript server."
	f.Ref = "go"
	return f, x
}

// TestGoSealedFixture: webhook secrets Go sealed open in varlatchd's
// delivery with the TypeScript server's answers and deliveries; with
// -write-go-sealed, the file for the TypeScript side (G3, go-to-ts).
func TestGoSealedFixture(t *testing.T) {
	f, x := goSealed(t)
	replayRequests(t, f)
	replayDeliveries(t, f, x)
	if *writeGoSealed == "" {
		return
	}
	var raw map[string]json.RawMessage
	b, err := os.ReadFile(paritytest.Path("webhooks-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	var requests []map[string]any
	if err := json.Unmarshal(raw["requests"], &requests); err != nil {
		t.Fatal(err)
	}
	for _, r := range requests {
		side, _ := r["side"].(map[string]any)
		changes, _ := side["webhooks"].(map[string]any)
		for _, rows := range changes {
			for _, row := range rows.([]any) {
				resealSide([]paritytest.Row{row.(map[string]any)}, sealedEnvelopes(f))
			}
		}
	}
	for k, v := range map[string]any{"comment": f.Comment, "ref": f.Ref, "rows": f.Rows, "requests": requests} {
		enc, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		raw[k] = enc
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(*writeGoSealed, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// resealSide puts the envelope Go sealed into side rows of the webhooks it
// sealed one for.
func resealSide(rows []paritytest.Row, sealedOf map[string]map[string]any) {
	for _, row := range rows {
		if id, ok := row["id"].(string); ok && row["secret_envelope"] != nil && sealedOf[id] != nil {
			row["secret_envelope"] = sealedOf[id]
		}
	}
}

func sealedEnvelopes(f paritytest.Fixture) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, w := range f.Rows["webhooks"] {
		out[w["id"].(string)] = w["secret_envelope"].(map[string]any)
	}
	return out
}
