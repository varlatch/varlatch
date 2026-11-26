// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// retireHarness is varlatchd on capabilities-v0.22.0.json's rows, with
// its writer, for the retirement tests.
type retireHarness struct {
	t     *testing.T
	f     paritytest.Fixture
	store *storage.DB
	w     *write.Writer
	h     http.Handler
	vs    *values.Service
	fill  func(string) string
}

func newRetireHarness(t *testing.T) *retireHarness {
	t.Helper()
	f, err := paritytest.Read(paritytest.Path("capabilities-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(dbPath, f.Rows, capabilitiesTables); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := url.Parse("http://127.0.0.1:8686")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	now := paritytest.HourClock()
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PublicURL: public, PersonGate: w.Gates.PersonGate, Now: now})
	vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates, Now: now})
	h, err := httpserver.New(httpserver.Options{
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: public,
		Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vs.Settled)
	return &retireHarness{t: t, f: f, store: store, w: w, h: h, vs: vs, fill: fillPath(f, nil)}
}

func (r *retireHarness) call(method, path, credential, body string) (int, string) {
	r.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "http://127.0.0.1:8686"+r.fill(path), rd)
	req.Header.Set("Authorization", "Bearer "+r.f.Tokens[credential])
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	r.vs.Settled()
	return rec.Code, rec.Body.String()
}

func (r *retireHarness) count(q string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.store.Reader().QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

const (
	exercises = "/v1/organizations/cap/projects/api/environments/development/capabilities/{cap:live}/exercises"
	exercise  = `{"capabilitySecret":"vlt_cap_known_live","destination":{"host":"api.example.com","port":443},` +
		`"placements":[{"item":"SECRET_A","target":"header:authorization"}]}`
	issuances = "/v1/organizations/cap/projects/api/environments/development/capabilities"
	issuance  = `{"agentIdentityId":"{idn:agent}","items":["SECRET_A"],"destinations":["api.example.com"],` +
		`"targets":{"SECRET_A":["header:authorization"]},"ttlSeconds":600}`
)

func refusalReason(t *testing.T, body string) string {
	t.Helper()
	var refusal struct {
		Error struct {
			Details struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &refusal); err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	return refusal.Error.Details.Reason
}

// TestRetiringTheAgentRevokesItsCapabilities: a retired Agent's
// Capabilities stop working at once, not when they expire, and stay
// revoked (ADR-0034 §3: retirement revokes what was issued, so a later
// reactivation resurrects nothing).
func TestRetiringTheAgentRevokesItsCapabilities(t *testing.T) {
	r := newRetireHarness(t)
	if code, body := r.call(http.MethodPost, exercises, "broker", exercise); code != http.StatusOK {
		t.Fatalf("exercise before retirement: %d %s", code, body)
	}
	if code, body := r.call(http.MethodPost, "/v1/organizations/cap/identities/{idn:agent}/retire", "alice", ""); code != http.StatusOK {
		t.Fatalf("retire the Agent: %d %s", code, body)
	}
	code, body := r.call(http.MethodPost, exercises, "broker", exercise)
	if code != http.StatusForbidden || refusalReason(t, body) != "revoked" {
		t.Fatalf("exercise after retirement: %d %s, want 403 (revoked)", code, body)
	}

	// Every live Capability of the Agent is revoked, each audited; another
	// Agent's are untouched.
	agent := r.fill("{idn:agent}")
	if n := r.count("SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL", agent); n != 0 {
		t.Fatalf("%d of the retired Agent's Capabilities are still live", n)
	}
	if r.count("SELECT count(*) FROM capabilities WHERE agent_identity_id <> ? AND revoked_at IS NULL", agent) == 0 {
		t.Fatal("another Agent's Capabilities were revoked too")
	}
	// known-untargeted, known-live, known-theirs, known-expired, known-prod:
	// the Agent's unrevoked ones (an expired one is revoked too, harmlessly).
	if n := r.count("SELECT count(*) FROM audit_events WHERE event_type = 'capability.revoked'"); n != 5 {
		t.Fatalf("%d capability.revoked events, want 5", n)
	}
}

// TestReactivatingTheAgentResurrectsNoCapability: what retirement revoked
// stays revoked once the Agent is reactivated.
func TestReactivatingTheAgentResurrectsNoCapability(t *testing.T) {
	r := newRetireHarness(t)
	if code, body := r.call(http.MethodPost, "/v1/organizations/cap/identities/{idn:agent}/retire", "alice", ""); code != http.StatusOK {
		t.Fatalf("retire the Agent: %d %s", code, body)
	}
	if code, body := r.call(http.MethodPost, "/v1/organizations/cap/identities/{idn:agent}/reactivate", "alice", ""); code != http.StatusOK {
		t.Fatalf("reactivate the Agent: %d %s", code, body)
	}
	code, body := r.call(http.MethodPost, exercises, "broker", exercise)
	if code != http.StatusForbidden || refusalReason(t, body) != "revoked" {
		t.Fatalf("exercise after reactivation: %d %s, want 403 (revoked)", code, body)
	}
	if n := r.count("SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL", r.fill("{idn:agent}")); n != 0 {
		t.Fatalf("%d of the reactivated Agent's Capabilities are live again", n)
	}
	// A Capability issued after the reactivation works.
	if code, body := r.call(http.MethodPost, issuances, "broker", r.fill(issuance)); code != http.StatusCreated {
		t.Fatalf("issue after reactivation: %d %s", code, body)
	}
}

// TestRetiringTheBrokerRevokesItsCapabilities: the Capabilities a retired
// Broker issued are revoked with it, each audited; another Broker's are
// untouched, and a reactivation brings none back.
func TestRetiringTheBrokerRevokesItsCapabilities(t *testing.T) {
	r := newRetireHarness(t)
	broker := r.fill("{idn:broker}")
	live := r.count("SELECT count(*) FROM capabilities WHERE broker_identity_id = ? AND revoked_at IS NULL", broker)
	if live == 0 {
		t.Fatal("the fixture's Broker has no live Capability")
	}
	others := r.count("SELECT count(*) FROM capabilities WHERE broker_identity_id <> ? AND revoked_at IS NULL", broker)
	if code, body := r.call(http.MethodPost, "/v1/organizations/cap/identities/{idn:broker}/retire", "alice", ""); code != http.StatusOK {
		t.Fatalf("retire the Broker: %d %s", code, body)
	}
	if code, body := r.call(http.MethodPost, "/v1/organizations/cap/identities/{idn:broker}/reactivate", "alice", ""); code != http.StatusOK {
		t.Fatalf("reactivate the Broker: %d %s", code, body)
	}
	if n := r.count("SELECT count(*) FROM capabilities WHERE broker_identity_id = ? AND revoked_at IS NULL", broker); n != 0 {
		t.Fatalf("%d of the retired Broker's Capabilities are live", n)
	}
	if n := r.count("SELECT count(*) FROM capabilities WHERE broker_identity_id <> ? AND revoked_at IS NULL", broker); n != others {
		t.Fatalf("another Broker's live Capabilities went from %d to %d", others, n)
	}
	n := r.count(`SELECT count(*) FROM audit_events WHERE event_type = 'capability.revoked'
		AND json_extract(metadata, '$.reason') = 'identity-retired' AND json_extract(metadata, '$.identityId') = ?`, broker)
	if n != live {
		t.Fatalf("%d capability.revoked events, want %d", n, live)
	}
}

// issueWhileRetiring retires identity while an issuance by the Broker,
// already authenticated, waits for its gates: the test holds the
// identity's gate shared, the retirement waits for it exclusive, and the
// issuance, behind the waiting retirement, until it is done. The issuance's
// answer is returned.
func issueWhileRetiring(t *testing.T, r *retireHarness, identity string) (int, string) {
	t.Helper()
	id := r.fill("{idn:" + identity + "}")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, release, err := r.w.Gates.Acquire(ctx, write.Person(id, write.Shared))
	if err != nil {
		t.Fatal(err)
	}
	waiting := func(mode write.Mode, n int) {
		t.Helper()
		for ctx.Err() == nil {
			seen := 0
			for _, g := range r.w.Gates.Waiting() {
				if g.Key == id && g.Mode == mode {
					seen++
				}
			}
			if seen >= n {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("no %s taker waited on %s's gate", mode, identity)
	}
	type answer struct {
		code int
		body string
	}
	retired, issued := make(chan answer, 1), make(chan answer, 1)
	go func() {
		code, body := r.call(http.MethodPost, "/v1/organizations/cap/identities/{idn:"+identity+"}/retire", "alice", "")
		retired <- answer{code, body}
	}()
	waiting(write.Exclusive, 1)
	go func() {
		code, body := r.call(http.MethodPost, issuances, "broker", r.fill(issuance))
		issued <- answer{code, body}
	}()
	waiting(write.Shared, 1)
	release()
	if a := <-retired; a.code != http.StatusOK {
		t.Fatalf("retire %s: %d %s", identity, a.code, a.body)
	}
	a := <-issued
	return a.code, a.body
}

// TestIssuanceForAnAgentRetiredMeanwhile: an issuance that authenticated
// before the Agent's retirement and gets its gates after it is refused,
// and leaves no live Capability.
func TestIssuanceForAnAgentRetiredMeanwhile(t *testing.T) {
	r := newRetireHarness(t)
	code, body := issueWhileRetiring(t, r, "agent")
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "Agent identity is disabled") {
		t.Fatalf("issuance: %d %s, want 422 (Agent identity is disabled)", code, body)
	}
	if n := r.count("SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL", r.fill("{idn:agent}")); n != 0 {
		t.Fatalf("%d of the retired Agent's Capabilities are live", n)
	}
}

// TestIssuanceByABrokerRetiredMeanwhile: a Broker's issuance that
// authenticated before the Broker's retirement and gets its gates after it
// is refused, and leaves no live Capability to work after a reactivation.
func TestIssuanceByABrokerRetiredMeanwhile(t *testing.T) {
	r := newRetireHarness(t)
	code, body := issueWhileRetiring(t, r, "broker")
	if code != http.StatusUnauthorized || !strings.Contains(body, "INVALID_CREDENTIAL") {
		t.Fatalf("issuance: %d %s, want 401 (INVALID_CREDENTIAL)", code, body)
	}
	if n := r.count("SELECT count(*) FROM capabilities WHERE broker_identity_id = ? AND revoked_at IS NULL", r.fill("{idn:broker}")); n != 0 {
		t.Fatalf("%d of the retired Broker's Capabilities are live", n)
	}
}
