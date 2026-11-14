// SPDX-License-Identifier: AGPL-3.0-or-later

package realtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
)

var bg = context.Background()

func openStore(t *testing.T) *storage.DB {
	t.Helper()
	s, err := storage.Open(bg, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := db.Init(bg, s, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	return s
}

func exec(t *testing.T, s *storage.DB, stmt string, args ...any) {
	t.Helper()
	if err := s.Write(bg, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(bg, stmt, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", stmt, err)
	}
}

func org(t *testing.T, s *storage.DB, id string, deleted bool) {
	t.Helper()
	var at any
	if deleted {
		at = int64(1)
	}
	exec(t, s, `INSERT INTO organizations (id, slug, name, wrapped_org_kek, deleted_at) VALUES (?, ?, ?, '{}', ?)`, id, id, id, at)
}

type vectorEvent struct {
	ID             string  `json:"id"`
	Type           string  `json:"type"`
	OrganizationID *string `json:"organizationId"`
	Actor          *string `json:"actor"`
	CredentialID   *string `json:"credentialId"`
	Resource       any     `json:"resource"`
	OccurredAt     string  `json:"occurredAt"`
}

type vectorSignal struct {
	Kind        string   `json:"kind"`
	Key         string   `json:"key"`
	LastEventID string   `json:"lastEventId"`
	OccurredAt  string   `json:"occurredAt"`
	Domains     []string `json:"domains"`
}

// testdata/ts-vectors.json comes from the TypeScript server's own mirror
// publisher (services/varlatchd/test/go-realtime-vectors.test.ts, which also
// checks it is current): for each batch of audit events, the signals one
// syncNewMirrorEvents pass pushes. One pass of the hub over the same events
// gives the same signals, in the same order.
func TestSignalsMatchTheTypeScriptPublisher(t *testing.T) {
	raw, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Organizations []struct {
			ID      string `json:"id"`
			Deleted bool   `json:"deleted"`
		} `json:"organizations"`
		Batches []struct {
			Name    string         `json:"name"`
			Events  []vectorEvent  `json:"events"`
			Signals []vectorSignal `json:"signals"`
		} `json:"batches"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Batches) < 7 {
		t.Fatalf("only %d batches", len(v.Batches))
	}
	s := openStore(t)
	for _, o := range v.Organizations {
		org(t, s, o.ID, o.Deleted)
	}
	h := New(Options{Store: s})
	var cursor int64
	if err := s.Reader().QueryRowContext(bg, `SELECT coalesce(max(event_order), 0) FROM audit_events`).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	for _, b := range v.Batches {
		for _, e := range b.Events {
			types[e.Type] = true
			at, err := time.Parse(time.RFC3339Nano, e.OccurredAt)
			if err != nil {
				t.Fatal(err)
			}
			var resource any
			if e.Resource != nil {
				j, _ := json.Marshal(e.Resource)
				resource = string(j)
			}
			exec(t, s, `INSERT INTO audit_events (id, event_type, decision, organization_id, actor_identity_id, credential_id, resource, occurred_at)
				VALUES (?, ?, 'info', ?, ?, ?, ?, ?)`, e.ID, e.Type, e.OrganizationID, e.Actor, e.CredentialID, resource, at.UnixMicro())
		}
		p, err := h.pass(bg, cursor)
		if err != nil {
			t.Fatal(err)
		}
		if p.read != len(b.Events) {
			t.Fatalf("%s: read %d events, want %d", b.Name, p.read, len(b.Events))
		}
		cursor = p.next
		got := make([]vectorSignal, 0, len(p.signals))
		for _, sg := range p.signals {
			got = append(got, vectorSignal{Kind: sg.Kind, Key: sg.Key, LastEventID: sg.LastEventID, OccurredAt: sg.OccurredAt, Domains: sg.Domains})
		}
		want := b.Signals
		if want == nil {
			want = []vectorSignal{}
		}
		if !reflect.DeepEqual(got, want) {
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(want)
			t.Errorf("%s:\n go %s\n ts %s", b.Name, gj, wj)
		}
	}
	if len(types) < 100 {
		t.Fatalf("the vectors cover only %d event types", len(types))
	}
}

// world: two Organizations, three people, browser sessions.
//
//	alice  member of org_a
//	bob    member of org_b
//	carol  member of org_a and org_b
type world struct {
	t     *testing.T
	store *storage.DB
	hub   *Hub
	now   time.Time
}

func newWorld(t *testing.T, opts Options) *world {
	t.Helper()
	s := openStore(t)
	w := &world{t: t, store: s, now: time.Now()}
	opts.Store = s
	opts.Now = func() time.Time { return w.now }
	w.hub = New(opts)
	org(t, s, "org_a", false)
	org(t, s, "org_b", false)
	for _, p := range []string{"alice", "bob", "carol"} {
		exec(t, s, `INSERT INTO identities (id, kind, name) VALUES (?, 'human', ?)`, "idn_"+p, p)
		exec(t, s, `INSERT INTO auth_users (id, name, email) VALUES (?, ?, ?)`, "usr_"+p, p, p+"@example.com")
		exec(t, s, `INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES (?, ?)`, "usr_"+p, "idn_"+p)
	}
	for _, m := range [][2]string{{"org_a", "alice"}, {"org_b", "bob"}, {"org_a", "carol"}, {"org_b", "carol"}} {
		exec(t, s, `INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, ?, 'member')`, m[0], "idn_"+m[1])
	}
	return w
}

// session starts a browser session for a person; its id.
func (w *world) session(person string) string {
	w.t.Helper()
	id := fmt.Sprintf("ses_%s_%d", person, time.Now().UnixNano())
	exec(w.t, w.store, `INSERT INTO auth_sessions (id, expires_at, token_hash, user_id) VALUES (?, ?, ?, ?)`,
		id, w.now.Add(time.Hour).UnixMicro(), "hash_"+id, "usr_"+person)
	return id
}

func (w *world) subscribe(person, session string) *Stream {
	w.t.Helper()
	st, err := w.hub.Subscribe(bg, session, "idn_"+person)
	if err != nil {
		w.t.Fatal(err)
	}
	return st
}

var serial int

// event records an audit event and publishes everything after cursor.
func (w *world) event(typ, orgID, actor string, resource map[string]any, credential string) {
	w.t.Helper()
	serial++
	var res any
	if resource != nil {
		j, _ := json.Marshal(resource)
		res = string(j)
	}
	null := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	exec(w.t, w.store, `INSERT INTO audit_events (id, event_type, decision, organization_id, actor_identity_id, credential_id, resource) VALUES (?, ?, 'info', ?, ?, ?, ?)`,
		fmt.Sprintf("evt_t%05d", serial), typ, null(orgID), null(actor), null(credential), res)
}

// publish runs the hub's publication from position 0 (the test's events
// only: Init records none) up to now, once.
func (w *world) publish(cursor int64) int64 {
	w.t.Helper()
	next, err := w.hub.publish(bg, cursor)
	if err != nil {
		w.t.Fatal(err)
	}
	return next
}

// received drains what a stream has queued.
func received(st *Stream) []string {
	var out []string
	for {
		select {
		case batch := <-st.Messages():
			for _, m := range batch {
				out = append(out, m.Event+" "+string(m.Data))
			}
		default:
			return out
		}
	}
}

func ended(st *Stream) string {
	select {
	case <-st.Done():
		r, _ := st.Ending()
		return r
	default:
		return ""
	}
}

func position(t *testing.T, s *storage.DB) int64 {
	var p int64
	if err := s.Reader().QueryRowContext(bg, `SELECT coalesce(max(event_order), 0) FROM audit_events`).Scan(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

// G11: no signal crosses Organizations, and an identitySignal reaches only
// its own identity.
func TestSignalsStayInScope(t *testing.T) {
	w := newWorld(t, Options{})
	alice := w.subscribe("alice", w.session("alice"))
	bob := w.subscribe("bob", w.session("bob"))
	carol := w.subscribe("carol", w.session("carol"))
	cursor := position(t, w.store)
	w.event("project.created", "org_b", "idn_bob", nil, "")
	w.event("credential.issued", "", "idn_bob", nil, "")
	cursor = w.publish(cursor)
	if got := received(alice); len(got) != 0 {
		t.Fatalf("alice received %v from org_b and bob's identity", got)
	}
	gotBob := received(bob)
	if len(gotBob) != 2 || !strings.HasPrefix(gotBob[0], `change {"organizationId":"org_b"`) || !strings.HasPrefix(gotBob[1], `identity {"lastEventId"`) {
		t.Fatalf("bob received %v", gotBob)
	}
	if strings.Contains(gotBob[1], "organizationId") {
		t.Fatalf("an identity event names an Organization: %s", gotBob[1])
	}
	if got := received(carol); len(got) != 1 || !strings.Contains(got[0], `"org_b"`) {
		t.Fatalf("carol received %v", got)
	}
	w.event("grant.created", "org_a", "idn_alice", nil, "")
	w.publish(cursor)
	if got := received(bob); len(got) != 0 {
		t.Fatalf("bob received %v from org_a", got)
	}
	if got := received(alice); len(got) != 1 || !strings.Contains(got[0], `"domains":["grant"]`) {
		t.Fatalf("alice received %v", got)
	}
}

// Membership is read when a signal is sent, not when the stream opened.
func TestMembershipCheckedAtDispatch(t *testing.T) {
	w := newWorld(t, Options{})
	carol := w.subscribe("carol", w.session("carol"))
	cursor := position(t, w.store)
	// Removed without an event (as a concurrent write would be seen).
	exec(t, w.store, `UPDATE org_memberships SET removed_at = 1 WHERE organization_id = 'org_b' AND identity_id = 'idn_carol'`)
	w.event("project.created", "org_b", "idn_bob", nil, "")
	w.event("project.created", "org_a", "idn_alice", nil, "")
	w.publish(cursor)
	if got := received(carol); len(got) != 1 || !strings.Contains(got[0], `"org_a"`) {
		t.Fatalf("carol received %v", got)
	}
	// A deleted Organization's signals reach nobody.
	exec(t, w.store, `UPDATE organizations SET deleted_at = 1 WHERE id = 'org_a'`)
	cursor = position(t, w.store)
	w.event("project.created", "org_a", "idn_alice", nil, "")
	w.publish(cursor)
	if got := received(carol); len(got) != 0 {
		t.Fatalf("carol received %v from a deleted Organization", got)
	}
}

// G11: a session's end, a revoked credential of the session and a removal
// close streams; other streams stay open.
func TestRevocationAndRemovalCloseStreams(t *testing.T) {
	w := newWorld(t, Options{})
	signedOut := w.session("alice")
	revoked := w.session("alice")
	kept := w.session("alice")
	s1 := w.subscribe("alice", signedOut)
	s2 := w.subscribe("alice", revoked)
	s3 := w.subscribe("alice", kept)
	bob := w.subscribe("bob", w.session("bob"))
	carol := w.subscribe("carol", w.session("carol"))

	// Sign-out: the session row goes. The periodic check finds it even
	// with nothing published.
	exec(t, w.store, `DELETE FROM auth_sessions WHERE id = ?`, signedOut)
	w.hub.validateAll(bg)
	if r := ended(s1); r != ReasonSessionEnded {
		t.Fatalf("signed-out stream: %q", r)
	}
	if ended(s2) != "" || ended(s3) != "" {
		t.Fatal("another session's stream closed")
	}

	// A browser credential of the session revoked.
	exec(t, w.store, `INSERT INTO credentials (id, identity_id, kind, token_hash, auth_session_id, revoked_at) VALUES ('crd_b', 'idn_alice', 'browser', 'h_crd_b', ?, 1)`, revoked)
	cursor := position(t, w.store)
	w.event("credential.revoked", "", "idn_alice", map[string]any{"identityId": "idn_alice"}, "crd_b")
	cursor = w.publish(cursor)
	if r := ended(s2); r != ReasonCredentialRevoked {
		t.Fatalf("revoked credential's stream: %q", r)
	}
	if ended(s3) != "" {
		t.Fatal("the kept session's stream closed")
	}
	if got := received(s3); len(got) != 1 || !strings.HasPrefix(got[0], "identity ") {
		t.Fatalf("the kept session received %v", got)
	}

	// Carol removed from org_b, with a publication of hers still queued
	// and another Organization's change in the same commit: her queue is
	// dropped, and only the identitySignal that tells her is left to send
	// before the stream closes. Bob's stays open and sees the change.
	cursor = position(t, w.store)
	w.event("project.created", "org_a", "idn_alice", nil, "")
	cursor = w.publish(cursor) // queued, never taken by carol's client
	exec(t, w.store, `UPDATE org_memberships SET removed_at = 1 WHERE organization_id = 'org_b' AND identity_id = 'idn_carol'`)
	w.event("membership.removed", "org_b", "idn_bob", map[string]any{"identityId": "idn_carol"}, "")
	w.event("grant.created", "org_a", "idn_alice", nil, "")
	w.publish(cursor)
	if r := ended(carol); r != ReasonMembershipRemoved {
		t.Fatalf("removed member's stream: %q", r)
	}
	if got := received(carol); len(got) != 0 {
		t.Fatalf("the removed member's queue was kept: %v", got)
	}
	if _, final := carol.Ending(); len(final) != 1 || final[0].Event != Identity || !strings.Contains(string(final[0].Data), `"membership"`) {
		t.Fatalf("the removal's final events: %v", final)
	}
	if ended(bob) != "" {
		t.Fatal("bob's stream closed")
	}
	if got := received(bob); len(got) != 1 || !strings.Contains(got[0], `"org_b"`) || !strings.Contains(got[0], `"membership"`) {
		t.Fatalf("bob received %v", got)
	}

	// Disabled: every session of the identity ends.
	exec(t, w.store, `UPDATE identities SET disabled = 1 WHERE id = 'idn_alice'`)
	w.hub.validateAll(bg)
	if r := ended(s3); r != ReasonSessionEnded {
		t.Fatalf("disabled identity's stream: %q", r)
	}

	// Expiry.
	w.now = w.now.Add(2 * time.Hour)
	w.hub.validateAll(bg)
	if r := ended(bob); r != ReasonSessionEnded {
		t.Fatalf("expired session's stream: %q", r)
	}

	// No new stream for a session that is not live.
	if _, err := w.hub.Subscribe(bg, signedOut, "idn_alice"); err != ErrNotLive {
		t.Fatalf("subscribe after sign-out: %v", err)
	}
	if _, err := w.hub.Subscribe(bg, w.session("bob"), "idn_alice"); err != ErrNotLive {
		t.Fatalf("subscribe with another identity's session: %v", err)
	}
}

// G11: a client that does not take its events is disconnected when its
// buffer fills, and the others get every signal.
func TestSlowClientCutOffAlone(t *testing.T) {
	w := newWorld(t, Options{Buffer: 4})
	slow := w.subscribe("alice", w.session("alice"))
	fast := w.subscribe("carol", w.session("carol"))
	cursor := position(t, w.store)
	var got []string
	for i := range 10 {
		w.event("project.created", "org_a", "idn_bob", nil, "")
		cursor = w.publish(cursor)
		got = append(got, received(fast)...)
		if i < 4 && ended(slow) != "" {
			t.Fatalf("cut off after %d signals with a buffer of 4", i+1)
		}
	}
	if r := ended(slow); r != ReasonSlowClient {
		t.Fatalf("slow client: %q", r)
	}
	if len(got) != 10 || ended(fast) != "" {
		t.Fatalf("the other client got %d of 10 signals (ended %q)", len(got), ended(fast))
	}
	// Its queue is dropped at the cut: nothing more is written to it.
	if n := len(received(slow)); n != 0 {
		t.Fatalf("the slow client's queue still holds %d publications", n)
	}
}

func TestPerSessionLimitClosesTheOldest(t *testing.T) {
	w := newWorld(t, Options{PerSession: 2})
	s := w.session("alice")
	a := w.subscribe("alice", s)
	b := w.subscribe("alice", s)
	c := w.subscribe("alice", s)
	if ended(a) != ReasonReplaced || ended(b) != "" || ended(c) != "" {
		t.Fatalf("ended: %q %q %q", ended(a), ended(b), ended(c))
	}
	if n := w.hub.Streams(); n != 2 {
		t.Fatalf("%d streams", n)
	}
}

func TestCloseEndsEveryStream(t *testing.T) {
	w := newWorld(t, Options{})
	a := w.subscribe("alice", w.session("alice"))
	w.hub.Close()
	if ended(a) != ReasonShutdown {
		t.Fatal("not closed")
	}
	if _, err := w.hub.Subscribe(bg, w.session("bob"), "idn_bob"); err != ErrClosed {
		t.Fatalf("subscribe after Close: %v", err)
	}
}

// Run publishes on Notify and, for another process's commits, on its poll;
// it starts after the events committed before it.
func TestRunPublishesAfterCommits(t *testing.T) {
	w := newWorld(t, Options{Poll: 50 * time.Millisecond})
	w.event("project.created", "org_a", "idn_alice", nil, "") // before Run: never sent
	ctx, cancel := context.WithCancel(bg)
	done := make(chan error, 1)
	go func() { done <- w.hub.Run(ctx) }()
	defer func() { cancel(); <-done }()
	st := w.subscribe("alice", w.session("alice"))
	time.Sleep(150 * time.Millisecond)
	w.event("grant.created", "org_a", "idn_alice", nil, "")
	w.hub.Notify()
	select {
	case batch := <-st.Messages():
		if len(batch) != 1 || !strings.Contains(string(batch[0].Data), `"domains":["grant"]`) {
			t.Fatalf("got %v", batch)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no signal")
	}
	select {
	case batch := <-st.Messages():
		t.Fatalf("an event committed before Run was sent: %v", batch)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestChangedDomain(t *testing.T) {
	for typ, want := range map[string]string{"grant.created": "grant", "value.disclosed": "", "capability.denied": "", "x": "x", "a.b.c": "a"} {
		if got := ChangedDomain(typ); got != want {
			t.Errorf("%s: %q, want %q", typ, got, want)
		}
	}
}

// What one wake reads goes to a stream as one publication, however many
// passes and Organizations it covers: a person in many Organizations is
// not a slow client for it.
func TestOnePublicationPerWake(t *testing.T) {
	w := newWorld(t, Options{Buffer: 2})
	var orgs []string
	for i := range 30 {
		id := fmt.Sprintf("org_many%02d", i)
		org(t, w.store, id, false)
		exec(t, w.store, `INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, 'idn_carol', 'member')`, id)
		orgs = append(orgs, id)
	}
	carol := w.subscribe("carol", w.session("carol"))
	cursor := position(t, w.store)
	if err := w.store.Write(bg, func(tx *storage.Tx) error {
		for i := range 450 {
			if _, err := tx.ExecContext(bg, `INSERT INTO audit_events (id, event_type, decision, organization_id) VALUES (?, ?, 'info', ?)`,
				fmt.Sprintf("evt_many%04d", i), []string{"project.created", "grant.created", "value.updated"}[(i/len(orgs))%3], orgs[i%len(orgs)]); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if next := w.publish(cursor); next != cursor+450 {
		t.Fatalf("cursor %d, want %d", next, cursor+450)
	}
	if ended(carol) != "" {
		t.Fatalf("cut off: %s", ended(carol))
	}
	select {
	case batch := <-carol.Messages():
		if len(batch) != 30 {
			t.Fatalf("one publication of %d events, want 30", len(batch))
		}
		var last struct {
			LastEventID string   `json:"lastEventId"`
			Domains     []string `json:"domains"`
		}
		if err := json.Unmarshal(batch[0].Data, &last); err != nil || last.LastEventID != "evt_many0420" || len(last.Domains) != 3 {
			t.Fatalf("merged signal %s", batch[0].Data)
		}
	default:
		t.Fatal("nothing published")
	}
	if got := received(carol); len(got) != 0 {
		t.Fatalf("more than one publication: %d", len(got))
	}
}

func TestMergeSignals(t *testing.T) {
	a := []Signal{{Kind: Change, Key: "o1", LastEventID: "e1", Domains: []string{"x"}}, {Kind: Identity, Key: "o1", LastEventID: "e2", Domains: []string{}}}
	b := []Signal{{Kind: Change, Key: "o2", LastEventID: "e3", Domains: []string{}}, {Kind: Change, Key: "o1", LastEventID: "e4", Domains: []string{"y", "x"}}}
	got := mergeSignals(a, b)
	if len(got) != 3 || got[0].LastEventID != "e4" || !reflect.DeepEqual(got[0].Domains, []string{"x", "y"}) || got[1].LastEventID != "e2" || got[2].Key != "o2" {
		t.Fatalf("%+v", got)
	}
}
