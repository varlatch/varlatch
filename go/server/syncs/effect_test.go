// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/freeze"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/people"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/syncs"
	"github.com/varlatch/varlatch/go/server/write"
)

// Decision 4's tests for checkConnectionAccess and
// listConnectionDestinations: each is an external effect holding the
// Organization and its requester (shared) across the platform call, with
// the fake platform blocked until the test releases it.

type world struct {
	t         *testing.T
	store     *storage.DB
	w         *write.Writer
	approvals *auth.Service
	org       authz.Organization
	s         *syncs.Service
	// The fake GitHub: a request blocks while block is open.
	mu       sync.Mutex
	block    chan struct{}
	reached  chan struct{}
	expiring bool
}

func person(id, credential string) *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: id, Kind: "human"}, Credential: auth.Credential{ID: credential, Kind: auth.KindCLI}}
}

var alice, bob = person("idn_a", "crd_a"), person("idn_b", "crd_b")

func newWorld(t *testing.T) *world {
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
	wd := &world{t: t, store: store, w: &write.Writer{Store: store, Gates: write.NewGates()}}
	wd.exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice'), ('idn_b', 'human', 'Bob')`)
	wd.exec(`INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_a', 'idn_a', 'cli', 'h_a'), ('crd_b', 'idn_b', 'cli', 'h_b')`)
	rootKEK := envelope.GenerateKey()
	org, err := orgs.Create(ctx, wd.w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	wd.org = authz.Organization{ID: org.ID, Name: "Acme"}
	wd.exec(`INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, 'idn_b', 'member')`, org.ID)
	public, _ := url.Parse("http://127.0.0.1:8686")
	wd.approvals = auth.New(store, auth.Options{PublicURL: public, RootKEK: rootKEK, PersonGate: wd.w.Gates.PersonGate})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := outbound.New(nil, outbound.Options{Log: log, Resolve: func(_ context.Context, name string) ([]outbound.Answer, error) {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}})
	t.Cleanup(policy.Close)
	wd.s = &syncs.Service{Writer: wd.w, Approvals: wd.approvals, RootKEK: rootKEK, Policy: policy, Now: time.Now, Log: log}
	syncs.UseClient(wd.s, &http.Client{Transport: roundTrip(wd.github)})
	return wd
}

func (wd *world) exec(q string, args ...any) {
	wd.t.Helper()
	if err := wd.store.Write(context.Background(), func(tx *storage.Tx) error { _, err := tx.ExecContext(context.Background(), q, args...); return err }); err != nil {
		wd.t.Fatal(err)
	}
}

// github is a fake GitHub that blocks while wd.block is set, after saying
// so on wd.reached.
func (wd *world) github(r *http.Request) (*http.Response, error) {
	wd.mu.Lock()
	block, reached := wd.block, wd.reached
	wd.mu.Unlock()
	if block != nil {
		select {
		case reached <- struct{}{}:
		default:
		}
		select {
		case <-block:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	h := http.Header{"Content-Type": {"application/json"}}
	if strings.Contains(r.Header.Get("Authorization"), "expiring") {
		h.Set("github-authentication-token-expiration", "2026-09-01 12:00:00 UTC")
	}
	body := `{"login":"acme","type":"Organization"}`
	if strings.Contains(r.URL.RequestURI(), "/repos?") {
		body = `[{"name":"api","owner":{"login":"acme"}}]`
	}
	return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func (wd *world) blockCalls() (release func()) {
	wd.mu.Lock()
	wd.block, wd.reached = make(chan struct{}), make(chan struct{}, 1)
	block := wd.block
	wd.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(block) }) }
}

func (wd *world) connection(name, credential string) string {
	wd.t.Helper()
	c, _, err := wd.s.Create(context.Background(), syncs.Request{Principal: alice, RequestID: "req_c"}, wd.org,
		syncs.CreateInput{Platform: "github-actions", BaseIdentity: "acme", Name: name, Credential: credential})
	if err != nil {
		wd.t.Fatal(err)
	}
	return c.ID
}

func (wd *world) count(q string, args ...any) int {
	wd.t.Helper()
	var n int
	if err := wd.store.Reader().QueryRow(q, args...).Scan(&n); err != nil {
		wd.t.Fatal(err)
	}
	return n
}

func code(err error) string {
	var de *domainerr.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

// effect runs a check (or a listing) by requester in the background and
// waits until its call reached the blocked platform.
func (wd *world) effect(requester *auth.Principal, connectionID string, listing bool) (release func(), done chan error) {
	wd.t.Helper()
	release = wd.blockCalls()
	done = make(chan error, 1)
	go func() {
		req := syncs.Request{Principal: requester, RequestID: "req_e"}
		in := syncs.CredentialInput{ConnectionID: connectionID}
		var err error
		if listing {
			_, _, err = wd.s.Destinations(context.Background(), req, wd.org, in)
		} else {
			_, _, err = wd.s.Check(context.Background(), req, wd.org, in, nil)
		}
		done <- err
	}()
	select {
	case <-wd.reached:
	case err := <-done:
		wd.t.Fatalf("the effect ended before its call: %v", err)
	case <-time.After(10 * time.Second):
		wd.t.Fatal("the effect never reached its call")
	}
	return release, done
}

// waitsFor runs op while an effect is blocked in its call: op must wait
// for one of the effect's gates and finish only once the effect ended.
func (wd *world) waitsFor(t *testing.T, listing bool, requester *auth.Principal, op func() error) error {
	connectionID := wd.connection("GitHub", "github_pat_effect")
	release, done := wd.effect(requester, connectionID, listing)
	defer release()
	waiting := make(chan struct{})
	var once sync.Once
	wd.w.Gates.Observe(func(event string, _ write.Gate) {
		if event == "waiting" {
			once.Do(func() { close(waiting) })
		}
	})
	defer wd.w.Gates.Observe(nil)
	finished := make(chan error, 1)
	go func() { finished <- op() }()
	select {
	case <-waiting:
	case err := <-finished:
		t.Fatalf("finished during the effect's call: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("never waited for the effect")
	}
	select {
	case err := <-finished:
		t.Fatalf("finished during the effect's call: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	effectErr := <-done
	if err := <-finished; err != nil {
		t.Fatalf("after the effect: %v", err)
	}
	return effectErr
}

// A freeze and a Security Control change (the Organization's exclusive
// takers) each wait for a check's or a listing's call, and run once it
// ended; the effect kept its outcome (its audit event).
func TestWritersWaitForACheckOrListing(t *testing.T) {
	for _, listing := range []bool{false, true} {
		kind := map[bool]string{false: "check", true: "listing"}[listing]
		event := map[bool]string{false: "sync.connection_checked", true: "sync.destinations_listed"}[listing]
		for name, run := range map[string]struct {
			requester *auth.Principal
			op        func(wd *world) error
		}{
			"freeze": {alice, func(wd *world) error {
				_, _, err := freeze.Freeze(context.Background(), wd.w, wd.approvals, freeze.FreezeInput{OrganizationID: wd.org.ID, Principal: alice, Reason: "drill", RequestID: "req_f"}, time.Now)
				return err
			}},
			"control change": {alice, func(wd *world) error {
				mode := security.Report
				_, _, err := security.ChangeControl(context.Background(), wd.w, wd.approvals, security.ChangeInput{
					OrganizationID: wd.org.ID, Control: security.AdminStepUp, Mode: &mode, Config: security.ConfigChange{Keep: true},
					Principal: alice, RequestID: "req_s",
				}, time.Now)
				return err
			}},
		} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				wd := newWorld(t)
				if err := wd.waitsFor(t, listing, run.requester, func() error { return run.op(wd) }); err != nil {
					t.Fatalf("the effect: %v", err)
				}
				if n := wd.count(`SELECT count(*) FROM audit_events WHERE event_type = ?`, event); n != 1 {
					t.Fatalf("%d %s events", n, event)
				}
			})
		}
	}
}

// The requester's removal does not wait for a check's call: both take the
// person shared, as the TypeScript code takes both identity rows for
// share (lockPeople); the check still records its outcome.
func TestRemovalOfTheRequesterDuringACheck(t *testing.T) {
	wd := newWorld(t)
	id := wd.connection("GitHub", "github_pat_effect")
	release, done := wd.effect(bob, id, false)
	defer release()
	if _, _, err := people.RemoveMember(context.Background(), wd.w, wd.approvals, wd.s.RootKEK, people.Request{Principal: alice, RequestID: "req_r"}, wd.org.ID, "idn_b", time.Now); err != nil {
		t.Fatalf("the removal: %v", err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("the check: %v", err)
	}
	if n := wd.count(`SELECT count(*) FROM audit_events WHERE event_type = 'sync.connection_checked'`); n != 1 {
		t.Fatalf("%d checks recorded", n)
	}
}

// A credential replaced during a check's call does not wait (it takes no
// gate the check holds exclusively), and the check's final job does not
// record the expiry it learned about the old credential on the new one.
func TestCheckRecordsAnExpiryOnlyForTheCredentialItUsed(t *testing.T) {
	wd := newWorld(t)
	id := wd.connection("Expiring", "github_pat_expiring")
	release, done := wd.effect(alice, id, false)
	_, _, err := wd.s.ReplaceCredential(context.Background(), syncs.Request{Principal: alice, RequestID: "req_x"}, wd.org, id,
		syncs.ReplaceInput{Credential: "github_pat_new", ExpectedVersion: 1}, func(context.Context, query.DBTX, syncs.Target) (any, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := wd.count(`SELECT count(*) FROM platform_connections WHERE id = ? AND credential_expires_at IS NOT NULL`, id); n != 0 {
		t.Fatal("the old credential's expiry was recorded on the new one")
	}
	// Without a replacement, the expiry the platform reported is recorded.
	other := wd.connection("Expiring 2", "github_pat_expiring")
	if _, _, err := wd.s.Check(context.Background(), syncs.Request{Principal: alice, RequestID: "req_y"}, wd.org, syncs.CredentialInput{ConnectionID: other}, nil); err != nil {
		t.Fatal(err)
	}
	var at sql.NullInt64
	if err := wd.store.Reader().QueryRow(`SELECT credential_expires_at FROM platform_connections WHERE id = ?`, other).Scan(&at); err != nil || !at.Valid ||
		time.UnixMicro(at.Int64).UTC() != time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("expiry %v, %v", at, err)
	}
}

// With passkey-verification active, a call that outlasts the effect's
// deadline keeps nothing: no audit event, no expiry, and the deadline's
// answer.
func TestCheckPastItsDeadlineKeepsNothing(t *testing.T) {
	for _, listing := range []bool{false, true} {
		t.Run(map[bool]string{false: "check", true: "listing"}[listing], func(t *testing.T) {
			wd := newWorld(t)
			id := wd.connection("Expiring", "github_pat_expiring")
			wd.exec(`INSERT INTO security_controls (organization_id, control, mode, version) VALUES (?, 'passkey-verification', 'report', 1)`, wd.org.ID)
			defer func(d time.Duration) { write.EffectDeadline = d }(write.EffectDeadline)
			write.EffectDeadline = 200 * time.Millisecond
			release, done := wd.effect(alice, id, listing)
			defer release()
			err := <-done
			if code(err) != "STATE_CHANGED" || !strings.Contains(err.Error(), "90 seconds") {
				t.Fatalf("got %v", err)
			}
			if n := wd.count(`SELECT count(*) FROM audit_events WHERE event_type IN ('sync.connection_checked', 'sync.destinations_listed')`); n != 0 {
				t.Fatalf("%d events kept", n)
			}
			if n := wd.count(`SELECT count(*) FROM platform_connections WHERE id = ? AND credential_expires_at IS NOT NULL`, id); n != 0 {
				t.Fatal("an expiry was kept")
			}
		})
	}
}
