// SPDX-License-Identifier: AGPL-3.0-or-later

package identities_test

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/identities"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/write"
)

type world struct {
	t         *testing.T
	store     *storage.DB
	w         *write.Writer
	approvals *auth.Service
	org       string
}

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
	wd.exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
	wd.exec(`INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_a', 'idn_a', 'cli', 'h_a')`)
	rootKEK := envelope.GenerateKey()
	org, err := orgs.Create(ctx, wd.w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	wd.org = org.ID
	public, _ := url.Parse("http://127.0.0.1:8686")
	wd.approvals = auth.New(store, auth.Options{PublicURL: public, RootKEK: rootKEK, PersonGate: wd.w.Gates.PersonGate})
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

func alice() *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: "idn_a", Kind: "human"}, Credential: auth.Credential{ID: "crd_a", Kind: auth.KindCLI}}
}

func code(err error) string {
	var de *domainerr.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

func (wd *world) create(name string) string {
	wd.t.Helper()
	out, _, err := identities.Create(context.Background(), wd.w, wd.approvals, identities.Request{Principal: alice()}, wd.org,
		identities.CreateInput{Name: name, Kind: "service"}, time.Now)
	if err != nil {
		wd.t.Fatal(err)
	}
	return out.ID
}

// An identity a deletion suspended comes back only through that
// deletion's cancellation: reactivating it is refused, before any
// approval is asked for under admin-step-up at enforce. The fixture
// cannot reach this: there the Organization's pending deletion refuses
// first.
func TestReactivateRefusesAnIdentitySuspendedByADeletion(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		wd := newWorld(t)
		id := wd.create("svc")
		wd.exec(`INSERT INTO organization_deletions (id, organization_id, requested_by, scheduled_at, run_after, approval_required, cancelled_by, cancelled_at)
			VALUES ('odl_cancelledaaaaaaaaaaaaaaaa', ?, 'idn_a', 0, 1, 0, 'idn_a', 1)`, wd.org)
		wd.exec(`UPDATE identities SET disabled = 1, suspended_by_deletion = 'odl_cancelledaaaaaaaaaaaaaaaa' WHERE id = ?`, id)
		if enforce {
			wd.exec(`INSERT INTO security_controls (organization_id, control, mode, version, changed_by) VALUES (?, 'admin-step-up', 'enforce', 1, 'idn_a')`, wd.org)
		}
		_, err := identities.Reactivate(context.Background(), wd.w, wd.approvals, identities.Request{Principal: alice()}, wd.org, id, time.Now)
		var de *domainerr.Error
		if !errors.As(err, &de) || de.Code != "ORGANIZATION_DELETING" ||
			de.Message != "This identity was suspended by the Organization's deletion; cancelling the deletion restores it" {
			t.Errorf("enforce %v: %v", enforce, err)
		}
		if n := wd.count(`SELECT count(*) FROM approval_intents`); n != 0 {
			t.Errorf("enforce %v: %d approval intents", enforce, n)
		}
	}
}

// Retiring an identity takes its gate exclusive; issuing a credential
// for it, shared. A retirement waits for an issuance holding the identity
// and then revokes the new credential too, so a reactivation never
// resurrects a credential minted before the retirement (ADR-0034 §3).
func TestRetireWaitsForAnIssuanceAndRevokesItsCredential(t *testing.T) {
	wd := newWorld(t)
	id := wd.create("svc")
	ctx := context.Background()
	_, release, err := wd.w.Gates.Acquire(ctx, write.Person(id, write.Shared))
	if err != nil {
		t.Fatal(err)
	}
	retired := make(chan error, 1)
	go func() {
		_, err := identities.Retire(ctx, wd.w, alice(), wd.org, id, time.Now)
		retired <- err
	}()
	// Retire waits on the identity's gate.
	deadline := time.Now().Add(5 * time.Second)
	for !waitingFor(wd.w.Gates.Waiting(), write.Person(id, write.Exclusive)) {
		if time.Now().After(deadline) {
			t.Fatal("the retirement never waited for the identity's gate")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-retired:
		t.Fatalf("retired while the identity was held: %v", err)
	default:
	}
	// The issuance holding it mints its credential, then lets go.
	wd.exec(`INSERT INTO credentials (id, identity_id, kind, name, token_hash) VALUES ('crd_held', ?, 'service', 'held', 'h_held')`, id)
	release()
	if err := <-retired; err != nil {
		t.Fatal(err)
	}
	if n := wd.count(`SELECT count(*) FROM credentials WHERE identity_id = ? AND revoked_at IS NULL`, id); n != 0 {
		t.Errorf("%d live credentials after the retirement", n)
	}
	// After it, the identity is not found for an issuance.
	_, _, err = identities.Issue(ctx, wd.w, wd.approvals, identities.Request{Principal: alice()}, wd.org, id, identities.IssueInput{Name: "late"}, time.Now)
	if code(err) != "RESOURCE_NOT_FOUND" {
		t.Errorf("an issuance after the retirement: %v", err)
	}
}

func waitingFor(waiting []write.Gate, g write.Gate) bool {
	for _, w := range waiting {
		if w == g {
			return true
		}
	}
	return false
}

// Issuances and retirements racing on one identity: whichever order the
// writer runs them in, a retired identity holds no live credential.
func TestIssueAndRetireRaceToNoLiveCredential(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	for i := range 10 {
		id := wd.create("svc")
		var wg sync.WaitGroup
		for j := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, err := identities.Issue(ctx, wd.w, wd.approvals, identities.Request{Principal: alice()}, wd.org, id,
					identities.IssueInput{Name: "c"}, time.Now)
				if err != nil && code(err) != "RESOURCE_NOT_FOUND" {
					t.Errorf("round %d issuance %d: %v", i, j, err)
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := identities.Retire(ctx, wd.w, alice(), wd.org, id, time.Now); err != nil {
				t.Errorf("round %d retirement: %v", i, err)
			}
		}()
		wg.Wait()
		if n := wd.count(`SELECT count(*) FROM credentials WHERE identity_id = ? AND revoked_at IS NULL`, id); n != 0 {
			t.Errorf("round %d: %d live credentials on a retired identity", i, n)
		}
	}
}
