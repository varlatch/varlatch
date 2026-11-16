// SPDX-License-Identifier: AGPL-3.0-or-later

package people_test

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/people"
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
	wd.exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice'), ('idn_b', 'human', 'Bob')`)
	rootKEK := envelope.GenerateKey()
	org, err := orgs.Create(ctx, wd.w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	wd.org = org.ID
	wd.exec(`INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, 'idn_b', 'admin')`, wd.org)
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
	if err := wd.store.Reader().QueryRow(q, args...).Scan(&n); err != nil {
		wd.t.Fatal(err)
	}
	return n
}

func person(id string) *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: id, Kind: "human"}, Credential: auth.Credential{ID: "crd_" + id, Kind: auth.KindCLI}}
}

func waitingFor(wd *world, g write.Gate) {
	wd.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, w := range wd.w.Gates.Waiting() {
			if w == g {
				return
			}
		}
		if time.Now().After(deadline) {
			wd.t.Fatalf("nothing waited for %+v", g)
		}
		time.Sleep(time.Millisecond)
	}
}

// An invitation is issued through a live membership, under the issuer's
// gate: a removal holding it (exclusive) comes first, and the invitation
// is refused (the Organization is not found for them), never left behind
// for the removal to miss.
func TestInvitationWaitsForTheIssuersRemoval(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	_, release, err := wd.w.Gates.Acquire(ctx, write.Person("idn_b", write.Exclusive))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := people.CreateInvitation(ctx, wd.w, wd.approvals, people.Request{Principal: person("idn_b")}, wd.org, "Nina", "member", time.Now)
		done <- err
	}()
	waitingFor(wd, write.Person("idn_b", write.Shared))
	wd.exec(`UPDATE org_memberships SET removed_at = 1 WHERE identity_id = 'idn_b'`)
	release()
	var de *domainerr.Error
	if err := <-done; !errors.As(err, &de) || de.Code != "RESOURCE_NOT_FOUND" {
		t.Fatalf("an invitation by a person removed meanwhile: %v", err)
	}
	if n := wd.count(`SELECT count(*) FROM setup_grants WHERE kind = 'invite'`); n != 0 {
		t.Errorf("%d invitations left behind", n)
	}
}

// A removal and a role change of the same person serialize on their gate:
// the second finds the first's outcome (promoting someone removed is not
// found), and the removal is recorded once.
func TestRemovalAndRoleChangeSerialize(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	wd.exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_c', 'human', 'Carol')`)
	wd.exec(`INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, 'idn_c', 'member')`, wd.org)
	_, release, err := wd.w.Gates.Acquire(ctx, write.Person("idn_c", write.Exclusive))
	if err != nil {
		t.Fatal(err)
	}
	removed := make(chan error, 1)
	go func() {
		_, _, err := people.RemoveMember(ctx, wd.w, wd.approvals, people.Request{Principal: person("idn_a")}, wd.org, "idn_c", time.Now)
		removed <- err
	}()
	waitingFor(wd, write.Person("idn_c", write.Exclusive))
	release()
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	var de *domainerr.Error
	if _, _, err := people.ChangeMemberRole(ctx, wd.w, wd.approvals, people.Request{Principal: person("idn_a")}, wd.org, "idn_c", "admin", time.Now); !errors.As(err, &de) || de.Code != "RESOURCE_NOT_FOUND" {
		t.Errorf("promoting someone removed: %v", err)
	}
	if n := wd.count(`SELECT count(*) FROM membership_removals WHERE identity_id = 'idn_c'`); n != 1 {
		t.Errorf("%d removal records", n)
	}
}
