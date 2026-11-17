// SPDX-License-Identifier: AGPL-3.0-or-later

package authz_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/write"
)

// RequireVisible lets through whoever can see the Organization: a member,
// a member whose only authority is a Grant scoped to a Project, a machine
// of the Organization. A person outside it gets the unknown Organization's
// answer and a denial event with no action; a machine of another
// Organization gets the same answer and no event.
func TestRequireVisible(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := db.Init(ctx, store, "test"); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if err := store.Write(ctx, func(tx *storage.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_admin', 'human', 'Admin'), ('idn_member', 'human', 'Member'),
		('idn_scoped', 'human', 'Scoped'), ('idn_out', 'human', 'Outsider')`)
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	acme, err := orgs.Create(ctx, w, envelope.GenerateKey(), "idn_admin", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	beta, err := orgs.Create(ctx, w, envelope.GenerateKey(), "idn_admin", "beta", "Beta")
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, 'idn_member', 'member'), (?, 'idn_scoped', 'member')`, acme.ID, acme.ID)
	exec(`INSERT INTO grants (id, organization_id, subject_identity_id, scope, actions) VALUES ('grt_scoped', ?, 'idn_scoped', '{"kind":"project","projectId":"prj_web"}', '["project.read"]')`, acme.ID)
	exec(`INSERT INTO identities (id, kind, name, organization_id) VALUES ('idn_ownsvc', 'service', 'runner', ?), ('idn_othersvc', 'service', 'runner', ?)`, acme.ID, beta.ID)
	reader := store.Reader()
	for _, c := range []struct {
		name    string
		p       authz.Principal
		visible bool
		event   bool
	}{
		{"the creator, an admin", authz.Principal{IdentityID: "idn_admin", IdentityKind: "human"}, true, false},
		{"a member", authz.Principal{IdentityID: "idn_member", IdentityKind: "human"}, true, false},
		{"a member with a Project-scoped Grant only", authz.Principal{IdentityID: "idn_scoped", IdentityKind: "human"}, true, false},
		{"a machine of the Organization", authz.Principal{IdentityID: "idn_ownsvc", IdentityKind: "service", OrganizationID: acme.ID}, true, false},
		{"a person outside it", authz.Principal{IdentityID: "idn_out", IdentityKind: "human", CredentialID: "crd_out"}, false, true},
		{"a machine of another Organization", authz.Principal{IdentityID: "idn_othersvc", IdentityKind: "service", OrganizationID: beta.ID}, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			denied, event, err := authz.RequireVisible(ctx, reader, c.p, acme.ID, "req_x")
			if err != nil {
				t.Fatal(err)
			}
			if c.visible {
				if denied != nil || event != nil {
					t.Fatalf("refused: %v %+v", denied, event)
				}
				return
			}
			if denied == nil || denied.Code != "RESOURCE_NOT_FOUND" || denied.Message != "Organization not found" {
				t.Fatalf("got %v, want the unknown Organization's answer", denied)
			}
			if (event != nil) != c.event {
				t.Fatalf("event %+v, want one: %v", event, c.event)
			}
			if event != nil && (event.Type != "authorization.denied" || event.Action != nil || *event.OrganizationID != acme.ID || *event.RequestID != "req_x") {
				t.Fatalf("event %+v", event)
			}
		})
	}
}
