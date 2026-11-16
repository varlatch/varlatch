// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/write"
)

// A declaration may name more environments than SQLite binds variables in
// one statement (32,766), as a body under the 1 MiB limit can: the
// summary's lookups take them in chunks, and every one is named.
func TestNamesForTakesAnyNumberOfIDs(t *testing.T) {
	ctx := context.Background()
	s, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := db.Init(ctx, s, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	ids := make([]any, 40_000)
	for i := range ids {
		ids[i] = fmt.Sprintf("e%d", i)
	}
	scope := jsvalue.Object{{Key: "kind", Value: "environments"}, {Key: "projectId", Value: "prj_x"},
		{Key: "selector", Value: jsvalue.Object{{Key: "kind", Value: "environments"}, {Key: "environmentIds", Value: ids}}}}
	n, err := namesFor(ctx, s.Reader(), "org_x", Declaration{Scope: scope, Actions: []string{"project.read"}})
	if err != nil {
		t.Fatalf("40,000 environment ids: %v", err)
	}
	if got := describeScope(Declaration{Scope: scope}, n); len(got) == 0 {
		t.Error("no description")
	}
}

// Two of each kind in one summary are each named: the lookups bind the
// Organization before the list (a numbered parameter after it took the
// list's second element), as a replacement naming two roles, a group with
// a team scope or a Requirement on two environments do.
func TestNamesForNamesTwoOfEachKind(t *testing.T) {
	ctx := context.Background()
	s, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := db.Init(ctx, s, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	w := &write.Writer{Store: s, Gates: write.NewGates()}
	exec := func(q string, args ...any) {
		t.Helper()
		if err := s.Write(ctx, func(tx *storage.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
	org, err := orgs.Create(ctx, w, envelope.GenerateKey(), "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	o := org.ID
	exec(`INSERT INTO identities (id, kind, name, organization_id) VALUES ('idn_m1', 'service', 'm1', ?), ('idn_m2', 'service', 'm2', ?)`, o, o)
	exec(`INSERT INTO groups (id, organization_id, name, kind) VALUES ('grp_1', ?, 'g1', 'group'), ('tem_2', ?, 't2', 'team')`, o, o)
	exec(`INSERT INTO roles (id, organization_id, name, actions) VALUES ('rol_1', ?, 'r1', '["project.read"]'), ('rol_2', ?, 'r2', '["project.read"]')`, o, o)
	exec(`INSERT INTO projects (id, organization_id, slug, name, contract_authority) VALUES ('prj_1', ?, 'p1', 'P1', 'managed'), ('prj_2', ?, 'p2', 'P2', 'managed')`, o, o)
	exec(`INSERT INTO environments (id, project_id, name, kind, tier) VALUES ('env_1', 'prj_1', 'dev', 'shared', 'development'), ('env_2', 'prj_1', 'prod', 'shared', 'production')`)
	str := func(s string) *string { return &s }
	envs := jsvalue.Object{{Key: "kind", Value: "environments"}, {Key: "projectId", Value: "prj_1"},
		{Key: "selector", Value: jsvalue.Object{{Key: "kind", Value: "environments"}, {Key: "environmentIds", Value: []any{"env_1", "env_2"}}}}}
	n, err := namesFor(ctx, s.Reader(), o,
		Declaration{SubjectIdentityID: str("idn_m1"), Scope: envs, RoleID: str("rol_1")},
		Declaration{SubjectIdentityID: str("idn_m2"), Scope: jsvalue.Object{{Key: "kind", Value: "project"}, {Key: "projectId", Value: "prj_2"}}, RoleID: str("rol_2")},
		Declaration{SubjectGroupID: str("grp_1"), Scope: jsvalue.Object{{Key: "kind", Value: "team"}, {Key: "teamId", Value: "tem_2"}}, RoleID: str("rol_1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	for kind, m := range map[string]map[string]string{"identities": n.identities, "groups": n.groups, "roles": n.roles, "projects": n.projects, "environments": n.environments} {
		if len(m) != 2 {
			t.Errorf("%s: %d named of 2: %v", kind, len(m), m)
		}
	}
	names, err := environmentNames(ctx, s.Reader(), o, []string{"env_2", "env_1", "env_2"})
	if err != nil || len(names) != 2 {
		t.Errorf("environmentNames: %v, %v", names, err)
	}
}
