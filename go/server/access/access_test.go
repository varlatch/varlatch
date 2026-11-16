// SPDX-License-Identifier: AGPL-3.0-or-later

package access_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/access"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/write"
)

type world struct {
	t         *testing.T
	store     *storage.DB
	w         *write.Writer
	approvals *auth.Service
	rootKEK   []byte
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
	wd.exec(`INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_a', 'idn_a', 'cli', 'h_a')`)
	rootKEK := envelope.GenerateKey()
	org, err := orgs.Create(ctx, wd.w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	wd.org = org.ID
	wd.rootKEK = rootKEK
	wd.exec(`INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, 'idn_b', 'member')`, wd.org)
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

func alice() *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: "idn_a", Kind: "human"}, Credential: auth.Credential{ID: "crd_a", Kind: auth.KindCLI}}
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

// A Grant names a person whose membership is pinned for the job: its
// creation takes the person's gate shared, so it waits for a writer that
// holds it exclusive (the membership's removal) and then finds the person
// gone, never granting someone just removed.
func TestCreateGrantWaitsForTheSubjectsRemoval(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	_, release, err := wd.w.Gates.Acquire(ctx, write.Person("idn_b", write.Exclusive))
	if err != nil {
		t.Fatal(err)
	}
	subject := "idn_b"
	done := make(chan error, 1)
	go func() {
		_, _, err := access.CreateGrant(ctx, wd.w, wd.approvals, access.Request{Principal: alice()}, wd.org,
			access.Declaration{SubjectIdentityID: &subject, Scope: jsvalue.Object{{Key: "kind", Value: "organization"}}, Actions: []string{"project.read"}}, time.Now)
		done <- err
	}()
	waitingFor(wd, write.Person("idn_b", write.Shared))
	// The removal the exclusive holder stands for.
	wd.exec(`UPDATE org_memberships SET removed_at = 1 WHERE identity_id = 'idn_b'`)
	release()
	var de *domainerr.Error
	if err := <-done; !errors.As(err, &de) || de.Code != "RESOURCE_NOT_FOUND" {
		t.Fatalf("a Grant for a person removed meanwhile: %v", err)
	}
	var n int
	if err := wd.store.Reader().QueryRow(`SELECT count(*) FROM grants WHERE subject_identity_id = 'idn_b'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d Grants for the removed person", n)
	}
}

// Adding a member takes the identity's gate shared too, and refuses a
// person whose membership was removed while it waited.
func TestAddMemberWaitsForTheMembersRemoval(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	out, _, err := access.CreateGroup(ctx, wd.w, wd.approvals, access.Request{Principal: alice()}, wd.org, "devs", "group", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	group, _ := out.Get("id")
	_, release, err := wd.w.Gates.Acquire(ctx, write.Person("idn_b", write.Exclusive))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := access.AddMember(ctx, wd.w, wd.approvals, access.Request{Principal: alice()}, wd.org, group.(string), "idn_b", time.Now)
		done <- err
	}()
	waitingFor(wd, write.Person("idn_b", write.Shared))
	wd.exec(`UPDATE org_memberships SET removed_at = 1 WHERE identity_id = 'idn_b'`)
	release()
	var de *domainerr.Error
	if err := <-done; !errors.As(err, &de) || de.Code != "RESOURCE_NOT_FOUND" {
		t.Fatalf("a membership for a person removed meanwhile: %v", err)
	}
}

// A Grant names only its Organization's groups and roles: creating or
// replacing one that names another Organization's is refused as naming one
// that does not exist is, and Grants join only this Organization's groups
// and roles.
func TestGrantNamesOnlyItsOrganizationsGroupsAndRoles(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	req := access.Request{Principal: alice()}
	other, err := orgs.Create(ctx, wd.w, wd.rootKEK, "idn_a", "other", "Other")
	if err != nil {
		t.Fatal(err)
	}
	id := func(o jsvalue.Object, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		v, _ := o.Get("id")
		return v.(string)
	}
	created := func(o jsvalue.Object, _ []auth.PendingReport, err error) (jsvalue.Object, error) { return o, err }
	theirGroup := id(created(access.CreateGroup(ctx, wd.w, wd.approvals, req, other.ID, "devs", "group", time.Now)))
	theirRole := id(created(access.CreateRole(ctx, wd.w, wd.approvals, req, other.ID, "reader", []string{"project.read"}, time.Now)))
	ownGroup := id(created(access.CreateGroup(ctx, wd.w, wd.approvals, req, wd.org, "devs", "group", time.Now)))
	org := jsvalue.Object{{Key: "kind", Value: "organization"}}
	bob := "idn_b"

	for name, d := range map[string]access.Declaration{
		"another Organization's group": {SubjectGroupID: &theirGroup, Scope: org, Actions: []string{"project.read"}},
		"another Organization's role":  {SubjectIdentityID: &bob, Scope: org, RoleID: &theirRole},
	} {
		if _, _, err := access.CreateGrant(ctx, wd.w, wd.approvals, req, wd.org, d, time.Now); !errors.Is(err, access.ErrForeignReference) {
			t.Errorf("a Grant naming %s: %v", name, err)
		}
	}
	grant := id(created(access.CreateGrant(ctx, wd.w, wd.approvals, req, wd.org,
		access.Declaration{SubjectIdentityID: &bob, Scope: org, Actions: []string{"project.read"}}, time.Now)))
	in := access.Input{Declaration: access.Declaration{SubjectIdentityID: &bob, Scope: org, RoleID: &theirRole}, Body: jsvalue.Object{{Key: "roleId", Value: theirRole}}}
	if _, _, err := access.ReplaceGrant(ctx, wd.w, wd.approvals, wd.rootKEK, req, wd.org, grant, in, time.Now); !errors.Is(err, access.ErrForeignReference) {
		t.Errorf("a replacement naming another Organization's role: %v", err)
	}
	var live int
	if err := wd.store.Reader().QueryRow(`SELECT count(*) FROM grants WHERE organization_id = ? AND revoked_at IS NULL`, wd.org).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Errorf("%d live Grants, want the one replaced in vain", live)
	}

	// The evaluator joins only this Organization's groups and roles: Bob is
	// in both groups, and only the Grant to this Organization's counts.
	wd.exec(`UPDATE grants SET revoked_at = 1 WHERE id = ?`, grant)
	wd.exec(`INSERT INTO group_members (group_id, identity_id) VALUES (?, 'idn_b'), (?, 'idn_b')`, theirGroup, ownGroup)
	wd.exec(`INSERT INTO grants (id, organization_id, subject_group_id, scope, actions) VALUES ('grt_theirgroup', ?, ?, '{"kind":"organization"}', '["project.read"]')`, wd.org, theirGroup)
	wd.exec(`INSERT INTO grants (id, organization_id, subject_identity_id, scope, role_id) VALUES ('grt_theirrole', ?, 'idn_b', '{"kind":"organization"}', ?)`, wd.org, theirRole)
	grants, err := authz.LoadGrants(ctx, wd.store.Reader(), wd.org, "idn_b")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Errorf("Grants through another Organization's group or role: %+v", grants)
	}
	wd.exec(`INSERT INTO grants (id, organization_id, subject_group_id, scope, actions) VALUES ('grt_owngroup', ?, ?, '{"kind":"organization"}', '["project.read"]')`, wd.org, ownGroup)
	if grants, err = authz.LoadGrants(ctx, wd.store.Reader(), wd.org, "idn_b"); err != nil || len(grants) != 1 || grants[0].ID != "grt_owngroup" {
		t.Errorf("the Organization's own group: %+v, %v", grants, err)
	}
}

// A member or a Project added to a group or team deleted after the route
// read it, while the job waited, is refused: the job reads the group
// again, so no row and no event follow the deletion.
func TestMemberAndProjectWritesRecheckTheGroup(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	req := access.Request{Principal: alice()}
	create := func(name, kind string) string {
		out, _, err := access.CreateGroup(ctx, wd.w, wd.approvals, req, wd.org, name, kind, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := out.Get("id")
		return id.(string)
	}
	group, team := create("devs", "group"), create("backend", "team")
	wd.exec(`INSERT INTO projects (id, organization_id, slug, name, contract_authority) VALUES ('prj_api', ?, 'api', 'API', 'managed')`, wd.org)
	for name, add := range map[string]func() error{
		"a member": func() error {
			_, err := access.AddMember(ctx, wd.w, wd.approvals, req, wd.org, group, "idn_b", time.Now)
			return err
		},
		"a Project": func() error {
			_, err := access.AddTeamProject(ctx, wd.w, wd.approvals, req, wd.org, team, "prj_api", time.Now)
			return err
		},
	} {
		_, release, err := wd.w.Gates.Acquire(ctx, write.Organization(wd.org, write.Exclusive))
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- add() }()
		waitingFor(wd, write.Organization(wd.org, write.Shared))
		wd.exec(`UPDATE groups SET revoked_at = 1 WHERE id IN (?, ?)`, group, team)
		release()
		var de *domainerr.Error
		if err := <-done; !errors.As(err, &de) || de.Code != "RESOURCE_NOT_FOUND" {
			t.Errorf("%s for a group deleted meanwhile: %v", name, err)
		}
		wd.exec(`UPDATE groups SET revoked_at = NULL WHERE id IN (?, ?)`, group, team)
	}
	var rows int
	if err := wd.store.Reader().QueryRow(`SELECT (SELECT count(*) FROM group_members) + (SELECT count(*) FROM team_projects) +
		(SELECT count(*) FROM audit_events WHERE event_type IN ('group.member_added', 'team.project_added'))`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Errorf("%d member, Project or event rows after the refusals", rows)
	}
}

// The credential review's time edges, which a fixture replayed on later
// dates cannot pin: a service credential expiring within the warning
// window is "soon" up to its last microsecond, an expired one "expired"
// from its expiry on (and out of the review); idleness starts strictly
// after IdleDays.
func TestCredentialReviewTimeEdges(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	now := time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC)
	us := now.UnixMicro()
	day := int64(24 * time.Hour / time.Microsecond)
	wd.exec(`INSERT INTO identities (id, kind, name, organization_id) VALUES ('idn_m', 'service', 'm', ?)`, wd.org)
	creds := []struct {
		id      string
		expires any
		used    any
	}{
		{"crd_soonedge", us + access.ExpiryWarningDays*day, nil},
		{"crd_later", us + access.ExpiryWarningDays*day + 1, nil},
		{"crd_expiredge", us, nil},
		{"crd_idleedge", nil, us - access.IdleDays*day},
		{"crd_idle", nil, us - access.IdleDays*day - 1},
	}
	for _, c := range creds {
		wd.exec(`INSERT INTO credentials (id, identity_id, kind, token_hash, expires_at, last_used_at) VALUES (?, 'idn_m', 'service', ?, ?, ?)`, c.id, "h_"+c.id, c.expires, c.used)
	}
	out, err := access.CredentialReview(ctx, wd.store.Reader(), wd.org, now)
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	items, _ := out.Get("items")
	for _, it := range items.([]any) {
		o := it.(jsvalue.Object)
		id, _ := o.Get("id")
		r, _ := o.Get("reasons")
		reasons[id.(string)] = string(jsvalue.Stringify(r))
	}
	want := map[string]string{
		"crd_soonedge": `["never-used"]`, "crd_later": `["never-used"]`,
		"crd_idleedge": `["no-expiry"]`, "crd_idle": `["idle","no-expiry"]`,
	}
	for id, w := range want {
		if reasons[id] != w {
			t.Errorf("%s: reasons %s, want %s", id, reasons[id], w)
		}
	}
	if _, listed := reasons["crd_expiredge"]; listed {
		t.Error("a credential expiring now is still reviewed")
	}
	expiry, _ := out.Get("expiry")
	states := map[string]string{}
	expiring, _ := expiry.(jsvalue.Object).Get("items")
	for _, it := range expiring.([]any) {
		o := it.(jsvalue.Object)
		id, _ := o.Get("id")
		st, _ := o.Get("state")
		states[id.(string)] = st.(string)
	}
	if fmt.Sprint(states) != fmt.Sprint(map[string]string{"crd_soonedge": "soon", "crd_expiredge": "expired"}) {
		t.Errorf("expiry warnings %v", states)
	}
	if g, _ := out.Get("generatedAt"); g != "2030-06-01T12:00:00.000Z" {
		t.Errorf("generatedAt %v", g)
	}
}

// loadTailnetRequirements reads without an ORDER BY: the TypeScript
// server's order is unspecified, in a small table PostgreSQL's heap order,
// where an updated row goes last. Go emulates it: of three Requirements,
// the first, once changed, is read last. (Once the TypeScript line is
// retired, a step 7/8 follow-up, the read can take ORDER BY created_at,
// id instead.)
func TestUpdatedRequirementMovesToTheEnd(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	tier := jsvalue.Object{{Key: "kind", Value: "tier"}, {Key: "tier", Value: "production"}}
	selector := func(tailnet string) jsvalue.Object {
		return jsvalue.Object{{Key: "tailnet", Value: tailnet}, {Key: "tags", Value: []any{"tag:ci"}}}
	}
	var ids []string
	for _, tn := range []string{"one.ts.net", "two.ts.net", "three.ts.net"} {
		out, _, err := access.CreateRequirement(ctx, wd.w, alice(), wd.org, tier, selector(tn), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := out.Get("id")
		ids = append(ids, id.(string))
	}
	order := func() []string {
		t.Helper()
		reqs, err := authz.LoadRequirements(ctx, wd.store.Reader(), wd.org)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range reqs {
			out = append(out, r.ID)
		}
		return out
	}
	if got := order(); fmt.Sprint(got) != fmt.Sprint(ids) {
		t.Fatalf("before the change: %v, want %v", got, ids)
	}
	edited := selector("one.ts.net")
	edited[1].Value = []any{"tag:edited"}
	if _, _, err := access.UpdateRequirement(ctx, wd.w, wd.approvals, wd.rootKEK, access.Request{Principal: alice()}, wd.org, ids[0],
		access.RequirementPatch{ExpectedVersion: 1, Selector: edited, Body: jsvalue.Object{{Key: "expectedVersion", Value: float64(1)}, {Key: "selector", Value: edited}}}, time.Now); err != nil {
		t.Fatal(err)
	}
	if got, want := order(), []string{ids[1], ids[2], ids[0]}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("after changing the first: %v, want %v", got, want)
	}
}

// The credential review and machine reach name nothing of another
// Organization: its machine and credentials are not reviewed here, and
// its machine has no reach here (not found, as an unknown one).
func TestReportsKeepToTheirOrganization(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	other, err := orgs.Create(ctx, wd.w, wd.rootKEK, "idn_a", "other", "Other")
	if err != nil {
		t.Fatal(err)
	}
	wd.exec(`INSERT INTO identities (id, kind, name, organization_id) VALUES ('idn_here', 'service', 'here', ?), ('idn_there', 'service', 'there', ?)`, wd.org, other.ID)
	wd.exec(`INSERT INTO credentials (id, identity_id, kind, token_hash, expires_at) VALUES
		('crd_here', 'idn_here', 'service', 'h_here', NULL), ('crd_there', 'idn_there', 'service', 'h_there', NULL),
		('crd_theresoon', 'idn_there', 'service', 'h_theresoon', ?)`, time.Now().Add(time.Hour).UnixMicro())
	review, err := access.CredentialReview(ctx, wd.store.Reader(), wd.org, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	text := string(jsvalue.Stringify(review))
	if !strings.Contains(text, "crd_here") || strings.Contains(text, "there") {
		t.Errorf("the review: %s", text)
	}
	var de *domainerr.Error
	if _, err := access.MachineReach(ctx, wd.store.Reader(), wd.org, "idn_there", time.Now()); !errors.As(err, &de) || de.Code != "RESOURCE_NOT_FOUND" {
		t.Errorf("reach of another Organization's machine: %v", err)
	}
	reach, err := access.MachineReach(ctx, wd.store.Reader(), wd.org, "idn_here", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if text := string(jsvalue.Stringify(reach)); strings.Contains(text, other.ID) || strings.Contains(text, "there") {
		t.Errorf("reach names the other Organization: %s", text)
	}
}
