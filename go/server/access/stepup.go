// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// admin-step-up for the access structure (ADR-0054 Decision 5;
// domain/accessstepup.ts): what an approval binds for each operation on
// Grants, roles, groups and teams, their memberships and Team-Project
// links, and the summary its approver reads. None carries a secret; each
// binds the query {}. Group or team comes from the stored row: a team
// reached through a /groups/ route is team.*.

// jsLess is JavaScript's a < b on strings: by UTF-16 code units.
func jsLess(a, b string) bool {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b))) < 0
}

// jsSet is [...new Set(values)].sort(): without duplicates, in
// JavaScript's default order.
func jsSet(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		switch {
		case jsLess(a, b):
			return -1
		case jsLess(b, a):
			return 1
		}
		return 0
	})
	return out
}

func stringsJS(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func added(field, to string) auth.ApprovalChange { return auth.ApprovalChange{Field: field, To: &to} }

func plural(n int64, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// GroupOperation is groupOperation: group.update or team.update, from the
// stored kind.
func GroupOperation(kind, verb string) string { return kind + "." + verb }

func binding(operation, organizationID string, target map[string]string, body any, expected *int64, summary auth.ApprovalSummary) *auth.Binding {
	org := organizationID
	if summary.Changes == nil {
		summary.Changes = []auth.ApprovalChange{}
	}
	return &auth.Binding{Operation: operation, OrganizationID: &org, Target: target, Body: body, Query: map[string]string{},
		ExpectedVersion: expected, Summary: summary}
}

// ---- Grants

// Declaration is a Grant as the routes take it (zod's output) or as a
// row stores it: exactly one subject, exactly one permission. A field the
// request left out is nil.
type Declaration struct {
	SubjectIdentityID, SubjectGroupID *string
	// Scope is the parsed scope, its members in the schema's order (or a
	// row's).
	Scope   jsvalue.Object
	Actions []string // nil: none
	RoleID  *string
}

func truthy(s *string) bool { return s != nil && *s != "" }

// pgText refuses what PostgreSQL refuses in a text parameter: U+0000
// fails the TypeScript server's statement, so the route answers 500 at the
// first query that takes such a string (write.ErrPostgresText). Every
// lookup by a string from the request checks it first.
func pgText(values ...string) error {
	for _, v := range values {
		if strings.IndexByte(v, 0) >= 0 {
			return write.ErrPostgresText
		}
	}
	return nil
}

func str(o jsvalue.Object, key string) string {
	v, _ := o.Get(key)
	s, _ := v.(string)
	return s
}

func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// normalizedScope is the scope as bound: an environments selector's ids as
// a set.
func normalizedScope(s jsvalue.Object) any {
	if str(s, "kind") == "environments" {
		sel, _ := s.Get("selector")
		if so, ok := sel.(jsvalue.Object); ok && str(so, "kind") == "environments" {
			ids, _ := so.Get("environmentIds")
			return jsvalue.Object{{Key: "kind", Value: "environments"}, {Key: "projectId", Value: str(s, "projectId")},
				{Key: "selector", Value: jsvalue.Object{{Key: "kind", Value: "environments"}, {Key: "environmentIds", Value: stringsJS(jsSet(stringList(ids)))}}}}
		}
	}
	return s
}

// Normalized is normalizedGrant: the bound form of a declaration, sets
// sorted and without duplicates.
func (d Declaration) Normalized() jsvalue.Object {
	var subject jsvalue.Object
	if truthy(d.SubjectIdentityID) {
		subject = jsvalue.Object{{Key: "identityId", Value: *d.SubjectIdentityID}}
	} else {
		var group any
		if d.SubjectGroupID != nil {
			group = *d.SubjectGroupID
		}
		subject = jsvalue.Object{{Key: "groupId", Value: group}}
	}
	var permission jsvalue.Object
	if truthy(d.RoleID) {
		permission = jsvalue.Object{{Key: "roleId", Value: *d.RoleID}}
	} else {
		permission = jsvalue.Object{{Key: "actions", Value: stringsJS(jsSet(d.Actions))}}
	}
	return jsvalue.Object{{Key: "subject", Value: subject}, {Key: "scope", Value: normalizedScope(d.Scope)}, {Key: "permission", Value: permission}}
}

// SameGrant is sameGrant: two declarations that mean the same Grant.
func SameGrant(a, b Declaration) bool {
	return auth.CanonicalJSON(a.Normalized()) == auth.CanonicalJSON(b.Normalized())
}

// Stored is a Grant row as a declaration.
type Stored struct {
	Declaration
	ID      string
	Revoked bool
}

func nullable(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	return &n.String
}

// storedGrant reads a grants row.
func storedGrant(id string, subjectIdentity, subjectGroup sql.NullString, scope string, actions, role sql.NullString, revoked bool) (Stored, error) {
	s, err := jsvalue.Parse([]byte(scope))
	if err != nil {
		return Stored{}, err
	}
	so, _ := s.(jsvalue.Object)
	d := Declaration{SubjectIdentityID: nullable(subjectIdentity), SubjectGroupID: nullable(subjectGroup), Scope: so, RoleID: nullable(role)}
	if actions.Valid {
		a, err := jsvalue.Parse([]byte(actions.String))
		if err != nil {
			return Stored{}, err
		}
		d.Actions = stringList(a)
		if d.Actions == nil {
			d.Actions = []string{}
		}
	}
	return Stored{Declaration: d, ID: id, Revoked: revoked}, nil
}

// ReadGrant is readGrant: a Grant of the Organization, live or not; nil
// when there is none.
func ReadGrant(ctx context.Context, db query.DBTX, organizationID, grantID string) (*Stored, error) {
	if err := pgText(grantID); err != nil {
		return nil, err
	}
	r, err := query.New(db).GrantOf(ctx, query.GrantOfParams{ID: grantID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	g, err := storedGrant(r.ID, r.SubjectIdentityID, r.SubjectGroupID, r.Scope, r.Actions, r.RoleID, r.RevokedAt.Valid)
	return &g, err
}

func notInOrganization() error {
	return domainerr.New("RESOURCE_NOT_FOUND", "Identity not in this organization")
}

// CheckGrantSubject is checkGrantSubject: a machine of this Organization,
// or a person with a live membership.
func CheckGrantSubject(ctx context.Context, db query.DBTX, organizationID, identityID string) error {
	if err := pgText(identityID); err != nil {
		return err
	}
	r, err := query.New(db).GrantSubject(ctx, query.GrantSubjectParams{OrganizationID: organizationID, ID: identityID})
	if errors.Is(err, sql.ErrNoRows) {
		return notInOrganization()
	}
	if err != nil {
		return err
	}
	if r.Kind == "human" {
		if !r.Member {
			return notInOrganization()
		}
		return nil
	}
	if !r.OrganizationID.Valid || r.OrganizationID.String != organizationID {
		return notInOrganization()
	}
	return nil
}

// names is namesFor: what declarations refer to, in this Organization, as
// summaries write them.
type names struct {
	identities, roles, projects, environments map[string]string
	groups                                    map[string]string
}

func idsOf(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func namesFor(ctx context.Context, db query.DBTX, organizationID string, decls ...Declaration) (names, error) {
	want := struct{ identities, groups, roles, projects, environments map[string]bool }{
		map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{},
	}
	for _, d := range decls {
		if truthy(d.SubjectIdentityID) {
			want.identities[*d.SubjectIdentityID] = true
		}
		if truthy(d.SubjectGroupID) {
			want.groups[*d.SubjectGroupID] = true
		}
		if truthy(d.RoleID) {
			want.roles[*d.RoleID] = true
		}
		switch str(d.Scope, "kind") {
		case "team":
			want.groups[str(d.Scope, "teamId")] = true
		case "project":
			want.projects[str(d.Scope, "projectId")] = true
		case "environments":
			want.projects[str(d.Scope, "projectId")] = true
			sel, _ := d.Scope.Get("selector")
			if so, ok := sel.(jsvalue.Object); ok && str(so, "kind") == "environments" {
				ids, _ := so.Get("environmentIds")
				for _, e := range stringList(ids) {
					want.environments[e] = true
				}
			}
		}
	}
	for _, set := range []map[string]bool{want.identities, want.groups, want.roles, want.projects, want.environments} {
		if err := pgText(idsOf(set)...); err != nil {
			return names{}, err
		}
	}
	q := query.New(db)
	org := sql.NullString{String: organizationID, Valid: true}
	n := names{identities: map[string]string{}, groups: map[string]string{}, roles: map[string]string{}, projects: map[string]string{}, environments: map[string]string{}}
	if len(want.identities) > 0 {
		rows, err := q.NamedIdentities(ctx, query.NamedIdentitiesParams{Ids: idsOf(want.identities), OrganizationID: org})
		if err != nil {
			return n, err
		}
		for _, r := range rows {
			n.identities[r.ID] = security.LabelWithID("", r.Name, r.ID)
		}
	}
	if len(want.groups) > 0 {
		rows, err := q.NamedGroups(ctx, query.NamedGroupsParams{Ids: idsOf(want.groups), OrganizationID: organizationID})
		if err != nil {
			return n, err
		}
		for _, r := range rows {
			n.groups[r.ID] = security.LabelWithID(r.Kind, r.Name, r.ID)
		}
	}
	if len(want.roles) > 0 {
		rows, err := q.NamedRoles(ctx, query.NamedRolesParams{Ids: idsOf(want.roles), OrganizationID: organizationID})
		if err != nil {
			return n, err
		}
		for _, r := range rows {
			n.roles[r.ID] = security.LabelWithID("role", r.Name, r.ID)
		}
	}
	if len(want.projects) > 0 {
		rows, err := q.NamedProjects(ctx, query.NamedProjectsParams{Ids: idsOf(want.projects), OrganizationID: organizationID})
		if err != nil {
			return n, err
		}
		for _, r := range rows {
			n.projects[r.ID] = security.LabelWithID("project", r.Slug, r.ID)
		}
	}
	if len(want.environments) > 0 {
		rows, err := q.NamedEnvironments(ctx, query.NamedEnvironmentsParams{Ids: idsOf(want.environments), OrganizationID: organizationID})
		if err != nil {
			return n, err
		}
		for _, r := range rows {
			n.environments[r.ID] = security.LabelWithID("", fmt.Sprint(r.Name), r.ID)
		}
	}
	return n, nil
}

func or(m map[string]string, id, kind string) string {
	if l, ok := m[id]; ok {
		return l
	}
	return security.Unnamed(kind, id)
}

func describeSubject(d Declaration, n names) string {
	if truthy(d.SubjectIdentityID) {
		return or(n.identities, *d.SubjectIdentityID, "identity")
	}
	g := ""
	if d.SubjectGroupID != nil {
		g = *d.SubjectGroupID
	}
	return or(n.groups, g, "group")
}

func describeScope(d Declaration, n names) string {
	s := d.Scope
	switch str(s, "kind") {
	case "organization":
		return "the whole organization"
	case "project":
		return or(n.projects, str(s, "projectId"), "project")
	case "environments":
		project := or(n.projects, str(s, "projectId"), "project")
		sel, _ := s.Get("selector")
		so, _ := sel.(jsvalue.Object)
		if str(so, "kind") == "tier" {
			return "the " + str(so, "tier") + " environments of " + project
		}
		ids, _ := so.Get("environmentIds")
		var labels []string
		for _, id := range stringList(ids) {
			labels = append(labels, or(n.environments, id, "environment"))
		}
		return "environments " + security.LabelList(jsSet(labels)) + " of " + project
	case "team":
		return "the projects of " + or(n.groups, str(s, "teamId"), "team")
	}
	return ""
}

func describePermission(d Declaration, n names) string {
	if truthy(d.RoleID) {
		return or(n.roles, *d.RoleID, "role")
	}
	return "actions " + security.QuotedList(jsSet(d.Actions))
}

type described struct{ subject, scope, permission string }

func describe(d Declaration, n names) described {
	return described{describeSubject(d, n), describeScope(d, n), describePermission(d, n)}
}

// grantCreateBinding is grantCreateBinding.
func grantCreateBinding(ctx context.Context, db query.DBTX, organizationID string, d Declaration) (*auth.Binding, error) {
	n, err := namesFor(ctx, db, organizationID, d)
	if err != nil {
		return nil, err
	}
	g := describe(d, n)
	return binding("grant.create", organizationID, map[string]string{"organizationId": organizationID}, d.Normalized(), nil, auth.ApprovalSummary{
		Title:   "Grant " + g.permission + " on " + g.scope + " to " + g.subject,
		Changes: []auth.ApprovalChange{added("subject", g.subject), added("scope", g.scope), added("permission", g.permission)},
	}), nil
}

// grantReplaceBinding is grantReplaceBinding of a live Grant by a
// replacement that differs from it.
func grantReplaceBinding(ctx context.Context, db query.DBTX, organizationID string, old Stored, next Declaration) (*auth.Binding, error) {
	n, err := namesFor(ctx, db, organizationID, old.Declaration, next)
	if err != nil {
		return nil, err
	}
	before, after := describe(old.Declaration, n), describe(next, n)
	from, to := old.Normalized(), next.Normalized()
	var changes []auth.ApprovalChange
	for _, f := range []struct {
		field string
		b, a  string
	}{{"subject", before.subject, after.subject}, {"scope", before.scope, after.scope}, {"permission", before.permission, after.permission}} {
		fv, _ := from.Get(f.field)
		tv, _ := to.Get(f.field)
		a, b := auth.CanonicalJSON(fv), auth.CanonicalJSON(tv)
		if a == b {
			continue
		}
		fromLabel, toLabel := f.b, f.a
		if f.b == f.a {
			fromLabel, toLabel = f.b+" "+security.Quoted(a), f.a+" "+security.Quoted(b)
		}
		changes = append(changes, auth.ApprovalChange{Field: f.field, From: &fromLabel, To: &toLabel})
	}
	return binding("grant.replace", organizationID, map[string]string{"grantId": old.ID}, next.Normalized(), nil, auth.ApprovalSummary{
		Title:   "Change the Grant " + old.ID + " of " + before.permission + " on " + before.scope + " to " + before.subject,
		Changes: changes,
	}), nil
}

// grantRevokeBinding is grantRevokeBinding of a live Grant.
func grantRevokeBinding(ctx context.Context, db query.DBTX, organizationID string, g Stored) (*auth.Binding, error) {
	n, err := namesFor(ctx, db, organizationID, g.Declaration)
	if err != nil {
		return nil, err
	}
	d := describe(g.Declaration, n)
	return binding("grant.revoke", organizationID, map[string]string{"grantId": g.ID}, nil, nil, auth.ApprovalSummary{
		Title: "Revoke the Grant " + g.ID + " of " + d.permission + " on " + d.scope + " to " + d.subject,
	}), nil
}

// ---- Roles

// Role is a live role (RoleRef).
type Role struct {
	ID, Name  string
	Actions   []string
	Version   int64
	UpdatedAt sql.NullInt64
}

// SameRole is sameRole: the same name and the same set of actions.
func SameRole(a, b Role) bool {
	return a.Name == b.Name && auth.CanonicalJSON(stringsJS(jsSet(a.Actions))) == auth.CanonicalJSON(stringsJS(jsSet(b.Actions)))
}

func roleCreateBinding(organizationID, name string, actions []string) *auth.Binding {
	set := jsSet(actions)
	return binding("role.create", organizationID, map[string]string{"organizationId": organizationID},
		jsvalue.Object{{Key: "name", Value: name}, {Key: "actions", Value: stringsJS(set)}}, nil, auth.ApprovalSummary{
			Title:   "Create role " + security.Quoted(name) + " with actions " + security.QuotedList(set),
			Changes: []auth.ApprovalChange{added("name", security.Quoted(name)), added("actions", security.QuotedList(set))},
		})
}

func roleUpdateBinding(ctx context.Context, db query.DBTX, organizationID string, current, next Role, expected int64) (*auth.Binding, error) {
	grants, err := query.New(db).RoleGrantCount(ctx, query.RoleGrantCountParams{RoleID: sql.NullString{String: current.ID, Valid: true}, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	before, after := map[string]bool{}, map[string]bool{}
	for _, a := range current.Actions {
		before[a] = true
	}
	for _, a := range next.Actions {
		after[a] = true
	}
	var gained, lost []string
	for _, a := range next.Actions {
		if !before[a] {
			gained = append(gained, a)
		}
	}
	for _, a := range current.Actions {
		if !after[a] {
			lost = append(lost, a)
		}
	}
	var changes []auth.ApprovalChange
	if next.Name != current.Name {
		from, to := security.Quoted(current.Name), security.Quoted(next.Name)
		changes = append(changes, auth.ApprovalChange{Field: "name", From: &from, To: &to})
	}
	if g := jsSet(gained); len(g) > 0 {
		to := security.QuotedList(g)
		changes = append(changes, auth.ApprovalChange{Field: "actionsAdded", To: &to, Loosens: true})
	}
	if l := jsSet(lost); len(l) > 0 {
		from := security.QuotedList(l)
		changes = append(changes, auth.ApprovalChange{Field: "actionsRemoved", From: &from})
	}
	uses := "use"
	if grants == 1 {
		uses = "uses"
	}
	return binding("role.update", organizationID, map[string]string{"roleId": current.ID},
		jsvalue.Object{{Key: "name", Value: next.Name}, {Key: "actions", Value: stringsJS(jsSet(next.Actions))}}, &expected, auth.ApprovalSummary{
			Title:   "Change " + security.LabelWithID("role", current.Name, current.ID) + ", which " + plural(grants, "Grant") + " " + uses,
			Changes: changes,
		}), nil
}

func roleDeleteBinding(organizationID string, r Role) *auth.Binding {
	v := r.Version
	return binding("role.delete", organizationID, map[string]string{"roleId": r.ID}, nil, &v, auth.ApprovalSummary{
		Title: "Delete " + security.LabelWithID("role", r.Name, r.ID),
	})
}

// ---- Groups and teams

// Group is a live group or team (GroupRef).
type Group struct {
	ID, Name, Kind string
	Version        int64
	UpdatedAt      sql.NullInt64
}

func groupCreateBinding(organizationID, name, kind string) *auth.Binding {
	return binding(GroupOperation(kind, "create"), organizationID, map[string]string{"organizationId": organizationID},
		jsvalue.Object{{Key: "kind", Value: kind}, {Key: "name", Value: name}}, nil, auth.ApprovalSummary{
			Title:   "Create " + kind + " " + security.Quoted(name),
			Changes: []auth.ApprovalChange{added("name", security.Quoted(name))},
		})
}

func groupUpdateBinding(organizationID string, g Group, name string, expected int64) *auth.Binding {
	from, to := security.Quoted(g.Name), security.Quoted(name)
	return binding(GroupOperation(g.Kind, "update"), organizationID, map[string]string{"groupId": g.ID},
		jsvalue.Object{{Key: "name", Value: name}}, &expected, auth.ApprovalSummary{
			Title:   "Rename " + security.LabelWithID(g.Kind, g.Name, g.ID) + " to " + security.Quoted(name),
			Changes: []auth.ApprovalChange{{Field: "name", From: &from, To: &to}},
		})
}

func groupDeleteBinding(ctx context.Context, db query.DBTX, organizationID string, g Group) (*auth.Binding, error) {
	members, err := query.New(db).GroupMemberCount(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	lose := "lose"
	if members == 1 {
		lose = "loses"
	}
	v := g.Version
	return binding(GroupOperation(g.Kind, "delete"), organizationID, map[string]string{"groupId": g.ID}, nil, &v, auth.ApprovalSummary{
		Title: "Delete " + security.LabelWithID(g.Kind, g.Name, g.ID) + ". Its " + plural(members, "member") + " " + lose + " what its Grants gave them",
	}), nil
}

// Person is an identity as a summary names it.
type Person struct{ ID, Name string }

func memberAddBinding(organizationID string, g Group, p Person) *auth.Binding {
	return binding(GroupOperation(g.Kind, "member_add"), organizationID, map[string]string{"groupId": g.ID, "identityId": p.ID}, nil, nil, auth.ApprovalSummary{
		Title: "Add " + security.LabelWithID("", p.Name, p.ID) + " to " + security.LabelWithID(g.Kind, g.Name, g.ID),
	})
}

func memberRemoveBinding(organizationID string, g Group, p Person) *auth.Binding {
	return binding(GroupOperation(g.Kind, "member_remove"), organizationID, map[string]string{"groupId": g.ID, "identityId": p.ID}, nil, nil, auth.ApprovalSummary{
		Title: "Remove " + security.LabelWithID("", p.Name, p.ID) + " from " + security.LabelWithID(g.Kind, g.Name, g.ID),
	})
}

// Project is a Project as a summary names it.
type Project struct{ ID, Name, Slug string }

func teamProjectAddBinding(organizationID string, team Group, p Project) *auth.Binding {
	return binding("team.project_add", organizationID, map[string]string{"teamId": team.ID, "projectId": p.ID}, nil, nil, auth.ApprovalSummary{
		Title: "Give " + security.LabelWithID("team", team.Name, team.ID) + " the " + security.LabelWithID("project", p.Slug, p.ID),
	})
}

func teamProjectRemoveBinding(organizationID string, team Group, p Project) *auth.Binding {
	return binding("team.project_remove", organizationID, map[string]string{"teamId": team.ID, "projectId": p.ID}, nil, nil, auth.ApprovalSummary{
		Title: "Take the " + security.LabelWithID("project", p.Slug, p.ID) + " from " + security.LabelWithID("team", team.Name, team.ID),
	})
}
