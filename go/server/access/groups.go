// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// Groups and Teams (ADR-0028): identity sets; a Team is a Group that owns
// Projects. They share their writers: kind is the route's for a creation
// and a rename (which finds only its own kind), the stored row's for a
// deletion and for memberships.

// JS is the group as the API gives it.
func (g Group) JS() jsvalue.Object {
	return jsvalue.Object{{Key: "id", Value: g.ID}, {Key: "name", Value: g.Name}, {Key: "kind", Value: g.Kind},
		{Key: "version", Value: g.Version}, {Key: "updatedAt", Value: isoNullable(g.UpdatedAt)}}
}

// Groups is listGroups: the live groups (or teams), by name.
func Groups(ctx context.Context, db query.DBTX, organizationID, kind string) ([]any, error) {
	rows, err := query.New(db).OrganizationGroups(ctx, query.OrganizationGroupsParams{OrganizationID: organizationID, Kind: kind})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, Group{ID: r.ID, Name: r.Name, Kind: r.Kind, Version: r.Version, UpdatedAt: r.UpdatedAt}.JS())
	}
	return out, nil
}

// ReadGroup is readGroup: a live group or team of the Organization, of
// kind when kind is not ""; nil when there is none.
func ReadGroup(ctx context.Context, db query.DBTX, organizationID, groupID, kind string) (*Group, error) {
	if err := pgText(groupID); err != nil {
		return nil, err
	}
	r, err := query.New(db).LiveGroup(ctx, query.LiveGroupParams{ID: groupID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if kind != "" && r.Kind != kind {
		return nil, nil
	}
	return &Group{ID: r.ID, Name: r.Name, Kind: r.Kind, Version: r.Version, UpdatedAt: r.UpdatedAt}, nil
}

func groupNotFound(kind string) error {
	if kind == "team" {
		return domainerr.New("RESOURCE_NOT_FOUND", "Team not found")
	}
	return domainerr.New("RESOURCE_NOT_FOUND", "Group not found")
}

func groupNameTaken(kind string) error {
	return domainerr.New("VALIDATION_FAILED", "A "+kind+" with that name already exists")
}

// RequireGroup is requireGroup: a live group of the Organization, a team
// when kind is "team"; not found otherwise.
func RequireGroup(ctx context.Context, db query.DBTX, organizationID, groupID, kind string) (Group, error) {
	g, err := ReadGroup(ctx, db, organizationID, groupID, "")
	if err != nil {
		return Group{}, err
	}
	if g == nil || (kind != "" && g.Kind != kind) {
		return Group{}, groupNotFound(kind)
	}
	return *g, nil
}

func refuseTakenGroup(ctx context.Context, db query.DBTX, organizationID, name, except, kind string) error {
	if err := pgText(name, except); err != nil {
		return err
	}
	// The name as the driver sends it: a lone surrogate as U+FFFD, as
	// write.Text stores it.
	name, _ = write.Text(name)
	n, err := query.New(db).GroupNameTaken(ctx, query.GroupNameTakenParams{OrganizationID: organizationID, Name: name, ExceptID: except})
	if err != nil {
		return err
	}
	if n > 0 {
		return groupNameTaken(kind)
	}
	return nil
}

func groupEvent(kind, verb string) string { return kind + "." + verb }

// CreateGroup is createGroup: a protected operation (group.create or
// team.create); a name a live group or team already has is refused first.
func CreateGroup(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, name, kind string, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	if name == "" || jsLength(name) > 200 {
		return nil, nil, domainerr.New("VALIDATION_FAILED", "Invalid group name")
	}
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	var out jsvalue.Object
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: GroupOperation(kind, "create")}},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				if err := refuseTakenGroup(ctx, db, organizationID, name, "", kind); err != nil {
					return nil, err
				}
				return groupCreateBinding(organizationID, name, kind), nil
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		// The insert fails on U+0000 in the name, which the TypeScript code
		// reads as the name taken, as any failure of it.
		stored, err := write.Text(name)
		if err != nil {
			return groupNameTaken(kind)
		}
		prefix := ids.Group
		if kind == "team" {
			prefix = ids.Team
		}
		id := ids.New(prefix)
		if err := query.New(tx).InsertGroup(ctx, query.InsertGroupParams{
			ID: id, OrganizationID: organizationID, Name: stored, Kind: kind, CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: now().UnixMicro(),
		}); err != nil {
			return groupNameTaken(kind)
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "policy.manage"
		if _, err := audit.Record(ctx, tx, audit.Event{Type: groupEvent(kind, "created"), Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Action: &action, Resource: jsvalue.Object{{Key: "groupId", Value: id}},
			Metadata: append(jsvalue.Object{{Key: "name", Value: name}}, security.ApprovalMetadata(p.Approval)...)}); err != nil {
			return err
		}
		out = Group{ID: id, Name: name, Kind: kind, Version: 1}.JS()
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out, reports, nil
}

// GroupPatch is updateGroup's patch.
type GroupPatch struct {
	ExpectedVersion int64
	Name            *string
	Body            jsvalue.Object
}

// UpdateGroup is updateGroup (ADR-0029): a rename in place, under an
// Idempotency-Key when the request has one. A protected operation
// (group.update or team.update); keeping the name needs none.
func UpdateGroup(ctx context.Context, w *write.Writer, approvals *auth.Service, rootKEK []byte, req Request, organizationID, groupID, kind string, patch GroupPatch, now func() time.Time) (write.Response, []auth.PendingReport, error) {
	if patch.Name != nil && (*patch.Name == "" || jsLength(*patch.Name) > 200) {
		return write.Response{}, nil, domainerr.New("VALIDATION_FAILED", "Invalid group name")
	}
	conflict := func() error {
		word := "Group"
		if kind == "team" {
			word = "Team"
		}
		return domainerr.New("VERSION_CONFLICT", word+" was modified concurrently; reload and retry")
	}
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	claim := write.Claim{IdentityID: actor, Endpoint: "PATCH " + kind + "s " + groupID, Key: req.IdempotencyKey, Digest: write.BodyHash(patch.Body, rootKEK)}
	return security.IdempotentProtected(ctx, w, r, organizationID, claim, func(ctx context.Context, tx *storage.Tx, reports *[]auth.PendingReport) (write.Response, error) {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: GroupOperation(kind, "update")}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				g, err := ReadGroup(ctx, db, organizationID, groupID, kind)
				if err == nil && g == nil {
					err = groupNotFound(kind)
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				current, err := ReadGroup(ctx, db, organizationID, groupID, kind)
				switch {
				case err != nil:
					return nil, err
				case current == nil:
					return nil, groupNotFound(kind)
				case current.Version != patch.ExpectedVersion:
					return nil, conflict()
				}
				name := current.Name
				if patch.Name != nil {
					name = *patch.Name
				}
				if name == current.Name {
					return nil, nil
				}
				if err := refuseTakenGroup(ctx, db, organizationID, name, groupID, kind); err != nil {
					return nil, err
				}
				return groupUpdateBinding(organizationID, *current, name, patch.ExpectedVersion), nil
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return write.Response{}, err
		}
		*reports = p.Access
		row, err := ReadGroup(ctx, tx, organizationID, groupID, kind)
		switch {
		case err != nil:
			return write.Response{}, err
		case row == nil:
			return write.Response{}, groupNotFound(kind)
		case row.Version != patch.ExpectedVersion:
			return write.Response{}, conflict()
		}
		name := row.Name
		if patch.Name != nil {
			name = *patch.Name
		}
		if name == row.Name {
			return write.Response{Status: 200, Payload: row.JS()}, nil
		}
		// As the insert: a failing update is the name taken.
		stored, err := write.Text(name)
		if err != nil {
			return write.Response{}, groupNameTaken(kind)
		}
		updated, err := query.New(tx).RenameGroup(ctx, query.RenameGroupParams{Name: stored, UpdatedAt: sql.NullInt64{Int64: now().UnixMicro(), Valid: true}, ID: groupID})
		if err != nil {
			return write.Response{}, groupNameTaken(kind)
		}
		if err := p.Count(ctx, tx); err != nil {
			return write.Response{}, err
		}
		action := "policy.manage"
		md := jsvalue.Object{{Key: "oldName", Value: row.Name}, {Key: "newName", Value: name}, {Key: "version", Value: updated.Version}}
		if _, err := audit.Record(ctx, tx, audit.Event{Type: groupEvent(kind, "updated"), Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Action: &action, Resource: jsvalue.Object{{Key: "groupId", Value: groupID}}, Metadata: append(md, security.ApprovalMetadata(p.Approval)...)}); err != nil {
			return write.Response{}, err
		}
		return write.Response{Status: 200, Payload: Group{ID: groupID, Name: name, Kind: kind, Version: updated.Version, UpdatedAt: updated.UpdatedAt}.JS()}, nil
	})
}

// DeleteGroup is deleteGroup: a protected operation, group.delete or
// team.delete after the stored kind, bound to the version the server read
// and checked again before the deletion.
func DeleteGroup(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, groupID string, now func() time.Time) ([]auth.PendingReport, error) {
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		// The kind names the operation report mode counts; it never changes.
		if err := pgText(groupID); err != nil {
			return err
		}
		storedKind, err := query.New(tx).GroupKindOf(ctx, query.GroupKindOfParams{ID: groupID, OrganizationID: organizationID})
		if errors.Is(err, sql.ErrNoRows) {
			storedKind, err = "group", nil
		}
		if err != nil {
			return err
		}
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: GroupOperation(storedKind, "delete")}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				g, err := ReadGroup(ctx, db, organizationID, groupID, "")
				if err == nil && g == nil {
					err = groupNotFound("group")
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				g, err := ReadGroup(ctx, db, organizationID, groupID, "")
				switch {
				case err != nil:
					return nil, err
				case g == nil:
					return nil, groupNotFound("group")
				}
				return groupDeleteBinding(ctx, db, organizationID, *g)
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		locked, err := ReadGroup(ctx, tx, organizationID, groupID, "")
		switch {
		case err != nil:
			return err
		case locked == nil:
			return groupNotFound("group")
		case p.Binding != nil && p.Binding.ExpectedVersion != nil && locked.Version != *p.Binding.ExpectedVersion:
			return domainerr.New("STATE_CHANGED", "The "+locked.Kind+" changed while it was being deleted; nothing was deleted. Read it again and ask for a new approval")
		}
		if err := query.New(tx).RevokeGroup(ctx, query.RevokeGroupParams{RevokedAt: sql.NullInt64{Int64: now().UnixMicro(), Valid: true}, ID: groupID}); err != nil {
			return err
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "policy.manage"
		e := audit.Event{Type: groupEvent(locked.Kind, "deleted"), Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Action: &action, Resource: jsvalue.Object{{Key: "groupId", Value: groupID}}}
		if p.Approval != nil {
			e.Metadata = security.ApprovalMetadata(p.Approval)
		}
		_, err = audit.Record(ctx, tx, e)
		return err
	})
	return reports, err
}

// Members is listGroupMembers: the group's members, oldest first; the
// group must be live (of either kind).
func Members(ctx context.Context, db query.DBTX, organizationID, groupID string) ([]any, error) {
	if _, err := RequireGroup(ctx, db, organizationID, groupID, ""); err != nil {
		return nil, err
	}
	if err := pgText(groupID); err != nil {
		return nil, err
	}
	rows, err := query.New(db).GroupMembers(ctx, groupID)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(rows))
	for _, id := range rows {
		out = append(out, jsvalue.Object{{Key: "identityId", Value: id}})
	}
	return out, nil
}

func readEligibleMember(ctx context.Context, db query.DBTX, organizationID, identityID string) (*Person, error) {
	if err := pgText(identityID); err != nil {
		return nil, err
	}
	r, err := query.New(db).EligibleMember(ctx, query.EligibleMemberParams{ID: identityID, OrganizationID: sql.NullString{String: organizationID, Valid: true}})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Person{ID: r.ID, Name: r.Name}, nil
}

func isGroupMember(ctx context.Context, db query.DBTX, groupID, identityID string) (bool, error) {
	if err := pgText(groupID, identityID); err != nil {
		return false, err
	}
	n, err := query.New(db).IsGroupMember(ctx, query.IsGroupMemberParams{GroupID: groupID, IdentityID: identityID})
	return n > 0, err
}

func memberEvent(g Group, verb string, actor, organizationID, groupID, identityID string, approval *auth.UsedApproval) audit.Event {
	action := "policy.manage"
	e := audit.Event{Type: groupEvent(g.Kind, verb), Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
		Resource: jsvalue.Object{{Key: "groupId", Value: groupID}, {Key: "identityId", Value: identityID}}}
	if approval != nil {
		e.Metadata = security.ApprovalMetadata(approval)
	}
	return e
}

// AddMember is addGroupMember: a protected operation (group.member_add or
// team.member_add, after the stored kind). Adding a current member
// changes nothing and needs no approval; a membership removed in between
// is refused (STATE_CHANGED).
func AddMember(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, groupID, identityID string, now func() time.Time) ([]auth.PendingReport, error) {
	g, err := RequireGroup(ctx, w.Store.Reader(), organizationID, groupID, "")
	if err != nil {
		return nil, err
	}
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	var reports []auth.PendingReport
	err = w.Job(ctx, r.Gates(organizationID, write.Person(identityID, write.Shared)), func(ctx context.Context, tx *storage.Tx) error {
		boundMember := false
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: GroupOperation(g.Kind, "member_add")}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				m, err := readEligibleMember(ctx, db, organizationID, identityID)
				if err == nil && m == nil {
					err = notInOrganization()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				m, err := readEligibleMember(ctx, db, organizationID, identityID)
				if err != nil {
					return nil, err
				}
				if m == nil {
					return nil, notInOrganization()
				}
				member, err := isGroupMember(ctx, db, groupID, identityID)
				if err != nil {
					return nil, err
				}
				if member {
					boundMember = true
					return nil, nil
				}
				return memberAddBinding(organizationID, g, *m), nil
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		if err := groupStillLive(ctx, tx, organizationID, groupID); err != nil {
			return err
		}
		q := query.New(tx)
		kind, err := q.EnabledMemberKind(ctx, query.EnabledMemberKindParams{ID: identityID, OrganizationID: sql.NullString{String: organizationID, Valid: true}})
		if errors.Is(err, sql.ErrNoRows) {
			return notInOrganization()
		}
		if err != nil {
			return err
		}
		if kind == "human" {
			live, err := q.LiveMembershipOf(ctx, query.LiveMembershipOfParams{OrganizationID: organizationID, IdentityID: identityID})
			if err != nil {
				return err
			}
			if live == 0 {
				return notInOrganization()
			}
		}
		added, err := q.AddGroupMember(ctx, query.AddGroupMemberParams{GroupID: groupID, IdentityID: identityID, CreatedAt: now().UnixMicro()})
		if err != nil {
			return err
		}
		if boundMember && len(added) > 0 {
			return domainerr.New("STATE_CHANGED", "The membership was removed while it was being added; nothing changed. Add it again")
		}
		if len(added) > 0 {
			if err := p.Count(ctx, tx); err != nil {
				return err
			}
		}
		_, err = audit.Record(ctx, tx, memberEvent(g, "member_added", actor, organizationID, groupID, identityID, p.Approval))
		return err
	})
	return reports, err
}

// groupStillLive re-reads the group (or team) in the job: one deleted
// since the route read it takes no member and no Project. Hardening: the
// TypeScript code reads it once, outside its transaction.
func groupStillLive(ctx context.Context, tx query.DBTX, organizationID, groupID string) error {
	_, err := RequireGroup(ctx, tx, organizationID, groupID, "")
	return err
}

func membershipNotFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Membership not found") }

// RemoveMember is removeGroupMember: a protected operation
// (group.member_remove or team.member_remove, after the stored kind); a
// membership that does not exist is refused first.
func RemoveMember(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, groupID, identityID string, now func() time.Time) ([]auth.PendingReport, error) {
	g, err := RequireGroup(ctx, w.Store.Reader(), organizationID, groupID, "")
	if err != nil {
		return nil, err
	}
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	var reports []auth.PendingReport
	err = w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		member := func(ctx context.Context, db query.DBTX) error {
			ok, err := isGroupMember(ctx, db, groupID, identityID)
			if err == nil && !ok {
				err = membershipNotFound()
			}
			return err
		}
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:     write.Scope{OrganizationID: organizationID},
			Checks:    []security.Check{{Control: security.AdminStepUp, Operation: GroupOperation(g.Kind, "member_remove")}},
			Preflight: member,
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				if err := member(ctx, db); err != nil {
					return nil, err
				}
				person := Person{ID: identityID, Name: identityID}
				if err := pgText(identityID); err != nil {
					return nil, err
				}
				r, err := query.New(db).IdentityRef(ctx, identityID)
				if err == nil {
					person = Person{ID: r.ID, Name: r.Name}
				} else if !errors.Is(err, sql.ErrNoRows) {
					return nil, err
				}
				return memberRemoveBinding(organizationID, g, person), nil
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		if err := groupStillLive(ctx, tx, organizationID, groupID); err != nil {
			return err
		}
		removed, err := query.New(tx).RemoveGroupMember(ctx, query.RemoveGroupMemberParams{GroupID: groupID, IdentityID: identityID})
		if err != nil {
			return err
		}
		if len(removed) == 0 {
			return membershipNotFound()
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, memberEvent(g, "member_removed", actor, organizationID, groupID, identityID, p.Approval))
		return err
	})
	return reports, err
}

// TeamProjects is listTeamProjects: the team's Projects, oldest link
// first; the team must be live.
func TeamProjects(ctx context.Context, db query.DBTX, organizationID, teamID string) ([]any, error) {
	if _, err := RequireGroup(ctx, db, organizationID, teamID, "team"); err != nil {
		return nil, err
	}
	if err := pgText(teamID); err != nil {
		return nil, err
	}
	rows, err := query.New(db).TeamProjectIDs(ctx, teamID)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(rows))
	for _, id := range rows {
		out = append(out, jsvalue.Object{{Key: "projectId", Value: id}})
	}
	return out, nil
}

func isTeamProject(ctx context.Context, db query.DBTX, teamID, projectID string) (bool, error) {
	if err := pgText(teamID, projectID); err != nil {
		return false, err
	}
	n, err := query.New(db).IsTeamProject(ctx, query.IsTeamProjectParams{TeamID: teamID, ProjectID: projectID})
	return n > 0, err
}

func projectEvent(verb, actor, organizationID, teamID, projectID string, approval *auth.UsedApproval) audit.Event {
	action := "policy.manage"
	e := audit.Event{Type: "team.project_" + verb, Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
		Resource: jsvalue.Object{{Key: "groupId", Value: teamID}, {Key: "projectId", Value: projectID}}}
	if approval != nil {
		e.Metadata = security.ApprovalMetadata(approval)
	}
	return e
}

func projectNotFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Project not found") }

// AddTeamProject is addTeamProject: a protected operation
// (team.project_add) on a live Project of the Organization. Adding a
// linked project changes nothing and needs no approval; a link removed in
// between is refused (STATE_CHANGED).
func AddTeamProject(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, teamID, projectID string, now func() time.Time) ([]auth.PendingReport, error) {
	team, err := RequireGroup(ctx, w.Store.Reader(), organizationID, teamID, "team")
	if err != nil {
		return nil, err
	}
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	var reports []auth.PendingReport
	err = w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		boundLinked := false
		readProject := func(ctx context.Context, db query.DBTX) (*Project, error) {
			if err := pgText(projectID); err != nil {
				return nil, err
			}
			r, err := query.New(db).LiveProjectRef(ctx, query.LiveProjectRefParams{ID: projectID, OrganizationID: organizationID})
			if errors.Is(err, sql.ErrNoRows) {
				return nil, projectNotFound()
			}
			if err != nil {
				return nil, err
			}
			return &Project{ID: r.ID, Name: r.Name, Slug: r.Slug}, nil
		}
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:     write.Scope{OrganizationID: organizationID, ProjectID: projectID},
			Checks:    []security.Check{{Control: security.AdminStepUp, Operation: "team.project_add"}},
			Preflight: func(ctx context.Context, db query.DBTX) error { _, err := readProject(ctx, db); return err },
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				project, err := readProject(ctx, db)
				if err != nil {
					return nil, err
				}
				linked, err := isTeamProject(ctx, db, teamID, projectID)
				if err != nil {
					return nil, err
				}
				if linked {
					boundLinked = true
					return nil, nil
				}
				return teamProjectAddBinding(organizationID, team, *project), nil
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		if err := groupStillLive(ctx, tx, organizationID, teamID); err != nil {
			return err
		}
		added, err := query.New(tx).AddTeamProject(ctx, query.AddTeamProjectParams{TeamID: teamID, ProjectID: projectID, CreatedAt: now().UnixMicro()})
		if err != nil {
			return err
		}
		if boundLinked && len(added) > 0 {
			return domainerr.New("STATE_CHANGED", "The project was taken from the team while it was being added; nothing changed. Add it again")
		}
		if len(added) > 0 {
			if err := p.Count(ctx, tx); err != nil {
				return err
			}
		}
		_, err = audit.Record(ctx, tx, projectEvent("added", actor, organizationID, teamID, projectID, p.Approval))
		return err
	})
	return reports, err
}

func notOwned() error { return domainerr.New("RESOURCE_NOT_FOUND", "Team does not own that project") }

// RemoveTeamProject is removeTeamProject: a protected operation
// (team.project_remove); a link that does not exist is refused first.
func RemoveTeamProject(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, teamID, projectID string, now func() time.Time) ([]auth.PendingReport, error) {
	team, err := RequireGroup(ctx, w.Store.Reader(), organizationID, teamID, "team")
	if err != nil {
		return nil, err
	}
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	var reports []auth.PendingReport
	err = w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		linked := func(ctx context.Context, db query.DBTX) error {
			ok, err := isTeamProject(ctx, db, teamID, projectID)
			if err == nil && !ok {
				err = notOwned()
			}
			return err
		}
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:     write.Scope{OrganizationID: organizationID},
			Checks:    []security.Check{{Control: security.AdminStepUp, Operation: "team.project_remove"}},
			Preflight: linked,
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				if err := linked(ctx, db); err != nil {
					return nil, err
				}
				project := Project{ID: projectID, Name: projectID, Slug: projectID}
				if err := pgText(projectID); err != nil {
					return nil, err
				}
				r, err := query.New(db).ProjectRef(ctx, query.ProjectRefParams{ID: projectID, OrganizationID: organizationID})
				if err == nil {
					project = Project{ID: r.ID, Name: r.Name, Slug: r.Slug}
				} else if !errors.Is(err, sql.ErrNoRows) {
					return nil, err
				}
				return teamProjectRemoveBinding(organizationID, team, project), nil
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		if err := groupStillLive(ctx, tx, organizationID, teamID); err != nil {
			return err
		}
		removed, err := query.New(tx).RemoveTeamProject(ctx, query.RemoveTeamProjectParams{TeamID: teamID, ProjectID: projectID})
		if err != nil {
			return err
		}
		if len(removed) == 0 {
			return notOwned()
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, projectEvent("removed", actor, organizationID, teamID, projectID, p.Approval))
		return err
	})
	return reports, err
}
