// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"
	"unicode/utf16"

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

// Roles (ADR-0028, ADR-0029): named action bundles, which take effect
// only through the Grants that cite them, expanded on each decision.

// jsLength is a string's length as JavaScript counts it.
func jsLength(s string) int { return len(utf16.Encode([]rune(s))) }

func parseActions(text string) ([]string, error) {
	v, err := jsvalue.Parse([]byte(text))
	if err != nil {
		return nil, err
	}
	out := stringList(v)
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// JS is the role as the API gives it.
func (r Role) JS() jsvalue.Object {
	return jsvalue.Object{{Key: "id", Value: r.ID}, {Key: "name", Value: r.Name}, {Key: "actions", Value: stringsJS(r.Actions)},
		{Key: "version", Value: r.Version}, {Key: "updatedAt", Value: isoNullable(r.UpdatedAt)}}
}

// Roles is listRoles: the live roles, by name.
func Roles(ctx context.Context, db query.DBTX, organizationID string) ([]any, error) {
	rows, err := query.New(db).OrganizationRoles(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		actions, err := parseActions(r.Actions)
		if err != nil {
			return nil, err
		}
		out = append(out, Role{ID: r.ID, Name: r.Name, Actions: actions, Version: r.Version, UpdatedAt: r.UpdatedAt}.JS())
	}
	return out, nil
}

// ReadRole is readRole: a live role of the Organization; nil when there is
// none.
func ReadRole(ctx context.Context, db query.DBTX, organizationID, roleID string) (*Role, error) {
	if err := pgText(roleID); err != nil {
		return nil, err
	}
	r, err := query.New(db).LiveRole(ctx, query.LiveRoleParams{ID: roleID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	actions, err := parseActions(r.Actions)
	if err != nil {
		return nil, err
	}
	return &Role{ID: r.ID, Name: r.Name, Actions: actions, Version: r.Version, UpdatedAt: r.UpdatedAt}, nil
}

func roleNameTaken() error {
	return domainerr.New("VALIDATION_FAILED", "A role with that name already exists")
}
func roleNotFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Role not found") }
func roleConflict() error {
	return domainerr.New("VERSION_CONFLICT", "Role was modified concurrently; reload and retry")
}

// refuseTakenRole is refuseTakenName on roles.
func refuseTakenRole(ctx context.Context, db query.DBTX, organizationID, name, except string) error {
	if err := pgText(name, except); err != nil {
		return err
	}
	n, err := query.New(db).RoleNameTaken(ctx, query.RoleNameTakenParams{OrganizationID: organizationID, Name: name, ExceptID: except})
	if err != nil {
		return err
	}
	if n > 0 {
		return roleNameTaken()
	}
	return nil
}

func actionsText(actions []string) string { return string(jsvalue.Stringify(stringsJS(actions))) }

// CreateRole is createRole: a protected operation (role.create); a name a
// live role already has is refused first.
func CreateRole(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, name string, actions []string, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	if name == "" || jsLength(name) > 200 {
		return nil, nil, domainerr.New("VALIDATION_FAILED", "Invalid role name")
	}
	if len(actions) == 0 {
		return nil, nil, domainerr.New("VALIDATION_FAILED", "A role must grant at least one action")
	}
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	var out jsvalue.Object
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "role.create"}},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				if err := refuseTakenRole(ctx, db, organizationID, name, ""); err != nil {
					return nil, err
				}
				return roleCreateBinding(organizationID, name, actions), nil
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		// The insert fails on U+0000 in the name or an action, which the
		// TypeScript code reads as the name taken, as any failure of it.
		stored, err := write.Text(name)
		if err != nil || pgText(actions...) != nil {
			return roleNameTaken()
		}
		id := ids.New(ids.Role)
		// Any failure of the insert is the name taken, as the TypeScript
		// code reads it.
		if err := query.New(tx).InsertRole(ctx, query.InsertRoleParams{
			ID: id, OrganizationID: organizationID, Name: stored, Actions: actionsText(actions),
			CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: now().UnixMicro(),
		}); err != nil {
			return roleNameTaken()
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "policy.manage"
		md := jsvalue.Object{{Key: "name", Value: name}, {Key: "actions", Value: joinActions(actions)}}
		if _, err := audit.Record(ctx, tx, audit.Event{Type: "role.created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Action: &action, Resource: jsvalue.Object{{Key: "roleId", Value: id}}, Metadata: append(md, security.ApprovalMetadata(p.Approval)...)}); err != nil {
			return err
		}
		out = Role{ID: id, Name: name, Actions: actions, Version: 1}.JS()
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out, reports, nil
}

func joinActions(actions []string) string {
	s := ""
	for i, a := range actions {
		if i > 0 {
			s += ","
		}
		s += a
	}
	return s
}

// RolePatch is updateRole's patch: the version the request expects, and
// what it changes (nil: unchanged).
type RolePatch struct {
	ExpectedVersion int64
	Name            *string
	Actions         []string // nil: unchanged
	// Body is zod's output, which the Idempotency-Key's digest covers.
	Body jsvalue.Object
}

// UpdateRole is updateRole (ADR-0029): the role changed in place, taking
// effect on the next decision of every Grant citing it, under an
// Idempotency-Key when the request has one. A protected operation
// (role.update): a patch that means the same role (a reordering included)
// needs no approval and is not counted, yet is written as before; one
// that changes nothing at all answers the current row.
func UpdateRole(ctx context.Context, w *write.Writer, approvals *auth.Service, rootKEK []byte, req Request, organizationID, roleID string, patch RolePatch, now func() time.Time) (write.Response, []auth.PendingReport, error) {
	if patch.Name != nil && (*patch.Name == "" || jsLength(*patch.Name) > 200) {
		return write.Response{}, nil, domainerr.New("VALIDATION_FAILED", "Invalid role name")
	}
	if patch.Actions != nil && len(patch.Actions) == 0 {
		return write.Response{}, nil, domainerr.New("VALIDATION_FAILED", "A role must grant at least one action")
	}
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	claim := write.Claim{IdentityID: actor, Endpoint: "PATCH roles " + roleID, Key: req.IdempotencyKey, Digest: write.BodyHash(patch.Body, rootKEK)}
	return idempotentProtected(ctx, w, r, organizationID, claim, func(ctx context.Context, tx *storage.Tx, reports *[]auth.PendingReport) (write.Response, error) {
		next := func(current Role) Role {
			n := Role{ID: current.ID, Name: current.Name, Actions: current.Actions}
			if patch.Name != nil {
				n.Name = *patch.Name
			}
			if patch.Actions != nil {
				n.Actions = patch.Actions
			}
			return n
		}
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "role.update"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				role, err := ReadRole(ctx, db, organizationID, roleID)
				if err == nil && role == nil {
					err = roleNotFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				current, err := ReadRole(ctx, db, organizationID, roleID)
				switch {
				case err != nil:
					return nil, err
				case current == nil:
					return nil, roleNotFound()
				case current.Version != patch.ExpectedVersion:
					return nil, roleConflict()
				}
				n := next(*current)
				if SameRole(*current, n) {
					return nil, nil
				}
				if n.Name != current.Name {
					if err := refuseTakenRole(ctx, db, organizationID, n.Name, roleID); err != nil {
						return nil, err
					}
				}
				return roleUpdateBinding(ctx, db, organizationID, *current, n, patch.ExpectedVersion)
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return write.Response{}, err
		}
		*reports = p.Access
		row, err := ReadRole(ctx, tx, organizationID, roleID)
		switch {
		case err != nil:
			return write.Response{}, err
		case row == nil:
			return write.Response{}, roleNotFound()
		case row.Version != patch.ExpectedVersion:
			return write.Response{}, roleConflict()
		}
		n := next(*row)
		if n.Name == row.Name && slices.Equal(n.Actions, row.Actions) {
			return write.Response{Status: 200, Payload: row.JS()}, nil
		}
		// As the insert: a failing update is the name taken.
		stored, err := write.Text(n.Name)
		if err != nil || pgText(n.Actions...) != nil {
			return write.Response{}, roleNameTaken()
		}
		at := now().UnixMicro()
		updated, err := query.New(tx).UpdateRole(ctx, query.UpdateRoleParams{Name: stored, Actions: actionsText(n.Actions), UpdatedAt: sql.NullInt64{Int64: at, Valid: true}, ID: roleID})
		if err != nil {
			return write.Response{}, roleNameTaken()
		}
		if !SameRole(*row, n) {
			if err := p.Count(ctx, tx); err != nil {
				return write.Response{}, err
			}
		}
		action := "policy.manage"
		md := jsvalue.Object{
			{Key: "oldName", Value: row.Name}, {Key: "newName", Value: n.Name},
			{Key: "oldActions", Value: joinActions(row.Actions)}, {Key: "newActions", Value: joinActions(n.Actions)}, {Key: "version", Value: updated.Version},
		}
		if _, err := audit.Record(ctx, tx, audit.Event{Type: "role.updated", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Action: &action, Resource: jsvalue.Object{{Key: "roleId", Value: roleID}}, Metadata: append(md, security.ApprovalMetadata(p.Approval)...)}); err != nil {
			return write.Response{}, err
		}
		return write.Response{Status: 200, Payload: Role{ID: roleID, Name: n.Name, Actions: n.Actions, Version: updated.Version, UpdatedAt: updated.UpdatedAt}.JS()}, nil
	})
}

// idempotentProtected runs a protected write under an Idempotency-Key
// claim (withIdempotency inside withApproval): the Organization's gate and
// the requester's (exclusive when it carries an approval) taken first; a
// replay runs the requester's checkpoint before answering from the claim.
func idempotentProtected(ctx context.Context, w *write.Writer, r security.Request, organizationID string, claim write.Claim,
	run func(ctx context.Context, tx *storage.Tx, reports *[]auth.PendingReport) (write.Response, error)) (write.Response, []auth.PendingReport, error) {
	ctx, release, err := w.Gates.Acquire(ctx, r.Gates(organizationID)...)
	if err != nil {
		return write.Response{}, nil, err
	}
	defer release()
	var reports []auth.PendingReport
	resp, _, err := write.Idempotent(ctx, w.Store, claim,
		func(tx *storage.Tx) error {
			var err error
			reports, err = write.Checkpoint(ctx, tx, r.Principal, organizationID)
			return err
		},
		func(tx *storage.Tx) (write.Response, error) { return run(ctx, tx, &reports) })
	return resp, reports, err
}

func roleChanged() error {
	return domainerr.New("STATE_CHANGED", "The role changed while it was being deleted; nothing was deleted. Read it again and ask for a new approval")
}

// DeleteRole is deleteRole: a protected operation (role.delete), bound to
// the version the server read and checked again before the deletion.
func DeleteRole(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, roleID string, now func() time.Time) ([]auth.PendingReport, error) {
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: "role.delete"}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				role, err := ReadRole(ctx, db, organizationID, roleID)
				if err == nil && role == nil {
					err = roleNotFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				role, err := ReadRole(ctx, db, organizationID, roleID)
				switch {
				case err != nil:
					return nil, err
				case role == nil:
					return nil, roleNotFound()
				}
				return roleDeleteBinding(organizationID, *role), nil
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		locked, err := ReadRole(ctx, tx, organizationID, roleID)
		switch {
		case err != nil:
			return err
		case locked == nil:
			return roleNotFound()
		case p.Binding != nil && p.Binding.ExpectedVersion != nil && locked.Version != *p.Binding.ExpectedVersion:
			return roleChanged()
		}
		if err := query.New(tx).RevokeRole(ctx, query.RevokeRoleParams{RevokedAt: sql.NullInt64{Int64: now().UnixMicro(), Valid: true}, ID: roleID}); err != nil {
			return err
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "policy.manage"
		e := audit.Event{Type: "role.deleted", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "roleId", Value: roleID}}}
		if p.Approval != nil {
			e.Metadata = security.ApprovalMetadata(p.Approval)
		}
		_, err = audit.Record(ctx, tx, e)
		return err
	})
	return reports, err
}
