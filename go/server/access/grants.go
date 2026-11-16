// SPDX-License-Identifier: AGPL-3.0-or-later

// Package access is an Organization's access structure (ADR-0015,
// ADR-0028, ADR-0029; ADR-0059 step 4.4b): Grants, Roles, Groups and
// Teams, their memberships and Team-Project links, as http/app.ts,
// domain/policy.ts and accessstepup.ts write them. Every write is a
// protected operation (ADR-0054, security.Prepare): admin-step-up at
// enforce asks for the requester's approval of exactly that request, and
// policy.manage is rechecked once it is consumed.
package access

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// Request is who asks, with what Varlatch-Approval header (nil for none;
// read only when an approval is due), the request's id, and for the writes
// that take one its Idempotency-Key ("" for none).
type Request struct {
	Principal      *auth.Principal
	Approval       *string
	RequestID      string
	IdempotencyKey string
}

func (r Request) security(approvals *auth.Service) security.Request {
	out := security.Request{Principal: r.Principal, Approvals: approvals}
	if r.Approval != nil {
		if out.ApprovalID = auth.ParseApprovalID(*r.Approval); out.ApprovalID == "" {
			out.ApprovalMalformed = true
		}
	}
	return out
}

// policyManageIn is policyManageIn: policy.manage rechecked in a protected
// operation's job once its approval was consumed. A denial's event is
// recorded after the job (authorizeInTransaction).
func policyManageIn(p *auth.Principal, organizationID, requestID string) func(ctx context.Context, tx query.DBTX) error {
	return func(ctx context.Context, tx query.DBTX) error {
		ap := authz.Principal{IdentityID: p.Identity.ID, IdentityKind: p.Identity.Kind, CredentialID: p.Credential.ID}
		if p.Identity.OrganizationID != nil {
			ap.OrganizationID = *p.Identity.OrganizationID
		}
		d, err := authz.Decide(ctx, tx, ap, "policy.manage", authz.Resource{OrganizationID: organizationID}, authz.Options{HideExistence: true, RequestID: requestID})
		if err != nil || d.Allowed {
			return err
		}
		if d.DenialEvent != nil {
			return &security.DeferredDenial{Err: d.Err, Event: *d.DenialEvent}
		}
		return d.Err
	}
}

func isoNullable(n sql.NullInt64) any {
	if !n.Valid {
		return nil
	}
	return audit.ISOTime(n.Int64)
}

// jsNow is new Date().toISOString(): the clock in milliseconds.
func jsNow(now func() time.Time) string { return audit.ISOTime(now().UnixMilli() * 1000) }

func stringOrNull(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func nullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

// Grants is GET …/grants' items: the live Grants, oldest first, each
// scope as jsonb gives it back.
func Grants(ctx context.Context, db query.DBTX, organizationID string) ([]any, error) {
	rows, err := query.New(db).OrganizationGrants(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		scope, err := jsvalue.Parse([]byte(r.Scope))
		if err != nil {
			return nil, err
		}
		var actions any
		if r.Actions.Valid {
			if actions, err = jsvalue.Parse([]byte(r.Actions.String)); err != nil {
				return nil, err
			}
		}
		out = append(out, jsvalue.Object{
			{Key: "id", Value: r.ID}, {Key: "organizationId", Value: r.OrganizationID},
			{Key: "subjectIdentityId", Value: stringOrNull(nullable(r.SubjectIdentityID))}, {Key: "subjectGroupId", Value: stringOrNull(nullable(r.SubjectGroupID))},
			{Key: "scope", Value: jsvalue.Jsonb(scope)}, {Key: "actions", Value: actions}, {Key: "roleId", Value: stringOrNull(nullable(r.RoleID))},
			{Key: "createdAt", Value: audit.ISOTime(r.CreatedAt)},
		})
	}
	return out, nil
}

// requireGrantSubject is requireGrantSubject: the subject can act in the
// Organization, read under its person gate (the TypeScript code pins its
// membership).
func requireGrantSubject(ctx context.Context, tx query.DBTX, organizationID, identityID string) error {
	return CheckGrantSubject(ctx, tx, organizationID, identityID)
}

// Input is a Grant declaration as the route parsed it, with zod's output
// (the parsed body, which an Idempotency-Key's digest covers).
type Input struct {
	Declaration
	// Body is the parsed body as zod gives it on.
	Body jsvalue.Object
}

// grantJS is a Grant as the create and replace answers write it.
func grantJS(id, organizationID string, d Declaration, createdAt string) jsvalue.Object {
	var actions any
	if d.Actions != nil {
		actions = stringsJS(d.Actions)
	}
	return jsvalue.Object{
		{Key: "id", Value: id}, {Key: "organizationId", Value: organizationID},
		{Key: "subjectIdentityId", Value: stringOrNull(d.SubjectIdentityID)}, {Key: "subjectGroupId", Value: stringOrNull(d.SubjectGroupID)},
		{Key: "scope", Value: d.Scope}, {Key: "actions", Value: actions}, {Key: "roleId", Value: stringOrNull(d.RoleID)},
		{Key: "createdAt", Value: createdAt},
	}
}

// ErrForeignReference refuses a Grant naming a group or role of another
// Organization. It is answered as a group or role that does not exist is,
// whose insert fails on its foreign key: an internal error, so the answer
// does not tell the two apart.
var ErrForeignReference = errors.New("access: a Grant names a group or role of another Organization")

// requireOwnReferences lets a Grant name only its Organization's groups and
// roles (live or not, as the foreign keys allow); one that does not exist
// is left to the insert.
func requireOwnReferences(ctx context.Context, tx query.DBTX, organizationID string, d Declaration) error {
	q := query.New(tx)
	check := func(id *string, read func(context.Context, string) (string, error)) error {
		if id == nil {
			return nil
		}
		org, err := read(ctx, *id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil
		case err != nil:
			return err
		case org != organizationID:
			return ErrForeignReference
		}
		return nil
	}
	if err := check(d.SubjectGroupID, q.GroupOrganization); err != nil {
		return err
	}
	return check(d.RoleID, q.RoleOrganization)
}

// insertGrant writes the declaration as a new Grant, naming only the
// Organization's own groups and roles.
func insertGrant(ctx context.Context, tx query.DBTX, id, organizationID, actor string, d Declaration, at int64) error {
	if err := requireOwnReferences(ctx, tx, organizationID, d); err != nil {
		return err
	}
	// The scope is jsonb: U+0000 or a lone surrogate in it fails the insert.
	if err := jsvalue.JsonbRefuses(d.Scope); err != nil {
		return err
	}
	var actions sql.NullString
	if d.Actions != nil {
		actions = sql.NullString{String: string(jsvalue.Stringify(stringsJS(d.Actions))), Valid: true}
	}
	return query.New(tx).InsertGrant(ctx, query.InsertGrantParams{
		ID: id, OrganizationID: organizationID, SubjectIdentityID: nullString(d.SubjectIdentityID), SubjectGroupID: nullString(d.SubjectGroupID),
		Scope: string(jsvalue.Stringify(jsvalue.Jsonb(d.Scope))), Actions: actions, RoleID: nullString(d.RoleID),
		CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: at,
	})
}

// createdEvent is grant.created's event.
func createdEvent(actor, organizationID, id string, d Declaration, extra jsvalue.Object, approval *auth.UsedApproval) audit.Event {
	resource := jsvalue.Object{{Key: "grantId", Value: id}}
	if truthy(d.SubjectIdentityID) {
		resource = append(resource, jsvalue.Member{Key: "subjectIdentityId", Value: *d.SubjectIdentityID})
	}
	if truthy(d.SubjectGroupID) {
		resource = append(resource, jsvalue.Member{Key: "subjectGroupId", Value: *d.SubjectGroupID})
	}
	md := extra
	if truthy(d.RoleID) {
		md = append(md, jsvalue.Member{Key: "roleId", Value: *d.RoleID})
	} else {
		joined := ""
		for i, a := range d.Actions {
			if i > 0 {
				joined += ","
			}
			joined += a
		}
		md = append(md, jsvalue.Member{Key: "actions", Value: joined})
	}
	md = append(md, security.ApprovalMetadata(approval)...)
	action := "policy.manage"
	return audit.Event{Type: "grant.created", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
		Resource: resource, Metadata: md}
}

// subjectGates are a declaration's subject's person gate, shared.
func subjectGates(d Declaration) []write.Gate {
	if truthy(d.SubjectIdentityID) {
		return []write.Gate{write.Person(*d.SubjectIdentityID, write.Shared)}
	}
	return nil
}

// CreateGrant is POST …/grants: a protected operation (grant.create). The
// subject exists, whatever the controls, before passkey-verification; the
// approval binds exactly this declaration.
func CreateGrant(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID string, d Declaration, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	id := ids.New(ids.Grant)
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID, subjectGates(d)...), func(ctx context.Context, tx *storage.Tx) error {
		subject := func(ctx context.Context, db query.DBTX) error {
			if truthy(d.SubjectIdentityID) {
				return CheckGrantSubject(ctx, db, organizationID, *d.SubjectIdentityID)
			}
			return nil
		}
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:     write.Scope{OrganizationID: organizationID},
			Checks:    []security.Check{{Control: security.AdminStepUp, Operation: "grant.create"}},
			Preflight: subject,
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				if err := subject(ctx, db); err != nil {
					return nil, err
				}
				return grantCreateBinding(ctx, db, organizationID, d)
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		if truthy(d.SubjectIdentityID) {
			if err := requireGrantSubject(ctx, tx, organizationID, *d.SubjectIdentityID); err != nil {
				return err
			}
		}
		if err := insertGrant(ctx, tx, id, organizationID, actor, d, now().UnixMicro()); err != nil {
			return err
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, createdEvent(actor, organizationID, id, d, nil, p.Approval))
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return grantJS(id, organizationID, d, jsNow(now)), reports, nil
}

func grantNotFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Grant not found") }

// RevokeGrant is DELETE …/grants/{grant}: a protected operation
// (grant.revoke), recovery while frozen, where its approval may still be
// asked for.
func RevokeGrant(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, grantID string, now func() time.Time) ([]auth.PendingReport, error) {
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		live := func(ctx context.Context, db query.DBTX) (*Stored, error) {
			g, err := ReadGrant(ctx, db, organizationID, grantID)
			if err != nil {
				return nil, err
			}
			if g == nil || g.Revoked {
				return nil, grantNotFound()
			}
			return g, nil
		}
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:     write.Scope{OrganizationID: organizationID, DuringFreeze: authz.DuringFreezeRecovery},
			Checks:    []security.Check{{Control: security.AdminStepUp, Operation: "grant.revoke"}},
			Preflight: func(ctx context.Context, db query.DBTX) error { _, err := live(ctx, db); return err },
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				g, err := live(ctx, db)
				if err != nil {
					return nil, err
				}
				return grantRevokeBinding(ctx, db, organizationID, *g)
			},
			AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		revoked, err := query.New(tx).RevokeGrant(ctx, query.RevokeGrantParams{RevokedAt: sql.NullInt64{Int64: now().UnixMicro(), Valid: true}, ID: grantID, OrganizationID: organizationID})
		if err != nil {
			return err
		}
		if len(revoked) == 0 {
			return grantNotFound()
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		action := "policy.manage"
		e := audit.Event{Type: "grant.revoked", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "grantId", Value: grantID}}}
		if p.Approval != nil {
			e.Metadata = security.ApprovalMetadata(p.Approval)
		}
		_, err = audit.Record(ctx, tx, e)
		return err
	})
	return reports, err
}

func alreadyReplaced() error {
	return domainerr.New("VERSION_CONFLICT", "Grant is already revoked or replaced")
}

// ReplaceGrant is POST …/grants/{grant}/replace (ADR-0029): the Grant
// revoked and its successor created in one job, under an Idempotency-Key
// when the request has one. A protected operation (grant.replace), bound
// to the old Grant and the complete normalized replacement; a replacement
// identical to the old declaration needs no approval and report mode does
// not count it, yet still replaces the Grant. It returns the response (its
// status and payload, replayed from the claim when it was stored) and the
// report counts.
func ReplaceGrant(ctx context.Context, w *write.Writer, approvals *auth.Service, rootKEK []byte, req Request, organizationID, grantID string, in Input, now func() time.Time) (write.Response, []auth.PendingReport, error) {
	r := req.security(approvals)
	actor := req.Principal.Identity.ID
	d := in.Declaration
	ctx, release, err := w.Gates.Acquire(ctx, r.Gates(organizationID, subjectGates(d)...)...)
	if err != nil {
		return write.Response{}, nil, err
	}
	defer release()
	claim := write.Claim{IdentityID: actor, Endpoint: "POST grants " + grantID + " replace", Key: req.IdempotencyKey, Digest: write.BodyHash(in.Body, rootKEK)}
	var reports []auth.PendingReport
	resp, _, err := write.Idempotent(ctx, w.Store, claim,
		func(tx *storage.Tx) error {
			var err error
			reports, err = write.Checkpoint(ctx, tx, req.Principal, organizationID)
			return err
		},
		func(tx *storage.Tx) (write.Response, error) {
			subject := func(ctx context.Context, db query.DBTX) error {
				if truthy(d.SubjectIdentityID) {
					return CheckGrantSubject(ctx, db, organizationID, *d.SubjectIdentityID)
				}
				return nil
			}
			p, err := security.Prepare(ctx, tx, r, security.Protected{
				Scope:  write.Scope{OrganizationID: organizationID},
				Checks: []security.Check{{Control: security.AdminStepUp, Operation: "grant.replace"}},
				Preflight: func(ctx context.Context, db query.DBTX) error {
					if err := subject(ctx, db); err != nil {
						return err
					}
					g, err := ReadGrant(ctx, db, organizationID, grantID)
					if err == nil && g == nil {
						err = grantNotFound()
					}
					return err
				},
				Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
					if err := subject(ctx, db); err != nil {
						return nil, err
					}
					old, err := ReadGrant(ctx, db, organizationID, grantID)
					switch {
					case err != nil:
						return nil, err
					case old == nil:
						return nil, grantNotFound()
					case old.Revoked:
						return nil, alreadyReplaced()
					case SameGrant(old.Declaration, d):
						return nil, nil
					}
					return grantReplaceBinding(ctx, db, organizationID, *old, d)
				},
				AuthorizeIn: policyManageIn(req.Principal, organizationID, req.RequestID),
			}, now)
			if err != nil {
				return write.Response{}, err
			}
			reports = p.Access
			if truthy(d.SubjectIdentityID) {
				if err := requireGrantSubject(ctx, tx, organizationID, *d.SubjectIdentityID); err != nil {
					return write.Response{}, err
				}
			}
			old, err := ReadGrant(ctx, tx, organizationID, grantID)
			switch {
			case err != nil:
				return write.Response{}, err
			case old == nil:
				return write.Response{}, grantNotFound()
			case old.Revoked:
				return write.Response{}, alreadyReplaced()
			}
			same := SameGrant(old.Declaration, d)
			at := now().UnixMicro()
			q := query.New(tx)
			if _, err := q.RevokeGrant(ctx, query.RevokeGrantParams{RevokedAt: sql.NullInt64{Int64: at, Valid: true}, ID: grantID, OrganizationID: organizationID}); err != nil {
				return write.Response{}, err
			}
			newID := ids.New(ids.Grant)
			if err := insertGrant(ctx, tx, newID, organizationID, actor, d, at); err != nil {
				return write.Response{}, err
			}
			if !same {
				if err := p.Count(ctx, tx); err != nil {
					return write.Response{}, err
				}
			}
			action := "policy.manage"
			revoked := audit.Event{Type: "grant.revoked", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
				Resource: jsvalue.Object{{Key: "grantId", Value: grantID}},
				Metadata: append(jsvalue.Object{{Key: "replacedBy", Value: newID}}, security.ApprovalMetadata(p.Approval)...)}
			if _, err := audit.Record(ctx, tx, revoked); err != nil {
				return write.Response{}, err
			}
			if _, err := audit.Record(ctx, tx, createdEvent(actor, organizationID, newID, d, jsvalue.Object{{Key: "replaces", Value: grantID}}, p.Approval)); err != nil {
				return write.Response{}, err
			}
			return write.Response{Status: 201, Payload: jsvalue.Object{
				{Key: "replacedGrantId", Value: grantID}, {Key: "grant", Value: grantJS(newID, organizationID, d, jsNow(now))},
			}}, nil
		})
	return resp, reports, err
}
