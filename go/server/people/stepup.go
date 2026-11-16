// SPDX-License-Identifier: AGPL-3.0-or-later

// Package people is an Organization's people (ADR-0006, ADR-0052, step
// 4.5): invitations, removing a member or leaving, role changes, the
// review of what a person set up, and the profile a person edits.
package people

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// Request is who asks, with what Varlatch-Approval header (nil for none;
// read only when an approval is due) and the request's id.
type Request struct {
	Principal *auth.Principal
	Approval  *string
	RequestID string
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

// identityManageIn is identityManageIn: identity.manage rechecked in a
// protected operation's job once its approval was consumed. A denial's
// event is recorded after the job (authorizeInTransaction).
func identityManageIn(p *auth.Principal, organizationID, requestID string) func(ctx context.Context, tx query.DBTX) error {
	return func(ctx context.Context, tx query.DBTX) error {
		ap := authz.Principal{IdentityID: p.Identity.ID, IdentityKind: p.Identity.Kind, CredentialID: p.Credential.ID}
		if p.Identity.OrganizationID != nil {
			ap.OrganizationID = *p.Identity.OrganizationID
		}
		d, err := authz.Decide(ctx, tx, ap, "identity.manage", authz.Resource{OrganizationID: organizationID}, authz.Options{HideExistence: true, RequestID: requestID})
		if err != nil || d.Allowed {
			return err
		}
		if d.DenialEvent != nil {
			return &security.DeferredDenial{Err: d.Err, Event: *d.DenialEvent}
		}
		return d.Err
	}
}

// pgText refuses what PostgreSQL refuses in a text parameter: U+0000
// fails the TypeScript server's statement, so the route answers 500 at the
// first query that takes such a string.
func pgText(values ...string) error {
	for _, v := range values {
		if strings.IndexByte(v, 0) >= 0 {
			return write.ErrPostgresText
		}
	}
	return nil
}

func memberNotFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Member not found") }

func orgNotFound() error { return domainerr.New("RESOURCE_NOT_FOUND", "Organization not found") }

// Member is MemberRef: a live membership, as a binding and its summary
// name it.
type Member struct {
	IdentityID, Name, Role string
	Version                int64
}

// readMember is readMember: a person's live membership in the
// Organization; nil when there is none.
func readMember(ctx context.Context, db query.DBTX, organizationID, identityID string) (*Member, error) {
	if err := pgText(identityID); err != nil {
		return nil, err
	}
	r, err := query.New(db).LiveMember(ctx, query.LiveMemberParams{OrganizationID: organizationID, IdentityID: identityID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Member{IdentityID: r.IdentityID, Name: r.Name, Role: r.Role, Version: r.Version}, nil
}

func plural(n int64, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func binding(operation, organizationID string, target map[string]string, body any, expected *int64, summary auth.ApprovalSummary) *auth.Binding {
	org := organizationID
	if summary.Changes == nil {
		summary.Changes = []auth.ApprovalChange{}
	}
	return &auth.Binding{Operation: operation, OrganizationID: &org, Target: target, Body: body, Query: map[string]string{},
		ExpectedVersion: expected, Summary: summary}
}

func strp(s string) *string { return &s }

// inviteAdminBinding is inviteAdminBinding: member.invite_admin, bound to
// the Organization, the name and the role (always admin).
func inviteAdminBinding(organizationID, name string) *auth.Binding {
	q := security.Quoted(name)
	return binding("member.invite_admin", organizationID, map[string]string{"organizationId": organizationID},
		jsvalue.Object{{Key: "name", Value: name}, {Key: "role", Value: "admin"}}, nil, auth.ApprovalSummary{
			Title: "Invite " + q + " as an Organization Admin",
			Changes: []auth.ApprovalChange{
				{Field: "name", To: strp(q)},
				{Field: "role", To: strp("admin")},
			},
		})
}

// memberRoleBinding is memberRoleBinding: member.promote or member.demote
// of a live membership whose role differs.
func memberRoleBinding(organizationID string, m Member, role string) *auth.Binding {
	op, title := "member.demote", "Make "+security.LabelWithID("", m.Name, m.IdentityID)+" a member instead of an admin"
	if role == "admin" {
		op, title = "member.promote", "Make "+security.LabelWithID("", m.Name, m.IdentityID)+" an Organization Admin"
	}
	version := m.Version
	return binding(op, organizationID, map[string]string{"identityId": m.IdentityID}, jsvalue.Object{{Key: "role", Value: role}}, &version,
		auth.ApprovalSummary{Title: title, Changes: []auth.ApprovalChange{{Field: "role", From: strp(m.Role), To: strp(role)}}})
}

// removalCounts is removalCounts: what ending this membership would end
// now: the person's live direct Grants, group and team links, and pending
// invitations they issued.
type removalCounts struct{ grants, groups, invitations int64 }

func readRemovalCounts(ctx context.Context, db query.DBTX, organizationID, identityID string, now int64) (removalCounts, error) {
	r, err := query.New(db).RemovalCounts(ctx, query.RemovalCountsParams{OrganizationID: organizationID, IdentityID: sql.NullString{String: identityID, Valid: true}, Now: now})
	if err != nil {
		return removalCounts{}, err
	}
	return removalCounts{grants: r.GrantCount, groups: r.GroupCount, invitations: r.InvitationCount}, nil
}

// memberRemoveBinding is memberRemoveBinding: member.remove of someone
// else's live membership, bound to the version the server read.
func memberRemoveBinding(organizationID, organizationName string, m Member, c removalCounts) *auth.Binding {
	who := "a member"
	if m.Role == "admin" {
		who = "an admin"
	}
	version := m.Version
	return binding("member.remove", organizationID, map[string]string{"identityId": m.IdentityID}, nil, &version, auth.ApprovalSummary{
		Title: "Remove " + security.LabelWithID("", m.Name, m.IdentityID) + ", " + who + ", from " +
			security.LabelWithID("organization", organizationName, organizationID) + ": " +
			plural(c.grants, "direct Grant") + " revoked, " + plural(c.groups, "group") + " left, " + plural(c.invitations, "invitation") + " revoked",
	})
}
