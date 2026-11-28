// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"regexp"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/people"
	"github.com/varlatch/varlatch/go/server/security"
)

// Step 4.5: an Organization's people (http/app.ts, domain/invitations.ts,
// domain/members.ts, domain/peoplestepup.ts): invitations, members
// removed or leaving, role changes, the review before a removal, and the
// profile a person edits.

const (
	listInvitationsPattern  = "GET /v1/organizations/{org}/invitations"
	createInvitationPattern = "POST /v1/organizations/{org}/invitations"
	revokeInvitationPattern = "DELETE /v1/organizations/{org}/invitations/{invitation}"
	reviewMemberPattern     = "GET /v1/organizations/{org}/members/{member}/review"
	removeMemberPattern     = "DELETE /v1/organizations/{org}/members/{member}"
	changeMemberRolePattern = "PATCH /v1/organizations/{org}/members/{member}"
	updateMyProfilePattern  = "PATCH /v1/me/profile"
	// Step 4.5b.
	memberExposurePattern            = "GET /v1/organizations/{org}/members/{member}/exposure"
	confirmExposureRevocationPattern = "POST /v1/organizations/{org}/members/{member}/exposure/confirmations"
)

func init() {
	for _, p := range []string{
		listInvitationsPattern, createInvitationPattern, revokeInvitationPattern,
		reviewMemberPattern, removeMemberPattern, changeMemberRolePattern, updateMyProfilePattern,
		memberExposurePattern, confirmExposureRevocationPattern,
	} {
		readsItself[p] = true
	}
}

func (r reply) VisitListInvitationsResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitCreateInvitationResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitRevokeInvitationResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitReviewMemberResponse(w http.ResponseWriter) error     { return r.visit(w) }
func (r reply) VisitRemoveMemberResponse(w http.ResponseWriter) error     { return r.visit(w) }
func (r reply) VisitChangeMemberRoleResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitUpdateMyProfileResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitMemberExposureResponse(w http.ResponseWriter) error   { return r.visit(w) }
func (r reply) VisitConfirmExposureRevocationResponse(w http.ResponseWriter) error {
	return r.visit(w)
}

const (
	invitationsRoute = "/v1/organizations/:org/invitations"
	membersRoute     = "/v1/organizations/:org/members/:member"
)

var orgRoles = zEnum{"admin", "member"}

var invitationBody = zObject{{name: "name", schema: zString{min: 1, max: 200}}, {name: "role", schema: orgRoles}}

var memberRoleBody = zStrict{{name: "role", schema: orgRoles}}

var profileBody = zObject{
	{name: "name", schema: zString{min: 1, max: 200}, optional: true},
	{name: "image", schema: zNullable{zString{max: 102_400}}, optional: true},
}

func (q *orgRequest) peopleRequest(ctx context.Context) people.Request {
	return people.Request{Principal: q.p, Approval: approvalHeaderOf(ctx), RequestID: requestIDOf(q.r)}
}

// invitationLimit is parseLimit: absent, 100; otherwise one to three
// digits, 1 to 500.
var limitDigits = regexp.MustCompile(`^\d{1,3}$`)

func invitationLimit(raw []string) (int, error) {
	if len(raw) == 0 {
		return 100, nil
	}
	n := 0
	if limitDigits.MatchString(raw[0]) {
		for _, c := range raw[0] {
			n = n*10 + int(c-'0')
		}
	}
	if !limitDigits.MatchString(raw[0]) || n < 1 || n > 500 {
		return 0, domainerr.New("VALIDATION_FAILED", "limit must be an integer in 1..500")
	}
	return n, nil
}

// ListInvitations is GET …/invitations: inspection while frozen,
// identity.manage; a page of invitations, newest first by (createdAt,
// id), pending only unless status=all. Metadata only.
func (o *operations) ListInvitations(ctx context.Context, _ api.ListInvitationsRequestObject) (api.ListInvitationsResponseObject, error) {
	q, err := o.enterRoute(ctx, invitationsRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "identity.manage"); err != nil {
		return nil, err
	}
	raw := rawOf(ctx).query
	status := "pending"
	if s, ok := raw["status"]; ok {
		status = s[0]
	}
	if status != "pending" && status != "all" {
		return nil, domainerr.New("VALIDATION_FAILED", "status must be pending or all")
	}
	limit, err := invitationLimit(raw["limit"])
	if err != nil {
		return nil, err
	}
	var after []string
	cursor, hasCursor := raw["cursor"]
	if hasCursor {
		if after = decodeCursor(cursor[0]); len(after) != 2 {
			return nil, domainerr.New("VALIDATION_FAILED", "Invalid cursor")
		}
	}
	now := o.s.opts.Now().UnixMicro()
	where, args := "kind = 'invite' AND invite_organization_id = ?", []any{q.org.ID}
	if status == "pending" {
		where += " AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ?"
		args = append(args, now)
	}
	if after != nil {
		// (created_at, id) < ($3::timestamptz, $4), the time read as
		// PostgreSQL reads it.
		t, err := o.cursorTime(after[0])
		if err != nil {
			return nil, err
		}
		where += " AND (created_at < ? OR (created_at = ? AND id < ?))"
		args = append(args, t, t, after[1])
	}
	rows, err := o.s.opts.Auth.Store().Reader().QueryContext(ctx,
		"SELECT id, invite_name, invite_role, created_at, expires_at, created_by, consumed_at, revoked_at FROM setup_grants WHERE "+
			where+" ORDER BY created_at DESC, id DESC LIMIT ?", append(args, limit+1)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var page []people.Invitation
	for rows.Next() {
		var i people.Invitation
		var role sql.NullString
		if err := rows.Scan(&i.ID, &i.Name, &role, &i.CreatedAt, &i.ExpiresAt, &i.CreatedBy, &i.ConsumedAt, &i.RevokedAt); err != nil {
			return nil, err
		}
		i.Role = role.String
		page = append(page, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	more := len(page) > limit
	if more {
		page = page[:limit]
	}
	items := make([]any, len(page))
	for i, inv := range page {
		items[i] = inv.JS(now)
	}
	var next any
	if more && len(page) > 0 {
		last := page[len(page)-1]
		next = encodeCursor([]string{pgTimestamptzText(last.CreatedAt), last.ID})
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: next}}), nil
}

// CreateInvitation is POST …/invitations: identity.manage, the body, then
// issueInviteGrant (a protected operation for an admin). 201; the caller
// composes the browser URL <dashboard-origin>/enroll#<token>.
func (o *operations) CreateInvitation(ctx context.Context, _ api.CreateInvitationRequestObject) (api.CreateInvitationResponseObject, error) {
	q, err := o.enterRoute(ctx, invitationsRoute, "")
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "identity.manage"); err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(invitationBody, body)
	if err != nil {
		return nil, err
	}
	obj := parsed.(jsvalue.Object)
	name, _ := obj.Get("name")
	role, _ := obj.Get("role")
	type result struct {
		out     jsvalue.Object
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := people.CreateInvitation(ctx, o.s.opts.Writer, o.s.opts.Auth, q.peopleRequest(ctx), q.org.ID, name.(string), role.(string), o.s.opts.Now)
		return result{out, reports}, err
	})
	if refusal := (people.AdminInvitationRefused{}); errors.As(err, &refusal) {
		// Audited after the job, like any other denial.
		actor, org, action, reqID := q.p.Identity.ID, q.org.ID, "identity.manage", requestIDOf(q.r)
		e := audit.Event{Type: "authorization.denied", Decision: audit.Deny, ActorIdentityID: &actor, CredentialID: audit.Value(q.p.Credential.ID),
			OrganizationID: &org, Action: &action, Resource: jsvalue.Object{{Key: "projectId", Value: nil}, {Key: "environmentId", Value: nil}},
			Authz:     jsvalue.Object{{Key: "denial", Value: "no-grant"}, {Key: "requirements", Value: []any{}}},
			Metadata:  jsvalue.Object{{Key: "operation", Value: "POST invitations"}, {Key: "reason", Value: "not-admin"}},
			RequestID: &reqID}
		if werr := o.s.opts.Auth.Store().Write(ctx, func(tx *storage.Tx) error {
			_, e := audit.Record(ctx, tx, e)
			return e
		}); werr != nil {
			return nil, werr
		}
	}
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	// The answer carries the invitation's token, shown once: never cached.
	// An intended difference: the TypeScript route sets no Cache-Control.
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return reply{status: http.StatusCreated, body: res.out}, nil
}

// RevokeInvitation is DELETE …/invitations/{invitation}: recovery while
// frozen, identity.manage. 204.
func (o *operations) RevokeInvitation(ctx context.Context, _ api.RevokeInvitationRequestObject) (api.RevokeInvitationResponseObject, error) {
	q, err := o.enterRoute(ctx, invitationsRoute+"/:invitation", authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "identity.manage"); err != nil {
		return nil, err
	}
	reports, err := people.RevokeInvitation(ctx, o.s.opts.Writer, q.p, q.org.ID, pathSegment(q.r, 4), o.s.opts.Now)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

// memberRequest enters a member route: organization.read hides the
// Organization from people who cannot see it; the admin checks run in
// the operation. memberParam's "me" is the caller.
func (o *operations) memberRequest(ctx context.Context, route, exception string) (*orgRequest, string, error) {
	q, err := o.enterRoute(ctx, route, exception)
	if err != nil {
		return nil, "", err
	}
	if err := q.authorize(ctx, "organization.read"); err != nil {
		return nil, "", err
	}
	member := pathSegment(q.r, 4)
	if member == "me" {
		member = q.p.Identity.ID
	}
	return q, member, nil
}

// memberDenied is auditMemberDenial: a PERMISSION_DENIED from inside a
// member operation (which its job rolled back) is audited after it, like
// any other denial: no grant, the admin check.
func (o *operations) memberDenied(ctx context.Context, q *orgRequest, member string, err error) error {
	var de *domainerr.Error
	if !errors.As(err, &de) || de.Code != "PERMISSION_DENIED" {
		return err
	}
	actor, org, action, reqID := q.p.Identity.ID, q.org.ID, "identity.manage", requestIDOf(q.r)
	e := audit.Event{Type: "authorization.denied", Decision: audit.Deny, ActorIdentityID: &actor, CredentialID: audit.Value(q.p.Credential.ID),
		OrganizationID: &org, Action: &action, Resource: jsvalue.Object{{Key: "identityId", Value: member}},
		Authz:     jsvalue.Object{{Key: "denial", Value: "no-grant"}, {Key: "requirements", Value: []any{}}},
		Metadata:  jsvalue.Object{{Key: "operation", Value: q.r.Method + " members"}, {Key: "reason", Value: "not-admin"}},
		RequestID: &reqID}
	if werr := o.s.opts.Auth.Store().Write(ctx, func(tx *storage.Tx) error {
		_, e := audit.Record(ctx, tx, e)
		return e
	}); werr != nil {
		return werr
	}
	return err
}

// ReviewMember is GET …/members/{member}/review: inspection while
// frozen; what the person set up that may keep working without them, for
// a live admin about any live member, for a member about themselves.
func (o *operations) ReviewMember(ctx context.Context, _ api.ReviewMemberRequestObject) (api.ReviewMemberResponseObject, error) {
	q, member, err := o.memberRequest(ctx, membersRoute+"/review", authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	tx, err := o.s.opts.Auth.Store().Reader().BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	review, err := people.PreviewReview(ctx, tx, o.s.opts.RootKEK, q.org.ID, member, q.p, o.s.opts.Now().UnixMicro())
	if err != nil {
		return nil, o.memberDenied(ctx, q, member, err)
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(review), nil
}

// RemoveMember is DELETE …/members/{member}: recovery while frozen;
// removing someone else (protected, member.remove) or leaving.
func (o *operations) RemoveMember(ctx context.Context, _ api.RemoveMemberRequestObject) (api.RemoveMemberResponseObject, error) {
	q, member, err := o.memberRequest(ctx, membersRoute, authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	type result struct {
		out     jsvalue.Object
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := people.RemoveMember(ctx, o.s.opts.Writer, o.s.opts.Auth, o.s.opts.RootKEK, q.peopleRequest(ctx), q.org.ID, member, o.s.opts.Now)
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, o.memberDenied(ctx, q, member, err))
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	return ok(res.out), nil
}

// ChangeMemberRole is PATCH …/members/{member}: recovery while frozen at
// the route (promotion is refused in the operation), the strict body,
// then the protected operation (member.promote or member.demote).
func (o *operations) ChangeMemberRole(ctx context.Context, _ api.ChangeMemberRoleRequestObject) (api.ChangeMemberRoleResponseObject, error) {
	q, err := o.enterRoute(ctx, membersRoute, authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.read"); err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(memberRoleBody, body)
	if err != nil {
		return nil, err
	}
	role, _ := parsed.(jsvalue.Object).Get("role")
	member := pathSegment(q.r, 4)
	if member == "me" {
		member = q.p.Identity.ID
	}
	type result struct {
		out     jsvalue.Object
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := people.ChangeMemberRole(ctx, o.s.opts.Writer, o.s.opts.Auth, q.peopleRequest(ctx), q.org.ID, member, role.(string), o.s.opts.Now)
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, o.memberDenied(ctx, q, member, err))
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	return ok(res.out), nil
}

// The image checks are JavaScript's /i without the u flag, which folds
// case within ASCII only: explicit classes, so U+017F (long s) or U+212A
// (Kelvin sign) never stand for s or k, as Go's (?i) would let them.
var (
	dataImage  = regexp.MustCompile(`^[dD][aA][tT][aA]:[iI][mM][aA][gG][eE]/[a-zA-Z0-9.+-]+;`)
	httpsImage = regexp.MustCompile(`^[hH][tT][tT][pP][sS]://`)
)

// UpdateMyProfile is PATCH /v1/me/profile: a person's display name and
// image (a data:image URL or an https URL, 100KB at most); machines have
// no profile.
func (o *operations) UpdateMyProfile(ctx context.Context, _ api.UpdateMyProfileRequestObject) (api.UpdateMyProfileResponseObject, error) {
	p := principalOf(ctx)
	if p.Identity.Kind != "human" {
		return nil, domainerr.New("RESOURCE_NOT_FOUND", "Machine identities have no profile")
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(profileBody, body)
	if err != nil {
		return nil, err
	}
	obj := parsed.(jsvalue.Object)
	var change people.ProfileChange
	if v, ok := obj.Get("name"); ok {
		s := v.(string)
		change.Name = &s
	}
	if v, ok := obj.Get("image"); ok {
		change.SetImage = true
		if s, isStr := v.(string); isStr {
			if !dataImage.MatchString(s) && !httpsImage.MatchString(s) {
				return nil, domainerr.New("VALIDATION_FAILED", "image must be a data:image/… URL or an https:// URL")
			}
			if len(s) > 102_400 { // TextEncoder's bytes: a lone surrogate is 3 either way
				return nil, domainerr.New("VALIDATION_FAILED", "image must be at most 100KB")
			}
			change.Image = &s
		}
	}
	out, err := people.UpdateProfile(ctx, o.s.opts.Writer, p, change, o.s.opts.Now)
	if err != nil {
		return nil, err
	}
	return ok(out), nil
}

// MemberExposure is GET …/members/{member}/exposure (ADR-0052 Decision
// 6): inspection while frozen, audit.read; the exposure report for a
// current or former member, from one read snapshot, Cache-Control:
// no-store.
func (o *operations) MemberExposure(ctx context.Context, _ api.MemberExposureRequestObject) (api.MemberExposureResponseObject, error) {
	q, err := o.enterRoute(ctx, membersRoute+"/exposure", authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "audit.read"); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	member := pathSegment(q.r, 4)
	if member == "me" {
		member = q.p.Identity.ID
	}
	tx, err := o.s.opts.Auth.Store().Reader().BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	report, err := people.MemberExposure(ctx, tx, o.s.opts.RootKEK, q.org.ID, member, o.s.opts.Now().UnixMicro())
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(report), nil
}

var confirmationBody = zStrict{{name: "versionId", schema: zString{min: 1, max: 200}}}

// ConfirmExposureRevocation is POST …/members/{member}/exposure/
// confirmations (ADR-0052 Decision 7): an operator's confirmation that an
// exposed version was revoked at its provider. config.value.write where
// the value lives, or, once the value or its environment is gone, a live
// built-in admin. 201, or 200 for a version already confirmed.
func (o *operations) ConfirmExposureRevocation(ctx context.Context, _ api.ConfirmExposureRevocationRequestObject) (api.ConfirmExposureRevocationResponseObject, error) {
	q, err := o.enterRoute(ctx, membersRoute+"/exposure/confirmations", "")
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.read"); err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(confirmationBody, body)
	if err != nil {
		return nil, err
	}
	versionID, _ := parsed.(jsvalue.Object).Get("versionId")
	member := pathSegment(q.r, 4)
	if member == "me" {
		member = q.p.Identity.ID
	}
	reader := o.s.opts.Auth.Store().Reader()
	version, err := people.ReadExposedVersion(ctx, reader, q.org.ID, member, versionID.(string))
	if err != nil {
		return nil, err
	}
	if version == nil {
		return nil, people.NotExposed()
	}
	if version.Live && version.EnvironmentID.Valid && version.ProjectID.Valid {
		env, err := query.New(reader).EnvironmentForAuthorization(ctx, version.EnvironmentID.String)
		if err != nil {
			return nil, err
		}
		root := env.ID
		if env.ParentEnvironmentID.Valid {
			root = env.ParentEnvironmentID.String
		}
		if err := q.authorizeWith(ctx, "config.value.write", authz.Resource{OrganizationID: q.org.ID, ProjectID: version.ProjectID.String,
			Environment: &authz.Environment{ID: env.ID, RootID: root, Tier: env.Tier}}, false); err != nil {
			return nil, err
		}
	} else {
		role := ""
		if q.p.Identity.Kind == "human" {
			if role, err = authz.OrgRole(ctx, reader, q.org.ID, q.p.Identity.ID); err != nil {
				return nil, err
			}
		}
		if role != "admin" {
			return nil, domainerr.New("PERMISSION_DENIED", "The value or its environment was deleted: only an Organization Admin can confirm its revocation")
		}
	}
	out, created, reports, err := people.ConfirmRevocation(ctx, o.s.opts.Writer, q.p, q.org.ID, member, versionID.(string), *version, o.s.opts.Now)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return reply{status: status, body: out}, nil
}
