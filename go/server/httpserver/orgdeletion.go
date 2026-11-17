// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/http"
	"strings"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgdeletion"
	"github.com/varlatch/varlatch/go/server/security"
)

// Organization deletion (ADR-0051, capability organizations.delete;
// ADR-0059 step 4.12b), as http/app.ts serves it: the request's lifecycle
// (getOrganizationDeletion, scheduleOrganizationDeletion,
// approveOrganizationDeletion, cancelOrganizationDeletion), each behind
// organization.read with the checks (a live built-in admin, the second
// admin, the freeze) inside its job; and the audit-access tombstone
// (ADR-0051 Decision 8): a deleted Organization's audit log for its
// readers (listDeletedOrganizationAuditEvents,
// exportDeletedOrganizationAuditEvents), and the Installation Admin's view
// of the tombstones and their readers (listDeletedOrganizations,
// removeDeletedOrganizationReader).

const (
	getOrganizationDeletionPattern      = "GET /v1/organizations/{org}/deletion"
	scheduleOrganizationDeletionPattern = "POST /v1/organizations/{org}/deletion"
	approveOrganizationDeletionPattern  = "POST /v1/organizations/{org}/deletion/{deletion}/approve"
	cancelOrganizationDeletionPattern   = "POST /v1/organizations/{org}/deletion/{deletion}/cancel"
	deletedAuditEventsPattern           = "GET /v1/deleted-organizations/{organization}/audit-events"
	deletedAuditExportPattern           = "GET /v1/deleted-organizations/{organization}/audit-events/export"
	listDeletedOrganizationsPattern     = "GET /v1/installation/deleted-organizations"
	removeDeletedReaderPattern          = "DELETE /v1/installation/deleted-organizations/{organization}/readers/{identity}"
	deletionRoute                       = "/v1/organizations/:org/deletion"
	approveDeletionRoute                = "/v1/organizations/:org/deletion/:deletion/approve"
	cancelDeletionRoute                 = "/v1/organizations/:org/deletion/:deletion/cancel"
)

func init() {
	for _, p := range []string{getOrganizationDeletionPattern, scheduleOrganizationDeletionPattern, approveOrganizationDeletionPattern,
		cancelOrganizationDeletionPattern, deletedAuditEventsPattern, deletedAuditExportPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitGetOrganizationDeletionResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitScheduleOrganizationDeletionResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitApproveOrganizationDeletionResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitCancelOrganizationDeletionResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitListDeletedOrganizationAuditEventsResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitListDeletedOrganizationsResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitRemoveDeletedOrganizationReaderResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r ndjsonReply) VisitExportDeletedOrganizationAuditEventsResponse(w http.ResponseWriter) error {
	return r.VisitExportAuditEventsResponse(w)
}

// GetOrganizationDeletion is GET …/deletion: inspection, organization.read;
// {deletion}, the open request or null.
func (o *operations) GetOrganizationDeletion(ctx context.Context, _ api.GetOrganizationDeletionRequestObject) (api.GetOrganizationDeletionResponseObject, error) {
	q, err := o.enterRoute(ctx, deletionRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.read"); err != nil {
		return nil, err
	}
	view, err := orgdeletion.Get(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	var deletion any
	if view != nil {
		deletion = view
	}
	return ok(jsvalue.Object{{Key: "deletion", Value: deletion}}), nil
}

// scheduleBody is z.object({ afterDays:
// z.number().int().min(1).max(30).optional() }).strict().
var scheduleBody = zStrict{{name: "afterDays", schema: zNumber{min: bound(1), max: bound(30)}, optional: true}}

// ScheduleOrganizationDeletion is POST …/deletion: organization.read, the
// body (c.req.json(), which throws on a body that is not JSON), then, under
// admin-step-up's organization.delete, the requester's approval of exactly
// this waiting period (withApproval). 201 with the request.
func (o *operations) ScheduleOrganizationDeletion(ctx context.Context, _ api.ScheduleOrganizationDeletionRequestObject) (api.ScheduleOrganizationDeletionResponseObject, error) {
	q, err := o.enterRoute(ctx, deletionRoute, "")
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
	parsed, err := zParse(scheduleBody, body)
	if err != nil {
		return nil, err
	}
	in := orgdeletion.ScheduleRequest{Security: security.Request{Principal: q.p, Approvals: o.s.opts.Auth}}
	if v, has := parsed.(jsvalue.Object).Get("afterDays"); has {
		days := int64(v.(float64))
		in.AfterDays = &days
	}
	if raw := rawOf(ctx); raw.approvalPresent {
		if in.Security.ApprovalID = auth.ParseApprovalID(raw.approval); in.Security.ApprovalID == "" {
			in.Security.ApprovalMalformed = true
		}
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (orgdeletion.Scheduled, error) {
		return orgdeletion.Schedule(ctx, o.s.opts.Writer, in, q.org.ID, o.s.opts.Now)
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	q.checked, q.reports, q.at = true, res.Reports, o.s.opts.Now().UnixMicro()
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: res.View}, nil
}

// ApproveOrganizationDeletion is POST …/deletion/{deletion}/approve:
// organization.read, then the approval in its job.
func (o *operations) ApproveOrganizationDeletion(ctx context.Context, _ api.ApproveOrganizationDeletionRequestObject) (api.ApproveOrganizationDeletionResponseObject, error) {
	q, err := o.enterRoute(ctx, approveDeletionRoute, "")
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.read"); err != nil {
		return nil, err
	}
	out, reports, err := orgdeletion.Approve(ctx, o.s.opts.Writer, q.p, q.org.ID, pathSegment(q.r, 4), o.s.opts.Now)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	q.checked, q.reports, q.at = true, reports, o.s.opts.Now().UnixMicro()
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(out), nil
}

// CancelOrganizationDeletion is POST …/deletion/{deletion}/cancel:
// recovery (it runs while frozen for an incident), organization.read,
// then the cancellation in its job.
func (o *operations) CancelOrganizationDeletion(ctx context.Context, _ api.CancelOrganizationDeletionRequestObject) (api.CancelOrganizationDeletionResponseObject, error) {
	q, err := o.enterRoute(ctx, cancelDeletionRoute, authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.read"); err != nil {
		return nil, err
	}
	out, reports, err := orgdeletion.Cancel(ctx, o.s.opts.Writer, q.p, q.org.ID, pathSegment(q.r, 4), o.s.opts.Now)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	q.checked, q.reports, q.at = true, reports, o.s.opts.Now().UnixMicro()
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(out), nil
}

// cursorConditions is (occurred_at, id) < ($3::timestamptz, $4) for a
// decoded cursor, read by PostgreSQL with JavaScript's undefined for a
// missing part: no time matches nothing; no id leaves the time to decide.
func (o *operations) cursorConditions(decoded []string) ([]string, []any, error) {
	switch len(decoded) {
	case 0:
		return []string{"0"}, nil, nil
	case 1:
		at, err := o.cursorTime(decoded[0])
		return []string{"occurred_at < ?"}, []any{at}, err
	default:
		at, err := o.cursorTime(decoded[0])
		return []string{"(occurred_at, id) < (?, ?)"}, []any{at, decoded[1]}, err
	}
}

// ListDeletedOrganizationAuditEvents is GET /v1/deleted-organizations/
// {organization}/audit-events: a reader fixed at the deletion (anyone
// else learns nothing); a page of events, newest first, as the live log
// pages them, without filters and without the credentials.
func (o *operations) ListDeletedOrganizationAuditEvents(ctx context.Context, _ api.ListDeletedOrganizationAuditEventsRequestObject) (api.ListDeletedOrganizationAuditEventsResponseObject, error) {
	r := httpRequestOf(ctx)
	organizationID := pathSegment(r, 2)
	reader := o.s.opts.Auth.Store().Reader()
	if err := orgdeletion.RequireReader(ctx, reader, principalOf(ctx), organizationID); err != nil {
		return nil, err
	}
	raw := rawOf(ctx).query
	limit := auditLimit(raw["limit"])
	where := []string{"organization_id = ?"}
	args := []any{organizationID}
	if c, present := raw["cursor"]; present && c[0] != "" {
		decoded := decodeCursor(c[0])
		if decoded == nil {
			return nil, domainerr.New("VALIDATION_FAILED", "Invalid cursor")
		}
		conds, more, err := o.cursorConditions(decoded)
		if err != nil {
			return nil, err
		}
		where, args = append(where, conds...), append(args, more...)
	}
	args = append(args, limit+1)
	rows, err := reader.QueryContext(ctx, "SELECT "+auditEventColumns+" FROM audit_events WHERE "+strings.Join(where, " AND ")+
		" ORDER BY occurred_at DESC, id DESC LIMIT ?", args...)
	if err != nil {
		return nil, err
	}
	events, err := scanAuditEvents(rows)
	if err != nil {
		return nil, err
	}
	page := events[:min(len(events), limit)]
	var next any
	if len(events) > limit && len(page) > 0 {
		last := page[len(page)-1]
		next = encodeCursor([]string{pgTimestamptzText(last.OccurredAt), last.ID})
	}
	items := make([]any, 0, len(page))
	for _, e := range page {
		v, err := audit.Serialize(e)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return ok(jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: next}}), nil
}

// ExportDeletedOrganizationAuditEvents is GET …/audit-events/export of a
// deleted Organization: a reader fixed at the deletion; NDJSON in audit
// order up to the high-water mark when the export starts, without filters.
func (o *operations) ExportDeletedOrganizationAuditEvents(ctx context.Context, _ api.ExportDeletedOrganizationAuditEventsRequestObject) (api.ExportDeletedOrganizationAuditEventsResponseObject, error) {
	organizationID := pathSegment(httpRequestOf(ctx), 2)
	reader := o.s.opts.Auth.Store().Reader()
	if err := orgdeletion.RequireReader(ctx, reader, principalOf(ctx), organizationID); err != nil {
		return nil, err
	}
	return o.auditExportStream(ctx, organizationID, audit.Filters{})
}

// ListDeletedOrganizations is GET /v1/installation/deleted-organizations:
// Installation Admins see each tombstone and who may read it.
func (o *operations) ListDeletedOrganizations(ctx context.Context, _ api.ListDeletedOrganizationsRequestObject) (api.ListDeletedOrganizationsResponseObject, error) {
	out, err := orgdeletion.ListDeleted(ctx, o.s.opts.Auth.Store().Reader(), principalOf(ctx))
	if err != nil {
		return nil, err
	}
	return ok(out), nil
}

// RemoveDeletedOrganizationReader is DELETE …/deleted-organizations/
// {organization}/readers/{identity}: an Installation Admin removes a
// reader; 204.
func (o *operations) RemoveDeletedOrganizationReader(ctx context.Context, _ api.RemoveDeletedOrganizationReaderRequestObject) (api.RemoveDeletedOrganizationReaderResponseObject, error) {
	r := httpRequestOf(ctx)
	if err := orgdeletion.RemoveReader(ctx, o.s.opts.Writer, principalOf(ctx), pathSegment(r, 3), pathSegment(r, 5), o.s.opts.Now); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}
