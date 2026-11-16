// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/varlatch/varlatch/go/server/access"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// Step 4.4c: Tailnet Requirements (ADR-0014, ADR-0029, ADR-0054
// requirement-protection) and the access reports: machine reach, the
// credential review and the caller's own Organization permissions
// (ADR-0054 Decision 8; http/app.ts, domain/reach.ts,
// domain/credentialReview.ts, domain/requirementprotection.ts).

const (
	listRequirementsPattern  = "GET /v1/organizations/{org}/requirements"
	createRequirementPattern = "POST /v1/organizations/{org}/requirements"
	updateRequirementPattern = "PATCH /v1/organizations/{org}/requirements/{requirement}"
	deleteRequirementPattern = "DELETE /v1/organizations/{org}/requirements/{requirement}"
	credentialReviewPattern  = "GET /v1/organizations/{org}/security/credential-review"
	machineReachPattern      = "GET /v1/organizations/{org}/identities/{identity}/reach"
	myPermissionsPattern     = "GET /v1/organizations/{org}/me/permissions"
)

func init() {
	for _, p := range []string{
		listRequirementsPattern, createRequirementPattern, updateRequirementPattern, deleteRequirementPattern,
		credentialReviewPattern, machineReachPattern, myPermissionsPattern,
	} {
		readsItself[p] = true
	}
}

func (r reply) VisitListRequirementsResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitCreateRequirementResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitUpdateRequirementResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitDeleteRequirementResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitCredentialReviewResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitMachineReachResponse(w http.ResponseWriter) error      { return r.visit(w) }
func (r reply) VisitMyOrganizationPermissionsResponse(w http.ResponseWriter) error {
	return r.visit(w)
}

// requirementTarget is the target's schema: a tier, or Environments.
var requirementTarget = zUnion{
	zObject{{name: "kind", schema: zLiteral("tier")}, {name: "tier", schema: tiers}},
	zObject{{name: "kind", schema: zLiteral("environments")}, {name: "environmentIds", schema: zArray{element: zString{}, min: 1}}},
}

// requirementSelector is the selector's schema.
var requirementSelector = zObject{
	{name: "tailnet", schema: zString{min: 1}},
	{name: "tags", schema: zArray{element: zString{}}, optional: true},
	{name: "users", schema: zArray{element: zString{}}, optional: true},
	{name: "nodes", schema: zArray{element: zString{}}, optional: true},
}

var requirementCreateBody = zObject{
	{name: "kind", schema: zLiteral("tailnet")},
	{name: "target", schema: requirementTarget},
	{name: "selector", schema: requirementSelector},
}

var requirementUpdateBody = zObject{
	{name: "expectedVersion", schema: zInt{min: 1}},
	{name: "target", schema: requirementTarget, optional: true},
	{name: "selector", schema: requirementSelector, optional: true},
}

const requirementsRoute = "/v1/organizations/:org/requirements"

// snapshotTx is a report's one read snapshot.
type snapshotTx = sql.Tx

func objectMember(o jsvalue.Object, key string) jsvalue.Object {
	v, ok := o.Get(key)
	if !ok {
		return nil
	}
	return v.(jsvalue.Object)
}

// ListRequirements is GET …/requirements: inspection while frozen,
// policy.read; the live Requirements, oldest first.
func (o *operations) ListRequirements(ctx context.Context, _ api.ListRequirementsRequestObject) (api.ListRequirementsResponseObject, error) {
	return o.readList(ctx, requirementsRoute, func(q *orgRequest) ([]any, error) {
		return access.Requirements(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	})
}

// CreateRequirement is POST …/requirements: recovery while frozen (a new
// Requirement only restricts), policy.manage, the body, then the selector
// check. Never protected. 201.
func (o *operations) CreateRequirement(ctx context.Context, _ api.CreateRequirementRequestObject) (api.CreateRequirementResponseObject, error) {
	q, err := o.policyManage(ctx, requirementsRoute, authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(requirementCreateBody, body)
	if err != nil {
		return nil, err
	}
	obj := parsed.(jsvalue.Object)
	selector := objectMember(obj, "selector")
	if err := access.CheckSelector(selector); err != nil {
		return nil, err
	}
	out, reports, err := access.CreateRequirement(ctx, o.s.opts.Writer, q.p, q.org.ID, objectMember(obj, "target"), selector, o.s.opts.Now)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: out}, nil
}

// UpdateRequirement is PATCH …/requirements/{requirement} (ADR-0029):
// policy.manage, the body, the selector check, then the protected
// operation (requirement.update) under an Idempotency-Key. 200.
func (o *operations) UpdateRequirement(ctx context.Context, _ api.UpdateRequirementRequestObject) (api.UpdateRequirementResponseObject, error) {
	q, err := o.policyManage(ctx, requirementsRoute+"/:requirement", "")
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(requirementUpdateBody, body)
	if err != nil {
		return nil, err
	}
	obj := parsed.(jsvalue.Object)
	version, _ := obj.Get("expectedVersion")
	patch := access.RequirementPatch{ExpectedVersion: int64(version.(float64)), Target: objectMember(obj, "target"), Selector: objectMember(obj, "selector"), Body: obj}
	if patch.Selector != nil {
		if err := access.CheckSelector(patch.Selector); err != nil {
			return nil, err
		}
	}
	requirementID := pathSegment(q.r, 4)
	type result struct {
		resp    write.Response
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		resp, reports, err := access.UpdateRequirement(ctx, o.s.opts.Writer, o.s.opts.Auth, o.s.opts.RootKEK, q.accessRequest(ctx), q.org.ID, requirementID, patch, o.s.opts.Now)
		return result{resp, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	return idempotentReply(res.resp), nil
}

// DeleteRequirement is DELETE …/requirements/{requirement}: policy.manage,
// the protected operation (requirement.revoke). 204.
func (o *operations) DeleteRequirement(ctx context.Context, _ api.DeleteRequirementRequestObject) (api.DeleteRequirementResponseObject, error) {
	q, err := o.policyManage(ctx, requirementsRoute+"/:requirement", "")
	if err != nil {
		return nil, err
	}
	requirementID := pathSegment(q.r, 4)
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return access.DeleteRequirement(ctx, o.s.opts.Writer, o.s.opts.Auth, q.accessRequest(ctx), q.org.ID, requirementID, o.s.opts.Now)
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

// readReport answers a report read from one snapshot, Cache-Control:
// no-store.
func (o *operations) readReport(ctx context.Context, q *orgRequest, read func(db *snapshotTx) (jsvalue.Object, error)) (reply, error) {
	tx, err := o.s.opts.Auth.Store().Reader().BeginTx(ctx, nil)
	if err != nil {
		return reply{}, err
	}
	defer func() { _ = tx.Rollback() }()
	// Set before the read, as the route sets it: a refusal carries it too.
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	out, err := read(tx)
	if err != nil {
		return reply{}, err
	}
	if err := q.settle(ctx); err != nil {
		return reply{}, err
	}
	return ok(out), nil
}

// CredentialReview is GET …/security/credential-review: inspection while
// frozen, identity.manage.
func (o *operations) CredentialReview(ctx context.Context, _ api.CredentialReviewRequestObject) (api.CredentialReviewResponseObject, error) {
	q, err := o.enterRoute(ctx, "/v1/organizations/:org/security/credential-review", authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "identity.manage"); err != nil {
		return nil, err
	}
	return o.readReport(ctx, q, func(db *snapshotTx) (jsvalue.Object, error) {
		return access.CredentialReview(ctx, db, q.org.ID, o.s.opts.Now())
	})
}

// MachineReach is GET …/identities/{identity}/reach: inspection while
// frozen; it names the identity (identity.read) and shows its Grants and
// the Requirements covering them (policy.read), so it needs both.
func (o *operations) MachineReach(ctx context.Context, _ api.MachineReachRequestObject) (api.MachineReachResponseObject, error) {
	q, err := o.enterRoute(ctx, "/v1/organizations/:org/identities/:identity/reach", authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "identity.read"); err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "policy.read"); err != nil {
		return nil, err
	}
	identityID := pathSegment(q.r, 4)
	return o.readReport(ctx, q, func(db *snapshotTx) (jsvalue.Object, error) {
		return access.MachineReach(ctx, db, q.org.ID, identityID, o.s.opts.Now())
	})
}

// MyOrganizationPermissions is GET …/me/permissions: inspection while
// frozen, organization.read (every member holds it).
func (o *operations) MyOrganizationPermissions(ctx context.Context, _ api.MyOrganizationPermissionsRequestObject) (api.MyOrganizationPermissionsResponseObject, error) {
	q, err := o.enterRoute(ctx, "/v1/organizations/:org/me/permissions", authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.read"); err != nil {
		return nil, err
	}
	return o.readReport(ctx, q, func(db *snapshotTx) (jsvalue.Object, error) {
		return access.MyPermissions(ctx, db, q.org.ID, q.p.Identity.ID, q.p.Identity.Kind == "human")
	})
}
