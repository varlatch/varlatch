// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/http"
	"strings"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/freeze"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/security"
)

// The incident freeze (ADR-0055; capability organizations.incident-freeze;
// ADR-0059 step 4.3c): getIncidentFreeze, freezeOrganization and
// liftIncidentFreeze, as http/app.ts serves them. Reading it is
// inspection, for every member (organization.read). Freezing needs
// organization.manage and a person's credential, no approval; lifting needs
// organization.manage, a person's credential and, always, a step-up
// approval for exactly this freeze.

const (
	getIncidentFreezePattern  = "GET /v1/organizations/{org}/incident-freeze"
	freezeOrganizationPattern = "POST /v1/organizations/{org}/incident-freeze"
	liftIncidentFreezePattern = "POST /v1/organizations/{org}/incident-freeze/{freeze}/lift"
	incidentFreezeRoute       = "/v1/organizations/:org/incident-freeze"
	liftFreezeRoute           = "/v1/organizations/:org/incident-freeze/:freeze/lift"
)

func init() {
	for _, p := range []string{getIncidentFreezePattern, freezeOrganizationPattern, liftIncidentFreezePattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitGetIncidentFreezeResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitFreezeOrganizationResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitLiftIncidentFreezeResponse(w http.ResponseWriter) error { return r.visit(w) }

// mayListTargets is decide(config.sync.manage) without recording a denial:
// whether the caller may read the Organization's Sync Targets, which the
// freeze's answers name only then.
func (q *orgRequest) mayListTargets(ctx context.Context) (bool, error) {
	d, err := authz.Decide(ctx, q.o.s.opts.Auth.Store().Reader(), authzPrincipal(q.p), "config.sync.manage",
		authz.Resource{OrganizationID: q.org.ID}, authz.Options{RequestID: requestIDOf(q.r)})
	return d.Allowed, err
}

// GetIncidentFreeze is GET …/incident-freeze: inspection, organization.read;
// the open freeze, the Sync Targets that resume when it is lifted (null for
// a caller who may not read them), and the history. Never cached.
func (o *operations) GetIncidentFreeze(ctx context.Context, _ api.GetIncidentFreezeRequestObject) (api.GetIncidentFreezeResponseObject, error) {
	q, err := o.enterRoute(ctx, incidentFreezeRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.read"); err != nil {
		return nil, err
	}
	reader := o.s.opts.Auth.Store().Reader()
	current, err := orgs.CurrentFreeze(ctx, reader, q.org.ID)
	if err != nil {
		return nil, err
	}
	may, err := q.mayListTargets(ctx)
	if err != nil {
		return nil, err
	}
	var resuming any
	if may {
		resuming = []any{}
		if current != nil {
			targets, err := freeze.ResumingTargets(ctx, reader, q.org.ID)
			if err != nil {
				return nil, err
			}
			resuming = freeze.TargetsJS(targets)
		}
	}
	history, err := freeze.History(ctx, reader, q.org.ID)
	if err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "freeze", Value: current}, {Key: "resumingTargets", Value: resuming}, {Key: "history", Value: history}}), nil
}

// FreezeOrganization is POST …/incident-freeze: the freeze exception,
// organization.manage, the body z.object({ reason: z.string().max(1000)
// }).strict(), then freeze.Freeze. 201 with the freeze.
func (o *operations) FreezeOrganization(ctx context.Context, _ api.FreezeOrganizationRequestObject) (api.FreezeOrganizationResponseObject, error) {
	q, err := o.enterRoute(ctx, incidentFreezeRoute, authz.DuringFreezeFreeze)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.manage"); err != nil {
		return nil, err
	}
	var body any = undefinedBody{}
	if v, err := jsvalue.Parse(rawOf(ctx).body); err == nil {
		body = v
	}
	reason, err := parseFreezeBody(body)
	if err != nil {
		return nil, err
	}
	out, reports, err := freeze.Freeze(ctx, o.s.opts.Writer, o.s.opts.Auth, freeze.FreezeInput{
		OrganizationID: q.org.ID, Principal: q.p, Reason: reason, RequestID: requestIDOf(q.r),
	}, o.s.opts.Now)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	q.checked, q.reports, q.at = true, reports, o.s.opts.Now().UnixMicro()
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: out}, nil
}

// parseFreezeBody is the freeze's zod schema: every issue, in zod's order.
func parseFreezeBody(body any) (string, error) {
	fail := func(issues []string) error { return domainerr.New("VALIDATION_FAILED", strings.Join(issues, "; ")) }
	obj, isObj := body.(jsvalue.Object)
	if !isObj {
		return "", fail([]string{"(root): Invalid input: expected object, received " + zodReceived(body)})
	}
	var issues []string
	var reason string
	switch v, present := obj.Get("reason"); {
	case !present:
		issues = append(issues, "reason: Invalid input: expected string, received undefined")
	default:
		s, isStr := v.(string)
		switch {
		case !isStr:
			issues = append(issues, "reason: Invalid input: expected string, received "+zodReceived(v))
		case codePoints(s) > 1000:
			issues = append(issues, "reason: Too big: expected string to have <=1000 characters")
		default:
			reason = s
		}
	}
	issues = append(issues, unrecognized("(root)", obj, "reason")...)
	if len(issues) > 0 {
		return "", fail(issues)
	}
	return reason, nil
}

// LiftIncidentFreeze is POST …/incident-freeze/{freeze}/lift: the freeze
// exception, organization.manage, whether the caller may read the Sync
// Targets, the Varlatch-Approval header (one that cannot be an approval id
// is not found), then freeze.Lift, which answers STEP_UP_REQUIRED without
// an approval.
func (o *operations) LiftIncidentFreeze(ctx context.Context, _ api.LiftIncidentFreezeRequestObject) (api.LiftIncidentFreezeResponseObject, error) {
	q, err := o.enterRoute(ctx, liftFreezeRoute, authz.DuringFreezeFreeze)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.manage"); err != nil {
		return nil, err
	}
	may, err := q.mayListTargets(ctx)
	if err != nil {
		return nil, err
	}
	in := freeze.LiftInput{OrganizationID: q.org.ID, Principal: q.p, RequestID: requestIDOf(q.r), MayListTargets: may}
	if raw := rawOf(ctx); raw.approvalPresent {
		if in.ApprovalID = auth.ParseApprovalID(raw.approval); in.ApprovalID == "" {
			return nil, auth.ApprovalInvalid("not-found", nil)
		}
	}
	segs := strings.Split(strings.TrimPrefix(q.r.URL.Path, "/"), "/")
	in.FreezeID = tryDecodeURIComponent(segs[4])
	type result struct {
		out     jsvalue.Object
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := freeze.Lift(ctx, o.s.opts.Writer, o.s.opts.Auth, in, o.s.opts.Now)
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	q.checked, q.reports, q.at = true, res.reports, o.s.opts.Now().UnixMicro()
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(res.out), nil
}
