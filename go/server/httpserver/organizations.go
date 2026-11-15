// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgs"
)

// Organizations (ADR-0059 step 4.1a): createOrganization,
// getOrganization and renameOrganization, as http/app.ts serves them, on
// the write path of go/server/write. Their bodies are read as the
// TypeScript routes read them, with c.req.json() and no fallback: a body
// that is not JSON throws there, and the onError handler answers 500
// INTERNAL (a wire quirk kept, step 4 decision 5).

const (
	createOrganizationPattern = "POST /v1/organizations"
	getOrganizationPattern    = "GET /v1/organizations/{org}"
	renameOrganizationPattern = "PATCH /v1/organizations/{org}"
	organizationRoute         = "/v1/organizations/:org"
)

func init() {
	for _, p := range []string{createOrganizationPattern, getOrganizationPattern, renameOrganizationPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitCreateOrganizationResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitGetOrganizationResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitRenameOrganizationResponse(w http.ResponseWriter) error { return r.visit(w) }

// orgRequest is a request inside one Organization, with what the
// TypeScript server keeps on the request's context for it
// (http/organization.ts, requestaccess.ts): the first action it was
// authorized for, whether its passkey-verification checkpoint ran, and the
// report counts to record once it succeeds.
type orgRequest struct {
	o *operations
	r *http.Request
	p *auth.Principal
	// route is the route as Hono names it, for an incident freeze's refusal.
	route string
	org   authz.Organization
	// action and resource are the first action the request was authorized
	// for (AUTHORIZED_ACTION, AUTHORIZED_RESOURCE).
	action   string
	resource authz.Resource
	checked  bool
	reports  []auth.PendingReport
	at       int64
}

func authzPrincipal(p *auth.Principal) authz.Principal {
	out := authz.Principal{IdentityID: p.Identity.ID, IdentityKind: p.Identity.Kind, CredentialID: p.Credential.ID}
	if p.Identity.OrganizationID != nil {
		out.OrganizationID = *p.Identity.OrganizationID
	}
	return out
}

// enter is resolveOrganization: the route's Organization (slug or id,
// decoded as Hono decodes it) must be live, then the incident freeze at
// entry unless the route names its exception.
func (o *operations) enter(ctx context.Context, exception string) (*orgRequest, error) {
	return o.enterRoute(ctx, organizationRoute, exception)
}

// enterRoute is enter for a route under an Organization's path.
func (o *operations) enterRoute(ctx context.Context, route, exception string) (*orgRequest, error) {
	r := httpRequestOf(ctx)
	q := &orgRequest{o: o, r: r, p: principalOf(ctx), route: route}
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	ap := authzPrincipal(q.p)
	org, err := authz.EnterOrganization(ctx, o.s.opts.Auth.Store().Reader(), tryDecodeURIComponent(segs[2]), &ap, exception)
	q.org = org
	if err != nil {
		return q, q.refused(ctx, err)
	}
	return q, nil
}

// authorize is authorize (http/support.ts): a denial is recorded, in a
// write job of its own, and answered.
func (q *orgRequest) authorize(ctx context.Context, action string) error {
	return q.authorizeOn(ctx, action, authz.Resource{OrganizationID: q.org.ID})
}

// authorizeOn is authorize on a resource inside the Organization.
func (q *orgRequest) authorizeOn(ctx context.Context, action string, resource authz.Resource) error {
	d, err := authz.Decide(ctx, q.o.s.opts.Auth.Store().Reader(), authzPrincipal(q.p), action, resource,
		authz.Options{HideExistence: true, RequestID: requestIDOf(q.r)})
	if err != nil {
		return err
	}
	if !d.Allowed {
		if d.DenialEvent != nil {
			if err := q.o.s.opts.Auth.Store().Write(ctx, func(tx *storage.Tx) error { return authz.RecordDenial(ctx, tx, d) }); err != nil {
				return err
			}
		}
		return d.Err
	}
	if q.action == "" {
		q.action, q.resource = action, resource
	}
	return nil
}

// refused audits a refusal the TypeScript server audits from app.onError,
// once, after the job or read that refused it: an authorization denial a
// job rolled back (auditDeferredDenial), the incident freeze
// (auditFrozenRefusal, with Retry-After) and passkey-verification
// (auditPasskeyRefusal). Best effort, as there.
func (q *orgRequest) refused(ctx context.Context, err error) error {
	q.recordDeferredDenial(ctx, err)
	var frozen *authz.FrozenError
	var verification *auth.VerificationRefusal
	var event *audit.Event
	switch {
	case errors.As(err, &frozen):
		ap := authzPrincipal(q.p)
		e := authz.FrozenRefusalEvent(&ap, frozen, q.r.Method, q.route, requestIDOf(q.r))
		event = &e
		err = &headerError{err: err, headers: retryAfter(300)}
	case errors.As(err, &verification) && !verification.SelfLockout:
		var action *string
		resource := jsvalue.Object{{Key: "projectId", Value: nil}, {Key: "environmentId", Value: nil}}
		if q.action != "" && q.resource.OrganizationID == verification.OrganizationID {
			action = &q.action
			if q.resource.ProjectID != "" {
				resource[0].Value = q.resource.ProjectID
			}
			if q.resource.Environment != nil {
				resource[1].Value = q.resource.Environment.ID
			}
		}
		org, actor, reqID := verification.OrganizationID, q.p.Identity.ID, requestIDOf(q.r)
		event = &audit.Event{
			Type: "authorization.denied", Decision: audit.Deny, ActorIdentityID: &actor, CredentialID: audit.Value(q.p.Credential.ID),
			OrganizationID: &org, Action: action, Resource: resource,
			Metadata:  jsvalue.Object{{Key: "reason", Value: "passkey_verification_required"}, {Key: "evidence", Value: verification.Reason}},
			RequestID: &reqID,
		}
	}
	if event != nil {
		if werr := q.o.s.opts.Auth.Store().Write(ctx, func(tx *storage.Tx) error { _, e := audit.Record(ctx, tx, *event); return e }); werr != nil {
			q.o.s.opts.Log.Error("could not audit a refusal", "type", event.Type, "requestId", requestIDOf(q.r), "error", werr)
		}
	}
	return err
}

// settle is settleOrganizationAccess for a request about to succeed: the
// checkpoint of an effect-free read that has not run one (read now,
// outside any job), then the report counts, under the first action the
// request was authorized for, after the response.
func (q *orgRequest) settle(ctx context.Context) error {
	if !q.checked {
		reports, err := checkpointNow(ctx, q)
		if err != nil {
			return q.refused(ctx, err)
		}
		q.reports, q.at = reports, q.o.s.opts.Now().UnixMicro()
	}
	action := q.action
	if action == "" {
		action = "organization.access"
	}
	if vs := q.o.s.opts.Values; vs != nil {
		for _, r := range q.reports {
			vs.QueueAccessCount(r, action, q.at)
		}
	}
	return nil
}

func checkpointNow(ctx context.Context, q *orgRequest) ([]auth.PendingReport, error) {
	out, err := auth.PasskeyVerification(ctx, q.o.s.opts.Auth.Store().Reader(), q.p, []string{q.org.ID})
	if err != nil {
		return nil, err
	}
	if reason, ok := out.Blocked[q.org.ID]; ok {
		return nil, auth.PasskeyVerificationRequired(q.org.ID, reason)
	}
	var reports []auth.PendingReport
	for _, r := range out.Reports {
		if r.OrganizationID == q.org.ID {
			reports = append(reports, r)
		}
	}
	return reports, nil
}

// jsonBody is c.req.json(): the body parsed as JSON.parse parses it. A body
// that is not JSON is an error the TypeScript server answers 500 INTERNAL.
func jsonBody(ctx context.Context) (any, error) {
	v, err := jsvalue.Parse(rawOf(ctx).body)
	if err != nil {
		return nil, fmt.Errorf("the request body is not JSON (c.req.json() throws): %w", err)
	}
	return v, nil
}

// zodIssues runs the fields' zod checks on a parsed body: the issues, or
// none.
func zodIssues(schema []bodyField, body any) error {
	_, issues := validateBody(schema, jsvalue.Stringify(body))
	if len(issues) > 0 {
		return domainerr.New("VALIDATION_FAILED", strings.Join(issues, "; "))
	}
	return nil
}

var noLimit = float64(1 << 53)

// CreateOrganization is POST /v1/organizations: people only; the body
// z.object({ name: z.string().min(1).max(200), slug: z.string() }).
func (o *operations) CreateOrganization(ctx context.Context, _ api.CreateOrganizationRequestObject) (api.CreateOrganizationResponseObject, error) {
	p := principalOf(ctx)
	if p.Identity.Kind != "human" {
		return nil, domainerr.New("PERMISSION_DENIED", "Only humans may create organizations")
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	if err := zodIssues([]bodyField{
		{name: "name", kind: kindString, required: true, min: 1, max: 200},
		{name: "slug", kind: kindString, required: true, min: 0, max: noLimit},
	}, body); err != nil {
		return nil, err
	}
	obj := body.(jsvalue.Object)
	name, _ := obj.Get("name")
	slug, _ := obj.Get("slug")
	org, err := orgs.Create(ctx, o.s.opts.Writer, o.s.opts.RootKEK, p.Identity.ID, slug.(string), name.(string))
	if err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: org.JS()}, nil
}

// GetOrganization is GET /v1/organizations/{org}: inspection (it runs
// while the Organization is frozen for an incident), organization.read
// with existence hidden, and the open freeze, which the dashboard reads
// here (ADR-0055 Decision 11).
func (o *operations) GetOrganization(ctx context.Context, _ api.GetOrganizationRequestObject) (api.GetOrganizationResponseObject, error) {
	q, err := o.enter(ctx, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.read"); err != nil {
		return nil, err
	}
	freeze, err := orgs.CurrentFreeze(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	org := orgs.Org{ID: q.org.ID, Slug: q.org.Slug, Name: q.org.Name, CreatedAt: q.org.CreatedAt}
	return ok(append(org.JS(), jsvalue.Member{Key: "incidentFreeze", Value: freeze})), nil
}

// RenameOrganization is PATCH /v1/organizations/{org}: the display name
// only (capability organizations.rename), organization.manage with
// existence hidden; the body z.object({ name: z.string().trim().min(1).max(200) }),
// parsed once authorization decided.
func (o *operations) RenameOrganization(ctx context.Context, _ api.RenameOrganizationRequestObject) (api.RenameOrganizationResponseObject, error) {
	q, err := o.enter(ctx, "")
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.manage"); err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	// .trim() runs before the length checks.
	if obj, isObj := body.(jsvalue.Object); isObj {
		if name, isStr := obj.Get("name"); isStr {
			if s, isStr := name.(string); isStr {
				body = obj.Set("name", whatwg.Trim(s))
			}
		}
	}
	if err := zodIssues([]bodyField{{name: "name", kind: kindString, required: true, min: 1, max: 200}}, body); err != nil {
		return nil, err
	}
	name, _ := body.(jsvalue.Object).Get("name")
	org, reports, err := orgs.Rename(ctx, o.s.opts.Writer, q.p, q.org.ID, name.(string))
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	q.checked, q.reports, q.at = true, reports, o.s.opts.Now().UnixMicro()
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(org.JS()), nil
}
