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
	"github.com/varlatch/varlatch/go/server/identities"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
)

// Machine identities and their credentials (ADR-0015, ADR-0023, ADR-0034;
// ADR-0059 step 4.4a): listIdentities, createServiceIdentity,
// renameIdentity, retireIdentity, reactivateIdentity,
// listIdentityCredentials, issueIdentityCredential and
// revokeIdentityCredential, as http/app.ts serves them. Listing needs
// identity.read; everything else identity.manage, but a Broker's
// agent-run credentials, which its own Organization's Agents get.

const (
	listIdentitiesPattern           = "GET /v1/organizations/{org}/identities"
	createServiceIdentityPattern    = "POST /v1/organizations/{org}/identities"
	renameIdentityPattern           = "PATCH /v1/organizations/{org}/identities/{identity}"
	retireIdentityPattern           = "POST /v1/organizations/{org}/identities/{identity}/retire"
	reactivateIdentityPattern       = "POST /v1/organizations/{org}/identities/{identity}/reactivate"
	listIdentityCredentialsPattern  = "GET /v1/organizations/{org}/identities/{identity}/credentials"
	issueIdentityCredentialPattern  = "POST /v1/organizations/{org}/identities/{identity}/credentials"
	revokeIdentityCredentialPattern = "DELETE /v1/organizations/{org}/identities/{identity}/credentials/{credential}"

	identitiesRoute          = "/v1/organizations/:org/identities"
	identityRoute            = "/v1/organizations/:org/identities/:identity"
	identityCredentialsRoute = "/v1/organizations/:org/identities/:identity/credentials"
	identityCredentialRoute  = "/v1/organizations/:org/identities/:identity/credentials/:credential"
)

func init() {
	for _, p := range []string{listIdentitiesPattern, createServiceIdentityPattern, renameIdentityPattern, retireIdentityPattern,
		reactivateIdentityPattern, listIdentityCredentialsPattern, issueIdentityCredentialPattern, revokeIdentityCredentialPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitListIdentitiesResponse(w http.ResponseWriter) error           { return r.visit(w) }
func (r reply) VisitCreateServiceIdentityResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitRenameIdentityResponse(w http.ResponseWriter) error           { return r.visit(w) }
func (r reply) VisitRetireIdentityResponse(w http.ResponseWriter) error           { return r.visit(w) }
func (r reply) VisitReactivateIdentityResponse(w http.ResponseWriter) error       { return r.visit(w) }
func (r reply) VisitListIdentityCredentialsResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitIssueIdentityCredentialResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitRevokeIdentityCredentialResponse(w http.ResponseWriter) error { return r.visit(w) }

// pathSegment is c.req.param(name) for the segment at index i of the path.
func pathSegment(r *http.Request, i int) string {
	return tryDecodeURIComponent(strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[i])
}

// approvalHeaderOf is approvalHeaderOf: the Varlatch-Approval header as
// sent, nil for none.
func approvalHeaderOf(ctx context.Context) *string {
	if raw := rawOf(ctx); raw.approvalPresent {
		h := raw.approval
		return &h
	}
	return nil
}

func intField(obj jsvalue.Object, name string) *int64 {
	if v, present := obj.Get(name); present {
		n := int64(v.(float64))
		return &n
	}
	return nil
}

func (q *orgRequest) identitiesRequest(ctx context.Context) identities.Request {
	return identities.Request{Principal: q.p, Approval: approvalHeaderOf(ctx), RequestID: requestIDOf(q.r)}
}

// written settles a request whose write job ran the checkpoint.
func (q *orgRequest) written(ctx context.Context, reports []auth.PendingReport) error {
	q.checked, q.reports, q.at = true, reports, q.o.s.opts.Now().UnixMicro()
	return q.settle(ctx)
}

// ListIdentities is GET …/identities: inspection while frozen,
// identity.read; the Organization's machines and its people, past members
// with no role.
func (o *operations) ListIdentities(ctx context.Context, _ api.ListIdentitiesRequestObject) (api.ListIdentitiesResponseObject, error) {
	q, err := o.enterRoute(ctx, identitiesRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "identity.read"); err != nil {
		return nil, err
	}
	items, err := identities.List(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: nil}}), nil
}

var serviceIdentityKinds = []string{"service", "workload", "ci", "broker", "agent"}

// CreateServiceIdentity is POST …/identities: identity.manage, the body
//
//	z.object({ name: z.string().min(1).max(200), kind: z.enum([...]),
//	  credentialTtlSeconds: z.number().int().min(1).max(315_360_000).optional(),
//	  credentialMaxUses: z.number().int().min(1).max(1_000_000).optional() })
//
// read with c.req.json() (not JSON: 500), then the protected operation
// (identities.Create), STEP_UP_REQUIRED when admin-step-up asks for an
// approval it was not given. 201 with the credential, shown once.
func (o *operations) CreateServiceIdentity(ctx context.Context, _ api.CreateServiceIdentityRequestObject) (api.CreateServiceIdentityResponseObject, error) {
	q, err := o.enterRoute(ctx, identitiesRoute, "")
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
	if err := zodIssues([]bodyField{
		{name: "name", kind: kindString, required: true, min: 1, max: 200},
		{name: "kind", kind: kindEnum, required: true, options: serviceIdentityKinds},
		{name: "credentialTtlSeconds", kind: kindInt, min: 1, max: maxTTL},
		{name: "credentialMaxUses", kind: kindInt, min: 1, max: 1_000_000},
	}, body); err != nil {
		return nil, err
	}
	obj := body.(jsvalue.Object)
	name, _ := obj.Get("name")
	kind, _ := obj.Get("kind")
	in := identities.CreateInput{Name: name.(string), Kind: kind.(string),
		CredentialTTLSeconds: intField(obj, "credentialTtlSeconds"), CredentialMaxUses: intField(obj, "credentialMaxUses")}
	type result struct {
		out     identities.Created
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := identities.Create(ctx, o.s.opts.Writer, o.s.opts.Auth, q.identitiesRequest(ctx), q.org.ID, in, o.s.opts.Now)
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: res.out.JS()}, nil
}

// loadMachine is loadMachineIdentity on the request's {identity}.
func (q *orgRequest) loadMachine(ctx context.Context) (id, kind string, disabled bool, err error) {
	id = pathSegment(q.r, 4)
	kind, disabled, err = identities.LoadMachine(ctx, q.o.s.opts.Auth.Store().Reader(), q.org.ID, id)
	return id, kind, disabled, err
}

// requireBroker is requireBroker: a Broker of this Organization, else not
// found.
func (q *orgRequest) requireBroker() error {
	p := q.p
	if p.Identity.Kind != "broker" || p.Identity.OrganizationID == nil || *p.Identity.OrganizationID != q.org.ID {
		return domainerr.New("RESOURCE_NOT_FOUND", "Not found")
	}
	return nil
}

// loadAgent is loadAgentIdentity on the request's {identity}.
func (q *orgRequest) loadAgent(ctx context.Context) (string, error) {
	id := pathSegment(q.r, 4)
	return id, identities.LoadAgent(ctx, q.o.s.opts.Auth.Store().Reader(), q.org.ID, id)
}

// IssueIdentityCredential is POST …/identities/{identity}/credentials.
// A Broker gets an agent-run credential for an enabled Agent of its own
// Organization (ADR-0023): the body z.object({ ttlSeconds:
// z.number().int().min(1).max(3600), runId: z.string().max(200).optional() }).
// Anyone else needs identity.manage and gets another service credential
// for an enabled machine identity of a service kind (every other one is not
// found): the body z.object({ name: z.string().min(1).max(200), ttlSeconds:
// ttl.optional(), maxUses: z.number().int().min(1).max(1_000_000).optional() }),
// then the protected operation (identities.Issue). Either answer is 201,
// never cached.
func (o *operations) IssueIdentityCredential(ctx context.Context, _ api.IssueIdentityCredentialRequestObject) (api.IssueIdentityCredentialResponseObject, error) {
	q, err := o.enterRoute(ctx, identityCredentialsRoute, "")
	if err != nil {
		return nil, err
	}
	if q.p.Identity.Kind != "broker" {
		return o.issueServiceCredential(ctx, q)
	}
	if err := q.requireBroker(); err != nil {
		return nil, err
	}
	agent, err := q.loadAgent(ctx)
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	if err := zodIssues([]bodyField{
		{name: "ttlSeconds", kind: kindInt, required: true, min: 1, max: 3600},
		{name: "runId", kind: kindString, min: 0, max: 200},
	}, body); err != nil {
		return nil, err
	}
	obj := body.(jsvalue.Object)
	in := identities.AgentRunInput{TTLSeconds: *intField(obj, "ttlSeconds")}
	if v, present := obj.Get("runId"); present {
		s := v.(string)
		in.RunID = &s
	}
	id, token, expires, reports, err := identities.IssueAgentRun(ctx, o.s.opts.Writer, q.p, q.org.ID, agent, in, o.s.opts.Now)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return reply{status: http.StatusCreated, body: jsvalue.Object{
		{Key: "id", Value: id}, {Key: "token", Value: token}, {Key: "expiresAt", Value: audit.ISOTime(expires)},
	}}, nil
}

func (o *operations) issueServiceCredential(ctx context.Context, q *orgRequest) (api.IssueIdentityCredentialResponseObject, error) {
	if err := q.authorize(ctx, "identity.manage"); err != nil {
		return nil, err
	}
	id, kind, disabled, err := q.loadMachine(ctx)
	if err != nil {
		return nil, err
	}
	if !containsString(identities.ServiceCredentialKinds, kind) || disabled {
		return nil, domainerr.New("RESOURCE_NOT_FOUND", "Not found")
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	if err := zodIssues([]bodyField{
		{name: "name", kind: kindString, required: true, min: 1, max: 200},
		{name: "ttlSeconds", kind: kindInt, min: 1, max: maxTTL},
		{name: "maxUses", kind: kindInt, min: 1, max: 1_000_000},
	}, body); err != nil {
		return nil, err
	}
	obj := body.(jsvalue.Object)
	name, _ := obj.Get("name")
	in := identities.IssueInput{Name: name.(string), TTLSeconds: intField(obj, "ttlSeconds"), MaxUses: intField(obj, "maxUses")}
	type result struct {
		out     identities.IssuedCredential
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := identities.Issue(ctx, o.s.opts.Writer, o.s.opts.Auth, q.identitiesRequest(ctx), q.org.ID, id, in, o.s.opts.Now)
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return reply{status: http.StatusCreated, body: res.out.JS()}, nil
}

// RevokeIdentityCredential is DELETE
// …/identities/{identity}/credentials/{credential}: recovery while frozen
// for identity.manage, which revokes a machine identity's service or oidc
// credential (ADR-0034 §1); a Broker revokes only its Agents' agent-run
// credentials, and not while the Organization is frozen. 204.
func (o *operations) RevokeIdentityCredential(ctx context.Context, _ api.RevokeIdentityCredentialRequestObject) (api.RevokeIdentityCredentialResponseObject, error) {
	q, err := o.enterRoute(ctx, identityCredentialRoute, authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	credential := pathSegment(q.r, 6)
	reader := o.s.opts.Auth.Store().Reader()
	var reports []auth.PendingReport
	if q.p.Identity.Kind == "broker" {
		if err := q.requireBroker(); err != nil {
			return nil, err
		}
		agent, err := q.loadAgent(ctx)
		if err != nil {
			return nil, err
		}
		if found, err := identities.CredentialOfKinds(ctx, reader, agent, credential, "agent-run"); err != nil || !found {
			return nil, notFoundUnless(err)
		}
		if reports, err = identities.Revoke(ctx, o.s.opts.Writer, q.p, q.org.ID, credential, false, o.s.opts.Now); err != nil {
			return nil, q.refused(ctx, err)
		}
	} else {
		if err := q.authorize(ctx, "identity.manage"); err != nil {
			return nil, err
		}
		id, _, _, err := q.loadMachine(ctx)
		if err != nil {
			return nil, err
		}
		if found, err := identities.CredentialOfKinds(ctx, reader, id, credential, "service", "oidc"); err != nil || !found {
			return nil, notFoundUnless(err)
		}
		if reports, err = identities.Revoke(ctx, o.s.opts.Writer, q.p, q.org.ID, credential, true, o.s.opts.Now); err != nil {
			return nil, q.refused(ctx, err)
		}
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

func notFoundUnless(err error) error {
	if err != nil {
		return err
	}
	return domainerr.New("RESOURCE_NOT_FOUND", "Not found")
}

// ListIdentityCredentials is GET …/identities/{identity}/credentials:
// inspection while frozen, identity.manage (revoking needs enumerating,
// ADR-0034 §2); metadata only, newest first.
func (o *operations) ListIdentityCredentials(ctx context.Context, _ api.ListIdentityCredentialsRequestObject) (api.ListIdentityCredentialsResponseObject, error) {
	q, err := o.enterRoute(ctx, identityCredentialsRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "identity.manage"); err != nil {
		return nil, err
	}
	id, _, _, err := q.loadMachine(ctx)
	if err != nil {
		return nil, err
	}
	items, err := identities.Credentials(ctx, o.s.opts.Auth.Store().Reader(), id)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: nil}}), nil
}

// RetireIdentity is POST …/identities/{identity}/retire: recovery while
// frozen, identity.manage; disabled, every live credential revoked.
func (o *operations) RetireIdentity(ctx context.Context, _ api.RetireIdentityRequestObject) (api.RetireIdentityResponseObject, error) {
	q, err := o.enterRoute(ctx, identityRoute+"/retire", authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "identity.manage"); err != nil {
		return nil, err
	}
	id, _, _, err := q.loadMachine(ctx)
	if err != nil {
		return nil, err
	}
	reports, err := identities.Retire(ctx, o.s.opts.Writer, q.p, q.org.ID, id, o.s.opts.Now)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "id", Value: id}, {Key: "disabled", Value: true}}), nil
}

// ReactivateIdentity is POST …/identities/{identity}/reactivate:
// identity.manage, then the protected operation (identities.Reactivate).
func (o *operations) ReactivateIdentity(ctx context.Context, _ api.ReactivateIdentityRequestObject) (api.ReactivateIdentityResponseObject, error) {
	q, err := o.enterRoute(ctx, identityRoute+"/reactivate", "")
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "identity.manage"); err != nil {
		return nil, err
	}
	id, _, _, err := q.loadMachine(ctx)
	if err != nil {
		return nil, err
	}
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return identities.Reactivate(ctx, o.s.opts.Writer, o.s.opts.Auth, q.identitiesRequest(ctx), q.org.ID, id, o.s.opts.Now)
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "id", Value: id}, {Key: "disabled", Value: false}}), nil
}

// RenameIdentity is PATCH …/identities/{identity}: identity.manage, the
// body z.object({ name: z.string().min(1).max(200) }), the display name
// only.
func (o *operations) RenameIdentity(ctx context.Context, _ api.RenameIdentityRequestObject) (api.RenameIdentityResponseObject, error) {
	q, err := o.enterRoute(ctx, identityRoute, "")
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "identity.manage"); err != nil {
		return nil, err
	}
	id, _, _, err := q.loadMachine(ctx)
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	if err := zodIssues([]bodyField{{name: "name", kind: kindString, required: true, min: 1, max: 200}}, body); err != nil {
		return nil, err
	}
	name, _ := body.(jsvalue.Object).Get("name")
	reports, err := identities.Rename(ctx, o.s.opts.Writer, q.p, q.org.ID, id, name.(string))
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "id", Value: id}, {Key: "name", Value: name}}), nil
}
