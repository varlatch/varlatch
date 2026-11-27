// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/identities"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/oidc/limits"
	"github.com/varlatch/varlatch/go/server/security"
)

// OIDC workload identity (capability auth.oidc; ADR-0059 step 4.8):
// listOidcBindings, createOidcBinding, revokeOidcBinding and
// exchangeOidcToken, as http/app.ts serves them. The bindings need
// identity.manage on a machine identity of the Organization (existence
// hidden); the exchange authenticates with the external token itself.

const (
	listOidcBindingsPattern  = "GET /v1/organizations/{org}/identities/{identity}/oidc-bindings"
	createOidcBindingPattern = "POST /v1/organizations/{org}/identities/{identity}/oidc-bindings"
	revokeOidcBindingPattern = "DELETE /v1/organizations/{org}/identities/{identity}/oidc-bindings/{binding}"
	exchangeOidcTokenPattern = "POST /v1/oidc/token"

	oidcBindingsRoute = "/v1/organizations/:org/identities/:identity/oidc-bindings"
)

func init() {
	for _, p := range []string{listOidcBindingsPattern, createOidcBindingPattern, revokeOidcBindingPattern, exchangeOidcTokenPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitListOidcBindingsResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitCreateOidcBindingResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitRevokeOidcBindingResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitExchangeOidcTokenResponse(w http.ResponseWriter) error { return r.visit(w) }

// The bodies' zod schemas (http/app.ts).
var (
	createOidcBindingSchema = zObject{
		{name: "issuer", schema: zString{min: 1, max: 2000}},
		{name: "audience", schema: zString{min: 1, max: 2000}},
		{name: "subject", schema: zString{min: 1, max: 2000}},
		{name: "claims", schema: zRecord{value: zString{max: 2000}}, optional: true},
		// What its exchanges are limited to (ADR-0060).
		{name: "exerciseOnly", schema: zBool{}, optional: true},
		{name: "runIdClaim", schema: zString{min: 1, max: 200}, optional: true},
		{name: "singleExchange", schema: zBool{}, optional: true},
	}
	exchangeOidcTokenSchema = zObject{
		{name: "token", schema: zString{min: 1, max: 100_000}},
		{name: "organization", schema: zString{min: 1, max: 200}},
		{name: "ttlSeconds", schema: zInt{min: 1, max: 3600}, optional: true},
	}
)

func stringMember(o jsvalue.Object, name string) string {
	v, _ := o.Get(name)
	s, _ := v.(string)
	return s
}

// ListOidcBindings is GET …/oidc-bindings: inspection while frozen,
// identity.manage, a machine identity; its live bindings.
func (o *operations) ListOidcBindings(ctx context.Context, _ api.ListOidcBindingsRequestObject) (api.ListOidcBindingsResponseObject, error) {
	q, err := o.enterRoute(ctx, oidcBindingsRoute, authz.DuringFreezeInspection)
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
	items, err := identities.ListOIDCBindings(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID, id)
	if err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: nil}}), nil
}

// CreateOidcBinding is POST …/oidc-bindings: identity.manage, a machine
// identity, the body read with c.req.json() (not JSON: 500) and its zod
// schema, then the protected operation (identities.CreateOIDCBinding),
// STEP_UP_REQUIRED when admin-step-up asks for an approval it was not
// given. 201 with the binding.
func (o *operations) CreateOidcBinding(ctx context.Context, _ api.CreateOidcBindingRequestObject) (api.CreateOidcBindingResponseObject, error) {
	q, err := o.enterRoute(ctx, oidcBindingsRoute, "")
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
	raw, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(createOidcBindingSchema, raw)
	if err != nil {
		return nil, err
	}
	body := parsed.(jsvalue.Object)
	in := identities.OIDCBindingInput{Issuer: stringMember(body, "issuer"), Audience: stringMember(body, "audience"), Subject: stringMember(body, "subject")}
	if c, ok := body.Get("claims"); ok {
		in.Claims = c.(jsvalue.Object)
		if err := limits.CheckClaims(in.Claims); err != nil {
			return nil, err
		}
	}
	var exerciseOnly bool
	var runIDClaim *string
	var singleExchange *bool
	if v, ok := body.Get("exerciseOnly"); ok {
		exerciseOnly = v.(bool)
	}
	if _, ok := body.Get("runIdClaim"); ok {
		s := stringMember(body, "runIdClaim")
		runIDClaim = &s
	}
	if v, ok := body.Get("singleExchange"); ok {
		b := v.(bool)
		singleExchange = &b
	}
	if in.Limits, err = limits.New(exerciseOnly, runIDClaim, singleExchange); err != nil {
		return nil, err
	}
	type result struct {
		out     jsvalue.Object
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := identities.CreateOIDCBinding(ctx, o.s.opts.Writer, o.s.opts.Auth, o.s.opts.Outbound, q.identitiesRequest(ctx), q.org.ID, id, in, o.s.opts.Now)
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: res.out}, nil
}

// RevokeOidcBinding is DELETE …/oidc-bindings/{binding}: recovery while
// frozen, identity.manage, a machine identity, then the protected
// operation (identities.RevokeOIDCBinding). 204.
func (o *operations) RevokeOidcBinding(ctx context.Context, _ api.RevokeOidcBindingRequestObject) (api.RevokeOidcBindingResponseObject, error) {
	q, err := o.enterRoute(ctx, oidcBindingsRoute+"/:binding", authz.DuringFreezeRecovery)
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
	binding := pathSegment(q.r, 6)
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return identities.RevokeOIDCBinding(ctx, o.s.opts.Writer, o.s.opts.Auth, q.identitiesRequest(ctx), q.org.ID, id, binding, o.s.opts.Now)
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

// ExchangeOidcToken is POST /v1/oidc/token: no bearer (the token is the
// credential), the body read with c.req.json() (not JSON: 500) and its zod
// schema, then the exchange (oidc.Service). 201 with the credential, never
// cached.
func (o *operations) ExchangeOidcToken(ctx context.Context, _ api.ExchangeOidcTokenRequestObject) (api.ExchangeOidcTokenResponseObject, error) {
	raw, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(exchangeOidcTokenSchema, raw)
	if err != nil {
		return nil, err
	}
	body := parsed.(jsvalue.Object)
	var ttl *int64
	if v, ok := body.Get("ttlSeconds"); ok {
		n := int64(v.(float64))
		ttl = &n
	}
	if o.s.oidc == nil {
		return nil, errors.New("httpserver: the OIDC exchange needs the outbound policy")
	}
	r := httpRequestOf(ctx)
	issued, err := o.s.oidc.Exchange(ctx, stringMember(body, "token"), stringMember(body, "organization"), ttl, requestIDOf(r))
	var frozen *authz.FrozenError
	if errors.As(err, &frozen) {
		// app.onError's auditFrozenRefusal: the freeze's refusal, recorded
		// once without a principal, with Retry-After.
		e := authz.FrozenRefusalEvent(nil, frozen, r.Method, "/v1/oidc/token", requestIDOf(r))
		if werr := o.s.opts.Writer.Store.Write(ctx, func(tx *storage.Tx) error { _, e := audit.Record(ctx, tx, e); return e }); werr != nil {
			o.s.opts.Log.Error("could not audit a refusal", "type", e.Type, "requestId", requestIDOf(r), "error", werr)
		}
		return nil, &headerError{err: err, headers: retryAfter(300)}
	}
	if err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return reply{status: http.StatusCreated, body: issued.JS()}, nil
}
