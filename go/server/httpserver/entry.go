// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/totp"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/entry"
	"github.com/varlatch/varlatch/go/server/environments"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/values"
)

// Entry links (ADR-0063, server/entry): made, listed and cancelled by the
// identity that needs a value, under its environment; looked at and used by
// whoever holds one, with the link's own secret in the body and, for a link
// that is not open to anyone, a person's bearer beside it. Cookies
// authenticate neither, so another site can make a browser use neither.

const (
	entryLinksBase = "/v1/organizations/{org}/projects/{project}/environments/{environment}/entry-links"

	listEntryLinksPattern  = "GET " + entryLinksBase
	createEntryLinkPattern = "POST " + entryLinksBase
	getEntryLinkPattern    = "GET " + entryLinksBase + "/{entryLink}"
	cancelEntryLinkPattern = "DELETE " + entryLinksBase + "/{entryLink}"
	lookupEntryLinkPattern = "POST /v1/entry-links/lookup"
	submitEntryLinkPattern = "POST /v1/entry-links/submit"

	entryLinksRoute = "/v1/organizations/:org/projects/:project/environments/:environment/entry-links"
	entryLinkRoute  = entryLinksRoute + "/:entryLink"
)

// optionalBearer are the operations a bearer credential is read for when
// there is one, and none is needed.
var optionalBearer = map[string]bool{lookupEntryLinkPattern: true, submitEntryLinkPattern: true}

func init() {
	for _, p := range []string{createEntryLinkPattern, lookupEntryLinkPattern, submitEntryLinkPattern} {
		readsItself[p] = true
		noStore[p] = true
	}
}

func (r reply) VisitListEntryLinksResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitCreateEntryLinkResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitGetEntryLinkResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitCancelEntryLinkResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitLookupEntryLinkResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitSubmitEntryLinkResponse(w http.ResponseWriter) error { return r.visit(w) }

var (
	entryLinkSchema = zObject{
		{name: "item", schema: zString{min: 1, max: 200}},
		{name: "accepts", schema: zEnum{entry.Value, entry.OTPAuth}, optional: true},
		{name: "replace", schema: zBool{}, optional: true},
		{name: "restrictedTo", schema: zEnum{entry.Anyone, entry.Member, entry.Identity}, optional: true},
		{name: "identityId", schema: zString{min: 1, max: 200}, optional: true},
		{name: "description", schema: zString{max: entry.MaxDescription}, optional: true},
		{name: "ttlSeconds", schema: zNumber{min: bound(entry.MinTTLSeconds), max: bound(entry.MaxTTLSeconds)}, optional: true},
	}
	entryTokenSchema  = zObject{{name: "token", schema: zString{min: 1, max: 200}}}
	entrySubmitSchema = zObject{
		{name: "token", schema: zString{min: 1, max: 200}},
		{name: "value", schema: zString{min: 1, max: entry.MaxValue}, optional: true},
		{name: "otpauth", schema: zString{min: 1, max: 2048}, optional: true},
	}
)

// entryTarget enters the environment a link is of.
func (o *operations) entryTarget(ctx context.Context, route, exception string) (*projectRequest, entry.Request, environments.Environment, error) {
	p, env, err := o.enterEnvironment(ctx, route, exception)
	if err != nil {
		return nil, entry.Request{}, env, err
	}
	return p, entry.Request{Principal: p.p, RequestID: requestIDOf(p.r),
		Target: values.Target{OrganizationID: p.org.ID, Project: p.project, Env: env}}, env, nil
}

// entryOwner is whose links the caller sees: a machine its own, a person,
// with config.value.write, everybody's ("").
func (p *projectRequest) entryOwner(ctx context.Context, env environments.Environment) (string, error) {
	if p.p.Identity.Kind != "human" {
		return p.p.Identity.ID, nil
	}
	return "", p.authorizeOn(ctx, "config.value.write", p.envResource(env))
}

// mayMakeEntryLinks refuses, before anything of the request is judged, a
// machine that may make no link here at all, and a person who may not write.
func (p *projectRequest) mayMakeEntryLinks(ctx context.Context, env environments.Environment) error {
	if p.p.Identity.Kind != "human" {
		d, err := authz.DecideEntryLink(ctx, p.o.s.opts.Auth.Store().Reader(), authzPrincipal(p.p), true, p.envResource(env),
			authz.Options{HideExistence: true, RequestID: requestIDOf(p.r)})
		if err != nil || d.Allowed {
			return err
		}
	}
	d, err := authz.DecideEntryLink(ctx, p.o.s.opts.Auth.Store().Reader(), authzPrincipal(p.p), false, p.envResource(env),
		authz.Options{HideExistence: true, RequestID: requestIDOf(p.r)})
	if err != nil || d.Allowed {
		return err
	}
	if err := p.o.s.opts.Auth.Store().Write(ctx, func(tx *storage.Tx) error { return authz.RecordDenial(ctx, tx, d) }); err != nil {
		return err
	}
	return d.Err
}

// CreateEntryLink is POST …/entry-links. 201, never cached, under no
// Idempotency-Key: its answer holds the link's secret.
func (o *operations) CreateEntryLink(ctx context.Context, _ api.CreateEntryLinkRequestObject) (api.CreateEntryLinkResponseObject, error) {
	p, req, env, err := o.entryTarget(ctx, entryLinksRoute, "")
	if err != nil {
		return nil, err
	}
	if err := p.mayMakeEntryLinks(ctx, env); err != nil {
		return nil, err
	}
	body, err := parsedBody(ctx, entryLinkSchema)
	if err != nil {
		return nil, err
	}
	base := o.s.deviceBase()
	if base == nil {
		return nil, &domainerr.Error{Code: "VALIDATION_FAILED", Details: jsvalue.Object{{Key: "reason", Value: "no-public-url"}},
			Message: "Entry links need this Installation's public URL (public_url) over HTTPS, or a loopback address in local development"}
	}
	out, reports, err := o.s.entry.Create(ctx, req, entry.Input{
		Item: str(body, "item"), Accepts: str(body, "accepts"), Replace: boolean(body, "replace"), RestrictedTo: str(body, "restrictedTo"),
		IdentityID: str(body, "identityId"), Description: str(body, "description"), TTLSeconds: number(body, "ttlSeconds"),
	}, base)
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	p.orgRequest.action, p.orgRequest.resource = authz.EntryLinkAction(p.p.Identity.Kind, str(body, "restrictedTo") == entry.Anyone), p.envResource(env)
	if err := p.orgRequest.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: out}, nil
}

// ListEntryLinks is GET …/entry-links: inspection while frozen.
func (o *operations) ListEntryLinks(ctx context.Context, _ api.ListEntryLinksRequestObject) (api.ListEntryLinksResponseObject, error) {
	p, _, env, err := o.entryTarget(ctx, entryLinksRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	owner, err := p.entryOwner(ctx, env)
	if err != nil {
		return nil, err
	}
	out, err := o.s.entry.List(ctx, o.s.opts.Auth.Store().Reader(), env.ID, owner)
	if err != nil {
		return nil, err
	}
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	return ok(out), nil
}

// GetEntryLink is GET …/entry-links/{entryLink}: inspection while frozen.
func (o *operations) GetEntryLink(ctx context.Context, _ api.GetEntryLinkRequestObject) (api.GetEntryLinkResponseObject, error) {
	p, _, env, err := o.entryTarget(ctx, entryLinkRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	owner, err := p.entryOwner(ctx, env)
	if err != nil {
		return nil, err
	}
	out, err := o.s.entry.Get(ctx, o.s.opts.Auth.Store().Reader(), env.ID, tryDecodeURIComponent(p.segs[8]), owner)
	if err != nil {
		return nil, err
	}
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	return ok(out), nil
}

// CancelEntryLink is DELETE …/entry-links/{entryLink}: recovery while
// frozen. 204.
func (o *operations) CancelEntryLink(ctx context.Context, _ api.CancelEntryLinkRequestObject) (api.CancelEntryLinkResponseObject, error) {
	p, req, env, err := o.entryTarget(ctx, entryLinkRoute, authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	owner, err := p.entryOwner(ctx, env)
	if err != nil {
		return nil, err
	}
	reports, err := o.s.entry.Cancel(ctx, req, tryDecodeURIComponent(p.segs[8]), owner)
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	if err := p.orgRequest.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

// entryError answers a refusal, with Retry-After where it says when.
func entryError(err error) error {
	var de *domainerr.Error
	if errors.As(err, &de) {
		if after, ok := de.Details.Get("retryAfterSeconds"); ok {
			return &headerError{err: err, headers: retryAfter(after.(int64))}
		}
	}
	return err
}

// LookupEntryLink is POST /v1/entry-links/lookup: nothing is written,
// however often it is asked.
func (o *operations) LookupEntryLink(ctx context.Context, _ api.LookupEntryLinkRequestObject) (api.LookupEntryLinkResponseObject, error) {
	body, err := parsedBody(ctx, entryTokenSchema)
	if err != nil {
		return nil, err
	}
	out, err := o.s.entry.Lookup(ctx, principalOf(ctx), str(body, "token"), devicePeer(ctx))
	if err != nil {
		return nil, entryError(err)
	}
	return ok(out), nil
}

// SubmitEntryLink is POST /v1/entry-links/submit: the value, once.
func (o *operations) SubmitEntryLink(ctx context.Context, _ api.SubmitEntryLinkRequestObject) (api.SubmitEntryLinkResponseObject, error) {
	body, err := parsedBody(ctx, entrySubmitSchema)
	if err != nil {
		return nil, err
	}
	in := entry.Entered{Value: str(body, "value")}
	if len(in.Value) > entry.MaxValue {
		return nil, domainerr.New("VALIDATION_FAILED", "value: at most 65536 bytes")
	}
	switch {
	case has(body, "value") == has(body, "otpauth"):
		return nil, domainerr.New("VALIDATION_FAILED", "value: a value or the seed of a one-time code (otpauth), and not both")
	case has(body, "otpauth"):
		var seed totp.Seed
		if seed, err = values.ParseSeed(str(body, "otpauth")); err != nil {
			return nil, err
		}
		in.Seed = &seed
	}
	p := principalOf(ctx)
	reports, err := o.s.entry.Submit(ctx, p, str(body, "token"), devicePeer(ctx), requestIDOf(httpRequestOf(ctx)), in)
	if err != nil {
		return nil, entryError(err)
	}
	o.s.queueReports(reports, "config.value.write")
	return ok(jsvalue.Object{{Key: "status", Value: "entered"}}), nil
}

// queueReports counts what passkey-verification's report would have refused
// (settle's, for a request that enters no Organization by its route).
func (s *Server) queueReports(reports []auth.PendingReport, action string) {
	if s.opts.Values == nil {
		return
	}
	for _, r := range reports {
		s.opts.Values.QueueAccessCount(r, action, s.opts.Now().UnixMicro())
	}
}
