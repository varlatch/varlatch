// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/oauth"
	"github.com/varlatch/varlatch/go/server/oauth/oauthparams"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// OAuth connections (ADR-0062, server/oauth), an item of an environment:
// reading one needs config.metadata.read there, anything else
// config.value.write, as writing its value would. Their tokens go to Brokers
// in an exercise (capabilities.go) and nowhere else: no answer here has a
// secret in it but the state of an authorization, which is the caller's own.

const (
	oauthBase = "/v1/organizations/{org}/projects/{project}/environments/{environment}/oauth-connections"

	listOAuthConnectionsPattern       = "GET " + oauthBase
	createOAuthConnectionPattern      = "POST " + oauthBase
	discoverOAuthProviderPattern      = "POST " + oauthBase + "/discovery"
	getOAuthConnectionPattern         = "GET " + oauthBase + "/{item}"
	updateOAuthConnectionPattern      = "PATCH " + oauthBase + "/{item}"
	startOAuthAuthorizationPattern    = "POST " + oauthBase + "/{item}/authorizations"
	completeOAuthAuthorizationPattern = "POST " + oauthBase + "/{item}/authorizations/complete"
	refreshOAuthConnectionPattern     = "POST " + oauthBase + "/{item}/refresh"
	disconnectOAuthConnectionPattern  = "POST " + oauthBase + "/{item}/disconnect"

	oauthRoute     = "/v1/organizations/:org/projects/:project/environments/:environment/oauth-connections"
	oauthItemRoute = oauthRoute + "/:item"
)

func init() {
	for _, p := range []string{listOAuthConnectionsPattern, createOAuthConnectionPattern, discoverOAuthProviderPattern, getOAuthConnectionPattern,
		updateOAuthConnectionPattern, startOAuthAuthorizationPattern, completeOAuthAuthorizationPattern, refreshOAuthConnectionPattern, disconnectOAuthConnectionPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitListOAuthConnectionsResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitCreateOAuthConnectionResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitDiscoverOAuthProviderResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitGetOAuthConnectionResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitUpdateOAuthConnectionResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitStartOAuthAuthorizationResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitCompleteOAuthAuthorizationResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitRefreshOAuthConnectionResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitDisconnectOAuthConnectionResponse(w http.ResponseWriter) error {
	return r.visit(w)
}

var (
	oauthGrant        = zEnum{oauthparams.AuthorizationCode, oauthparams.ClientCredentials}
	oauthScopesSchema = zArray{element: zString{min: 1, max: 512}, max: 100}
	oauthHostsSchema  = zArray{element: zString{min: 1}, max: 50}

	oauthProviderSchema = zObject{
		{name: "preset", schema: zEnum{"google", "microsoft", oauthparams.Generic}},
		{name: "tenant", schema: zString{min: 1, max: 100}, optional: true},
		{name: "issuer", schema: zString{min: 1, max: 2000}, optional: true},
		{name: "authorizationEndpoint", schema: zString{min: 1, max: 2000}, optional: true},
		{name: "tokenEndpoint", schema: zString{min: 1, max: 2000}, optional: true},
		{name: "revocationEndpoint", schema: zString{min: 1, max: 2000}, optional: true},
		{name: "userinfoEndpoint", schema: zString{min: 1, max: 2000}, optional: true},
		{name: "tokenEndpointAuthMethod", schema: zEnum{oauthparams.AuthBasic, oauthparams.AuthPost, oauthparams.AuthNone}, optional: true},
		{name: "authorizationParams", schema: zRecord{value: zString{max: 512}}, optional: true},
		{name: "accessTokenLifetimeSeconds", schema: zNumber{min: bound(1), max: bound(oauthparams.MaxLifetimeSeconds)}, optional: true},
		{name: "refreshTokenIdleDays", schema: zNumber{min: bound(1), max: bound(oauthparams.MaxIdleDays)}, optional: true},
	}
	oauthConnectionSchema = zObject{
		{name: "item", schema: zString{min: 1}},
		{name: "provider", schema: oauthProviderSchema},
		{name: "grant", schema: oauthGrant, optional: true},
		{name: "clientId", schema: zString{min: 1, max: 512}},
		{name: "clientSecret", schema: zString{min: 1, max: 2048}, optional: true},
		{name: "scopes", schema: oauthScopesSchema, optional: true},
		{name: "hosts", schema: oauthHostsSchema, optional: true},
	}
	oauthChangeSchema = zObject{
		{name: "provider", schema: oauthProviderSchema, optional: true},
		{name: "clientId", schema: zString{min: 1, max: 512}, optional: true},
		{name: "clientSecret", schema: zString{min: 1, max: 2048}, optional: true},
		{name: "scopes", schema: oauthScopesSchema, optional: true},
		{name: "hosts", schema: oauthHostsSchema, optional: true},
		{name: "paused", schema: zBool{}, optional: true},
		{name: "expectedVersionId", schema: zString{}, optional: true},
	}
	oauthDiscoverySchema = zObject{
		{name: "provider", schema: oauthProviderSchema},
		{name: "grant", schema: oauthGrant, optional: true},
	}
	oauthAuthorizationSchema = zObject{{name: "confirmAccountChange", schema: zBool{}, optional: true}}
	oauthAnswerSchema        = zObject{
		{name: "state", schema: zString{min: 1, max: 200}},
		{name: "redirectUri", schema: zString{min: 1, max: 2000}},
		{name: "code", schema: zString{max: 8192}, optional: true},
		{name: "error", schema: zString{max: 200}, optional: true},
		{name: "iss", schema: zString{max: 2000}, optional: true},
	}
	oauthDisconnectSchema = zObject{{name: "revokeAtProvider", schema: zBool{}, optional: true}}
)

// oauthService is the process's server/oauth.
func (o *operations) oauthService() (*oauth.Service, error) {
	if o.s.opts.OAuth == nil {
		return nil, errors.New("httpserver: no OAuth connections service")
	}
	return o.s.opts.OAuth, nil
}

// oauthBaseURL is the public URL a provider can send the browser back to.
func (o *operations) oauthBaseURL() (*url.URL, error) {
	if base := o.s.deviceBase(); base != nil {
		return base, nil
	}
	return nil, &domainerr.Error{Code: "VALIDATION_FAILED", Details: jsvalue.Object{{Key: "reason", Value: "no-public-url"}},
		Message: "Connecting an OAuth connection needs this Installation's public URL (public_url) over HTTPS, or a loopback address in local development"}
}

// oauthTarget enters the environment and authorizes action on it.
func (o *operations) oauthTarget(ctx context.Context, route, action, exception string) (*projectRequest, oauth.Request, *oauth.Service, error) {
	svc, err := o.oauthService()
	if err != nil {
		return nil, oauth.Request{}, nil, err
	}
	p, env, err := o.enterEnvironment(ctx, route, exception)
	if err != nil {
		return nil, oauth.Request{}, nil, err
	}
	if err := p.authorizeOn(ctx, action, p.envResource(env)); err != nil {
		return nil, oauth.Request{}, nil, err
	}
	return p, oauth.Request{Principal: p.p, RequestID: requestIDOf(p.r),
		Target: values.Target{OrganizationID: p.org.ID, Project: p.project, Env: env}}, svc, nil
}

func (p *projectRequest) itemSegment() string { return tryDecodeURIComponent(p.segs[8]) }

func has(o jsvalue.Object, k string) bool { _, ok := o.Get(k); return ok }

func number(o jsvalue.Object, k string) int64 {
	v, _ := o.Get(k)
	f, _ := v.(float64)
	return int64(f)
}

func boolean(o jsvalue.Object, k string) bool {
	v, _ := o.Get(k)
	b, _ := v.(bool)
	return b
}

func texts(o jsvalue.Object, k string) []string {
	v, ok := o.Get(k)
	if !ok {
		return nil
	}
	return stringArray(v)
}

func providerOf(o jsvalue.Object) oauth.Provider {
	v, _ := o.Get("provider")
	p, _ := v.(jsvalue.Object)
	out := oauth.Provider{
		Preset: str(p, "preset"), Tenant: str(p, "tenant"), Issuer: str(p, "issuer"),
		AuthorizationEndpoint: str(p, "authorizationEndpoint"), TokenEndpoint: str(p, "tokenEndpoint"),
		RevocationEndpoint: str(p, "revocationEndpoint"), UserinfoEndpoint: str(p, "userinfoEndpoint"),
		Method: str(p, "tokenEndpointAuthMethod"), Lifetime: number(p, "accessTokenLifetimeSeconds"), IdleDays: number(p, "refreshTokenIdleDays"),
	}
	if x, ok := p.Get("authorizationParams"); ok {
		for _, m := range x.(jsvalue.Object) {
			out.Params = append(out.Params, oauthparams.Param{Name: m.Key, Value: m.Value.(string)})
		}
	}
	return out
}

func grantOf(o jsvalue.Object) string {
	if g := str(o, "grant"); g != "" {
		return g
	}
	return oauthparams.AuthorizationCode
}

// oauthReply settles a write and answers it.
func (p *projectRequest) oauthReply(ctx context.Context, status int, out jsvalue.Object, reports []auth.PendingReport, err error) (reply, error) {
	if err != nil {
		return reply{}, p.refused(ctx, err)
	}
	return p.written(ctx, write.Response{Status: status, Payload: out}, reports)
}

// ListOAuthConnections is GET …/oauth-connections: inspection while frozen.
func (o *operations) ListOAuthConnections(ctx context.Context, _ api.ListOAuthConnectionsRequestObject) (api.ListOAuthConnectionsResponseObject, error) {
	p, req, svc, err := o.oauthTarget(ctx, oauthRoute, "config.metadata.read", authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	base := o.s.deviceBase()
	items, err := svc.List(ctx, o.s.opts.Auth.Store().Reader(), req.Target, base)
	if err != nil {
		return nil, err
	}
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	var redirect any
	if base != nil {
		redirect = oauth.RedirectURI(base, oauthparams.Params{})
	}
	return ok(append(list(items), jsvalue.Member{Key: "redirectBase", Value: redirect})), nil
}

// GetOAuthConnection is GET …/oauth-connections/{item}.
func (o *operations) GetOAuthConnection(ctx context.Context, _ api.GetOAuthConnectionRequestObject) (api.GetOAuthConnectionResponseObject, error) {
	p, req, svc, err := o.oauthTarget(ctx, oauthItemRoute, "config.metadata.read", authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	out, err := svc.Get(ctx, o.s.opts.Auth.Store().Reader(), req.Target, p.itemSegment(), o.s.deviceBase())
	if err != nil {
		return nil, err
	}
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	return ok(out), nil
}

// CreateOAuthConnection is POST …/oauth-connections. 201.
func (o *operations) CreateOAuthConnection(ctx context.Context, _ api.CreateOAuthConnectionRequestObject) (api.CreateOAuthConnectionResponseObject, error) {
	p, req, svc, err := o.oauthTarget(ctx, oauthRoute, "config.value.write", "")
	if err != nil {
		return nil, err
	}
	body, err := parsedBody(ctx, oauthConnectionSchema)
	if err != nil {
		return nil, err
	}
	out, reports, err := svc.Create(ctx, req, oauth.Input{
		Item: str(body, "item"), Provider: providerOf(body), Grant: grantOf(body), ClientID: str(body, "clientId"), ClientSecret: str(body, "clientSecret"),
		Scopes: texts(body, "scopes"), Hosts: texts(body, "hosts"),
	}, o.s.deviceBase())
	return p.oauthReply(ctx, http.StatusCreated, out, reports, err)
}

// DiscoverOAuthProvider is POST …/oauth-connections/discovery.
func (o *operations) DiscoverOAuthProvider(ctx context.Context, _ api.DiscoverOAuthProviderRequestObject) (api.DiscoverOAuthProviderResponseObject, error) {
	p, req, svc, err := o.oauthTarget(ctx, oauthRoute+"/discovery", "config.value.write", "")
	if err != nil {
		return nil, err
	}
	body, err := parsedBody(ctx, oauthDiscoverySchema)
	if err != nil {
		return nil, err
	}
	in := providerOf(body)
	found, err := svc.Resolve(ctx, req, in, grantOf(body), nil, in.Method != oauthparams.AuthNone)
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	out := jsvalue.Object{{Key: "provider", Value: found.JS()}}
	if base := o.s.deviceBase(); base != nil && found.Grant == oauthparams.AuthorizationCode {
		out = append(out, jsvalue.Member{Key: "redirectUri", Value: oauth.RedirectURI(base, found)})
	}
	return ok(out), nil
}

// UpdateOAuthConnection is PATCH …/oauth-connections/{item}.
func (o *operations) UpdateOAuthConnection(ctx context.Context, _ api.UpdateOAuthConnectionRequestObject) (api.UpdateOAuthConnectionResponseObject, error) {
	p, req, svc, err := o.oauthTarget(ctx, oauthItemRoute, "config.value.write", "")
	if err != nil {
		return nil, err
	}
	body, err := parsedBody(ctx, oauthChangeSchema)
	if err != nil {
		return nil, err
	}
	in := oauth.Change{}
	if has(body, "provider") {
		x := providerOf(body)
		in.Provider = &x
	}
	for k, to := range map[string]**string{"clientId": &in.ClientID, "clientSecret": &in.ClientSecret, "expectedVersionId": &in.ExpectedVersionID} {
		if has(body, k) {
			x := str(body, k)
			*to = &x
		}
	}
	for k, to := range map[string]**[]string{"scopes": &in.Scopes, "hosts": &in.Hosts} {
		if has(body, k) {
			x := texts(body, k)
			*to = &x
		}
	}
	if has(body, "paused") {
		x := boolean(body, "paused")
		in.Paused = &x
	}
	out, reports, err := svc.Update(ctx, req, p.itemSegment(), in, o.s.deviceBase())
	return p.oauthReply(ctx, http.StatusOK, out, reports, err)
}

// optionalBody is a body that may be left out.
func optionalBody(ctx context.Context, schema zSchema) (jsvalue.Object, error) {
	if len(rawOf(ctx).body) == 0 {
		return jsvalue.Object{}, nil
	}
	return parsedBody(ctx, schema)
}

// StartOAuthAuthorization is POST …/{item}/authorizations: 201, never cached.
func (o *operations) StartOAuthAuthorization(ctx context.Context, _ api.StartOAuthAuthorizationRequestObject) (api.StartOAuthAuthorizationResponseObject, error) {
	p, req, svc, err := o.oauthTarget(ctx, oauthItemRoute+"/authorizations", "config.value.write", "")
	if err != nil {
		return nil, err
	}
	body, err := optionalBody(ctx, oauthAuthorizationSchema)
	if err != nil {
		return nil, err
	}
	base, err := o.oauthBaseURL()
	if err != nil {
		return nil, err
	}
	out, reports, err := svc.Start(ctx, req, p.itemSegment(), boolean(body, "confirmAccountChange"), base)
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return p.oauthReply(ctx, http.StatusCreated, out, reports, err)
}

// CompleteOAuthAuthorization is POST …/{item}/authorizations/complete.
func (o *operations) CompleteOAuthAuthorization(ctx context.Context, _ api.CompleteOAuthAuthorizationRequestObject) (api.CompleteOAuthAuthorizationResponseObject, error) {
	p, req, svc, err := o.oauthTarget(ctx, oauthItemRoute+"/authorizations/complete", "config.value.write", "")
	if err != nil {
		return nil, err
	}
	body, err := parsedBody(ctx, oauthAnswerSchema)
	if err != nil {
		return nil, err
	}
	out, reports, err := svc.Complete(ctx, req, p.itemSegment(), oauth.Answer{State: str(body, "state"), Code: str(body, "code"),
		Error: str(body, "error"), Issuer: str(body, "iss"), RedirectURI: str(body, "redirectUri")}, o.s.deviceBase())
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return p.oauthReply(ctx, http.StatusOK, out, reports, err)
}

// RefreshOAuthConnection is POST …/{item}/refresh.
func (o *operations) RefreshOAuthConnection(ctx context.Context, _ api.RefreshOAuthConnectionRequestObject) (api.RefreshOAuthConnectionResponseObject, error) {
	p, req, svc, err := o.oauthTarget(ctx, oauthItemRoute+"/refresh", "config.value.write", "")
	if err != nil {
		return nil, err
	}
	// The checkpoint first: a refresh uses up what it uses.
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	out, err := svc.RefreshNow(ctx, req, p.itemSegment(), o.s.deviceBase())
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	return ok(out), nil
}

// DisconnectOAuthConnection is POST …/{item}/disconnect: recovery while
// frozen.
func (o *operations) DisconnectOAuthConnection(ctx context.Context, _ api.DisconnectOAuthConnectionRequestObject) (api.DisconnectOAuthConnectionResponseObject, error) {
	p, req, svc, err := o.oauthTarget(ctx, oauthItemRoute+"/disconnect", "config.value.write", authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	body, err := optionalBody(ctx, oauthDisconnectSchema)
	if err != nil {
		return nil, err
	}
	out, reports, err := svc.Disconnect(ctx, req, p.itemSegment(), !has(body, "revokeAtProvider") || boolean(body, "revokeAtProvider"), o.s.deviceBase())
	return p.oauthReply(ctx, http.StatusOK, out, reports, err)
}
