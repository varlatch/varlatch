// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/http"
	"slices"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/syncs"
)

// Platform Connections (ADR-0031 §1-2; ADR-0059 step 4.9b), as http/app.ts
// serves them: every operation needs config.sync.manage on the
// Organization, with existence hidden. Listing is inspection while frozen
// and revoking a recovery operation; the writes are protected operations
// and the check and the listing external effects (server/syncs). The
// writes, the check and the listing need the installation's sync switch
// on.

const (
	listConnectionsPattern   = "GET /v1/organizations/{org}/platform-connections"
	createConnectionPattern  = "POST /v1/organizations/{org}/platform-connections"
	checkPlatformPattern     = "POST /v1/organizations/{org}/platform-connections/check"
	listDestinationsPattern  = "POST /v1/organizations/{org}/platform-connections/destinations"
	getConnectionPattern     = "GET /v1/organizations/{org}/platform-connections/{connection}"
	replaceCredentialPattern = "POST /v1/organizations/{org}/platform-connections/{connection}/credential"
	revokeConnectionPattern  = "DELETE /v1/organizations/{org}/platform-connections/{connection}"
	connectionsRoute         = "/v1/organizations/:org/platform-connections"
)

func init() {
	for _, p := range []string{listConnectionsPattern, createConnectionPattern, checkPlatformPattern, listDestinationsPattern,
		getConnectionPattern, replaceCredentialPattern, revokeConnectionPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitListPlatformConnectionsResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitCreatePlatformConnectionResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitCheckPlatformAccessResponse(w http.ResponseWriter) error      { return r.visit(w) }
func (r reply) VisitListPlatformDestinationsResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitGetPlatformConnectionResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitReplacePlatformCredentialResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitRevokePlatformConnectionResponse(w http.ResponseWriter) error { return r.visit(w) }

// syncService is the operations' server/syncs, on this server's writer,
// approvals, Root KEK, outbound policy and allowed adapters.
func (o *operations) syncService() *syncs.Service {
	s := &syncs.Service{Writer: o.s.opts.Writer, Approvals: o.s.opts.Auth, RootKEK: o.s.opts.RootKEK, Policy: o.policy(),
		Adapters: o.s.opts.SyncAdapters, Now: o.clock(), Log: o.s.opts.Log}
	if o.s.opts.SyncClient != nil {
		syncs.UseClient(s, o.s.opts.SyncClient)
	}
	return s
}

func (q *orgRequest) syncRequest(ctx context.Context) syncs.Request {
	return syncs.Request{Principal: q.p, Approval: approvalHeaderOf(ctx), RequestID: requestIDOf(q.r)}
}

// assertSyncEnabled refuses the writes, the check and the listing while
// the installation's sync switch is off (sync = off).
func (o *operations) assertSyncEnabled() error {
	if !o.s.opts.Sync {
		return domainerr.New("PERMISSION_DENIED", "Outbound sync is disabled on this Installation; use the CLI mode (varlatch sync push)")
	}
	return nil
}

// syncManage enters the route under exception and authorizes
// config.sync.manage, existence hidden.
func (o *operations) syncManage(ctx context.Context, route, exception string) (*orgRequest, error) {
	q, err := o.enterRoute(ctx, route, exception)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "config.sync.manage"); err != nil {
		return nil, err
	}
	return q, nil
}

var (
	appConnectionBody = zObject{
		{name: "credentialKind", schema: zLiteral("github-app")},
		{name: "installationId", schema: zNumber{gt0: true, max: bound(maxSafeInt)}},
		{name: "name", schema: zString{min: 1, max: 200}},
	}
	tokenConnectionBody = zObject{
		{name: "platform", schema: zString{min: 1, max: 50}},
		{name: "baseIdentity", schema: zString{min: 1, max: 500}},
		{name: "name", schema: zString{min: 1, max: 200}},
		{name: "credential", schema: zString{min: 1, max: 10_000}},
		{name: "credentialKind", schema: zLiteral("token"), optional: true},
	}
	credentialFields = zObject{
		{name: "connectionId", schema: zString{min: 1}, optional: true},
		{name: "platform", schema: zString{min: 1, max: 50}, optional: true},
		{name: "baseIdentity", schema: zString{min: 1, max: 500}, optional: true},
		{name: "credential", schema: zString{min: 1, max: 10_000}, optional: true},
	}
	checkBody       = append(slices.Clone(credentialFields), zField{name: "destination", schema: zRecord{value: zUnknown{}}, optional: true})
	replaceCredBody = zObject{
		{name: "credential", schema: zString{min: 1, max: 10_000}},
		{name: "expectedVersion", schema: zInt{min: 1}},
	}
)

// zUnknown is z.unknown().
type zUnknown struct{}

func (zUnknown) parse(v any, _ bool, _ []string) (any, []zIssue) { return v, nil }

// ListPlatformConnections is GET …/platform-connections: inspection while
// frozen.
func (o *operations) ListPlatformConnections(ctx context.Context, _ api.ListPlatformConnectionsRequestObject) (api.ListPlatformConnectionsResponseObject, error) {
	q, err := o.syncManage(ctx, connectionsRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	items, err := syncs.List(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return listed(items), nil
}

// CreatePlatformConnection is POST …/platform-connections: a token
// Connection, or one on an installation of the Organization's GitHub App
// (ADR-0047 Decision 2; step 4.10). 201, never cached.
func (o *operations) CreatePlatformConnection(ctx context.Context, _ api.CreatePlatformConnectionRequestObject) (api.CreatePlatformConnectionResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	q, err := o.syncManage(ctx, connectionsRoute, "")
	if err != nil {
		return nil, err
	}
	raw, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	if obj, isObject := raw.(jsvalue.Object); isObject {
		if kind, _ := obj.Get("credentialKind"); kind == "github-app" {
			parsed, err := zParse(appConnectionBody, raw)
			if err != nil {
				return nil, err
			}
			body := parsed.(jsvalue.Object)
			installation, _ := body.Get("installationId")
			name, _ := body.Get("name")
			in := syncs.AppInput{InstallationID: int64(installation.(float64)), Name: name.(string)}
			// Under enforce, GitHub is asked for the installation only after
			// the precheck found an approved intent (amendment D).
			return o.createdConnection(ctx, q, func() (syncs.Connection, []auth.PendingReport, error) {
				return o.syncService().CreateApp(ctx, q.syncRequest(ctx), q.org, in)
			})
		}
	}
	parsed, err := zParse(tokenConnectionBody, raw)
	if err != nil {
		return nil, err
	}
	body := parsed.(jsvalue.Object)
	str := func(k string) string { v, _ := body.Get(k); s, _ := v.(string); return s }
	if a := o.s.opts.SyncAdapters; a != nil && !slices.Contains(a, str("platform")) {
		return nil, domainerr.New("VALIDATION_FAILED", "This Installation does not allow the requested platform adapter")
	}
	in := syncs.CreateInput{Platform: str("platform"), BaseIdentity: str("baseIdentity"), Name: str("name"), Credential: str("credential")}
	return o.createdConnection(ctx, q, func() (syncs.Connection, []auth.PendingReport, error) {
		return o.syncService().Create(ctx, q.syncRequest(ctx), q.org, in)
	})
}

// createdConnection runs a Connection's creation behind its approval: 201
// with the Connection, never cached.
func (o *operations) createdConnection(ctx context.Context, q *orgRequest, create func() (syncs.Connection, []auth.PendingReport, error)) (api.CreatePlatformConnectionResponseObject, error) {
	type result struct {
		c       syncs.Connection
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		c, reports, err := create()
		return result{c, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return reply{status: http.StatusCreated, body: res.c.JS()}, nil
}

// credentialInput is credentialInput: a Connection's stored credential (or
// a replacement for it), or a new one.
func credentialInput(body jsvalue.Object) (syncs.CredentialInput, error) {
	str := func(k string) *string { return optionalString(body, k) }
	connectionID, platform, baseIdentity, credential := str("connectionId"), str("platform"), str("baseIdentity"), str("credential")
	if connectionID != nil {
		if platform != nil || baseIdentity != nil {
			return syncs.CredentialInput{}, domainerr.New("VALIDATION_FAILED", "Name a Connection, or a platform and base identity, not both")
		}
		return syncs.CredentialInput{ConnectionID: *connectionID, Credential: credential}, nil
	}
	if platform != nil && baseIdentity != nil && credential != nil {
		return syncs.CredentialInput{Platform: *platform, BaseIdentity: *baseIdentity, Credential: credential}, nil
	}
	return syncs.CredentialInput{}, domainerr.New("VALIDATION_FAILED", "Name a Connection, or a platform, base identity and credential")
}

// CheckPlatformAccess is POST …/platform-connections/check: a read-only
// access check (ADR-0031, amendment 2026-10-09), never cached.
func (o *operations) CheckPlatformAccess(ctx context.Context, _ api.CheckPlatformAccessRequestObject) (api.CheckPlatformAccessResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	q, err := o.syncManage(ctx, connectionsRoute+"/check", "")
	if err != nil {
		return nil, err
	}
	raw, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(checkBody, raw)
	if err != nil {
		return nil, err
	}
	body := parsed.(jsvalue.Object)
	in, err := credentialInput(body)
	if err != nil {
		return nil, err
	}
	var destination jsvalue.Object
	if d, has := body.Get("destination"); has {
		destination, _ = d.(jsvalue.Object)
	}
	result, reports, err := o.syncService().Check(ctx, q.syncRequest(ctx), q.org, in, destination)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return ok(result), nil
}

// ListPlatformDestinations is POST …/platform-connections/destinations:
// what a credential can see, for the dashboard's pickers, never cached.
func (o *operations) ListPlatformDestinations(ctx context.Context, _ api.ListPlatformDestinationsRequestObject) (api.ListPlatformDestinationsResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	q, err := o.syncManage(ctx, connectionsRoute+"/destinations", "")
	if err != nil {
		return nil, err
	}
	raw, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(credentialFields, raw)
	if err != nil {
		return nil, err
	}
	in, err := credentialInput(parsed.(jsvalue.Object))
	if err != nil {
		return nil, err
	}
	result, reports, err := o.syncService().Destinations(ctx, q.syncRequest(ctx), q.org, in)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return ok(result), nil
}

// GetPlatformConnection is GET …/platform-connections/{connection}: the
// Connection and every Target it feeds.
func (o *operations) GetPlatformConnection(ctx context.Context, _ api.GetPlatformConnectionRequestObject) (api.GetPlatformConnectionResponseObject, error) {
	q, err := o.syncManage(ctx, connectionsRoute+"/:connection", "")
	if err != nil {
		return nil, err
	}
	out, err := syncs.GetWithTargets(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID, pathSegment(q.r, 4), o.s.opts.Now().UnixMicro())
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(out), nil
}

// ReplacePlatformCredential is POST …/{connection}/credential: a new
// disclosure grant for every Target of the Connection at once, each
// Target's write-time disclosure gate passing for this requester.
func (o *operations) ReplacePlatformCredential(ctx context.Context, _ api.ReplacePlatformCredentialRequestObject) (api.ReplacePlatformCredentialResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	q, err := o.syncManage(ctx, connectionsRoute+"/:connection/credential", "")
	if err != nil {
		return nil, err
	}
	raw, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(replaceCredBody, raw)
	if err != nil {
		return nil, err
	}
	body := parsed.(jsvalue.Object)
	credential, _ := body.Get("credential")
	version, _ := body.Get("expectedVersion")
	in := syncs.ReplaceInput{Credential: credential.(string), ExpectedVersion: int64(version.(float64))}
	gate := syncs.DisclosureGate(q.p, q.org.ID, requestIDOf(q.r),
		"Replacing this credential re-authorizes every referencing Sync Target; you lack disclosure authority for at least one")
	type result struct {
		c       syncs.Connection
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		c, reports, err := o.syncService().ReplaceCredential(ctx, q.syncRequest(ctx), q.org, pathSegment(q.r, 4), in, gate)
		return result{c, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return ok(res.c.JS()), nil
}

// RevokePlatformConnection is DELETE …/{connection}: a recovery operation
// during an incident freeze, where its approval may still be asked for.
func (o *operations) RevokePlatformConnection(ctx context.Context, _ api.RevokePlatformConnectionRequestObject) (api.RevokePlatformConnectionResponseObject, error) {
	q, err := o.syncManage(ctx, connectionsRoute+"/:connection", authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return o.syncService().Revoke(ctx, q.syncRequest(ctx), q.org.ID, pathSegment(q.r, 4))
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}
