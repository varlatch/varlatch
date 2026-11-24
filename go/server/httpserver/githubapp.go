// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/githubapps"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/syncs"
)

// The Organization's GitHub App (ADR-0047; ADR-0059 step 4.10a), as
// http/app.ts serves it: getGitHubApp, startGitHubAppRegistration,
// completeGitHubAppRegistration, attachGitHubAppRegistration,
// discardGitHubAppRegistration, importGitHubApp and removeGitHubApp, each
// behind config.sync.manage on the Organization with existence hidden
// (server/githubapps). The registration's routes need the installation's
// sync switch on, the github-actions adapter allowed and, to register, a
// public URL over HTTPS or on a loopback host.

const (
	getGitHubAppPattern         = "GET /v1/organizations/{org}/github-app"
	removeGitHubAppPattern      = "DELETE /v1/organizations/{org}/github-app"
	startRegistrationPattern    = "POST /v1/organizations/{org}/github-app/registrations"
	completeRegistrationPattern = "POST /v1/organizations/{org}/github-app/registrations/complete"
	attachRegistrationPattern   = "POST /v1/organizations/{org}/github-app/registrations/{registration}/attach"
	discardRegistrationPattern  = "DELETE /v1/organizations/{org}/github-app/registrations/{registration}"
	importGitHubAppPattern      = "POST /v1/organizations/{org}/github-app/import"
	rotateGitHubAppKeyPattern   = "POST /v1/organizations/{org}/github-app/key"
	listInstallationsPattern    = "GET /v1/organizations/{org}/github-app/installations"
	githubAppRoute              = "/v1/organizations/:org/github-app"
	registrationsRoute          = "/v1/organizations/:org/github-app/registrations"
	completeRoute               = "/v1/organizations/:org/github-app/registrations/complete"
	attachRoute                 = "/v1/organizations/:org/github-app/registrations/:registration/attach"
	registrationRoute           = "/v1/organizations/:org/github-app/registrations/:registration"
	importRoute                 = "/v1/organizations/:org/github-app/import"
	keyRoute                    = "/v1/organizations/:org/github-app/key"
	installationsRoute          = "/v1/organizations/:org/github-app/installations"
)

func init() {
	for _, p := range []string{getGitHubAppPattern, removeGitHubAppPattern, startRegistrationPattern, completeRegistrationPattern,
		attachRegistrationPattern, discardRegistrationPattern, importGitHubAppPattern, rotateGitHubAppKeyPattern, listInstallationsPattern} {
		readsItself[p] = true
	}
	// The generated binder needs appId; the route reads the request's own.
	boundQuery[removeGitHubAppPattern] = "appId=x"
}

func (r reply) VisitGetGitHubAppResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitRemoveGitHubAppResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitStartGitHubAppRegistrationResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitCompleteGitHubAppRegistrationResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitAttachGitHubAppRegistrationResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitDiscardGitHubAppRegistrationResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitImportGitHubAppResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitRotateGitHubAppKeyResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitListGitHubAppInstallationsResponse(w http.ResponseWriter) error {
	return r.visit(w)
}

// githubAppService is the operations' server/githubapps.
func (o *operations) githubAppService() *githubapps.Service {
	s := &githubapps.Service{Writer: o.s.opts.Writer, Approvals: o.s.opts.Auth, RootKEK: o.s.opts.RootKEK, Policy: o.policy(),
		Now: o.clock(), Log: o.s.opts.Log}
	if o.s.opts.SyncClient != nil {
		githubapps.UseClient(s, o.s.opts.SyncClient)
	}
	return s
}

func (q *orgRequest) githubAppRequest(ctx context.Context) githubapps.Request {
	return githubapps.Request{Principal: q.p, Approval: approvalHeaderOf(ctx), RequestID: requestIDOf(q.r)}
}

// assertGitHubAdapterAllowed is assertGitHubAdapterAllowed: the sync
// switch on and the github-actions adapter allowed.
func (o *operations) assertGitHubAdapterAllowed() error {
	if err := o.assertSyncEnabled(); err != nil {
		return err
	}
	if a := o.s.opts.SyncAdapters; a != nil && !slices.Contains(a, "github-actions") {
		return domainerr.New("VALIDATION_FAILED", "This Installation does not allow the requested platform adapter")
	}
	return nil
}

// assertGitHubAppsAllowed is assertGitHubAppsAllowed: the adapter, and a
// public URL GitHub can send the browser back to.
func (o *operations) assertGitHubAppsAllowed() (*url.URL, error) {
	if err := o.assertGitHubAdapterAllowed(); err != nil {
		return nil, err
	}
	base := o.s.deviceBase()
	if base == nil {
		return nil, domainerr.New("VALIDATION_FAILED",
			"Registering a GitHub App needs this Installation's public URL (public_url in varlatchd.conf) over HTTPS, or a loopback address in local development")
	}
	return base, nil
}

// GetGitHubApp is GET …/github-app.
func (o *operations) GetGitHubApp(ctx context.Context, _ api.GetGitHubAppRequestObject) (api.GetGitHubAppResponseObject, error) {
	q, err := o.syncManage(ctx, githubAppRoute, "")
	if err != nil {
		return nil, err
	}
	a, err := githubapps.Get(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return ok(a.JS()), nil
}

var (
	startRegistrationBody = zObject{{name: "account", schema: zObject{
		{name: "login", schema: zString{min: 1, max: 39}},
		{name: "type", schema: zEnum{"organization", "user"}},
	}}}
	completeRegistrationBody = zObject{
		{name: "state", schema: zString{min: 1, max: 200}},
		{name: "code", schema: zString{min: 1, max: 200}},
	}
	importGitHubAppBody = zObject{
		{name: "appId", schema: zNumber{gt0: true, max: bound(maxSafeInt)}},
		{name: "privateKey", schema: zString{min: 1, max: 10_000}},
	}
	removeGitHubAppQuery = zObject{{name: "appId", schema: zString{min: 1, max: 100}}}
	rotateKeyBody        = zObject{
		{name: "privateKey", schema: zString{min: 1, max: 10_000}},
		{name: "expectedVersion", schema: zInt{min: 1}},
	}
)

// parsedBody is c.req.json() through a zod schema.
func parsedBody(ctx context.Context, schema zSchema) (jsvalue.Object, error) {
	raw, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	out, err := zParse(schema, raw)
	if err != nil {
		return nil, err
	}
	return out.(jsvalue.Object), nil
}

func str(o jsvalue.Object, k string) string {
	v, _ := o.Get(k)
	s, _ := v.(string)
	return s
}

// StartGitHubAppRegistration is POST …/github-app/registrations: 201 with
// the state, the manifest and where the browser posts it; never cached.
func (o *operations) StartGitHubAppRegistration(ctx context.Context, _ api.StartGitHubAppRegistrationRequestObject) (api.StartGitHubAppRegistrationResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	q, err := o.syncManage(ctx, registrationsRoute, "")
	if err != nil {
		return nil, err
	}
	base, err := o.assertGitHubAppsAllowed()
	if err != nil {
		return nil, err
	}
	body, err := parsedBody(ctx, startRegistrationBody)
	if err != nil {
		return nil, err
	}
	acct, _ := body.Get("account")
	a := acct.(jsvalue.Object)
	out, err := o.githubAppService().Start(ctx, q.p, q.org, githubapps.Account{Login: str(a, "login"), Type: str(a, "type")}, base)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return reply{status: http.StatusCreated, body: out}, nil
}

// registrationAnswer is registrationAnswer: registered 201 with the App,
// anything else 200.
func registrationAnswer(o githubapps.Outcome) reply {
	if o.Kind == "registered" {
		return reply{status: http.StatusCreated, body: o.JS()}
	}
	return reply{status: http.StatusOK, body: o.JS()}
}

// CompleteGitHubAppRegistration is POST …/registrations/complete: the
// callback, conversion then attachment. Its attachment's request never
// carries an approval (the callback is never repeated): when one is
// needed, the answer is STEP_UP_REQUIRED for the registration, with its id.
func (o *operations) CompleteGitHubAppRegistration(ctx context.Context, _ api.CompleteGitHubAppRegistrationRequestObject) (api.CompleteGitHubAppRegistrationResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	q, err := o.syncManage(ctx, completeRoute, "")
	if err != nil {
		return nil, err
	}
	if _, err := o.assertGitHubAppsAllowed(); err != nil {
		return nil, err
	}
	body, err := parsedBody(ctx, completeRegistrationBody)
	if err != nil {
		return nil, err
	}
	req := githubapps.Request{Principal: q.p, RequestID: requestIDOf(q.r)}
	var registrationID string
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (githubapps.CompleteResult, error) {
		res, err := o.githubAppService().Complete(ctx, req, q.org, str(body, "state"), str(body, "code"))
		if err == nil && res.Deferred != nil {
			var needed *auth.ApprovalNeeded
			if errors.As(res.Deferred, &needed) {
				registrationID = needed.Binding.Target["registrationId"]
			}
			return res, res.Deferred
		}
		return res, err
	})
	var de *domainerr.Error
	if errors.As(err, &de) && de.Code == "STEP_UP_REQUIRED" && registrationID != "" {
		err = &domainerr.Error{Code: de.Code, Message: de.Message, Details: append(slices.Clone(de.Details), jsvalue.Member{Key: "registrationId", Value: registrationID})}
	}
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.Reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return registrationAnswer(res.Outcome), nil
}

// AttachGitHubAppRegistration is POST …/registrations/{registration}/attach:
// github_app.register, protected; only the person who started the
// registration may attach it.
func (o *operations) AttachGitHubAppRegistration(ctx context.Context, _ api.AttachGitHubAppRegistrationRequestObject) (api.AttachGitHubAppRegistrationResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	q, err := o.syncManage(ctx, attachRoute, "")
	if err != nil {
		return nil, err
	}
	if _, err := o.assertGitHubAppsAllowed(); err != nil {
		return nil, err
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (githubapps.AttachResult, error) {
		return o.githubAppService().Attach(ctx, q.githubAppRequest(ctx), q.org, pathSegment(q.r, 5))
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.Reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return registrationAnswer(res.Outcome), nil
}

// DiscardGitHubAppRegistration is DELETE …/registrations/{registration}.
func (o *operations) DiscardGitHubAppRegistration(ctx context.Context, _ api.DiscardGitHubAppRegistrationRequestObject) (api.DiscardGitHubAppRegistrationResponseObject, error) {
	q, err := o.syncManage(ctx, registrationRoute, "")
	if err != nil {
		return nil, err
	}
	out, reports, err := o.githubAppService().Discard(ctx, q.p, q.org, pathSegment(q.r, 5))
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return ok(out), nil
}

// ImportGitHubApp is POST …/github-app/import: github_app.import, protected;
// registered 201 with the App, a failed check 200.
func (o *operations) ImportGitHubApp(ctx context.Context, _ api.ImportGitHubAppRequestObject) (api.ImportGitHubAppResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	q, err := o.syncManage(ctx, importRoute, "")
	if err != nil {
		return nil, err
	}
	if err := o.assertGitHubAdapterAllowed(); err != nil {
		return nil, err
	}
	body, err := parsedBody(ctx, importGitHubAppBody)
	if err != nil {
		return nil, err
	}
	appID, _ := body.Get("appId")
	type result struct {
		out     githubapps.ImportOutcome
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := o.githubAppService().Import(ctx, q.githubAppRequest(ctx), q.org, int64(appID.(float64)), str(body, "privateKey"))
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	if res.out.Registered {
		return reply{status: http.StatusCreated, body: res.out.JS()}, nil
	}
	return ok(res.out.JS()), nil
}

// RemoveGitHubApp is DELETE …/github-app?appId=: github_app.remove,
// protected; 204.
func (o *operations) RemoveGitHubApp(ctx context.Context, _ api.RemoveGitHubAppRequestObject) (api.RemoveGitHubAppResponseObject, error) {
	q, err := o.syncManage(ctx, githubAppRoute, "")
	if err != nil {
		return nil, err
	}
	in := jsvalue.Object{}
	if v, present := rawOf(ctx).query["appId"]; present {
		in = append(in, jsvalue.Member{Key: "appId", Value: v[0]})
	}
	parsed, err := zParse(removeGitHubAppQuery, in)
	if err != nil {
		return nil, err
	}
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return o.githubAppService().Remove(ctx, q.githubAppRequest(ctx), q.org, str(parsed.(jsvalue.Object), "appId"))
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

// RotateGitHubAppKey is POST …/github-app/key: github_app.replace_key,
// protected, behind every App Target's re-authorization gate; 200 with the
// rotated App or the failed check, never cached.
func (o *operations) RotateGitHubAppKey(ctx context.Context, _ api.RotateGitHubAppKeyRequestObject) (api.RotateGitHubAppKeyResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	q, err := o.syncManage(ctx, keyRoute, "")
	if err != nil {
		return nil, err
	}
	if err := o.assertGitHubAdapterAllowed(); err != nil {
		return nil, err
	}
	body, err := parsedBody(ctx, rotateKeyBody)
	if err != nil {
		return nil, err
	}
	version, _ := body.Get("expectedVersion")
	in := syncs.RotateInput{PrivateKey: str(body, "privateKey"), ExpectedVersion: int64(version.(float64))}
	gate := syncs.DisclosureGate(q.p, q.org.ID, requestIDOf(q.r),
		"Rotating the GitHub App's key re-authorizes every Sync Target on its Connections; you lack disclosure authority for at least one")
	type result struct {
		out     syncs.Rotation
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := o.syncService().RotateAppKey(ctx, q.syncRequest(ctx), q.org, in, gate)
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return ok(res.out.JS()), nil
}

// ListGitHubAppInstallations is GET …/github-app/installations: where the
// App is installed, read from GitHub as the App.
func (o *operations) ListGitHubAppInstallations(ctx context.Context, _ api.ListGitHubAppInstallationsRequestObject) (api.ListGitHubAppInstallationsResponseObject, error) {
	if err := o.assertSyncEnabled(); err != nil {
		return nil, err
	}
	q, err := o.syncManage(ctx, installationsRoute, "")
	if err != nil {
		return nil, err
	}
	if err := o.assertGitHubAdapterAllowed(); err != nil {
		return nil, err
	}
	out, reports, err := o.githubAppService().Installations(ctx, q.p, q.org)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return ok(out), nil
}
