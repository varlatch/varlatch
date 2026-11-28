// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/http"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/domainerr"
)

// Upgrades asked for in the web app (ADR-0065 phase 2, capability
// installation.upgrade, server/upgraderequests): an Installation Admin, on
// a dashboard session, files a request for the release the pre-flight
// offers, with a step-up approval for it; reads how far the host got; and
// cancels it until the host has taken it. Every answer is no-store
// (authn.go noStore).

func (r reply) VisitGetInstallationUpgradeRequestResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitRequestInstallationUpgradeResponse(w http.ResponseWriter) error {
	return r.visit(w)
}
func (r reply) VisitCancelInstallationUpgradeRequestResponse(w http.ResponseWriter) error {
	return r.visit(w)
}

const upgradeOwnerRefusal = "An upgrade is asked for from the dashboard, by an Installation Admin signed in there with a passkey"

// upgradeRoute is an upgrade request route's checks: served (a systemd
// host), and an Installation Admin.
func (o *operations) upgradeRoute(ctx context.Context) error {
	if o.s.opts.UpgradeRequests == nil {
		return domainerr.NotFound("Upgrade request")
	}
	return installationAdmin(ctx)
}

// GetInstallationUpgradeRequest is GET /v1/installation/upgrade-request.
func (o *operations) GetInstallationUpgradeRequest(ctx context.Context, _ api.GetInstallationUpgradeRequestRequestObject) (api.GetInstallationUpgradeRequestResponseObject, error) {
	if err := o.upgradeRoute(ctx); err != nil {
		return nil, err
	}
	st, err := o.s.opts.UpgradeRequests.Read(ctx)
	if err != nil {
		return nil, err
	}
	return ok(st.JS()), nil
}

// RequestInstallationUpgrade is POST /v1/installation/upgrade-request: a
// dashboard session's bearer only, so the approval is a dashboard intent
// (2 minutes) bound to that session.
func (o *operations) RequestInstallationUpgrade(ctx context.Context, req api.RequestInstallationUpgradeRequestObject) (api.RequestInstallationUpgradeResponseObject, error) {
	if err := o.upgradeRoute(ctx); err != nil {
		return nil, err
	}
	if _, _, err := dashboardSession(ctx, upgradeOwnerRefusal); err != nil {
		return nil, err
	}
	approvalID, err := approvalHeader(req.Params.VarlatchApproval)
	if err != nil {
		return nil, err
	}
	if err := bodyError(ctx); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, validation("version: Invalid input: expected string, received undefined")
	}
	st, err := o.s.opts.UpgradeRequests.Request(ctx, auth.RequesterOf(principalOf(ctx)), req.Body.Version, req.Body.RequestId, approvalID)
	if err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: st.JS()}, nil
}

// CancelInstallationUpgradeRequest is POST
// /v1/installation/upgrade-request/{upgradeRequest}/cancel: any Installation
// Admin.
func (o *operations) CancelInstallationUpgradeRequest(ctx context.Context, req api.CancelInstallationUpgradeRequestRequestObject) (api.CancelInstallationUpgradeRequestResponseObject, error) {
	if err := o.upgradeRoute(ctx); err != nil {
		return nil, err
	}
	st, err := o.s.opts.UpgradeRequests.Cancel(ctx, auth.RequesterOf(principalOf(ctx)), req.UpgradeRequest)
	if err != nil {
		return nil, err
	}
	return ok(st.JS()), nil
}
