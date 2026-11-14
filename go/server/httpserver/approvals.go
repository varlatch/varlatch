// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/http"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Step-up approvals (ADR-0054 Decision 3, capability security.controls):
// an operation that needs one answers STEP_UP_REQUIRED with a pending
// approval; its person, and only its person, reads it here, approves it in
// the dashboard with a trusted passkey (user verification required), or
// cancels it. The client then repeats the operation with the
// Varlatch-Approval header. Every answer here is Cache-Control: no-store.

func (r reply) VisitGetApprovalResponse(w http.ResponseWriter) error     { return r.visit(w) }
func (r reply) VisitStartApprovalResponse(w http.ResponseWriter) error   { return r.visit(w) }
func (r reply) VisitApproveApprovalResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitCancelApprovalResponse(w http.ResponseWriter) error  { return r.visit(w) }

const approvalOwnerRefusal = "Only a person signed in to the dashboard may approve; open the approval's address in a browser"

// approvalID is a route's approval id; one that cannot be an id is not found.
func approvalID(raw string) (string, error) {
	id := auth.ParseApprovalID(raw)
	if id == "" {
		return "", domainerr.NotFound("Approval")
	}
	return id, nil
}

// GetApproval is GET /v1/me/approvals/{approval}: any credential of its
// person.
func (o *operations) GetApproval(ctx context.Context, req api.GetApprovalRequestObject) (api.GetApprovalResponseObject, error) {
	id, err := approvalID(req.Approval)
	if err != nil {
		return nil, err
	}
	view, err := o.s.opts.Auth.GetApproval(ctx, auth.RequesterOf(principalOf(ctx)), id)
	if err != nil {
		return nil, err
	}
	return ok(view), nil
}

// StartApproval is POST /v1/me/approvals/{approval}/options: the dashboard's
// session bearer of the approval's person.
func (o *operations) StartApproval(ctx context.Context, req api.StartApprovalRequestObject) (api.StartApprovalResponseObject, error) {
	identityID, sessionID, err := dashboardSession(ctx, approvalOwnerRefusal)
	if err != nil {
		return nil, err
	}
	id, err := approvalID(req.Approval)
	if err != nil {
		return nil, err
	}
	options, err := o.s.opts.Auth.StartApproval(ctx, identityID, sessionID, id)
	if err != nil {
		return nil, err
	}
	pk, err := optionsJS(options)
	if err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{{Key: "publicKey", Value: pk}}), nil
}

// ApproveApproval is POST /v1/me/approvals/{approval}/approve.
func (o *operations) ApproveApproval(ctx context.Context, req api.ApproveApprovalRequestObject) (api.ApproveApprovalResponseObject, error) {
	identityID, sessionID, err := dashboardSession(ctx, approvalOwnerRefusal)
	if err != nil {
		return nil, err
	}
	id, err := approvalID(req.Approval)
	if err != nil {
		return nil, err
	}
	if err := bodyError(ctx); err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Assertion == nil {
		return nil, validation("assertion: Invalid input: expected record, received undefined")
	}
	view, err := o.s.opts.Auth.ApproveApproval(ctx, identityID, sessionID, id, rawAssertion(req.Body.Assertion), requestIDOf(httpRequestOf(ctx)))
	if err != nil {
		return nil, err
	}
	return ok(view), nil
}

// CancelApproval is POST /v1/me/approvals/{approval}/cancel: any credential
// of its person.
func (o *operations) CancelApproval(ctx context.Context, req api.CancelApprovalRequestObject) (api.CancelApprovalResponseObject, error) {
	id, err := approvalID(req.Approval)
	if err != nil {
		return nil, err
	}
	view, err := o.s.opts.Auth.CancelApproval(ctx, principalOf(ctx).Identity.ID, id)
	if err != nil {
		return nil, err
	}
	return ok(view), nil
}
