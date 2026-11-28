// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/http"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/webhooks"
	"github.com/varlatch/varlatch/go/server/write"
)

// Audit webhooks (ADR-0016, ADR-0029 section 8; ADR-0059 step 4.7b), as
// http/app.ts serves them: an operational sink for the Organization's
// audit stream. Every operation needs organization.manage (the receiver
// sees audit data), with existence hidden; listing is inspection while
// frozen, and the writes are protected operations (server/webhooks).

const (
	listWebhooksPattern  = "GET /v1/organizations/{org}/webhooks"
	createWebhookPattern = "POST /v1/organizations/{org}/webhooks"
	updateWebhookPattern = "PATCH /v1/organizations/{org}/webhooks/{webhook}"
	revokeWebhookPattern = "DELETE /v1/organizations/{org}/webhooks/{webhook}"
	webhooksRoute        = "/v1/organizations/:org/webhooks"
)

func init() {
	for _, p := range []string{listWebhooksPattern, createWebhookPattern, updateWebhookPattern, revokeWebhookPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitListWebhooksResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitCreateWebhookResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitUpdateWebhookResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitRevokeWebhookResponse(w http.ResponseWriter) error { return r.visit(w) }

// webhookService is the operations' server/webhooks, on this server's
// writer, approvals, Root KEK and outbound policy.
func (o *operations) webhookService() *webhooks.Service {
	return &webhooks.Service{Writer: o.s.opts.Writer, Approvals: o.s.opts.Auth, RootKEK: o.s.opts.RootKEK, Policy: o.policy(), Now: o.clock(), Log: o.s.opts.Log}
}

func (q *orgRequest) webhookRequest(ctx context.Context) webhooks.Request {
	return webhooks.Request{Principal: q.p, Approval: approvalHeaderOf(ctx), RequestID: requestIDOf(q.r), IdempotencyKey: q.r.Header.Get("Idempotency-Key")}
}

// organizationManage enters the route under exception and authorizes
// organization.manage.
func (o *operations) organizationManage(ctx context.Context, route, exception string) (*orgRequest, error) {
	q, err := o.enterRoute(ctx, route, exception)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "organization.manage"); err != nil {
		return nil, err
	}
	return q, nil
}

// eventTypesSchema is z.array(z.string().min(1).max(200)).min(1).max(100).
var eventTypesSchema = zArray{element: zString{min: 1, max: 200}, min: 1, max: 100}

var webhookCreateBody = zObject{
	{name: "url", schema: zString{min: 1, max: 2000}},
	{name: "eventTypes", schema: eventTypesSchema, optional: true},
}

var webhookUpdateBody = zObject{
	{name: "expectedVersion", schema: zInt{min: 1}},
	{name: "url", schema: zString{min: 1, max: 2000}, optional: true},
	{name: "eventTypes", schema: zNullable{eventTypesSchema}, optional: true},
}

// ListWebhooks is GET …/webhooks: inspection while frozen,
// organization.manage; the live webhooks, oldest first.
func (o *operations) ListWebhooks(ctx context.Context, _ api.ListWebhooksRequestObject) (api.ListWebhooksResponseObject, error) {
	q, err := o.organizationManage(ctx, webhooksRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	items, err := webhooks.List(ctx, o.s.opts.Auth.Store().Reader(), o.s.opts.RootKEK, q.org.ID)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return listed(items), nil
}

// CreateWebhook is POST …/webhooks: organization.manage, the body, then
// the protected operation (webhook.create). 201, never cached: the
// signing secret is shown once.
func (o *operations) CreateWebhook(ctx context.Context, _ api.CreateWebhookRequestObject) (api.CreateWebhookResponseObject, error) {
	q, err := o.organizationManage(ctx, webhooksRoute, "")
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(webhookCreateBody, body)
	if err != nil {
		return nil, err
	}
	obj := parsed.(jsvalue.Object)
	url, _ := obj.Get("url")
	var eventTypes []string
	if t, ok := obj.Get("eventTypes"); ok {
		eventTypes = stringArray(t)
	}
	type result struct {
		out     webhooks.Created
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := o.webhookService().Create(ctx, q.webhookRequest(ctx), q.org, url.(string), eventTypes)
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

// UpdateWebhook is PATCH …/webhooks/{webhook} (ADR-0029 section 8):
// organization.manage, the body, then the protected operation
// (webhook.update) under an Idempotency-Key.
func (o *operations) UpdateWebhook(ctx context.Context, _ api.UpdateWebhookRequestObject) (api.UpdateWebhookResponseObject, error) {
	q, err := o.organizationManage(ctx, webhooksRoute+"/:webhook", "")
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(webhookUpdateBody, body)
	if err != nil {
		return nil, err
	}
	obj := parsed.(jsvalue.Object)
	version, _ := obj.Get("expectedVersion")
	patch := webhooks.Patch{ExpectedVersion: int64(version.(float64)), URL: optionalString(obj, "url"), Body: obj}
	if t, ok := obj.Get("eventTypes"); ok {
		patch.SetEventTypes = true
		if t != nil {
			patch.EventTypes = stringArray(t)
		}
	}
	webhookID := pathSegment(q.r, 4)
	type result struct {
		resp    write.Response
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		resp, reports, err := o.webhookService().Update(ctx, q.webhookRequest(ctx), q.org.ID, webhookID, patch)
		return result{resp, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	return idempotentReply(res.resp), nil
}

// RevokeWebhook is DELETE …/webhooks/{webhook}: organization.manage, the
// protected operation (webhook.delete); refused while frozen (not a
// recovery operation). 204.
func (o *operations) RevokeWebhook(ctx context.Context, _ api.RevokeWebhookRequestObject) (api.RevokeWebhookResponseObject, error) {
	q, err := o.organizationManage(ctx, webhooksRoute+"/:webhook", "")
	if err != nil {
		return nil, err
	}
	webhookID := pathSegment(q.r, 4)
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return o.webhookService().Revoke(ctx, q.webhookRequest(ctx), q.org.ID, webhookID)
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}
