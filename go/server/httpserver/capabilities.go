// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/varlatch/varlatch/go/lib/targets"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/capabilities"
	"github.com/varlatch/varlatch/go/server/environments"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/values"
)

// Broker Capabilities (ADR-0022, ADR-0039; ADR-0059 step 4.6), as
// http/app.ts serves them: the mediation surface of a Broker. Only a
// Broker of the Organization issues and exercises (anyone else is told
// "Not found"); the Agent's secret.use is what an exercise evaluates.
// People with policy.read list every Capability of an environment and with
// policy.manage revoke one (oversight); a Broker lists and revokes its own.

const (
	listCapabilitiesPattern   = "GET /v1/organizations/{org}/projects/{project}/environments/{environment}/capabilities"
	issueCapabilityPattern    = "POST /v1/organizations/{org}/projects/{project}/environments/{environment}/capabilities"
	revokeCapabilityPattern   = "DELETE /v1/organizations/{org}/projects/{project}/environments/{environment}/capabilities/{capability}"
	exerciseCapabilityPattern = "POST /v1/organizations/{org}/projects/{project}/environments/{environment}/capabilities/{capability}/exercises"

	capabilitiesRoute = "/v1/organizations/:org/projects/:project/environments/:environment/capabilities"
	capabilityRoute   = capabilitiesRoute + "/:capability"
	exercisesRoute    = capabilityRoute + "/exercises"
)

func init() {
	for _, p := range []string{issueCapabilityPattern, exerciseCapabilityPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitListCapabilitiesResponse(w http.ResponseWriter) error   { return r.visit(w) }
func (r reply) VisitIssueCapabilityResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitRevokeCapabilityResponse(w http.ResponseWriter) error   { return r.visit(w) }
func (r reply) VisitExerciseCapabilityResponse(w http.ResponseWriter) error { return r.visit(w) }

// digest is z.string().regex(/^sha256:[0-9a-f]{64}$/).
var digest = zString{pattern: regexp.MustCompile(`^sha256:[0-9a-f]{64}$`), source: "/^sha256:[0-9a-f]{64}$/"}

var issueCapabilityBody = zObject{
	{name: "agentIdentityId", schema: zString{}},
	{name: "items", schema: zArray{element: zString{min: 1}, min: 1, max: 200}},
	{name: "destinations", schema: zArray{element: zString{min: 1}, min: 1, max: 50}},
	// Substitution targets per item (ADR-0039): required, but checked by
	// the issuance, so the error names the item, the rule, or the CLI
	// version an older CLI needs.
	{name: "targets", schema: zRecord{value: zArray{element: zString{}, max: 8}}, optional: true},
	{name: "ttlSeconds", schema: zNumber{gt0: true}},
	{name: "runId", schema: zString{max: 200}, optional: true},
	// The agent-safe strict preflight (ADR-0038 Decision 7): the state the
	// operator's preflight retrieval saw. It confers no authority.
	{name: "precondition", schema: zObject{
		{name: "projectId", schema: zString{}},
		{name: "environmentId", schema: zString{}},
		{name: "stateDigest", schema: digest},
		{name: "stateDigests", schema: zRecord{keys: zEnum{"environment", "contract", "items", "rotation"}, value: digest}},
	}, optional: true},
}

var exerciseCapabilityBody = zObject{
	{name: "capabilitySecret", schema: zString{min: 1}},
	{name: "destination", schema: zObject{
		{name: "host", schema: zString{min: 1}},
		{name: "port", schema: zNumber{min: bound(1), max: bound(65535)}},
	}},
	// Each substitution the Broker will make (ADR-0039 Decision 7).
	{name: "placements", schema: zArray{element: zObject{
		{name: "item", schema: zString{min: 1}},
		{name: "target", schema: zString{min: 1}},
	}, max: 200}, optional: true},
}

// brokerOf is the caller's Broker id when it is a Broker of q's
// Organization, else "".
func (q *orgRequest) brokerOf() string {
	if q.p.Identity.Kind == "broker" && q.p.Identity.OrganizationID != nil && *q.p.Identity.OrganizationID == q.org.ID {
		return q.p.Identity.ID
	}
	return ""
}

// IssueCapability is POST …/capabilities: the environment, the Broker,
// the body, the precondition when sent (its own snapshot: STATE_CHANGED
// with the categories that changed), then the issuance. 201, never
// cacheable.
func (o *operations) IssueCapability(ctx context.Context, _ api.IssueCapabilityRequestObject) (api.IssueCapabilityResponseObject, error) {
	p, env, err := o.enterEnvironment(ctx, capabilitiesRoute, "")
	if err != nil {
		return nil, err
	}
	if err := values.RequireBroker(p.p, p.org.ID); err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(issueCapabilityBody, body)
	if err != nil {
		return nil, err
	}
	obj := parsed.(jsvalue.Object)
	get := func(k string) any { v, _ := obj.Get(k); return v }
	in := capabilities.IssueInput{
		AgentIdentityID: get("agentIdentityId").(string), Items: stringArray(get("items")),
		Destinations: stringArray(get("destinations")), TTLSeconds: int64(get("ttlSeconds").(float64)),
	}
	if t, ok := obj.Get("targets"); ok {
		in.Targets = []targets.Item{}
		for _, m := range t.(jsvalue.Object) {
			in.Targets = append(in.Targets, targets.Item{Name: m.Key, Targets: stringArray(m.Value)})
		}
	}
	if r, ok := obj.Get("runId"); ok {
		s := r.(string)
		in.RunID = &s
	}
	var preflight []values.PreflightItem
	if pre, ok := obj.Get("precondition"); ok {
		po := pre.(jsvalue.Object)
		pg := func(k string) string { v, _ := po.Get(k); return v.(string) }
		digests := map[string]string{}
		d, _ := po.Get("stateDigests")
		for _, m := range d.(jsvalue.Object) {
			digests[m.Key] = m.Value.(string)
		}
		req, err := o.valuesRequest(ctx, capabilitiesRoute)
		if err != nil {
			return nil, err
		}
		preflight, err = o.s.opts.Values.CheckPrecondition(ctx, req, values.Precondition{
			ProjectID: pg("projectId"), EnvironmentID: pg("environmentId"), StateDigest: pg("stateDigest"), StateDigests: digests,
		}, in.AgentIdentityID, in.Items)
		if err != nil {
			return nil, valuesError(err)
		}
		if preflight == nil {
			preflight = []values.PreflightItem{}
		}
	}
	out, reports, err := capabilities.Issue(ctx, o.s.opts.Writer, p.p, capabilities.Scope{
		OrganizationID: p.org.ID, ProjectID: p.project.ID, EnvironmentID: env.ID,
		Environment: authz.Environment{ID: env.ID, RootID: environments.RootID(env), Tier: env.Tier},
	}, in, preflight, o.s.opts.Now)
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	if err := p.orgRequest.written(ctx, reports); err != nil {
		return nil, err
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return reply{status: http.StatusCreated, body: out}, nil
}

// ListCapabilities is GET …/capabilities: inspection while frozen; a
// Broker sees its own, anyone else needs policy.read (existence hidden).
func (o *operations) ListCapabilities(ctx context.Context, _ api.ListCapabilitiesRequestObject) (api.ListCapabilitiesResponseObject, error) {
	p, env, err := o.enterEnvironment(ctx, capabilitiesRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	broker := p.brokerOf()
	if broker == "" {
		if err := p.authorize(ctx, "policy.read"); err != nil {
			return nil, err
		}
	}
	out, err := capabilities.List(ctx, o.s.opts.Auth.Store().Reader(), p.org.ID, env.ID, broker)
	if err != nil {
		return nil, err
	}
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	return ok(out), nil
}

// RevokeCapability is DELETE …/capabilities/{capability}: recovery while
// frozen; a Broker revokes its own, anyone else needs policy.manage
// (existence hidden). 204.
func (o *operations) RevokeCapability(ctx context.Context, _ api.RevokeCapabilityRequestObject) (api.RevokeCapabilityResponseObject, error) {
	p, _, err := o.enterEnvironment(ctx, capabilityRoute, authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	broker := p.brokerOf()
	if broker == "" {
		if err := p.authorize(ctx, "policy.manage"); err != nil {
			return nil, err
		}
	}
	reports, err := capabilities.Revoke(ctx, o.s.opts.Writer, p.p, p.org.ID, tryDecodeURIComponent(p.segs[8]), broker, o.s.opts.Now)
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	if err := p.orgRequest.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

// ExerciseCapability is POST …/capabilities/{capability}/exercises: a
// retrieval (go/server/values). The body is read first and parsed once
// the Broker is known (readJson). Never cacheable.
func (o *operations) ExerciseCapability(ctx context.Context, _ api.ExerciseCapabilityRequestObject) (api.ExerciseCapabilityResponseObject, error) {
	req, err := o.valuesRequest(ctx, exercisesRoute)
	if err != nil {
		return nil, err
	}
	segs := strings.Split(strings.TrimPrefix(httpRequestOf(ctx).URL.Path, "/"), "/")
	parse := func() (values.Exercise, error) {
		body, err := jsonBody(ctx)
		if err != nil {
			return values.Exercise{}, err
		}
		parsed, err := zParse(exerciseCapabilityBody, body)
		if err != nil {
			return values.Exercise{}, err
		}
		obj := parsed.(jsvalue.Object)
		secret, _ := obj.Get("capabilitySecret")
		dest, _ := obj.Get("destination")
		host, _ := dest.(jsvalue.Object).Get("host")
		port, _ := dest.(jsvalue.Object).Get("port")
		in := values.Exercise{Secret: secret.(string), Host: host.(string), Port: int(port.(float64))}
		if list, ok := obj.Get("placements"); ok {
			in.Placements = []values.Placement{}
			for _, e := range list.([]any) {
				item, _ := e.(jsvalue.Object).Get("item")
				target, _ := e.(jsvalue.Object).Get("target")
				in.Placements = append(in.Placements, values.Placement{Item: item.(string), Target: target.(string)})
			}
		}
		return in, nil
	}
	out, err := o.s.opts.Values.ExerciseCapability(ctx, req, tryDecodeURIComponent(segs[8]), parse)
	if err != nil {
		return nil, valuesError(err)
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return ok(out), nil
}
