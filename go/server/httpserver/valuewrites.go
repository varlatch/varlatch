// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// The writes of values (ADR-0059 step 4.1d): setValue, deleteValue and
// applyChangeSet, as http/app.ts serves them, on go/server/values. Each
// enters its environment as envScope does and authorizes
// config.value.write on it with existence hidden; setValue and
// applyChangeSet then parse their bodies (zod's output, in its schema's
// member order, is what the Idempotency-Key's digest covers) and run under
// withIdempotency.

const (
	setValuePattern       = "PUT /v1/organizations/{org}/projects/{project}/environments/{environment}/values/{item}"
	deleteValuePattern    = "DELETE /v1/organizations/{org}/projects/{project}/environments/{environment}/values/{item}"
	applyChangeSetPattern = "POST /v1/organizations/{org}/projects/{project}/environments/{environment}/changes"

	valueRoute   = "/v1/organizations/:org/projects/:project/environments/:environment/values/:item"
	changesRoute = "/v1/organizations/:org/projects/:project/environments/:environment/changes"
)

func init() {
	for _, p := range []string{setValuePattern, applyChangeSetPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitSetValueResponse(w http.ResponseWriter) error       { return r.visit(w) }
func (r reply) VisitDeleteValueResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitApplyChangeSetResponse(w http.ResponseWriter) error { return r.visit(w) }

// writeTarget enters the environment and authorizes config.value.write on
// it.
func (o *operations) writeTarget(ctx context.Context, route string) (*projectRequest, values.Target, error) {
	p, env, err := o.enterEnvironment(ctx, route, "")
	if err != nil {
		return nil, values.Target{}, err
	}
	if err := p.authorizeOn(ctx, "config.value.write", p.envResource(env)); err != nil {
		return nil, values.Target{}, err
	}
	return p, values.Target{OrganizationID: p.org.ID, Project: p.project, Env: env}, nil
}

// claim is withIdempotency's claim for a write: the Idempotency-Key header
// (none when absent or empty), the endpoint, and the digest of the parsed
// body.
func (p *projectRequest) claim(endpoint string, body any) write.Claim {
	return write.Claim{
		IdentityID: p.p.Identity.ID, Endpoint: endpoint, Key: p.r.Header.Get("Idempotency-Key"),
		Digest: write.BodyHash(body, p.o.s.opts.RootKEK),
	}
}

// SetValue is PUT …/values/{item}: the body z.object({ value: z.string(),
// expectedVersionId: z.string().optional() }).
func (o *operations) SetValue(ctx context.Context, _ api.SetValueRequestObject) (api.SetValueResponseObject, error) {
	p, t, err := o.writeTarget(ctx, valueRoute)
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	if err := zodIssues([]bodyField{
		{name: "value", kind: kindString, required: true, min: 0, max: noLimit},
		{name: "expectedVersionId", kind: kindString, min: 0, max: noLimit},
	}, body); err != nil {
		return nil, err
	}
	obj := body.(jsvalue.Object)
	value, _ := obj.Get("value")
	parsed := jsvalue.Object{{Key: "value", Value: value}}
	in := values.SetInput{Value: value.(string)}
	if v, ok := obj.Get("expectedVersionId"); ok {
		s := v.(string)
		in.ExpectedVersionID = &s
		parsed = append(parsed, jsvalue.Member{Key: "expectedVersionId", Value: s})
	}
	item := tryDecodeURIComponent(p.segs[8])
	claim := p.claim("PUT values "+t.Env.ID+"/"+item, parsed)
	resp, _, reports, err := values.SetValue(ctx, o.s.opts.Writer, o.s.opts.RootKEK, p.p, t, item, in, claim, o.s.opts.Now)
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	return p.written(ctx, resp, reports)
}

// written settles a write that succeeded and answers its response.
func (p *projectRequest) written(ctx context.Context, resp write.Response, reports []auth.PendingReport) (reply, error) {
	p.checked, p.reports, p.at = true, reports, p.o.s.opts.Now().UnixMicro()
	if err := p.settle(ctx); err != nil {
		return reply{}, err
	}
	return reply{status: resp.Status, body: resp.Payload}, nil
}

// DeleteValue is DELETE …/values/{item}: no body; 204.
func (o *operations) DeleteValue(ctx context.Context, _ api.DeleteValueRequestObject) (api.DeleteValueResponseObject, error) {
	p, t, err := o.writeTarget(ctx, valueRoute)
	if err != nil {
		return nil, err
	}
	reports, err := values.DeleteValue(ctx, o.s.opts.Writer, p.p, t, tryDecodeURIComponent(p.segs[8]), o.s.opts.Now)
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	return p.written(ctx, write.Response{Status: http.StatusNoContent}, reports)
}

// ApplyChangeSet is POST …/changes: the body z.object({ changes:
// z.array(z.discriminatedUnion("op", [set, delete])).min(1).max(200) }).
func (o *operations) ApplyChangeSet(ctx context.Context, _ api.ApplyChangeSetRequestObject) (api.ApplyChangeSetResponseObject, error) {
	p, t, err := o.writeTarget(ctx, changesRoute)
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	changes, parsed, err := parseChanges(body)
	if err != nil {
		return nil, err
	}
	claim := p.claim("POST changes "+t.Env.ID, parsed)
	resp, _, reports, err := values.ApplyChangeSet(ctx, o.s.opts.Writer, o.s.opts.RootKEK, p.p, t, changes, requestIDOf(p.r), claim, o.s.opts.Now)
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	return p.written(ctx, resp, reports)
}

// parseChanges is the change set's zod schema: the issues as zod reports
// them (an array beyond its bounds reports only that), or the changes and
// zod's output (unknown members stripped, the schema's member order).
func parseChanges(body any) ([]values.Change, any, error) {
	fail := func(issues []string) error { return domainerr.New("VALIDATION_FAILED", strings.Join(issues, "; ")) }
	obj, ok := body.(jsvalue.Object)
	if !ok {
		return nil, nil, fail([]string{"(root): Invalid input: expected object, received " + zodType(body)})
	}
	raw, present := obj.Get("changes")
	list, isList := raw.([]any)
	switch {
	case !present:
		return nil, nil, fail([]string{"changes: Invalid input: expected array, received undefined"})
	case !isList:
		return nil, nil, fail([]string{"changes: Invalid input: expected array, received " + zodType(raw)})
	case len(list) < 1:
		return nil, nil, fail([]string{"changes: Too small: expected array to have >=1 items"})
	case len(list) > 200:
		return nil, nil, fail([]string{"changes: Too big: expected array to have <=200 items"})
	}
	var issues []string
	var out []values.Change
	var parsed []any
	for i, e := range list {
		at := fmt.Sprintf("changes.%d", i)
		c, ok := e.(jsvalue.Object)
		if !ok {
			issues = append(issues, at+": Invalid input: expected object, received "+zodType(e))
			continue
		}
		op, _ := c.Get("op")
		if op != "set" && op != "delete" {
			issues = append(issues, at+".op: Invalid discriminator value. Expected 'set' | 'delete'")
			continue
		}
		ch := values.Change{Op: op.(string)}
		member := jsvalue.Object{{Key: "op", Value: op}}
		str := func(key string, required bool, min int) (string, bool) {
			v, present := c.Get(key)
			if !present {
				if required {
					issues = append(issues, at+"."+key+": Invalid input: expected string, received undefined")
				}
				return "", false
			}
			s, isStr := v.(string)
			if !isStr {
				issues = append(issues, at+"."+key+": Invalid input: expected string, received "+zodType(v))
				return "", false
			}
			if codePoints(s) < min {
				issues = append(issues, fmt.Sprintf("%s.%s: Too small: expected string to have >=%d characters", at, key, min))
				return "", false
			}
			member = append(member, jsvalue.Member{Key: key, Value: s})
			return s, true
		}
		ch.Item, _ = str("item", true, 1)
		if ch.Op == "set" {
			ch.Value, _ = str("value", true, 0)
		}
		if s, ok := str("expectedVersionId", false, 0); ok {
			ch.ExpectedVersionID = &s
		}
		out = append(out, ch)
		parsed = append(parsed, member)
	}
	if len(issues) > 0 {
		return nil, nil, fail(issues)
	}
	return out, jsvalue.Object{{Key: "changes", Value: parsed}}, nil
}
