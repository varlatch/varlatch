// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/stages"
	"github.com/varlatch/varlatch/go/server/values"
)

// The read path of values (ADR-0059 step 3.6): the effective configuration
// and Secret disclosures, served by go/server/values. These two operations
// read their route parameters, query and body as the TypeScript server
// reads them (Hono's), not as the generated wrapper binds them: the
// parameters from the routed path, each decoded with
// tryDecodeURIComponent (and the environment with decodeURIComponent once
// more, as app.ts envScope does); the query's first value of each name; the
// body as sent, parsed only once authorization decided (readJson).

const (
	effectivePattern  = "GET /v1/organizations/{org}/projects/{project}/environments/{environment}/effective-configuration"
	disclosurePattern = "POST /v1/organizations/{org}/projects/{project}/environments/{environment}/disclosures"
	// Step 4.1d.
	validatePattern = "POST /v1/organizations/{org}/projects/{project}/environments/{environment}/validate"
	strictPattern   = "POST /v1/organizations/{org}/projects/{project}/environments/{environment}/retrievals"
)

// readsItself are the operations that read their own query and body (keepRaw).
var readsItself = map[string]bool{effectivePattern: true, disclosurePattern: true, validatePattern: true, strictPattern: true}

// The routes as Hono names them, for an incident freeze's refusal.
const (
	effectiveRoute  = "/v1/organizations/:org/projects/:project/environments/:environment/effective-configuration"
	disclosureRoute = "/v1/organizations/:org/projects/:project/environments/:environment/disclosures"
	validateRoute   = "/v1/organizations/:org/projects/:project/environments/:environment/validate"
	strictRoute     = "/v1/organizations/:org/projects/:project/environments/:environment/retrievals"
)

type rawKey struct{}

type keptRequest struct {
	query url.Values
	body  []byte
	// approval is the Varlatch-Approval header as sent (every line,
	// joined), present or not.
	approval        string
	approvalPresent bool
}

// keepRaw keeps the request's query and body for the operation, and hands
// the generated wrapper an empty object and no approval header, which it
// would otherwise bind (and could refuse) before the operation runs: an
// operation reads Varlatch-Approval where the TypeScript route does
// (approvalOf).
func keepRaw(r *http.Request) *http.Request {
	raw := keptRequest{query: parseQuery(r.URL.RawQuery)}
	if _, present := r.Header["Varlatch-Approval"]; present {
		raw.approval, raw.approvalPresent = headerValue(r, "Varlatch-Approval"), true
	}
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		b, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			b = nil
		}
		raw.body = b
	}
	r.Body = io.NopCloser(strings.NewReader("{}"))
	r.ContentLength = 2
	r.Header.Del("Varlatch-Approval")
	return r.WithContext(context.WithValue(r.Context(), rawKey{}, raw))
}

// parseQuery is the query as Hono's c.req.query reads it: each name's first
// value, '+' a space, an undecodable escape kept as written.
func parseQuery(raw string) url.Values {
	out := url.Values{}
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		k = tryDecodeURIComponent(strings.ReplaceAll(k, "+", " "))
		v = tryDecodeURIComponent(strings.ReplaceAll(v, "+", " "))
		out[k] = append(out[k], v)
	}
	return out
}

func rawOf(ctx context.Context) keptRequest {
	if r := httpRequestOf(ctx); r != nil {
		raw, _ := r.Context().Value(rawKey{}).(keptRequest)
		return raw
	}
	return keptRequest{}
}

// valuesRequest builds the read path's request from the routed path.
func (o *operations) valuesRequest(ctx context.Context, route string) (values.Request, error) {
	r := httpRequestOf(ctx)
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	// v1 organizations {org} projects {project} environments {environment} <op>
	if len(segs) != 8 {
		return values.Request{}, errors.New("values: unexpected route " + r.URL.Path)
	}
	env, ok := decodeURIComponent(tryDecodeURIComponent(segs[6]))
	if !ok {
		// decodeURIComponent throws a URIError: the TypeScript server's
		// onError answers it as an internal error.
		return values.Request{}, errors.New("values: the environment parameter is not decodable")
	}
	return values.Request{
		Principal: principalOf(ctx), RequestID: requestIDOf(r), Method: r.Method, Route: route,
		Org: tryDecodeURIComponent(segs[2]), Project: tryDecodeURIComponent(segs[4]), Environment: env,
	}, nil
}

func (r reply) VisitGetEffectiveConfigurationResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitDiscloseSecretsResponse(w http.ResponseWriter) error           { return r.visit(w) }

// valuesError adds what the TypeScript server's onError adds to a
// refusal: Retry-After for an incident freeze.
func valuesError(err error) error {
	var frozen *authz.FrozenError
	if errors.As(err, &frozen) {
		return &headerError{err: err, headers: retryAfter(300)}
	}
	return err
}

// GetEffectiveConfiguration is GET …/effective-configuration.
func (o *operations) GetEffectiveConfiguration(ctx context.Context, _ api.GetEffectiveConfigurationRequestObject) (api.GetEffectiveConfigurationResponseObject, error) {
	req, err := o.valuesRequest(ctx, effectiveRoute)
	if err != nil {
		return nil, err
	}
	q := rawOf(ctx).query
	var purpose *string
	if v, ok := q["purpose"]; ok {
		purpose = &v[0]
	}
	include := q["include"]
	body, err := o.s.opts.Values.EffectiveConfiguration(ctx, req, len(include) > 0 && include[0] == "values", purpose)
	if err != nil {
		return nil, valuesError(err)
	}
	return ok(body), nil
}

// DiscloseSecrets is POST …/disclosures. Never cacheable.
func (o *operations) DiscloseSecrets(ctx context.Context, _ api.DiscloseSecretsRequestObject) (api.DiscloseSecretsResponseObject, error) {
	req, err := o.valuesRequest(ctx, disclosureRoute)
	if err != nil {
		return nil, err
	}
	// The Varlatch-Approval header as sent: read only by an export under
	// admin-step-up's enforce, so with the control off a malformed one
	// changes nothing (approvalHeaderOf).
	if raw := rawOf(ctx); raw.approvalPresent {
		h := raw.approval
		req.Approval = &h
	}
	body, err := o.s.opts.Values.Disclose(ctx, req, rawOf(ctx).body)
	if err != nil {
		return nil, valuesError(err)
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	m := stages.Start()
	b := jsvalue.Stringify(body)
	stages.Since(ctx, "encoding", m)
	return ok(encoded(b)), nil
}

func (r reply) VisitValidateEnvironmentResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitStrictRetrievalResponse(w http.ResponseWriter) error     { return r.visit(w) }

// ValidateEnvironment is POST …/validate (ADR-0038 Decisions 5 and 6): no
// body. Never cacheable.
func (o *operations) ValidateEnvironment(ctx context.Context, _ api.ValidateEnvironmentRequestObject) (api.ValidateEnvironmentResponseObject, error) {
	req, err := o.valuesRequest(ctx, validateRoute)
	if err != nil {
		return nil, err
	}
	body, err := o.s.opts.Values.Validate(ctx, req)
	if err != nil {
		return nil, valuesError(err)
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	return ok(body), nil
}

// StrictRetrieval is POST …/retrievals (ADR-0038 Decision 6): the body is
// read with c.req.json() before the snapshot and parsed once metadata
// access decided (readJson: a body that is not JSON throws then, 500).
// Never cacheable.
func (o *operations) StrictRetrieval(ctx context.Context, _ api.StrictRetrievalRequestObject) (api.StrictRetrievalResponseObject, error) {
	req, err := o.valuesRequest(ctx, strictRoute)
	if err != nil {
		return nil, err
	}
	body, err := o.s.opts.Values.StrictRetrieval(ctx, req, func() (any, error) { return jsonBody(ctx) })
	if err != nil {
		return nil, valuesError(err)
	}
	writerOf(ctx).Header().Set("Cache-Control", "no-store")
	m := stages.Start()
	b := jsvalue.Stringify(body)
	stages.Since(ctx, "encoding", m)
	return ok(encoded(b)), nil
}
