// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/contracts"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Contracts (ADR-0059 step 4.1b): getActiveContract, pushContractRevision,
// getContractRevision and activateContractRevision, as http/app.ts serves
// them, on go/server/contracts. Each enters its Project as projectScope
// does (the Organization and its incident freeze, then the Project), and
// authorizes on the Project with existence hidden.

const (
	activeContractPattern   = "GET /v1/organizations/{org}/projects/{project}/contract"
	pushRevisionPattern     = "POST /v1/organizations/{org}/projects/{project}/contract/revisions"
	getRevisionPattern      = "GET /v1/organizations/{org}/projects/{project}/contract/revisions/{revision}"
	activateRevisionPattern = "POST /v1/organizations/{org}/projects/{project}/contract/revisions/{revision}/activate"
)

func init() {
	for _, p := range []string{activeContractPattern, pushRevisionPattern, getRevisionPattern, activateRevisionPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitGetActiveContractResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitPushContractRevisionResponse(w http.ResponseWriter) error     { return r.visit(w) }
func (r reply) VisitGetContractRevisionResponse(w http.ResponseWriter) error      { return r.visit(w) }
func (r reply) VisitActivateContractRevisionResponse(w http.ResponseWriter) error { return r.visit(w) }

// projectRequest is an orgRequest inside a Project (projectScope).
type projectRequest struct {
	*orgRequest
	project query.LiveProjectRow
	segs    []string
}

func (p *projectRequest) resource() authz.Resource {
	return authz.Resource{OrganizationID: p.org.ID, ProjectID: p.project.ID}
}

// enterProject is projectScope: the Organization as the request enters it
// (under the route's incident-freeze exception, "" for none), then the
// route's Project, live (RESOURCE_NOT_FOUND otherwise).
func (o *operations) enterProject(ctx context.Context, route, exception string) (*projectRequest, error) {
	q, err := o.enterRoute(ctx, route, exception)
	if err != nil {
		return nil, err
	}
	segs := strings.Split(strings.TrimPrefix(q.r.URL.Path, "/"), "/")
	project, err := query.New(o.s.opts.Auth.Store().Reader()).LiveProject(ctx, query.LiveProjectParams{OrganizationID: q.org.ID, SlugOrID: tryDecodeURIComponent(segs[4])})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domainerr.NotFound("Project")
	}
	if err != nil {
		return nil, err
	}
	return &projectRequest{orgRequest: q, project: project, segs: segs}, nil
}

func (p *projectRequest) activeID() string { return p.project.ActiveContractRevisionID.String }

// revisionReply answers a revision, then settles the request.
func (p *projectRequest) revisionReply(ctx context.Context, status int, rev query.ContractRevision, activeID string) (reply, error) {
	if err := p.settle(ctx); err != nil {
		return reply{}, err
	}
	body, err := contracts.RevisionJS(rev, activeID)
	if err != nil {
		return reply{}, err
	}
	return reply{status: status, body: body}, nil
}

// GetActiveContract is GET …/contract: the active revision, or
// RESOURCE_NOT_FOUND when the Project has none.
func (o *operations) GetActiveContract(ctx context.Context, _ api.GetActiveContractRequestObject) (api.GetActiveContractResponseObject, error) {
	p, err := o.enterProject(ctx, "/v1/organizations/:org/projects/:project/contract", "")
	if err != nil {
		return nil, err
	}
	if err := p.authorizeOn(ctx, "contract.read", p.resource()); err != nil {
		return nil, err
	}
	if p.activeID() == "" {
		return nil, domainerr.New("RESOURCE_NOT_FOUND", "No active Contract revision")
	}
	rev, err := contracts.Get(ctx, o.s.opts.Auth.Store().Reader(), p.project.ID, p.activeID())
	if err != nil {
		return nil, err
	}
	return p.revisionReply(ctx, http.StatusOK, rev, p.activeID())
}

// GetContractRevision is GET …/contract/revisions/{revision}: revisions are
// immutable and hold no values (ADR-0038 D6, D13).
func (o *operations) GetContractRevision(ctx context.Context, _ api.GetContractRevisionRequestObject) (api.GetContractRevisionResponseObject, error) {
	p, err := o.enterProject(ctx, "/v1/organizations/:org/projects/:project/contract/revisions/:revision", "")
	if err != nil {
		return nil, err
	}
	if err := p.authorizeOn(ctx, "contract.read", p.resource()); err != nil {
		return nil, err
	}
	rev, err := contracts.Get(ctx, o.s.opts.Auth.Store().Reader(), p.project.ID, tryDecodeURIComponent(p.segs[7]))
	if err != nil {
		return nil, err
	}
	return p.revisionReply(ctx, http.StatusOK, rev, p.activeID())
}

// PushContractRevision is POST …/contract/revisions: the body
// z.object({ contract: z.unknown(), provenance: z.record(z.string(), z.string()).optional() }),
// read with c.req.json() once authorization decided.
func (o *operations) PushContractRevision(ctx context.Context, _ api.PushContractRevisionRequestObject) (api.PushContractRevisionResponseObject, error) {
	p, err := o.enterProject(ctx, "/v1/organizations/:org/projects/:project/contract/revisions", "")
	if err != nil {
		return nil, err
	}
	if err := p.authorizeOn(ctx, "contract.submit", p.resource()); err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	obj, isObj := body.(jsvalue.Object)
	if !isObj {
		return nil, domainerr.New("VALIDATION_FAILED", "(root): Invalid input: expected object, received "+zodType(body))
	}
	// zod's issues in the schema's order: z.unknown() inside an object
	// still requires its key, then the record's members in key order.
	var issues []string
	input, present := obj.Get("contract")
	if !present {
		issues = append(issues, "contract: Invalid input: expected nonoptional, received undefined")
	}
	var provenance jsvalue.Object
	if v, present := obj.Get("provenance"); present {
		pv, ok := v.(jsvalue.Object)
		if ok {
			provenance = zodRecord(pv)
		} else {
			issues = append(issues, "provenance: Invalid input: expected record, received "+zodType(v))
		}
		for _, m := range provenance {
			if _, ok := m.Value.(string); !ok {
				issues = append(issues, "provenance."+m.Key+": Invalid input: expected string, received "+zodType(m.Value))
			}
		}
	}
	if len(issues) > 0 {
		return nil, domainerr.New("VALIDATION_FAILED", strings.Join(issues, "; "))
	}
	rev, reports, err := contracts.Push(ctx, o.s.opts.Writer, p.p, p.org.ID, p.project.ID, input, provenance)
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	p.checked, p.reports, p.at = true, reports, o.s.opts.Now().UnixMicro()
	return p.revisionReply(ctx, http.StatusCreated, rev, p.activeID())
}

// ActivateContractRevision is POST …/contract/revisions/{revision}/activate.
func (o *operations) ActivateContractRevision(ctx context.Context, _ api.ActivateContractRevisionRequestObject) (api.ActivateContractRevisionResponseObject, error) {
	p, err := o.enterProject(ctx, "/v1/organizations/:org/projects/:project/contract/revisions/:revision/activate", "")
	if err != nil {
		return nil, err
	}
	if err := p.authorizeOn(ctx, "contract.activate", p.resource()); err != nil {
		return nil, err
	}
	rev, reports, err := contracts.Activate(ctx, o.s.opts.Writer, p.p, p.org.ID, p.project.ID, tryDecodeURIComponent(p.segs[7]))
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	p.checked, p.reports, p.at = true, reports, o.s.opts.Now().UnixMicro()
	return p.revisionReply(ctx, http.StatusOK, rev, rev.ID)
}

// zodRecord is the object a z.record() checks and returns: zod skips a
// "__proto__" key (JSON.parse makes it an own member, but zod neither
// validates it nor copies it), so it is neither refused nor stored. The
// result is never nil: an object of no members is still one ({}).
func zodRecord(o jsvalue.Object) jsvalue.Object {
	out := jsvalue.Object{}
	for _, m := range o {
		if m.Key != "__proto__" {
			out = append(out, m)
		}
	}
	return out
}

// zodType is a JSON value's type as zod names it after "received".
func zodType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case jsvalue.Object:
		return "object"
	}
	return "unknown"
}
