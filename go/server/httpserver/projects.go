// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/environments"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/projects"
)

// Projects and environments (ADR-0059 step 4.1c): listProjects,
// createProject, getProject and renameProject, and listEnvironments,
// createEnvironment, getEnvironment and deleteEnvironment, as http/app.ts
// serves them, on go/server/projects and go/server/environments. Project
// deletion is step 4.12. The reads run while the Organization is frozen
// for an incident (inspection); the writes do not.

const (
	listProjectsPattern      = "GET /v1/organizations/{org}/projects"
	createProjectPattern     = "POST /v1/organizations/{org}/projects"
	getProjectPattern        = "GET /v1/organizations/{org}/projects/{project}"
	renameProjectPattern     = "PATCH /v1/organizations/{org}/projects/{project}"
	listEnvironmentsPattern  = "GET /v1/organizations/{org}/projects/{project}/environments"
	createEnvironmentPattern = "POST /v1/organizations/{org}/projects/{project}/environments"
	getEnvironmentPattern    = "GET /v1/organizations/{org}/projects/{project}/environments/{environment}"
	deleteEnvironmentPattern = "DELETE /v1/organizations/{org}/projects/{project}/environments/{environment}"

	projectsRoute     = "/v1/organizations/:org/projects"
	projectRoute      = "/v1/organizations/:org/projects/:project"
	environmentsRoute = "/v1/organizations/:org/projects/:project/environments"
	environmentRoute  = "/v1/organizations/:org/projects/:project/environments/:environment"
)

func init() {
	for _, p := range []string{createProjectPattern, renameProjectPattern, createEnvironmentPattern} {
		readsItself[p] = true
	}
}

func (r reply) VisitListProjectsResponse(w http.ResponseWriter) error      { return r.visit(w) }
func (r reply) VisitCreateProjectResponse(w http.ResponseWriter) error     { return r.visit(w) }
func (r reply) VisitGetProjectResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitRenameProjectResponse(w http.ResponseWriter) error     { return r.visit(w) }
func (r reply) VisitListEnvironmentsResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitCreateEnvironmentResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitGetEnvironmentResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitDeleteEnvironmentResponse(w http.ResponseWriter) error { return r.visit(w) }

// list is the API's list shape: the items, and no further page.
func list(items []any) jsvalue.Object {
	return jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: nil}}
}

// ListProjects is GET …/projects: inspection, project.read on the
// Organization.
func (o *operations) ListProjects(ctx context.Context, _ api.ListProjectsRequestObject) (api.ListProjectsResponseObject, error) {
	q, err := o.enterRoute(ctx, projectsRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "project.read"); err != nil {
		return nil, err
	}
	all, err := projects.List(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	if err != nil {
		return nil, err
	}
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	items := make([]any, len(all))
	for i, p := range all {
		items[i] = projects.JS(p)
	}
	return ok(list(items)), nil
}

// CreateProject is POST …/projects: project.manage on the Organization,
// then the body z.object({ name: z.string().min(1).max(200), slug:
// z.string(), contractAuthority: z.enum(["git", "managed"]) }).
func (o *operations) CreateProject(ctx context.Context, _ api.CreateProjectRequestObject) (api.CreateProjectResponseObject, error) {
	q, err := o.enterRoute(ctx, projectsRoute, "")
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "project.manage"); err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	if err := zodIssues([]bodyField{
		{name: "name", kind: kindString, required: true, min: 1, max: 200},
		{name: "slug", kind: kindString, required: true, min: 0, max: noLimit},
		{name: "contractAuthority", kind: kindEnum, required: true, options: []string{"git", "managed"}},
	}, body); err != nil {
		return nil, err
	}
	obj := body.(jsvalue.Object)
	name, _ := obj.Get("name")
	slug, _ := obj.Get("slug")
	authority, _ := obj.Get("contractAuthority")
	project, reports, err := projects.Create(ctx, o.s.opts.Writer, q.p, q.org.ID, slug.(string), name.(string), authority.(string), o.s.opts.Now)
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	q.checked, q.reports, q.at = true, reports, o.s.opts.Now().UnixMicro()
	if err := q.settle(ctx); err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: projects.JS(project)}, nil
}

// GetProject is GET …/projects/{project}: inspection, project.read on the
// Project.
func (o *operations) GetProject(ctx context.Context, _ api.GetProjectRequestObject) (api.GetProjectResponseObject, error) {
	p, err := o.enterProject(ctx, projectRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := p.authorizeOn(ctx, "project.read", p.resource()); err != nil {
		return nil, err
	}
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	return ok(projects.JS(p.project)), nil
}

// RenameProject is PATCH …/projects/{project}: the display name only
// (capability projects.rename), project.manage on the Project, then the
// body z.object({ name: z.string().min(1).max(200) }).
func (o *operations) RenameProject(ctx context.Context, _ api.RenameProjectRequestObject) (api.RenameProjectResponseObject, error) {
	p, err := o.enterProject(ctx, projectRoute, "")
	if err != nil {
		return nil, err
	}
	if err := p.authorizeOn(ctx, "project.manage", p.resource()); err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	if err := zodIssues([]bodyField{{name: "name", kind: kindString, required: true, min: 1, max: 200}}, body); err != nil {
		return nil, err
	}
	name, _ := body.(jsvalue.Object).Get("name")
	renamed, reports, err := projects.Rename(ctx, o.s.opts.Writer, p.p, p.org.ID, p.project.ID, name.(string))
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	p.checked, p.reports, p.at = true, reports, o.s.opts.Now().UnixMicro()
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	return ok(projects.JS(renamed)), nil
}

// envResource is envResource: an environment as authorization sees it.
func (p *projectRequest) envResource(e environments.Environment) authz.Resource {
	return authz.Resource{OrganizationID: p.org.ID, ProjectID: p.project.ID,
		Environment: &authz.Environment{ID: e.ID, RootID: environments.RootID(e), Tier: e.Tier}}
}

// environmentsOut is environmentsOut: environments as their callers see
// them. tailnetRequired says reading values there needs verified Tailnet
// Context, derived from the active Requirements with the evaluator's own
// targeting; the covering Requirements' IDs are policy, so only a caller
// holding policy.read gets them (decided, not authorized: a refusal is not
// recorded).
func (p *projectRequest) environmentsOut(ctx context.Context, envs []environments.Environment) ([]any, error) {
	reader := p.o.s.opts.Auth.Store().Reader()
	reqs, err := authz.LoadRequirements(ctx, reader, p.org.ID)
	if err != nil {
		return nil, err
	}
	covering := make([][]authz.Requirement, len(envs))
	covered := false
	for i, e := range envs {
		covering[i] = authz.RequirementsCovering(reqs, p.envResource(e))
		covered = covered || len(covering[i]) > 0
	}
	showIDs := false
	if covered {
		d, err := authz.Decide(ctx, reader, authzPrincipal(p.p), "policy.read", authz.Resource{OrganizationID: p.org.ID},
			authz.Options{RequestID: requestIDOf(p.r)})
		if err != nil {
			return nil, err
		}
		showIDs = d.Allowed
	}
	out := make([]any, len(envs))
	for i, e := range envs {
		js := append(environments.JS(e), jsvalue.Member{Key: "tailnetRequired", Value: len(covering[i]) > 0})
		if showIDs && len(covering[i]) > 0 {
			ids := make([]any, len(covering[i]))
			for j, r := range covering[i] {
				ids[j] = r.ID
			}
			js = append(js, jsvalue.Member{Key: "tailnetRequirementIds", Value: ids})
		}
		out[i] = js
	}
	return out, nil
}

// ListEnvironments is GET …/environments: inspection, project.read on the
// Project.
func (o *operations) ListEnvironments(ctx context.Context, _ api.ListEnvironmentsRequestObject) (api.ListEnvironmentsResponseObject, error) {
	p, err := o.enterProject(ctx, environmentsRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := p.authorizeOn(ctx, "project.read", p.resource()); err != nil {
		return nil, err
	}
	envs, err := environments.List(ctx, o.s.opts.Auth.Store().Reader(), p.project.ID)
	if err != nil {
		return nil, err
	}
	items, err := p.environmentsOut(ctx, envs)
	if err != nil {
		return nil, err
	}
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	return ok(list(items)), nil
}

// CreateEnvironment is POST …/environments: the body is parsed first,
// z.object({ name: z.string().min(1), tier: z.enum(TIERS).optional(), kind:
// z.enum(["shared", "personal", "preview"]).optional(), parentEnvironmentId:
// z.string().optional(), expiresAt: z.string().datetime().optional() });
// then a derived environment (a parentEnvironmentId that is not empty) is
// environment.manage on its parent, found first, and a root is
// project.manage on the Project.
func (o *operations) CreateEnvironment(ctx context.Context, _ api.CreateEnvironmentRequestObject) (api.CreateEnvironmentResponseObject, error) {
	p, err := o.enterProject(ctx, environmentsRoute, "")
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	if err := zodIssues([]bodyField{
		{name: "name", kind: kindString, required: true, min: 1, max: noLimit},
		{name: "tier", kind: kindEnum, options: contract.Tiers},
		{name: "kind", kind: kindEnum, options: []string{"shared", "personal", "preview"}},
		{name: "parentEnvironmentId", kind: kindString, min: 0, max: noLimit},
		{name: "expiresAt", kind: kindDatetime},
	}, body); err != nil {
		return nil, err
	}
	obj := body.(jsvalue.Object)
	field := func(key string) *string {
		if v, ok := obj.Get(key); ok {
			s := v.(string)
			return &s
		}
		return nil
	}
	name, _ := obj.Get("name")
	in := environments.Input{Name: name.(string), Tier: field("tier"), Kind: field("kind"), ParentEnvironmentID: field("parentEnvironmentId"), ExpiresAt: field("expiresAt")}
	if in.ParentEnvironmentID != nil && *in.ParentEnvironmentID != "" {
		parent, err := environments.Get(ctx, o.s.opts.Auth.Store().Reader(), p.project.ID, *in.ParentEnvironmentID)
		if err != nil {
			return nil, err
		}
		if err := p.authorizeOn(ctx, "environment.manage", p.envResource(parent)); err != nil {
			return nil, err
		}
	} else if err := p.authorizeOn(ctx, "project.manage", p.resource()); err != nil {
		return nil, err
	}
	env, reports, err := environments.Create(ctx, o.s.opts.Writer, p.p, p.org.ID, p.project.ID, in, o.s.opts.Now)
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	p.checked, p.reports, p.at = true, reports, o.s.opts.Now().UnixMicro()
	out, err := p.environmentsOut(ctx, []environments.Environment{env})
	if err != nil {
		return nil, err
	}
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: out[0]}, nil
}

// errEnvironmentParameter is decodeURIComponent's URIError: the TypeScript
// server's onError answers it as an internal error.
var errEnvironmentParameter = errors.New("httpserver: the environment parameter is not decodable")

// enterEnvironment is envScope: the Project, then the route's environment,
// its parameter decoded once more with decodeURIComponent (a malformed
// escape throws there: 500), live (RESOURCE_NOT_FOUND otherwise).
func (o *operations) enterEnvironment(ctx context.Context, route, exception string) (*projectRequest, environments.Environment, error) {
	p, err := o.enterProject(ctx, route, exception)
	if err != nil {
		return nil, environments.Environment{}, err
	}
	name, decodable := decodeURIComponent(tryDecodeURIComponent(p.segs[6]))
	if !decodable {
		return nil, environments.Environment{}, errEnvironmentParameter
	}
	env, err := environments.Get(ctx, o.s.opts.Auth.Store().Reader(), p.project.ID, name)
	if err != nil {
		return nil, environments.Environment{}, err
	}
	return p, env, nil
}

// GetEnvironment is GET …/environments/{environment}: inspection,
// environment.read on the environment.
func (o *operations) GetEnvironment(ctx context.Context, _ api.GetEnvironmentRequestObject) (api.GetEnvironmentResponseObject, error) {
	p, env, err := o.enterEnvironment(ctx, environmentRoute, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := p.authorizeOn(ctx, "environment.read", p.envResource(env)); err != nil {
		return nil, err
	}
	out, err := p.environmentsOut(ctx, []environments.Environment{env})
	if err != nil {
		return nil, err
	}
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	return ok(out[0]), nil
}

// DeleteEnvironment is DELETE …/environments/{environment} (ADR-0025):
// as creation, a derived environment is environment.manage on its context
// (its root's), a root project.manage; 204 without a body.
func (o *operations) DeleteEnvironment(ctx context.Context, _ api.DeleteEnvironmentRequestObject) (api.DeleteEnvironmentResponseObject, error) {
	p, env, err := o.enterEnvironment(ctx, environmentRoute, "")
	if err != nil {
		return nil, err
	}
	if env.ParentEnvironmentID.Valid {
		err = p.authorizeOn(ctx, "environment.manage", p.envResource(env))
	} else {
		err = p.authorizeOn(ctx, "project.manage", p.resource())
	}
	if err != nil {
		return nil, err
	}
	reports, err := environments.Delete(ctx, o.s.opts.Writer, o.s.opts.Auth.Store().Reader(), p.p, p.org.ID, p.project, env, o.s.opts.Now)
	if err != nil {
		return nil, p.refused(ctx, err)
	}
	p.checked, p.reports, p.at = true, reports, o.s.opts.Now().UnixMicro()
	if err := p.settle(ctx); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}
