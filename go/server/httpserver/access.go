// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"math"
	"net/http"

	"github.com/varlatch/varlatch/go/server/access"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/write"
)

// The access structure (ADR-0015, ADR-0028, ADR-0029; ADR-0059 step
// 4.4b): Grants, Roles, Groups and Teams, their memberships and
// Team-Project links, as http/app.ts serves them. Reading needs
// policy.read, as inspection while frozen; writing needs policy.manage,
// and every write is a protected operation (server/access).

const (
	listGrantsPattern        = "GET /v1/organizations/{org}/grants"
	createGrantPattern       = "POST /v1/organizations/{org}/grants"
	deleteGrantPattern       = "DELETE /v1/organizations/{org}/grants/{grant}"
	replaceGrantPattern      = "POST /v1/organizations/{org}/grants/{grant}/replace"
	listRolesPattern         = "GET /v1/organizations/{org}/roles"
	createRolePattern        = "POST /v1/organizations/{org}/roles"
	updateRolePattern        = "PATCH /v1/organizations/{org}/roles/{role}"
	deleteRolePattern        = "DELETE /v1/organizations/{org}/roles/{role}"
	listGroupsPattern        = "GET /v1/organizations/{org}/groups"
	createGroupPattern       = "POST /v1/organizations/{org}/groups"
	updateGroupPattern       = "PATCH /v1/organizations/{org}/groups/{group}"
	deleteGroupPattern       = "DELETE /v1/organizations/{org}/groups/{group}"
	listGroupMembersPattern  = "GET /v1/organizations/{org}/groups/{group}/members"
	addGroupMemberPattern    = "POST /v1/organizations/{org}/groups/{group}/members"
	removeGroupMemberPattern = "DELETE /v1/organizations/{org}/groups/{group}/members/{identity}"
	listTeamsPattern         = "GET /v1/organizations/{org}/teams"
	createTeamPattern        = "POST /v1/organizations/{org}/teams"
	updateTeamPattern        = "PATCH /v1/organizations/{org}/teams/{team}"
	deleteTeamPattern        = "DELETE /v1/organizations/{org}/teams/{team}"
	listTeamMembersPattern   = "GET /v1/organizations/{org}/teams/{team}/members"
	addTeamMemberPattern     = "POST /v1/organizations/{org}/teams/{team}/members"
	removeTeamMemberPattern  = "DELETE /v1/organizations/{org}/teams/{team}/members/{identity}"
	listTeamProjectsPattern  = "GET /v1/organizations/{org}/teams/{team}/projects"
	addTeamProjectPattern    = "POST /v1/organizations/{org}/teams/{team}/projects"
	removeTeamProjectPattern = "DELETE /v1/organizations/{org}/teams/{team}/projects/{project}"
)

func init() {
	for _, p := range []string{
		listGrantsPattern, createGrantPattern, deleteGrantPattern, replaceGrantPattern,
		listRolesPattern, createRolePattern, updateRolePattern, deleteRolePattern,
		listGroupsPattern, createGroupPattern, updateGroupPattern, deleteGroupPattern,
		listGroupMembersPattern, addGroupMemberPattern, removeGroupMemberPattern,
		listTeamsPattern, createTeamPattern, updateTeamPattern, deleteTeamPattern,
		listTeamMembersPattern, addTeamMemberPattern, removeTeamMemberPattern,
		listTeamProjectsPattern, addTeamProjectPattern, removeTeamProjectPattern,
	} {
		readsItself[p] = true
	}
}

func (r reply) VisitListGrantsResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitCreateGrantResponse(w http.ResponseWriter) error       { return r.visit(w) }
func (r reply) VisitDeleteGrantResponse(w http.ResponseWriter) error       { return r.visit(w) }
func (r reply) VisitReplaceGrantResponse(w http.ResponseWriter) error      { return r.visit(w) }
func (r reply) VisitListRolesResponse(w http.ResponseWriter) error         { return r.visit(w) }
func (r reply) VisitCreateRoleResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitUpdateRoleResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitDeleteRoleResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitListGroupsResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitCreateGroupResponse(w http.ResponseWriter) error       { return r.visit(w) }
func (r reply) VisitUpdateGroupResponse(w http.ResponseWriter) error       { return r.visit(w) }
func (r reply) VisitDeleteGroupResponse(w http.ResponseWriter) error       { return r.visit(w) }
func (r reply) VisitListGroupMembersResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitAddGroupMemberResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitRemoveGroupMemberResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitListTeamsResponse(w http.ResponseWriter) error         { return r.visit(w) }
func (r reply) VisitCreateTeamResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitUpdateTeamResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitDeleteTeamResponse(w http.ResponseWriter) error        { return r.visit(w) }
func (r reply) VisitListTeamMembersResponse(w http.ResponseWriter) error   { return r.visit(w) }
func (r reply) VisitAddTeamMemberResponse(w http.ResponseWriter) error     { return r.visit(w) }
func (r reply) VisitRemoveTeamMemberResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitListTeamProjectsResponse(w http.ResponseWriter) error  { return r.visit(w) }
func (r reply) VisitAddTeamProjectResponse(w http.ResponseWriter) error    { return r.visit(w) }
func (r reply) VisitRemoveTeamProjectResponse(w http.ResponseWriter) error { return r.visit(w) }

// zInt is z.number().int().min(min).
// zInt is z.number().int().min(min), with .max(max) when max is set.
type zInt struct{ min, max float64 }

func (z zInt) parse(v any, present bool, path []string) (any, []zIssue) {
	x, ok := v.(float64)
	if !present || !ok || math.IsInf(x, 0) || math.IsNaN(x) {
		return nil, []zIssue{{path, "Invalid input: expected number, received " + received(v, present), true}}
	}
	if x != math.Trunc(x) {
		return nil, []zIssue{{path, "Invalid input: expected int, received number", true}}
	}
	var issues []zIssue
	if x > maxSafeInt {
		issues = append(issues, zIssue{path, "Too big: expected int to be <=9007199254740991", false})
	}
	if x < -maxSafeInt {
		issues = append(issues, zIssue{path, "Too small: expected int to be >=-9007199254740991", false})
	}
	if x < z.min {
		issues = append(issues, zIssue{path, "Too small: expected number to be >=" + jsvalue.Number(z.min), false})
	}
	if z.max != 0 && x > z.max {
		issues = append(issues, zIssue{path, "Too big: expected number to be <=" + jsvalue.Number(z.max), false})
	}
	return x, issues
}

var tiers = zEnum{"development", "staging", "production"}

// grantBody is grantBodySchema: a complete Grant declaration, shared by
// create and replace.
var grantBody = zObject{
	{name: "subjectIdentityId", schema: zString{}, optional: true},
	{name: "subjectGroupId", schema: zString{}, optional: true},
	{name: "scope", schema: zUnion{
		zObject{{name: "kind", schema: zLiteral("organization")}},
		zObject{{name: "kind", schema: zLiteral("project")}, {name: "projectId", schema: zString{}}},
		zObject{{name: "kind", schema: zLiteral("environments")}, {name: "projectId", schema: zString{}}, {name: "selector", schema: zUnion{
			zObject{{name: "kind", schema: zLiteral("environments")}, {name: "environmentIds", schema: zArray{element: zString{}, min: 1}}},
			zObject{{name: "kind", schema: zLiteral("tier")}, {name: "tier", schema: tiers}},
		}}},
		zObject{{name: "kind", schema: zLiteral("team")}, {name: "teamId", schema: zString{}}},
	}},
	{name: "actions", schema: zArray{element: zString{}, min: 1}, optional: true},
	{name: "roleId", schema: zString{}, optional: true},
}

func optionalString(o jsvalue.Object, key string) *string {
	v, ok := o.Get(key)
	if !ok {
		return nil
	}
	s := v.(string)
	return &s
}

func stringArray(v any) []string {
	list := v.([]any)
	out := make([]string, len(list))
	for i, e := range list {
		out[i] = e.(string)
	}
	return out
}

// grantInput reads the body as grantBodySchema and requireOneOfEach do.
func grantInput(ctx context.Context) (access.Input, error) {
	body, err := jsonBody(ctx)
	if err != nil {
		return access.Input{}, err
	}
	out, err := zParse(grantBody, body)
	if err != nil {
		return access.Input{}, err
	}
	obj := out.(jsvalue.Object)
	scope, _ := obj.Get("scope")
	d := access.Declaration{
		SubjectIdentityID: optionalString(obj, "subjectIdentityId"), SubjectGroupID: optionalString(obj, "subjectGroupId"),
		Scope: scope.(jsvalue.Object), RoleID: optionalString(obj, "roleId"),
	}
	if a, ok := obj.Get("actions"); ok {
		d.Actions = stringArray(a)
	}
	truthy := func(s *string) int {
		if s != nil && *s != "" {
			return 1
		}
		return 0
	}
	if truthy(d.SubjectIdentityID)+truthy(d.SubjectGroupID) != 1 {
		return access.Input{}, domainerr.New("VALIDATION_FAILED", "Provide exactly one of subjectIdentityId or subjectGroupId")
	}
	hasActions := 0
	if d.Actions != nil {
		hasActions = 1
	}
	if hasActions+truthy(d.RoleID) != 1 {
		return access.Input{}, domainerr.New("VALIDATION_FAILED", "Provide exactly one of actions or roleId")
	}
	return access.Input{Declaration: d, Body: obj}, nil
}

func (q *orgRequest) accessRequest(ctx context.Context) access.Request {
	return access.Request{Principal: q.p, Approval: approvalHeaderOf(ctx), RequestID: requestIDOf(q.r), IdempotencyKey: q.r.Header.Get("Idempotency-Key")}
}

// policyRead is policyRead: inspection while frozen, policy.read.
func (o *operations) policyRead(ctx context.Context, route string) (*orgRequest, error) {
	q, err := o.enterRoute(ctx, route, authz.DuringFreezeInspection)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "policy.read"); err != nil {
		return nil, err
	}
	return q, nil
}

// policyManage is policyManage: policy.manage (no freeze exception, but a
// Grant's revocation's recovery).
func (o *operations) policyManage(ctx context.Context, route, exception string) (*orgRequest, error) {
	q, err := o.enterRoute(ctx, route, exception)
	if err != nil {
		return nil, err
	}
	if err := q.authorize(ctx, "policy.manage"); err != nil {
		return nil, err
	}
	return q, nil
}

func listed(items []any) reply {
	return ok(jsvalue.Object{{Key: "items", Value: items}, {Key: "nextCursor", Value: nil}})
}

// readList answers a policy.read list.
func (o *operations) readList(ctx context.Context, route string, read func(q *orgRequest) ([]any, error)) (reply, error) {
	q, err := o.policyRead(ctx, route)
	if err != nil {
		return reply{}, err
	}
	items, err := read(q)
	if err != nil {
		return reply{}, err
	}
	if err := q.settle(ctx); err != nil {
		return reply{}, err
	}
	return listed(items), nil
}

const grantsRoute = "/v1/organizations/:org/grants"

// ListGrants is GET …/grants: the live Grants, oldest first.
func (o *operations) ListGrants(ctx context.Context, _ api.ListGrantsRequestObject) (api.ListGrantsResponseObject, error) {
	return o.readList(ctx, grantsRoute, func(q *orgRequest) ([]any, error) {
		return access.Grants(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	})
}

// CreateGrant is POST …/grants: policy.manage, the declaration, then the
// protected operation (grant.create). 201.
func (o *operations) CreateGrant(ctx context.Context, _ api.CreateGrantRequestObject) (api.CreateGrantResponseObject, error) {
	q, err := o.policyManage(ctx, grantsRoute, "")
	if err != nil {
		return nil, err
	}
	in, err := grantInput(ctx)
	if err != nil {
		return nil, err
	}
	type result struct {
		out     jsvalue.Object
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := access.CreateGrant(ctx, o.s.opts.Writer, o.s.opts.Auth, q.accessRequest(ctx), q.org.ID, in.Declaration, o.s.opts.Now)
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: res.out}, nil
}

// DeleteGrant is DELETE …/grants/{grant}: recovery while frozen,
// policy.manage, the protected operation (grant.revoke). 204.
func (o *operations) DeleteGrant(ctx context.Context, _ api.DeleteGrantRequestObject) (api.DeleteGrantResponseObject, error) {
	q, err := o.policyManage(ctx, grantsRoute+"/:grant", authz.DuringFreezeRecovery)
	if err != nil {
		return nil, err
	}
	grantID := pathSegment(q.r, 4)
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return access.RevokeGrant(ctx, o.s.opts.Writer, o.s.opts.Auth, q.accessRequest(ctx), q.org.ID, grantID, o.s.opts.Now)
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

// idempotentReply answers a write's response, stored or not.
func idempotentReply(resp write.Response) reply {
	return reply{status: resp.Status, body: resp.Payload}
}

// ReplaceGrant is POST …/grants/{grant}/replace (ADR-0029):
// policy.manage, the declaration, then the protected operation
// (grant.replace) under an Idempotency-Key. 201.
func (o *operations) ReplaceGrant(ctx context.Context, _ api.ReplaceGrantRequestObject) (api.ReplaceGrantResponseObject, error) {
	q, err := o.policyManage(ctx, grantsRoute+"/:grant/replace", "")
	if err != nil {
		return nil, err
	}
	in, err := grantInput(ctx)
	if err != nil {
		return nil, err
	}
	grantID := pathSegment(q.r, 4)
	type result struct {
		resp    write.Response
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		resp, reports, err := access.ReplaceGrant(ctx, o.s.opts.Writer, o.s.opts.Auth, o.s.opts.RootKEK, q.accessRequest(ctx), q.org.ID, grantID, in, o.s.opts.Now)
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

const (
	rolesRoute  = "/v1/organizations/:org/roles"
	groupsRoute = "/v1/organizations/:org/groups"
	teamsRoute  = "/v1/organizations/:org/teams"
)

// ListRoles is GET …/roles: the live roles, by name.
func (o *operations) ListRoles(ctx context.Context, _ api.ListRolesRequestObject) (api.ListRolesResponseObject, error) {
	return o.readList(ctx, rolesRoute, func(q *orgRequest) ([]any, error) {
		return access.Roles(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID)
	})
}

var roleCreateBody = zObject{
	{name: "name", schema: zString{min: 1, max: 200}},
	{name: "actions", schema: zArray{element: zString{}, min: 1}},
}

// CreateRole is POST …/roles: policy.manage, the body z.object({ name:
// z.string().min(1).max(200), actions: z.array(z.string()).min(1) }), then
// the protected operation (role.create). 201.
func (o *operations) CreateRole(ctx context.Context, _ api.CreateRoleRequestObject) (api.CreateRoleResponseObject, error) {
	q, err := o.policyManage(ctx, rolesRoute, "")
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(roleCreateBody, body)
	if err != nil {
		return nil, err
	}
	obj := parsed.(jsvalue.Object)
	name, _ := obj.Get("name")
	actions, _ := obj.Get("actions")
	type result struct {
		out     jsvalue.Object
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := access.CreateRole(ctx, o.s.opts.Writer, o.s.opts.Auth, q.accessRequest(ctx), q.org.ID, name.(string), stringArray(actions), o.s.opts.Now)
		return result{out, reports}, err
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusCreated, body: res.out}, nil
}

var roleUpdateBody = zObject{
	{name: "expectedVersion", schema: zInt{min: 1}},
	{name: "name", schema: zString{min: 1, max: 200}, optional: true},
	{name: "actions", schema: zArray{element: zString{}, min: 1}, optional: true},
}

// UpdateRole is PATCH …/roles/{role}: policy.manage, the body, then the
// protected operation (role.update) under an Idempotency-Key.
func (o *operations) UpdateRole(ctx context.Context, _ api.UpdateRoleRequestObject) (api.UpdateRoleResponseObject, error) {
	q, err := o.policyManage(ctx, rolesRoute+"/:role", "")
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(roleUpdateBody, body)
	if err != nil {
		return nil, err
	}
	obj := parsed.(jsvalue.Object)
	version, _ := obj.Get("expectedVersion")
	patch := access.RolePatch{ExpectedVersion: int64(version.(float64)), Name: optionalString(obj, "name"), Body: obj}
	if a, ok := obj.Get("actions"); ok {
		patch.Actions = stringArray(a)
	}
	roleID := pathSegment(q.r, 4)
	type result struct {
		resp    write.Response
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		resp, reports, err := access.UpdateRole(ctx, o.s.opts.Writer, o.s.opts.Auth, o.s.opts.RootKEK, q.accessRequest(ctx), q.org.ID, roleID, patch, o.s.opts.Now)
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

// DeleteRole is DELETE …/roles/{role}: policy.manage, the protected
// operation (role.delete). 204.
func (o *operations) DeleteRole(ctx context.Context, _ api.DeleteRoleRequestObject) (api.DeleteRoleResponseObject, error) {
	q, err := o.policyManage(ctx, rolesRoute+"/:role", "")
	if err != nil {
		return nil, err
	}
	roleID := pathSegment(q.r, 4)
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return access.DeleteRole(ctx, o.s.opts.Writer, o.s.opts.Auth, q.accessRequest(ctx), q.org.ID, roleID, o.s.opts.Now)
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

func (o *operations) listGroups(ctx context.Context, route, kind string) (reply, error) {
	return o.readList(ctx, route, func(q *orgRequest) ([]any, error) {
		return access.Groups(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID, kind)
	})
}

var groupCreateBody = zObject{{name: "name", schema: zString{min: 1, max: 200}}}

// createGroup is createGroupRoute.
func (o *operations) createGroup(ctx context.Context, route, kind string) (reply, error) {
	q, err := o.policyManage(ctx, route, "")
	if err != nil {
		return reply{}, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return reply{}, err
	}
	parsed, err := zParse(groupCreateBody, body)
	if err != nil {
		return reply{}, err
	}
	name, _ := parsed.(jsvalue.Object).Get("name")
	type result struct {
		out     jsvalue.Object
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		out, reports, err := access.CreateGroup(ctx, o.s.opts.Writer, o.s.opts.Auth, q.accessRequest(ctx), q.org.ID, name.(string), kind, o.s.opts.Now)
		return result{out, reports}, err
	})
	if err != nil {
		return reply{}, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return reply{}, err
	}
	return reply{status: http.StatusCreated, body: res.out}, nil
}

var groupUpdateBody = zObject{
	{name: "expectedVersion", schema: zInt{min: 1}},
	{name: "name", schema: zString{min: 1, max: 200}, optional: true},
}

// updateGroup is updateGroupRoute.
func (o *operations) updateGroup(ctx context.Context, route, kind string) (reply, error) {
	q, err := o.policyManage(ctx, route, "")
	if err != nil {
		return reply{}, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return reply{}, err
	}
	parsed, err := zParse(groupUpdateBody, body)
	if err != nil {
		return reply{}, err
	}
	obj := parsed.(jsvalue.Object)
	version, _ := obj.Get("expectedVersion")
	patch := access.GroupPatch{ExpectedVersion: int64(version.(float64)), Name: optionalString(obj, "name"), Body: obj}
	id := pathSegment(q.r, 4)
	type result struct {
		resp    write.Response
		reports []auth.PendingReport
	}
	res, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() (result, error) {
		resp, reports, err := access.UpdateGroup(ctx, o.s.opts.Writer, o.s.opts.Auth, o.s.opts.RootKEK, q.accessRequest(ctx), q.org.ID, id, kind, patch, o.s.opts.Now)
		return result{resp, reports}, err
	})
	if err != nil {
		return reply{}, q.refused(ctx, err)
	}
	if err := q.written(ctx, res.reports); err != nil {
		return reply{}, err
	}
	return idempotentReply(res.resp), nil
}

// deleteGroup is deleteGroupRoute: the stored kind decides group or team.
func (o *operations) deleteGroup(ctx context.Context, route string) (reply, error) {
	q, err := o.policyManage(ctx, route, "")
	if err != nil {
		return reply{}, err
	}
	id := pathSegment(q.r, 4)
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return access.DeleteGroup(ctx, o.s.opts.Writer, o.s.opts.Auth, q.accessRequest(ctx), q.org.ID, id, o.s.opts.Now)
	})
	if err != nil {
		return reply{}, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return reply{}, err
	}
	return reply{status: http.StatusNoContent}, nil
}

func (o *operations) listMembers(ctx context.Context, route string) (reply, error) {
	return o.readList(ctx, route, func(q *orgRequest) ([]any, error) {
		return access.Members(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID, pathSegment(q.r, 4))
	})
}

var memberBody = zObject{{name: "identityId", schema: zString{}}}

// addMember is addMemberRoute.
func (o *operations) addMember(ctx context.Context, route string) (reply, error) {
	q, err := o.policyManage(ctx, route, "")
	if err != nil {
		return reply{}, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return reply{}, err
	}
	parsed, err := zParse(memberBody, body)
	if err != nil {
		return reply{}, err
	}
	identityID, _ := parsed.(jsvalue.Object).Get("identityId")
	groupID := pathSegment(q.r, 4)
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return access.AddMember(ctx, o.s.opts.Writer, o.s.opts.Auth, q.accessRequest(ctx), q.org.ID, groupID, identityID.(string), o.s.opts.Now)
	})
	if err != nil {
		return reply{}, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return reply{}, err
	}
	return reply{status: http.StatusNoContent}, nil
}

// removeMember is removeMemberRoute.
func (o *operations) removeMember(ctx context.Context, route string) (reply, error) {
	q, err := o.policyManage(ctx, route, "")
	if err != nil {
		return reply{}, err
	}
	groupID, identityID := pathSegment(q.r, 4), pathSegment(q.r, 6)
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return access.RemoveMember(ctx, o.s.opts.Writer, o.s.opts.Auth, q.accessRequest(ctx), q.org.ID, groupID, identityID, o.s.opts.Now)
	})
	if err != nil {
		return reply{}, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return reply{}, err
	}
	return reply{status: http.StatusNoContent}, nil
}

// ListGroups is GET …/groups.
func (o *operations) ListGroups(ctx context.Context, _ api.ListGroupsRequestObject) (api.ListGroupsResponseObject, error) {
	return o.listGroups(ctx, groupsRoute, "group")
}

// CreateGroup is POST …/groups.
func (o *operations) CreateGroup(ctx context.Context, _ api.CreateGroupRequestObject) (api.CreateGroupResponseObject, error) {
	return o.createGroup(ctx, groupsRoute, "group")
}

// UpdateGroup is PATCH …/groups/{group}.
func (o *operations) UpdateGroup(ctx context.Context, _ api.UpdateGroupRequestObject) (api.UpdateGroupResponseObject, error) {
	return o.updateGroup(ctx, groupsRoute+"/:group", "group")
}

// DeleteGroup is DELETE …/groups/{group}.
func (o *operations) DeleteGroup(ctx context.Context, _ api.DeleteGroupRequestObject) (api.DeleteGroupResponseObject, error) {
	return o.deleteGroup(ctx, groupsRoute+"/:group")
}

// ListGroupMembers is GET …/groups/{group}/members.
func (o *operations) ListGroupMembers(ctx context.Context, _ api.ListGroupMembersRequestObject) (api.ListGroupMembersResponseObject, error) {
	return o.listMembers(ctx, groupsRoute+"/:group/members")
}

// AddGroupMember is POST …/groups/{group}/members.
func (o *operations) AddGroupMember(ctx context.Context, _ api.AddGroupMemberRequestObject) (api.AddGroupMemberResponseObject, error) {
	return o.addMember(ctx, groupsRoute+"/:group/members")
}

// RemoveGroupMember is DELETE …/groups/{group}/members/{identity}.
func (o *operations) RemoveGroupMember(ctx context.Context, _ api.RemoveGroupMemberRequestObject) (api.RemoveGroupMemberResponseObject, error) {
	return o.removeMember(ctx, groupsRoute+"/:group/members/:identity")
}

// ListTeams is GET …/teams.
func (o *operations) ListTeams(ctx context.Context, _ api.ListTeamsRequestObject) (api.ListTeamsResponseObject, error) {
	return o.listGroups(ctx, teamsRoute, "team")
}

// CreateTeam is POST …/teams.
func (o *operations) CreateTeam(ctx context.Context, _ api.CreateTeamRequestObject) (api.CreateTeamResponseObject, error) {
	return o.createGroup(ctx, teamsRoute, "team")
}

// UpdateTeam is PATCH …/teams/{team}.
func (o *operations) UpdateTeam(ctx context.Context, _ api.UpdateTeamRequestObject) (api.UpdateTeamResponseObject, error) {
	return o.updateGroup(ctx, teamsRoute+"/:team", "team")
}

// DeleteTeam is DELETE …/teams/{team}.
func (o *operations) DeleteTeam(ctx context.Context, _ api.DeleteTeamRequestObject) (api.DeleteTeamResponseObject, error) {
	return o.deleteGroup(ctx, teamsRoute+"/:team")
}

// ListTeamMembers is GET …/teams/{team}/members.
func (o *operations) ListTeamMembers(ctx context.Context, _ api.ListTeamMembersRequestObject) (api.ListTeamMembersResponseObject, error) {
	return o.listMembers(ctx, teamsRoute+"/:team/members")
}

// AddTeamMember is POST …/teams/{team}/members.
func (o *operations) AddTeamMember(ctx context.Context, _ api.AddTeamMemberRequestObject) (api.AddTeamMemberResponseObject, error) {
	return o.addMember(ctx, teamsRoute+"/:team/members")
}

// RemoveTeamMember is DELETE …/teams/{team}/members/{identity}.
func (o *operations) RemoveTeamMember(ctx context.Context, _ api.RemoveTeamMemberRequestObject) (api.RemoveTeamMemberResponseObject, error) {
	return o.removeMember(ctx, teamsRoute+"/:team/members/:identity")
}

// ListTeamProjects is GET …/teams/{team}/projects.
func (o *operations) ListTeamProjects(ctx context.Context, _ api.ListTeamProjectsRequestObject) (api.ListTeamProjectsResponseObject, error) {
	return o.readList(ctx, teamsRoute+"/:team/projects", func(q *orgRequest) ([]any, error) {
		return access.TeamProjects(ctx, o.s.opts.Auth.Store().Reader(), q.org.ID, pathSegment(q.r, 4))
	})
}

var teamProjectBody = zObject{{name: "projectId", schema: zString{}}}

// AddTeamProject is POST …/teams/{team}/projects: policy.manage, the body
// z.object({ projectId: z.string() }), the protected operation
// (team.project_add). 204.
func (o *operations) AddTeamProject(ctx context.Context, _ api.AddTeamProjectRequestObject) (api.AddTeamProjectResponseObject, error) {
	q, err := o.policyManage(ctx, teamsRoute+"/:team/projects", "")
	if err != nil {
		return nil, err
	}
	body, err := jsonBody(ctx)
	if err != nil {
		return nil, err
	}
	parsed, err := zParse(teamProjectBody, body)
	if err != nil {
		return nil, err
	}
	projectID, _ := parsed.(jsvalue.Object).Get("projectId")
	teamID := pathSegment(q.r, 4)
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return access.AddTeamProject(ctx, o.s.opts.Writer, o.s.opts.Auth, q.accessRequest(ctx), q.org.ID, teamID, projectID.(string), o.s.opts.Now)
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}

// RemoveTeamProject is DELETE …/teams/{team}/projects/{project}. 204.
func (o *operations) RemoveTeamProject(ctx context.Context, _ api.RemoveTeamProjectRequestObject) (api.RemoveTeamProjectResponseObject, error) {
	q, err := o.policyManage(ctx, teamsRoute+"/:team/projects/:project", "")
	if err != nil {
		return nil, err
	}
	teamID, projectID := pathSegment(q.r, 4), pathSegment(q.r, 6)
	reports, err := security.WithApproval(ctx, o.s.opts.Auth, auth.RequesterOf(q.p), func() ([]auth.PendingReport, error) {
		return access.RemoveTeamProject(ctx, o.s.opts.Writer, o.s.opts.Auth, q.accessRequest(ctx), q.org.ID, teamID, projectID, o.s.opts.Now)
	})
	if err != nil {
		return nil, q.refused(ctx, err)
	}
	if err := q.written(ctx, reports); err != nil {
		return nil, err
	}
	return reply{status: http.StatusNoContent}, nil
}
