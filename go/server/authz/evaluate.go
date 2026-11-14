// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authz is the authorization evaluator (ADR-0015), a port of the
// TypeScript server's authz/evaluate.ts, with what it reads loaded as
// http/support.ts loads it (roles, groups and teams expanded, ADR-0028;
// decision-time provenance, ADR-0029 §6), the decision layer around it
// (decide: existence hiding, denial classes and the denial's audit event),
// and the incident freeze at the points the TypeScript server checks it
// (ADR-0055). Shared vectors exported from the TypeScript code
// (testdata/ts-vectors.json) hold every decision and reason to it.
//
// Roles expand into implied Grants, union with explicit Grants, default
// deny; Requirements then restrict. Grants permit; Requirements restrict;
// neither ever does the other's job. Rights are evaluated per request
// against current state: the caller loads it, Evaluate only decides.
package authz

import (
	"slices"

	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Organization roles.
const (
	Admin  = "admin"
	Member = "member"
)

// Denial classes.
const (
	NoGrant           = "no-grant"
	RequirementFailed = "requirement-failed"
)

// Actions is every action the Organization Admin bundle holds, in the
// TypeScript server's order (ALL_ORG_ACTIONS).
var Actions = []string{
	"organization.read",
	"organization.manage",
	"project.read",
	"project.manage",
	"environment.read",
	"environment.manage",
	"config.metadata.read",
	"config.value.read",
	"config.value.write",
	"secret.reveal",
	"secret.use",
	"contract.read",
	"contract.submit",
	"contract.activate",
	"identity.read",
	"identity.manage",
	"policy.read",
	"policy.manage",
	"audit.read",
	"config.sync.manage",
}

// tailnetConstrained are the retrieval and reveal actions Requirements
// constrain.
var tailnetConstrained = []string{"config.value.read", "secret.reveal", "secret.use"}

// Selector picks a Project's Environments for an environments scope: by
// ID (Kind "environments") or by tier (Kind "tier").
type Selector struct {
	Kind           string   `json:"kind"`
	EnvironmentIDs []string `json:"environmentIds,omitempty"`
	Tier           string   `json:"tier,omitempty"`
}

// Scope is a Grant's scope: "organization", "project", "environments" or
// "team". A team scope is expanded to project scopes by LoadGrants, so a
// raw one never matches (fail closed).
type Scope struct {
	Kind      string    `json:"kind"`
	ProjectID string    `json:"projectId,omitempty"`
	Selector  *Selector `json:"selector,omitempty"`
	TeamID    string    `json:"teamId,omitempty"`
}

// Grant is a GrantRecord: one flat Grant the evaluator consumes.
type Grant struct {
	ID                string
	SubjectIdentityID string
	Scope             Scope
	// Actions may hold null elements (a text[] may); they match nothing.
	Actions []*string
	// ViaGroupID is the Group whose membership pulled this Grant in.
	ViaGroupID string
	// RoleID is the Role its actions were expanded from.
	RoleID string
	// RoleVersion is the Role's version at load time (ADR-0029 §6).
	RoleVersion *int64
}

// Environment is the Environment a resource is in.
type Environment struct {
	ID string
	// RootID is the root environment's ID (its own for a root).
	RootID string
	Tier   string
}

// Resource is what an action targets, resolved by the caller. An empty
// ProjectID is no Project.
type Resource struct {
	OrganizationID string
	ProjectID      string
	Environment    *Environment
}

// Target is the resources a Requirement targets: a tier (Kind "tier") or
// Environments (Kind "environments").
type Target struct {
	Kind           string   `json:"kind"`
	Tier           string   `json:"tier,omitempty"`
	EnvironmentIDs []string `json:"environmentIds,omitempty"`
}

// TailnetSelector is which tailnet identities satisfy a Requirement. A nil
// list is absent (undefined).
type TailnetSelector struct {
	Tailnet string   `json:"tailnet"`
	Tags    []string `json:"tags,omitempty"`
	Users   []string `json:"users,omitempty"`
	Nodes   []string `json:"nodes,omitempty"`
}

// Requirement is a tailnet Requirement.
type Requirement struct {
	ID string
	// Version is the Requirement's version at load time (ADR-0029 §6).
	Version  *int64
	Target   Target
	Selector TailnetSelector
}

// TailnetContext is a verified Tailnet Context (ADR-0014), built only from
// the tailnet listener.
type TailnetContext struct {
	Tailnet string
	NodeID  string
	// NodeName is the device's machine name, for people reading audit;
	// never matched by a selector.
	NodeName  *string
	Tags      []string
	UserLogin *string
}

// Outcome is one Requirement's outcome: satisfied By a node, tag or user,
// or not, for a Reason.
type Outcome struct {
	RequirementID      string
	RequirementVersion *int64
	Satisfied          bool
	By                 string
	Reason             string
}

// JSValue is the outcome as the TypeScript server builds it.
func (o Outcome) JSValue() any {
	v := jsvalue.Object{{Key: "requirementId", Value: o.RequirementID}}
	if o.RequirementVersion != nil {
		v = append(v, jsvalue.Member{Key: "requirementVersion", Value: *o.RequirementVersion})
	}
	v = append(v, jsvalue.Member{Key: "satisfied", Value: o.Satisfied})
	if o.Satisfied {
		return append(v, jsvalue.Member{Key: "by", Value: o.By})
	}
	return append(v, jsvalue.Member{Key: "reason", Value: o.Reason})
}

// Applied is the decision-time snapshot of one applied Grant's mutable
// facts (ADR-0029 §6): Roles are editable and Group membership is
// unversioned, so audit records the facts the evaluator consumed.
type Applied struct {
	GrantID     string
	Actions     []*string
	ViaGroupID  string
	RoleID      string
	RoleVersion *int64
}

// JSValue is the snapshot as the TypeScript server builds it.
func (a Applied) JSValue() any {
	v := jsvalue.Object{{Key: "grantId", Value: a.GrantID}, {Key: "actions", Value: actionsValue(a.Actions)}}
	if a.ViaGroupID != "" {
		v = append(v, jsvalue.Member{Key: "viaGroupId", Value: a.ViaGroupID})
	}
	if a.RoleID != "" {
		v = append(v, jsvalue.Member{Key: "roleId", Value: a.RoleID})
	}
	if a.RoleVersion != nil {
		v = append(v, jsvalue.Member{Key: "roleVersion", Value: *a.RoleVersion})
	}
	return v
}

func actionsValue(actions []*string) []any {
	out := make([]any, len(actions))
	for i, a := range actions {
		if a != nil {
			out[i] = *a
		}
	}
	return out
}

// Provenance is why an evaluation came out as it did.
type Provenance struct {
	// Role is the built-in role, when it allowed the action.
	Role     string
	GrantIDs []string
	// GroupIDs are the Groups whose membership contributed an applied Grant.
	GroupIDs []string
	// RoleIDs are the Roles an applied Grant was expanded from.
	RoleIDs []string
	Applied []Applied
}

// JSValue is the provenance as the TypeScript server builds it.
func (p Provenance) JSValue() any {
	var v jsvalue.Object
	if p.Role != "" {
		v = append(v, jsvalue.Member{Key: "role", Value: p.Role})
	}
	v = append(v, jsvalue.Member{Key: "grantIds", Value: nonNil(p.GrantIDs)})
	if len(p.GroupIDs) > 0 {
		v = append(v, jsvalue.Member{Key: "groupIds", Value: p.GroupIDs})
	}
	if len(p.RoleIDs) > 0 {
		v = append(v, jsvalue.Member{Key: "roleIds", Value: p.RoleIDs})
	}
	if len(p.Applied) > 0 {
		v = append(v, jsvalue.Member{Key: "applied", Value: appliedValue(p.Applied)})
	}
	return v
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func appliedValue(a []Applied) []any {
	out := make([]any, len(a))
	for i, x := range a {
		out[i] = x
	}
	return out
}

func outcomesValue(o []Outcome) []any {
	out := make([]any, len(o))
	for i, x := range o {
		out[i] = x
	}
	return out
}

// Evaluation is an evaluation's result.
type Evaluation struct {
	Allowed bool
	// Denial is the denial class, when not Allowed.
	Denial       string
	Provenance   Provenance
	Requirements []Outcome
}

// JSValue is the evaluation as the TypeScript server builds it.
func (e Evaluation) JSValue() any {
	v := jsvalue.Object{{Key: "allowed", Value: e.Allowed}}
	if e.Denial != "" {
		v = append(v, jsvalue.Member{Key: "denial", Value: e.Denial})
	}
	return append(v,
		jsvalue.Member{Key: "provenance", Value: e.Provenance},
		jsvalue.Member{Key: "requirements", Value: outcomesValue(e.Requirements)})
}

// Input is what Evaluate decides on.
type Input struct {
	Action   string
	Resource Resource
	// OrgRole is the subject's role in the resource's Organization, if a
	// person with a live membership; "" otherwise.
	OrgRole string
	// Grants are the subject's unrevoked Grants in the Organization.
	Grants []Grant
	// Requirements are the Organization's active tailnet Requirements.
	Requirements []Requirement
	// TailnetContext is nil when the request has none.
	TailnetContext *TailnetContext
}

// memberAllows is the fixed Organization Member bundle (ADR-0015 §5):
// development, broad mutation; staging, broad consumption and explicit
// mutation; production, existence and navigation metadata only.
func memberAllows(action string, r Resource) bool {
	switch action {
	case "organization.read", "project.read", "contract.read":
		return true
	}
	if r.Environment == nil || r.Environment.Tier == "" {
		return false
	}
	switch r.Environment.Tier {
	case "development":
		switch action {
		case "environment.read", "environment.manage", "config.metadata.read", "config.value.read", "config.value.write", "secret.reveal":
			return true
		}
	case "staging":
		switch action {
		case "environment.read", "config.metadata.read", "config.value.read", "secret.reveal":
			return true
		}
	case "production":
		return action == "environment.read" || action == "config.metadata.read"
	}
	return false
}

func hasAction(actions []*string, action string) bool {
	for _, a := range actions {
		if a != nil && *a == action {
			return true
		}
	}
	return false
}

func grantApplies(g Grant, action string, r Resource) bool {
	if !hasAction(g.Actions, action) {
		return false
	}
	switch g.Scope.Kind {
	case "organization":
		return true
	case "project":
		return r.ProjectID == g.Scope.ProjectID
	case "environments":
		if r.ProjectID != g.Scope.ProjectID || r.Environment == nil || g.Scope.Selector == nil {
			return false
		}
		sel := g.Scope.Selector
		if sel.Kind == "tier" {
			return r.Environment.Tier == sel.Tier
		}
		// An explicit-environment selector matches the environment or its
		// root: a grant on a root covers its derived children, which share
		// the root's risk context (ADR-0012 §8) and inherit its values.
		return slices.Contains(sel.EnvironmentIDs, r.Environment.ID) || slices.Contains(sel.EnvironmentIDs, r.Environment.RootID)
	}
	// A team scope is expanded in LoadGrants; a raw one, or an unknown
	// kind, matches nothing.
	return false
}

func requirementTargets(req Requirement, r Resource) bool {
	if r.Environment == nil {
		return false
	}
	if req.Target.Kind == "tier" {
		return r.Environment.Tier == req.Target.Tier
	}
	return slices.Contains(req.Target.EnvironmentIDs, r.Environment.ID) || slices.Contains(req.Target.EnvironmentIDs, r.Environment.RootID)
}

// RequirementsCovering is requirementsCovering: the Requirements that
// constrain value reads in this resource (a tier, the Environment itself,
// or the root it derives from). Authorization and the Environment
// listing's tailnetRequired flag both use it.
func RequirementsCovering(reqs []Requirement, r Resource) []Requirement {
	var out []Requirement
	for _, req := range reqs {
		if requirementTargets(req, r) {
			out = append(out, req)
		}
	}
	return out
}

func evaluateRequirement(req Requirement, ctx *TailnetContext) Outcome {
	o := Outcome{RequirementID: req.ID, RequirementVersion: req.Version}
	if ctx == nil {
		o.Reason = "no-tailnet-context"
		return o
	}
	s := req.Selector
	if ctx.Tailnet != s.Tailnet {
		o.Reason = "tailnet-mismatch"
		return o
	}
	if slices.Contains(s.Nodes, ctx.NodeID) {
		o.Satisfied, o.By = true, "node:"+ctx.NodeID
		return o
	}
	// The selector's first tag the device has; an empty tag is falsy in
	// TypeScript, so it satisfies nothing, even when a later tag would.
	for _, t := range s.Tags {
		if slices.Contains(ctx.Tags, t) {
			if t != "" {
				o.Satisfied, o.By = true, t
				return o
			}
			break
		}
	}
	if ctx.UserLogin != nil && *ctx.UserLogin != "" && slices.Contains(s.Users, *ctx.UserLogin) {
		o.Satisfied, o.By = true, "user:"+*ctx.UserLogin
		return o
	}
	o.Reason = "selector-mismatch"
	return o
}

// Evaluate is evaluate: the pure decision.
func Evaluate(in Input) Evaluation {
	var applied []Grant
	for _, g := range in.Grants {
		if grantApplies(g, in.Action, in.Resource) {
			applied = append(applied, g)
		}
	}
	p := Provenance{GrantIDs: []string{}}
	for _, g := range applied {
		p.GrantIDs = append(p.GrantIDs, g.ID)
		if g.ViaGroupID != "" && !slices.Contains(p.GroupIDs, g.ViaGroupID) {
			p.GroupIDs = append(p.GroupIDs, g.ViaGroupID)
		}
		if g.RoleID != "" && !slices.Contains(p.RoleIDs, g.RoleID) {
			p.RoleIDs = append(p.RoleIDs, g.RoleID)
		}
		p.Applied = append(p.Applied, Applied{
			GrantID: g.ID, Actions: g.Actions, ViaGroupID: g.ViaGroupID, RoleID: g.RoleID, RoleVersion: g.RoleVersion,
		})
	}
	roleAllows := (in.OrgRole == Admin && slices.Contains(Actions, in.Action)) ||
		(in.OrgRole == Member && memberAllows(in.Action, in.Resource))
	if roleAllows {
		p.Role = in.OrgRole
	}
	if !roleAllows && len(p.GrantIDs) == 0 {
		return Evaluation{Denial: NoGrant, Provenance: p, Requirements: []Outcome{}}
	}
	// Requirements restrict: admins do not bypass them (ADR-0015 §4).
	outcomes := []Outcome{}
	if slices.Contains(tailnetConstrained, in.Action) {
		for _, req := range RequirementsCovering(in.Requirements, in.Resource) {
			outcomes = append(outcomes, evaluateRequirement(req, in.TailnetContext))
		}
	}
	for _, o := range outcomes {
		if !o.Satisfied {
			return Evaluation{Denial: RequirementFailed, Provenance: p, Requirements: outcomes}
		}
	}
	return Evaluation{Allowed: true, Provenance: p, Requirements: outcomes}
}

// AuditAuthz is auditAuthz: what an allowed action records in its audit
// events. The built-in role when that role allowed it (never inferred from
// an empty Grant list), the decision-time Grants, and for
// tailnet-constrained actions each applicable Requirement's outcome, in the
// shape denials record them (ADR-0046 Decision 8); no Requirement applies:
// an empty list.
func AuditAuthz(e Evaluation) jsvalue.Object {
	var v jsvalue.Object
	if e.Provenance.Role != "" {
		v = append(v, jsvalue.Member{Key: "role", Value: e.Provenance.Role})
	}
	v = append(v, jsvalue.Member{Key: "grantIds", Value: nonNil(e.Provenance.GrantIDs)})
	if len(e.Provenance.Applied) > 0 {
		v = append(v, jsvalue.Member{Key: "applied", Value: appliedValue(e.Provenance.Applied)})
	}
	return append(v, jsvalue.Member{Key: "requirements", Value: outcomesValue(e.Requirements)})
}
