// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// The access reports (ADR-0054 Decision 8): a machine's reach
// (domain/reach.ts), the credential review (domain/credentialReview.ts) and
// the caller's own Organization permissions. Read only, from one snapshot;
// they change no authorization and issue nothing.

// ---- Machine reach

// reachOrganizationActions are the actions decided for the Organization as
// a whole (no Project).
var reachOrganizationActions = []string{
	"organization.read", "organization.manage", "project.manage", "identity.read", "identity.manage",
	"policy.read", "policy.manage", "audit.read", "config.sync.manage",
}

// reachProjectActions are decided for one Project.
var reachProjectActions = []string{"project.read", "project.manage", "contract.read", "contract.submit", "contract.activate"}

// reachEnvironmentActions are decided for one Environment.
var reachEnvironmentActions = []string{
	"environment.read", "environment.manage", "config.metadata.read", "config.value.read", "config.value.write",
	"secret.reveal", "secret.use", authz.CapabilityIssue, "config.sync.manage",
}

// conditioned are the Environment actions Tailnet Requirements constrain.
var conditioned = map[string]bool{"config.value.read": true, "secret.reveal": true, "secret.use": true}

// jsNonSpace is /^\S+$/: not empty, and no character JavaScript's \s
// matches (WhiteSpace and LineTerminator).
func jsNonSpace(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', 0xFEFF, 0x2028, 0x2029:
			return false
		}
		if unicode.Is(unicode.Zs, r) {
			return false
		}
	}
	return true
}

// ConditionWords is conditionWords: a selector as the condition it sets,
// in words ("needs tailnet example.ts.net: tag:prod or user:alice").
func ConditionWords(selector jsvalue.Object) string {
	tailnet := str(selector, "tailnet")
	if !jsNonSpace(tailnet) {
		tailnet = string(jsvalue.Stringify(tailnet))
	}
	var by []string
	by = append(by, listOf(selector, "tags")...)
	for _, u := range listOf(selector, "users") {
		by = append(by, "user:"+u)
	}
	for _, n := range listOf(selector, "nodes") {
		by = append(by, "node:"+n)
	}
	out := "needs tailnet " + tailnet
	if len(by) > 0 {
		out += ": " + strings.Join(by, " or ")
	}
	return out
}

func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// decideAll is decideAll: the actions the Grants alone allow on resource,
// each with the Grants that allow it, and conditions on the actions
// Requirements constrain. No built-in role, no Requirement evaluated.
func decideAll(actions []string, resource authz.Resource, grants []authz.Grant, conditions []string) []any {
	out := []any{}
	for _, action := range actions {
		e := authz.Evaluate(authz.Input{Action: action, Resource: resource, Grants: grants})
		if !e.Allowed {
			continue
		}
		sources := make([]any, len(e.Provenance.Applied))
		for i, g := range e.Provenance.Applied {
			sources[i] = jsvalue.Object{{Key: "grantId", Value: g.GrantID}, {Key: "viaGroupId", Value: orNull(g.ViaGroupID)}, {Key: "roleId", Value: orNull(g.RoleID)}}
		}
		conds := []any{}
		if conditioned[action] {
			conds = stringsJS(conditions)
		}
		out = append(out, jsvalue.Object{{Key: "action", Value: action}, {Key: "grants", Value: sources}, {Key: "conditions", Value: conds}})
	}
	return out
}

func hasConditions(actions []any) bool {
	for _, a := range actions {
		if c, _ := a.(jsvalue.Object).Get("conditions"); len(c.([]any)) > 0 {
			return true
		}
	}
	return false
}

func identityState(disabled bool, suspendedByDeletion sql.NullString) (string, any) {
	switch {
	case !disabled:
		return "live", nil
	case suspendedByDeletion.Valid:
		return "disabled", "organization-deletion"
	}
	return "retired", nil
}

func humanIdentity() error {
	return &domainerr.Error{Code: "VALIDATION_FAILED",
		Message: "This identity is a person. Reach is for machine identities; for a member, see their exposure report.",
		Details: jsvalue.Object{{Key: "reason", Value: "human-identity"}}}
}

const (
	retiredNote  = "This identity is retired: it cannot sign in, so none of this is usable until it is reactivated and given a new credential."
	disabledNote = "This identity is suspended while the Organization is being deleted: none of this is usable unless the deletion is cancelled."
	brokerNote   = "As a Broker it also issues agent-run credentials and Capabilities for this Organization's Agents. Those are not its Grants: agent runs exercise a subset of an Agent's reach through Capabilities (one Environment, named Config Items and destinations), checked against the Agent's Grants on every use."
	agentNote    = "Agent-run credentials a Broker issues for this Agent make read requests only, within these Grants. Agent runs use Secrets through a Broker's Capabilities, each a subset of this reach (one Environment, named Config Items and destinations)."
)

// MachineReach is machineReach: what a machine identity's Grants allow in
// the Organization, per Project and Environment, with the Requirements
// that would constrain each action as conditions. db is one read
// snapshot; now is the time its expiry checks use.
func MachineReach(ctx context.Context, db query.DBTX, organizationID, identityID string, now time.Time) (jsvalue.Object, error) {
	if err := pgText(identityID); err != nil {
		return nil, err
	}
	q := query.New(db)
	at := now.UnixMicro()
	identity, err := q.ReachIdentity(ctx, query.ReachIdentityParams{OrganizationID: organizationID, ID: identityID})
	found := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if found && identity.Kind == "human" && identity.Member {
		return nil, humanIdentity()
	}
	if !found || identity.Kind == "human" || identity.OrganizationID.String != organizationID {
		return nil, domainerr.New("RESOURCE_NOT_FOUND", "Not found")
	}
	live, err := q.LiveCredentialCount(ctx, query.LiveCredentialCountParams{IdentityID: identity.ID, Now: sql.NullInt64{Int64: at, Valid: true}})
	if err != nil {
		return nil, err
	}
	grants, err := authz.LoadGrants(ctx, db, organizationID, identity.ID)
	if err != nil {
		return nil, err
	}
	requirements, err := authz.LoadRequirements(ctx, db, organizationID)
	if err != nil {
		return nil, err
	}
	// The Requirements as stored, for the answer: jsonb's order.
	stored, err := q.LoadTailnetRequirements(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	projects, err := q.ReachProjects(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	envs, err := q.ReachEnvironments(ctx, query.ReachEnvironmentsParams{OrganizationID: organizationID, Now: sql.NullInt64{Int64: at, Valid: true}})
	if err != nil {
		return nil, err
	}

	var used []string // Requirement ids, in the order first used
	outProjects := []any{}
	for _, p := range projects {
		projectActions := decideAll(reachProjectActions, authz.Resource{OrganizationID: organizationID, ProjectID: p.ID}, grants, nil)
		environments := []any{}
		for _, e := range envs {
			if e.ProjectID != p.ID {
				continue
			}
			// A derived Environment is decided with its root's ID and its
			// (inherited) tier.
			root := e.ID
			if e.ParentEnvironmentID.Valid {
				root = e.ParentEnvironmentID.String
			}
			resource := authz.Resource{OrganizationID: organizationID, ProjectID: p.ID, Environment: &authz.Environment{ID: e.ID, RootID: root, Tier: e.Tier}}
			covering := authz.RequirementsCovering(requirements, resource)
			ids := make([]string, len(covering))
			for i, r := range covering {
				ids[i] = r.ID
			}
			actions := decideAll(reachEnvironmentActions, resource, grants, ids)
			if len(actions) == 0 {
				continue
			}
			if hasConditions(actions) {
				for _, id := range ids {
					if !containsID(used, id) {
						used = append(used, id)
					}
				}
			}
			var parent any
			if e.ParentEnvironmentID.Valid {
				parent = e.ParentEnvironmentID.String
			}
			environments = append(environments, jsvalue.Object{
				{Key: "id", Value: e.ID}, {Key: "name", Value: e.Name}, {Key: "tier", Value: e.Tier}, {Key: "kind", Value: e.Kind},
				{Key: "parentEnvironmentId", Value: parent}, {Key: "actions", Value: actions},
			})
		}
		if len(projectActions) == 0 && len(environments) == 0 {
			continue
		}
		outProjects = append(outProjects, jsvalue.Object{
			{Key: "id", Value: p.ID}, {Key: "slug", Value: p.Slug}, {Key: "name", Value: p.Name},
			{Key: "actions", Value: projectActions}, {Key: "environments", Value: environments},
		})
	}

	outRequirements := []any{}
	for _, id := range used {
		for _, r := range stored {
			if r.ID != id {
				continue
			}
			target, err := parseObject(r.Target)
			if err != nil {
				return nil, err
			}
			selector, err := parseObject(r.Config)
			if err != nil {
				return nil, err
			}
			outRequirements = append(outRequirements, jsvalue.Object{
				{Key: "id", Value: r.ID}, {Key: "version", Value: r.Version}, {Key: "target", Value: jsvalue.Jsonb(target)}, {Key: "selector", Value: jsvalue.Jsonb(selector)},
				{Key: "condition", Value: ConditionWords(selector)},
			})
		}
	}

	state, reason := identityState(identity.Disabled, identity.SuspendedByDeletion)
	notes := []any{}
	switch state {
	case "retired":
		notes = append(notes, retiredNote)
	case "disabled":
		notes = append(notes, disabledNote)
	}
	switch identity.Kind {
	case "broker":
		notes = append(notes, brokerNote)
	case "agent":
		notes = append(notes, agentNote)
	}
	return jsvalue.Object{
		{Key: "identity", Value: jsvalue.Object{
			{Key: "id", Value: identity.ID}, {Key: "name", Value: identity.Name}, {Key: "kind", Value: identity.Kind},
			{Key: "state", Value: state}, {Key: "disabledReason", Value: reason}, {Key: "liveCredentials", Value: live},
		}},
		{Key: "organizationActions", Value: decideAll(reachOrganizationActions, authz.Resource{OrganizationID: organizationID}, grants, nil)},
		{Key: "projects", Value: outProjects},
		{Key: "requirements", Value: outRequirements},
		{Key: "notes", Value: notes},
	}, nil
}

func containsID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// ---- Credential review

// IdleDays is IDLE_DAYS: days without use after which a used credential
// counts as idle.
const IdleDays = 30

// ExpiryWarningDays is EXPIRY_WARNING_DAYS, the Varlatch-Credential-Expires
// window.
const ExpiryWarningDays = 7

const day = int64(24 * time.Hour / time.Microsecond)

type reviewRow struct {
	ID                  string
	Name                sql.NullString
	Kind                string
	CreatedAt           int64
	ExpiresAt           sql.NullInt64
	LastUsedAt          sql.NullInt64
	IssuedBy            sql.NullString
	IssuedByName        sql.NullString
	IdentityID          string
	IdentityName        string
	IdentityKind        string
	Disabled            bool
	SuspendedByDeletion sql.NullString
}

// reviewed is a credential's members up to its identity, as both lists
// give them.
func reviewed(r reviewRow) jsvalue.Object {
	var name any
	if r.Name.Valid {
		name = r.Name.String
	}
	var issuedBy any
	if r.IssuedBy.Valid {
		by := r.IssuedBy.String
		if r.IssuedByName.Valid {
			by = r.IssuedByName.String
		}
		issuedBy = jsvalue.Object{{Key: "id", Value: r.IssuedBy.String}, {Key: "name", Value: by}}
	}
	state, reason := identityState(r.Disabled, r.SuspendedByDeletion)
	return jsvalue.Object{
		{Key: "id", Value: r.ID}, {Key: "name", Value: name}, {Key: "kind", Value: r.Kind},
		{Key: "createdAt", Value: audit.ISOTime(r.CreatedAt)}, {Key: "expiresAt", Value: isoNullable(r.ExpiresAt)}, {Key: "lastUsedAt", Value: isoNullable(r.LastUsedAt)},
		{Key: "issuedBy", Value: issuedBy},
		{Key: "identity", Value: jsvalue.Object{
			{Key: "id", Value: r.IdentityID}, {Key: "name", Value: r.IdentityName}, {Key: "kind", Value: r.IdentityKind},
			{Key: "state", Value: state}, {Key: "disabledReason", Value: reason},
		}},
	}
}

// CredentialReview is credentialReview: the Organization's machine
// credentials worth a look (never used, idle, never expiring), and the
// service credentials that expire within the warning window or have
// expired, soonest first. now is the time every comparison uses.
func CredentialReview(ctx context.Context, db query.DBTX, organizationID string, now time.Time) (jsvalue.Object, error) {
	q := query.New(db)
	at := now.UnixMicro()
	rows, err := q.ReviewedCredentials(ctx, query.ReviewedCredentialsParams{OrganizationID: sql.NullString{String: organizationID, Valid: true}, Now: sql.NullInt64{Int64: at, Valid: true}})
	if err != nil {
		return nil, err
	}
	items := []any{}
	var neverUsed, idle, noExpiry int64
	for _, row := range rows {
		r := reviewRow(row)
		reasons := []any{}
		if !r.LastUsedAt.Valid {
			reasons = append(reasons, "never-used")
			neverUsed++
		}
		if r.LastUsedAt.Valid && r.LastUsedAt.Int64 < at-IdleDays*day {
			reasons = append(reasons, "idle")
			idle++
		}
		if !r.ExpiresAt.Valid {
			reasons = append(reasons, "no-expiry")
			noExpiry++
		}
		if len(reasons) == 0 {
			continue
		}
		items = append(items, append(reviewed(r), jsvalue.Member{Key: "reasons", Value: reasons}))
	}
	expiring, err := q.ExpiringCredentials(ctx, query.ExpiringCredentialsParams{OrganizationID: sql.NullString{String: organizationID, Valid: true}, Horizon: sql.NullInt64{Int64: at + ExpiryWarningDays*day, Valid: true}})
	if err != nil {
		return nil, err
	}
	soonItems := []any{}
	var soon, expired int64
	for _, row := range expiring {
		r := reviewRow(row)
		state := "soon"
		if r.ExpiresAt.Int64 <= at {
			state = "expired"
			expired++
		} else {
			soon++
		}
		soonItems = append(soonItems, append(reviewed(r), jsvalue.Member{Key: "state", Value: state}))
	}
	return jsvalue.Object{
		{Key: "generatedAt", Value: audit.ISOTime(at)},
		{Key: "idleDays", Value: int64(IdleDays)},
		{Key: "summary", Value: jsvalue.Object{
			{Key: "reviewed", Value: int64(len(rows))}, {Key: "listed", Value: int64(len(items))},
			{Key: "neverUsed", Value: neverUsed}, {Key: "idle", Value: idle}, {Key: "noExpiry", Value: noExpiry},
		}},
		{Key: "items", Value: items},
		{Key: "expiry", Value: jsvalue.Object{
			{Key: "warningDays", Value: int64(ExpiryWarningDays)},
			{Key: "summary", Value: jsvalue.Object{{Key: "soon", Value: soon}, {Key: "expired", Value: expired}}},
			{Key: "items", Value: soonItems},
		}},
	}, nil
}

// ---- My permissions

// organizationPermissionActions are ORGANIZATION_PERMISSION_ACTIONS: the
// Organization-scoped actions the caller's own permissions report.
var organizationPermissionActions = []string{
	"organization.read", "organization.manage", "project.read", "project.manage", "identity.read",
	"identity.manage", "policy.read", "policy.manage", "audit.read",
}

// MyPermissions is GET …/me/permissions: which Organization-scoped actions
// the caller's built-in role (a person's) and Organization-wide Grants
// allow. The outcome only: no Grant ids.
func MyPermissions(ctx context.Context, db query.DBTX, organizationID, identityID string, human bool) (jsvalue.Object, error) {
	var role string
	if human {
		var err error
		if role, err = authz.OrgRole(ctx, db, organizationID, identityID); err != nil {
			return nil, err
		}
	}
	grants, err := authz.LoadGrants(ctx, db, organizationID, identityID)
	if err != nil {
		return nil, err
	}
	actions := []any{}
	for _, action := range organizationPermissionActions {
		if authz.Evaluate(authz.Input{Action: action, Resource: authz.Resource{OrganizationID: organizationID}, OrgRole: role, Grants: grants}).Allowed {
			actions = append(actions, action)
		}
	}
	return jsvalue.Object{{Key: "organizationId", Value: organizationID}, {Key: "role", Value: orNull(role)}, {Key: "actions", Value: actions}}, nil
}
