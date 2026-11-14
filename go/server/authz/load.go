// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// OrgRole is getOrgRole: the built-in role of a live membership (ADR-0052
// Decision 1), or "". A removed membership has none, so a removed admin
// loses the admin bundle.
func OrgRole(ctx context.Context, db query.DBTX, organizationID, identityID string) (string, error) {
	role, err := query.New(db).GetOrgRole(ctx, query.GetOrgRoleParams{OrganizationID: organizationID, IdentityID: identityID})
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return role, err
}

func parseActions(text string) ([]*string, error) {
	var a []*string
	if err := json.Unmarshal([]byte(text), &a); err != nil {
		return nil, err
	}
	return a, nil
}

// LoadGrants is loadGrants: the subject's effective Grants in the
// Organization, with the ADR-0028 constructs expanded into flat Grants:
//   - direct Grants, and Grants to any live Group the subject is in (the
//     Group recorded as ViaGroupID);
//   - a Grant's Role expanded to the Role's current actions (none for a
//     revoked Role: default deny holds);
//   - a team-scoped Grant expanded to one project-scoped Grant per Project
//     the team owns.
//
// A person without a live membership has no Grants at all, whatever rows
// still name them (ADR-0052 Decision 1); a machine's are unaffected. A
// Grant whose actions come out empty is left out.
func LoadGrants(ctx context.Context, db query.DBTX, organizationID, subjectIdentityID string) ([]Grant, error) {
	q := query.New(db)
	rows, err := q.LoadGrantRows(ctx, query.LoadGrantRowsParams{OrganizationID: organizationID, SubjectIdentityID: subjectIdentityID})
	if err != nil {
		return nil, err
	}
	scopes := make([]Scope, len(rows))
	var teams []string
	for i, r := range rows {
		if err := json.Unmarshal([]byte(r.Scope), &scopes[i]); err != nil {
			return nil, fmt.Errorf("authz: grant %s: scope: %w", r.ID, err)
		}
		if scopes[i].Kind == "team" && !slices.Contains(teams, scopes[i].TeamID) {
			teams = append(teams, scopes[i].TeamID)
		}
	}
	teamProjects := map[string][]string{}
	for _, t := range teams {
		p, err := q.TeamProjects(ctx, t)
		if err != nil {
			return nil, err
		}
		teamProjects[t] = p
	}
	grants := []Grant{}
	for i, r := range rows {
		// A Role contributes its current actions; a revoked Role nothing
		// (never a wildcard).
		text := r.Actions
		if r.RoleID.Valid {
			text = r.RoleActions
			if r.RoleRevoked.Valid {
				text = sql.NullString{}
			}
		}
		var actions []*string
		if text.Valid {
			if actions, err = parseActions(text.String); err != nil {
				return nil, fmt.Errorf("authz: grant %s: actions: %w", r.ID, err)
			}
		}
		if len(actions) == 0 {
			continue
		}
		g := Grant{ID: r.ID, SubjectIdentityID: subjectIdentityID, Actions: actions}
		if r.SubjectIdentityID.Valid {
			g.SubjectIdentityID = r.SubjectIdentityID.String
		}
		if r.SubjectGroupID.Valid {
			g.ViaGroupID = r.SubjectGroupID.String
		}
		if r.RoleID.Valid {
			g.RoleID = r.RoleID.String
			if r.RoleVersion.Valid {
				v := r.RoleVersion.Int64
				g.RoleVersion = &v
			}
		}
		if scopes[i].Kind == "team" {
			for _, p := range teamProjects[scopes[i].TeamID] {
				tg := g
				tg.Scope = Scope{Kind: "project", ProjectID: p}
				grants = append(grants, tg)
			}
			continue
		}
		g.Scope = scopes[i]
		grants = append(grants, g)
	}
	return grants, nil
}

// LoadRequirements is loadTailnetRequirements: the Organization's active
// tailnet Requirements.
func LoadRequirements(ctx context.Context, db query.DBTX, organizationID string) ([]Requirement, error) {
	rows, err := query.New(db).LoadTailnetRequirements(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := []Requirement{}
	for _, r := range rows {
		req := Requirement{ID: r.ID}
		v := r.Version
		req.Version = &v
		if err := json.Unmarshal([]byte(r.Target), &req.Target); err != nil {
			return nil, fmt.Errorf("authz: requirement %s: target: %w", r.ID, err)
		}
		if err := json.Unmarshal([]byte(r.Config), &req.Selector); err != nil {
			return nil, fmt.Errorf("authz: requirement %s: config: %w", r.ID, err)
		}
		out = append(out, req)
	}
	return out, nil
}

// JSValue is the Grant as loadGrants builds a GrantRecord, for comparison
// with the TypeScript server's (the scope as this package reads it).
func (g Grant) JSValue() any {
	v := jsvalue.Object{
		{Key: "id", Value: g.ID},
		{Key: "subjectIdentityId", Value: g.SubjectIdentityID},
		{Key: "actions", Value: actionsValue(g.Actions)},
	}
	if g.ViaGroupID != "" {
		v = append(v, jsvalue.Member{Key: "viaGroupId", Value: g.ViaGroupID})
	}
	if g.RoleID != "" {
		v = append(v, jsvalue.Member{Key: "roleId", Value: g.RoleID})
	}
	if g.RoleVersion != nil {
		v = append(v, jsvalue.Member{Key: "roleVersion", Value: *g.RoleVersion})
	}
	return append(v, jsvalue.Member{Key: "scope", Value: g.Scope.JSValue()})
}

// JSValue is the scope's JSON.
func (s Scope) JSValue() any {
	v := jsvalue.Object{{Key: "kind", Value: s.Kind}}
	if s.ProjectID != "" {
		v = append(v, jsvalue.Member{Key: "projectId", Value: s.ProjectID})
	}
	if s.Selector != nil {
		sel := jsvalue.Object{{Key: "kind", Value: s.Selector.Kind}}
		if s.Selector.EnvironmentIDs != nil {
			sel = append(sel, jsvalue.Member{Key: "environmentIds", Value: s.Selector.EnvironmentIDs})
		}
		if s.Selector.Tier != "" {
			sel = append(sel, jsvalue.Member{Key: "tier", Value: s.Selector.Tier})
		}
		v = append(v, jsvalue.Member{Key: "selector", Value: sel})
	}
	if s.TeamID != "" {
		v = append(v, jsvalue.Member{Key: "teamId", Value: s.TeamID})
	}
	return v
}
