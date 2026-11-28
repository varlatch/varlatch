// SPDX-License-Identifier: AGPL-3.0-or-later

package people

import (
	"context"
	"database/sql"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/whatwg"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/webhooks"
	"github.com/varlatch/varlatch/go/server/write"
)

// Removing a person from an Organization, a member leaving, and role
// changes (ADR-0052 Decisions 1 to 5; domain/members.ts). The TypeScript
// code runs each as one SERIALIZABLE transaction; here each is one job on
// the single writer, so its checks, the last-admin rule and the authority
// snapshot read one state. As there, a removal takes the removed person
// shared (key share) and a role change nothing of the target: a reader
// with organization.read must not hold an admin's gate exclusive before
// the admin check. Writers relying on the membership (a Grant naming the
// person, a group they join, an invitation they issue) read it in their
// own job and pin it (its version moved on), so on the single writer they
// come before the removal or role change (which revokes, or whose bound
// version no longer holds) or after it (and find the membership gone or
// changed).

// snapshotActions are SNAPSHOT_ACTIONS: the value actions the authority
// snapshot records, per environment.
var snapshotActions = []string{"config.metadata.read", "config.value.read", "secret.reveal", "secret.use"}

var conditionedAction = map[string]bool{"config.value.read": true, "secret.reveal": true, "secret.use": true}

// requireLiveAdmin is requireLiveAdmin: removal, demotion and promotion
// need a live built-in admin membership; a Grant does not substitute.
func requireLiveAdmin(ctx context.Context, db query.DBTX, organizationID string, actor *auth.Principal) error {
	if actor.Identity.Kind == "human" {
		m, err := readMember(ctx, db, organizationID, actor.Identity.ID)
		if err != nil {
			return err
		}
		if m != nil && m.Role == "admin" {
			return nil
		}
	}
	return domainerr.New("PERMISSION_DENIED", "Only an Organization Admin can remove members or change their role")
}

// requireAnotherAdmin is requireAnotherAdmin: the last admin can neither
// be removed, nor leave, nor be demoted.
func requireAnotherAdmin(ctx context.Context, db query.DBTX, organizationID, identityID string) error {
	n, err := query.New(db).OtherLiveAdmins(ctx, query.OtherLiveAdminsParams{OrganizationID: organizationID, IdentityID: identityID})
	if err != nil {
		return err
	}
	if n == 0 {
		return &domainerr.Error{Code: "VALIDATION_FAILED", Message: "This is the Organization's last admin. Make another member an admin first.",
			Details: jsvalue.Object{{Key: "reason", Value: "last-admin"}}}
	}
	return nil
}

func nullable(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

// captureAuthority is captureAuthority: what the person could reach,
// recorded before anything is cleaned up. Per live environment, the value
// actions their built-in role and Grants allow and where each came from,
// and copies of the Tailnet Requirements those actions were conditional
// on (never evaluated: there is no request, so no device).
func captureAuthority(ctx context.Context, tx query.DBTX, organizationID, removalID, identityID, role string) error {
	q := query.New(tx)
	grants, err := authz.LoadGrants(ctx, tx, organizationID, identityID)
	if err != nil {
		return err
	}
	requirements, err := authz.LoadRequirements(ctx, tx, organizationID)
	if err != nil {
		return err
	}
	stored, err := q.LoadTailnetRequirements(ctx, organizationID)
	if err != nil {
		return err
	}
	envs, err := q.SnapshotEnvironments(ctx, organizationID)
	if err != nil {
		return err
	}
	type condition struct{ env, requirement string }
	var conditions []condition
	var copied []string // Requirement ids, in the order first copied
	for _, e := range envs {
		root := e.ID
		if e.ParentEnvironmentID.Valid {
			root = e.ParentEnvironmentID.String
		}
		resource := authz.Resource{OrganizationID: organizationID, ProjectID: e.ProjectID, Environment: &authz.Environment{ID: e.ID, RootID: root, Tier: e.Tier}}
		conditioned := false
		for _, action := range snapshotActions {
			r := authz.Evaluate(authz.Input{Action: action, Resource: resource, OrgRole: role, Grants: grants})
			if !r.Allowed {
				continue
			}
			if conditionedAction[action] {
				conditioned = true
			}
			if r.Provenance.Role != "" {
				if err := q.InsertRemovalAuthority(ctx, query.InsertRemovalAuthorityParams{RemovalID: removalID, EnvironmentID: e.ID, Action: action,
					Source: "role:" + r.Provenance.Role, Role: nullable(r.Provenance.Role)}); err != nil {
					return err
				}
			}
			for _, g := range r.Provenance.Applied {
				if err := q.InsertRemovalAuthority(ctx, query.InsertRemovalAuthorityParams{RemovalID: removalID, EnvironmentID: e.ID, Action: action,
					Source: "grant:" + g.GrantID, GrantID: nullable(g.GrantID), ViaGroupID: nullable(g.ViaGroupID), RoleID: nullable(g.RoleID)}); err != nil {
					return err
				}
			}
		}
		if !conditioned {
			continue
		}
		for _, r := range authz.RequirementsCovering(requirements, resource) {
			if !contains(copied, r.ID) {
				copied = append(copied, r.ID)
			}
			conditions = append(conditions, condition{e.ID, r.ID})
		}
	}
	for _, id := range copied {
		for _, r := range stored {
			if r.ID != id {
				continue
			}
			target, err := jsonbText(r.Target)
			if err != nil {
				return err
			}
			selector, err := jsonbText(r.Config)
			if err != nil {
				return err
			}
			if err := q.InsertRemovalRequirement(ctx, query.InsertRemovalRequirementParams{RemovalID: removalID, RequirementID: r.ID,
				RequirementVersion: sql.NullInt64{Int64: r.Version, Valid: true}, Target: target, Selector: selector}); err != nil {
				return err
			}
		}
	}
	for _, c := range conditions {
		if err := q.InsertRemovalCondition(ctx, query.InsertRemovalConditionParams{RemovalID: removalID, EnvironmentID: c.env, RequirementID: c.requirement}); err != nil {
			return err
		}
	}
	return nil
}

// jsonbText is a stored jsonb value written again as jsonb stores it.
func jsonbText(text string) (string, error) {
	v, err := jsvalue.Parse([]byte(text))
	if err != nil {
		return "", err
	}
	return string(jsvalue.Stringify(jsvalue.Jsonb(v))), nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// ended is what endMembership ended.
type ended struct {
	removalID                   string
	removedAt                   int64
	grants, groups, invitations int64
}

// endMembership is endMembership: inside the caller's job, the authority
// snapshot first, then removed_at on the membership, the person's direct
// Grants revoked, their group and team links removed, and the pending
// invitations they issued revoked; the caller appends its event last.
// Organization deletion's finalization (4.12b, EndMembership) calls it
// for every member.
func endMembership(ctx context.Context, tx query.DBTX, organizationID, identityID, role, actorID string, at int64) (ended, error) {
	q := query.New(tx)
	out := ended{removalID: ids.New(ids.MembershipRemoval), removedAt: at}
	if err := q.InsertMembershipRemoval(ctx, query.InsertMembershipRemovalParams{ID: out.removalID, OrganizationID: organizationID,
		IdentityID: identityID, Role: role, ActorIdentityID: actorID, RemovedAt: at}); err != nil {
		return ended{}, err
	}
	if err := captureAuthority(ctx, tx, organizationID, out.removalID, identityID, role); err != nil {
		return ended{}, err
	}
	now := sql.NullInt64{Int64: at, Valid: true}
	if err := q.EndMembershipRow(ctx, query.EndMembershipRowParams{RemovedAt: now, OrganizationID: organizationID, IdentityID: identityID}); err != nil {
		return ended{}, err
	}
	grants, err := q.RevokeMemberGrants(ctx, query.RevokeMemberGrantsParams{RevokedAt: now, OrganizationID: organizationID,
		SubjectIdentityID: sql.NullString{String: identityID, Valid: true}})
	if err != nil {
		return ended{}, err
	}
	groups, err := q.RemoveMemberGroups(ctx, query.RemoveMemberGroupsParams{IdentityID: identityID, OrganizationID: organizationID})
	if err != nil {
		return ended{}, err
	}
	invitations, err := q.RevokeMemberInvitations(ctx, query.RevokeMemberInvitationsParams{Now: now,
		OrganizationID: sql.NullString{String: organizationID, Valid: true}, IdentityID: sql.NullString{String: identityID, Valid: true}})
	if err != nil {
		return ended{}, err
	}
	if err := auth.EndEntryLinksOfMember(ctx, tx, at, organizationID, identityID, actorID); err != nil {
		return ended{}, err
	}
	out.grants, out.groups, out.invitations = int64(len(grants)), int64(len(groups)), int64(len(invitations))
	return out, nil
}

// Ended is what EndMembership ended.
type Ended struct {
	RemovalID                   string
	Grants, Groups, Invitations int64
}

// EndMembership is endMembership for Organization deletion's
// finalization (go/server/orgdeletion), inside its job: the same cleanup a
// removal makes, its event the caller's.
func EndMembership(ctx context.Context, tx query.DBTX, organizationID, identityID, role, actorID string, at int64) (Ended, error) {
	e, err := endMembership(ctx, tx, organizationID, identityID, role, actorID, at)
	if err != nil {
		return Ended{}, err
	}
	return Ended{RemovalID: e.removalID, Grants: e.grants, Groups: e.groups, Invitations: e.invitations}, nil
}

// changesOf is a review row's changes: "created" when the person created
// it, then the integration index's kinds, without repeats.
func changesOf(created bool, indexed sql.NullString) ([]any, error) {
	out := []any{}
	seen := map[string]bool{}
	add := func(c string) {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	if created {
		add("created")
	}
	if indexed.Valid {
		v, err := jsvalue.Parse([]byte(indexed.String))
		if err != nil {
			return nil, err
		}
		list, _ := v.([]any)
		for _, c := range list {
			if s, ok := c.(string); ok {
				add(s)
			}
		}
	}
	return out, nil
}

// urlHost is new URL(url).host: the host as the WHATWG URL parser gives
// it, with the port unless it is the scheme's default; "" when new URL
// throws.
func urlHost(raw string) string {
	u, ok := whatwg.ParseURL(raw)
	if !ok {
		return ""
	}
	return u.Host
}

// MemberReview is memberReview: what the person created or changed that
// may still work without them (ADR-0052 Decision 4). Names and states
// only; a webhook by the host of its URL, which is its envelope's
// (webhooks.URLs, under rootKEK). now is the time a credential's expiry is
// read against.
func MemberReview(ctx context.Context, db query.DBTX, rootKEK []byte, organizationID, identityID string, now int64) (jsvalue.Object, error) {
	q := query.New(db)
	org, who := organizationID, sql.NullString{String: identityID, Valid: true}
	targets, err := q.ReviewSyncTargets(ctx, query.ReviewSyncTargetsParams{IdentityID: identityID, OrganizationID: org})
	if err != nil {
		return nil, err
	}
	syncTargets := []any{}
	for _, t := range targets {
		changes, err := changesOf(t.CreatedBy.Valid && t.CreatedBy.String == identityID, t.Changes)
		if err != nil {
			return nil, err
		}
		state := t.State
		if t.RevokedAt.Valid {
			state = "revoked"
		}
		syncTargets = append(syncTargets, jsvalue.Object{{Key: "id", Value: t.ID}, {Key: "projectId", Value: t.ProjectID},
			{Key: "environmentId", Value: t.EnvironmentID}, {Key: "platform", Value: t.Platform}, {Key: "state", Value: state}, {Key: "changes", Value: changes}})
	}
	conns, err := q.ReviewConnections(ctx, query.ReviewConnectionsParams{IdentityID: identityID, OrganizationID: org})
	if err != nil {
		return nil, err
	}
	connections := []any{}
	for _, c := range conns {
		changes, err := changesOf(c.CreatedBy.Valid && c.CreatedBy.String == identityID, c.Changes)
		if err != nil {
			return nil, err
		}
		connections = append(connections, jsvalue.Object{{Key: "id", Value: c.ID}, {Key: "name", Value: c.Name}, {Key: "platform", Value: c.Platform},
			{Key: "credentialKind", Value: c.CredentialKind}, {Key: "revoked", Value: c.RevokedAt.Valid}, {Key: "changes", Value: changes}})
	}
	hooks, err := q.ReviewWebhooks(ctx, query.ReviewWebhooksParams{OrganizationID: org, CreatedBy: who})
	if err != nil {
		return nil, err
	}
	urls := webhooks.NewURLs(rootKEK, db)
	defer urls.Close()
	hookList := []any{}
	for _, w := range hooks {
		url, err := urls.Of(ctx, org, w.ID, w.Url, w.UrlEnvelope)
		if err != nil {
			return nil, err
		}
		hookList = append(hookList, jsvalue.Object{{Key: "id", Value: w.ID}, {Key: "host", Value: urlHost(url)}, {Key: "revoked", Value: w.RevokedAt.Valid}})
	}
	binds, err := q.ReviewOIDCBindings(ctx, query.ReviewOIDCBindingsParams{OrganizationID: org, CreatedBy: who})
	if err != nil {
		return nil, err
	}
	bindings := []any{}
	for _, b := range binds {
		bindings = append(bindings, jsvalue.Object{{Key: "id", Value: b.ID}, {Key: "identityId", Value: b.IdentityID},
			{Key: "identityName", Value: b.IdentityName}, {Key: "issuer", Value: b.Issuer}, {Key: "revoked", Value: b.RevokedAt.Valid}})
	}
	creds, err := q.ReviewCredentials(ctx, query.ReviewCredentialsParams{IdentityID: who, OrganizationID: sql.NullString{String: organizationID, Valid: true}})
	if err != nil {
		return nil, err
	}
	credentials := []any{}
	for _, c := range creds {
		state := "valid"
		switch {
		case c.RevokedAt.Valid:
			state = "revoked"
		case c.Disabled:
			state = "retired"
		case c.ExpiresAt.Valid && c.ExpiresAt.Int64 <= now:
			state = "expired"
		case c.MaxUses.Valid && c.UseCount >= c.MaxUses.Int64:
			state = "exhausted"
		}
		var name any
		if c.Name.Valid {
			name = c.Name.String
		}
		credentials = append(credentials, jsvalue.Object{{Key: "id", Value: c.ID}, {Key: "name", Value: name}, {Key: "identityId", Value: c.IdentityID},
			{Key: "identityName", Value: c.IdentityName}, {Key: "state", Value: state}})
	}
	envs, err := q.ReviewPersonalEnvironments(ctx, query.ReviewPersonalEnvironmentsParams{OrganizationID: org, OwnerIdentityID: who})
	if err != nil {
		return nil, err
	}
	personal := []any{}
	for _, e := range envs {
		personal = append(personal, jsvalue.Object{{Key: "id", Value: e.ID}, {Key: "name", Value: e.Name}, {Key: "projectId", Value: e.ProjectID}})
	}
	return jsvalue.Object{
		{Key: "syncTargets", Value: syncTargets}, {Key: "connections", Value: connections}, {Key: "webhooks", Value: hookList},
		{Key: "oidcBindings", Value: bindings}, {Key: "credentials", Value: credentials}, {Key: "personalEnvironments", Value: personal},
	}, nil
}

// PreviewReview is previewMemberReview: the review list before a removal
// or a leave, from one read snapshot: for a live admin about any live
// member, for a member about themselves.
func PreviewReview(ctx context.Context, db query.DBTX, rootKEK []byte, organizationID, identityID string, actor *auth.Principal, now int64) (jsvalue.Object, error) {
	if actor.Identity.ID != identityID {
		if err := requireLiveAdmin(ctx, db, organizationID, actor); err != nil {
			return nil, err
		}
	}
	m, err := readMember(ctx, db, organizationID, identityID)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, memberNotFound()
	}
	return MemberReview(ctx, db, rootKEK, organizationID, identityID, now)
}

func membershipChanged() error {
	return domainerr.New("STATE_CHANGED", "The membership changed since the approval was asked for; nothing was changed. Read it again and ask for a new approval")
}

// recheckVersion is recheckMembershipVersion: the version an approval
// bound, checked again in the job; a difference rolls the consumption back.
func recheckVersion(m *Member, expected *int64) error {
	if m == nil || expected == nil || m.Version != *expected {
		return membershipChanged()
	}
	return nil
}

// RemoveMember is removeMember: removing someone else (a protected
// operation, admin-step-up's member.remove), or leaving (the person
// removing themselves, exempt). Recovery while frozen: it only takes
// authority away. The admin check, a missing membership and the
// last-admin rule refuse before an approval is asked for, and run again
// once it is consumed. rootKEK reads the review's webhook URLs.
func RemoveMember(ctx context.Context, w *write.Writer, approvals *auth.Service, rootKEK []byte, req Request, organizationID, identityID string, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	r := req.security(approvals)
	actor := req.Principal
	left := actor.Identity.ID == identityID
	var checks []security.Check
	if !left {
		checks = []security.Check{{Control: security.AdminStepUp, Operation: "member.remove"}}
	}
	var out jsvalue.Object
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID, write.Person(identityID, write.Shared)), func(ctx context.Context, tx *storage.Tx) error {
		at := now().UnixMicro()
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID, DuringFreeze: authz.DuringFreezeRecovery},
			Checks: checks,
			Preflight: func(ctx context.Context, db query.DBTX) error {
				if !left {
					if err := requireLiveAdmin(ctx, db, organizationID, actor); err != nil {
						return err
					}
				}
				m, err := readMember(ctx, db, organizationID, identityID)
				if err == nil && m == nil {
					err = memberNotFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				if err := requireLiveAdmin(ctx, db, organizationID, actor); err != nil {
					return nil, err
				}
				m, err := readMember(ctx, db, organizationID, identityID)
				if err != nil {
					return nil, err
				}
				if m == nil {
					return nil, memberNotFound()
				}
				if m.Role == "admin" {
					if err := requireAnotherAdmin(ctx, db, organizationID, identityID); err != nil {
						return nil, err
					}
				}
				name, err := query.New(db).OrganizationNameOf(ctx, organizationID)
				if err != nil {
					return nil, err
				}
				counts, err := readRemovalCounts(ctx, db, organizationID, identityID, at)
				if err != nil {
					return nil, err
				}
				return memberRemoveBinding(organizationID, name, *m, counts), nil
			},
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		if !left {
			if err := requireLiveAdmin(ctx, tx, organizationID, actor); err != nil {
				return err
			}
		}
		m, err := readMember(ctx, tx, organizationID, identityID)
		if err != nil {
			return err
		}
		if m == nil {
			return memberNotFound()
		}
		if m.Role == "admin" {
			if err := requireAnotherAdmin(ctx, tx, organizationID, identityID); err != nil {
				return err
			}
		}
		if p.Binding != nil {
			if err := recheckVersion(m, p.Binding.ExpectedVersion); err != nil {
				return err
			}
		}
		e, err := endMembership(ctx, tx, organizationID, identityID, m.Role, actor.Identity.ID, at)
		if err != nil {
			return err
		}
		review, err := MemberReview(ctx, tx, rootKEK, organizationID, identityID, at)
		if err != nil {
			return err
		}
		// Report mode: removing someone else; leaving is not on the list.
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		var action *string
		if !left {
			a := "identity.manage"
			action = &a
		}
		actorID := actor.Identity.ID
		md := jsvalue.Object{{Key: "role", Value: m.Role}, {Key: "left", Value: left}, {Key: "grantsRevoked", Value: e.grants},
			{Key: "groupsLeft", Value: e.groups}, {Key: "invitationsRevoked", Value: e.invitations}}
		if _, err := audit.Record(ctx, tx, audit.Event{Type: "membership.removed", Decision: audit.Info, ActorIdentityID: &actorID, OrganizationID: &organizationID,
			Action: action, Resource: jsvalue.Object{{Key: "identityId", Value: identityID}, {Key: "removalId", Value: e.removalID}},
			Metadata: append(md, security.ApprovalMetadata(p.Approval)...)}); err != nil {
			return err
		}
		out = jsvalue.Object{
			{Key: "removalId", Value: e.removalID}, {Key: "identityId", Value: identityID}, {Key: "role", Value: m.Role}, {Key: "left", Value: left},
			{Key: "removedAt", Value: audit.ISOTime(e.removedAt)}, {Key: "grantsRevoked", Value: e.grants}, {Key: "groupsLeft", Value: e.groups},
			{Key: "invitationsRevoked", Value: e.invitations}, {Key: "review", Value: review},
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out, reports, nil
}

// ChangeMemberRole is changeMemberRole: admin and member (ADR-0052
// Decision 3), with removal's permission and last-admin rule. A protected
// operation (member.promote or member.demote); the same role again
// changes nothing, records nothing and needs no approval. Demotion is
// recovery while frozen; promotion is refused then.
func ChangeMemberRole(ctx context.Context, w *write.Writer, approvals *auth.Service, req Request, organizationID, identityID, role string, now func() time.Time) (jsvalue.Object, []auth.PendingReport, error) {
	r := req.security(approvals)
	actor := req.Principal
	op, freeze := "member.demote", authz.DuringFreezeRecovery
	if role == "admin" {
		op, freeze = "member.promote", ""
	}
	var out jsvalue.Object
	var reports []auth.PendingReport
	err := w.Job(ctx, r.Gates(organizationID), func(ctx context.Context, tx *storage.Tx) error {
		p, err := security.Prepare(ctx, tx, r, security.Protected{
			Scope:  write.Scope{OrganizationID: organizationID, DuringFreeze: freeze},
			Checks: []security.Check{{Control: security.AdminStepUp, Operation: op}},
			Preflight: func(ctx context.Context, db query.DBTX) error {
				if err := requireLiveAdmin(ctx, db, organizationID, actor); err != nil {
					return err
				}
				m, err := readMember(ctx, db, organizationID, identityID)
				if err == nil && m == nil {
					err = memberNotFound()
				}
				return err
			},
			Binding: func(ctx context.Context, db query.DBTX, _ *int64) (*auth.Binding, error) {
				if err := requireLiveAdmin(ctx, db, organizationID, actor); err != nil {
					return nil, err
				}
				m, err := readMember(ctx, db, organizationID, identityID)
				if err != nil {
					return nil, err
				}
				if m == nil {
					return nil, memberNotFound()
				}
				if m.Role == role {
					return nil, nil
				}
				if m.Role == "admin" {
					if err := requireAnotherAdmin(ctx, db, organizationID, identityID); err != nil {
						return nil, err
					}
				}
				return memberRoleBinding(organizationID, *m, role), nil
			},
		}, now)
		if err != nil {
			return err
		}
		reports = p.Access
		if err := requireLiveAdmin(ctx, tx, organizationID, actor); err != nil {
			return err
		}
		m, err := readMember(ctx, tx, organizationID, identityID)
		if err != nil {
			return err
		}
		if m == nil {
			return memberNotFound()
		}
		answer := func(previous string) {
			out = jsvalue.Object{{Key: "identityId", Value: identityID}, {Key: "role", Value: role}, {Key: "previousRole", Value: previous}}
		}
		if m.Role == role {
			answer(role)
			return nil
		}
		if m.Role == "admin" {
			if err := requireAnotherAdmin(ctx, tx, organizationID, identityID); err != nil {
				return err
			}
		}
		if p.Binding != nil {
			if err := recheckVersion(m, p.Binding.ExpectedVersion); err != nil {
				return err
			}
		}
		if err := query.New(tx).SetMemberRole(ctx, query.SetMemberRoleParams{Role: role, OrganizationID: organizationID, IdentityID: identityID}); err != nil {
			return err
		}
		if err := p.Count(ctx, tx); err != nil {
			return err
		}
		actorID, action := actor.Identity.ID, "identity.manage"
		md := jsvalue.Object{{Key: "previousRole", Value: m.Role}, {Key: "role", Value: role}}
		if _, err := audit.Record(ctx, tx, audit.Event{Type: "membership.role_changed", Decision: audit.Info, ActorIdentityID: &actorID, OrganizationID: &organizationID,
			Action: &action, Resource: jsvalue.Object{{Key: "identityId", Value: identityID}}, Metadata: append(md, security.ApprovalMetadata(p.Approval)...)}); err != nil {
			return err
		}
		answer(m.Role)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out, reports, nil
}
