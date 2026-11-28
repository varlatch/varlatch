// SPDX-License-Identifier: AGPL-3.0-or-later

package people

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// The exposure report (ADR-0052 Decisions 6 and 7; domain/exposure.ts):
// what a person received (observed in audit, read from the exposure index
// the audit package writes), what they could reach at their removal (the
// snapshot), and what is unknown, never mixed; and an operator's
// confirmation that an exposed version was revoked at its provider. The
// TypeScript backfill of the indexes is not ported (feature-parity
// decision 10): step 7's preflight requires it finished, and the report
// reads its state as the TypeScript server does.

// rotationHints is each involved Project's active Contract's rotation
// hints, by Project and item name.
func rotationHints(ctx context.Context, db query.DBTX, organizationID string, projectIDs []string) (map[[2]string]string, error) {
	hints := map[[2]string]string{}
	for len(projectIDs) > 0 {
		n := min(len(projectIDs), 500)
		rows, err := query.New(db).ActiveContracts(ctx, query.ActiveContractsParams{OrganizationID: organizationID, Ids: projectIDs[:n]})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			v, err := jsvalue.Parse([]byte(r.Contract))
			if err != nil {
				return nil, err
			}
			contract, _ := v.(jsvalue.Object)
			items, _ := contract.Get("items")
			list, _ := items.([]any)
			for _, it := range list {
				o, _ := it.(jsvalue.Object)
				name, _ := o.Get("name")
				hint, _ := o.Get("rotationHint")
				if n, ok := name.(string); ok {
					if h, ok := hint.(string); ok && h != "" {
						hints[[2]string{r.ID, n}] = h
					}
				}
			}
		}
		projectIDs = projectIDs[n:]
	}
	return hints, nil
}

func nullStringJS(s sql.NullString) any {
	if !s.Valid {
		return nil
	}
	return s.String
}

// MemberExposure is memberExposure: the exposure report for a current or
// former member, from one read snapshot (db); now is the time a retiring
// version's deadline is read against; rootKEK reads its review's webhook
// URLs.
func MemberExposure(ctx context.Context, db query.DBTX, rootKEK []byte, organizationID, identityID string, now int64) (jsvalue.Object, error) {
	if err := pgText(identityID); err != nil {
		return nil, err
	}
	q := query.New(db)
	member, err := q.AnyMembership(ctx, query.AnyMembershipParams{OrganizationID: organizationID, IdentityID: identityID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, memberNotFound()
	}
	if err != nil {
		return nil, err
	}
	rows, err := q.ExposureRows(ctx, query.ExposureRowsParams{OrganizationID: organizationID, IdentityID: identityID})
	if err != nil {
		return nil, err
	}
	var projects []string
	for _, r := range rows {
		if r.ProjectID.Valid && !contains(projects, r.ProjectID.String) {
			projects = append(projects, r.ProjectID.String)
		}
	}
	hints, err := rotationHints(ctx, db, organizationID, projects)
	if err != nil {
		return nil, err
	}
	var order []string
	received := map[string]jsvalue.Object{}
	receipts := map[string][]any{}
	for _, r := range rows {
		v := r.VersionID
		if _, seen := received[v]; !seen {
			known := r.OwnerEnv.Valid
			// A seed of one-time codes (ADR-0061) has a deleted_at and is live.
			deleted := r.ValueDeleted.Valid && r.Seed == 0
			var servedAs any
			switch {
			case !known || deleted || r.EnvDeleted.Valid:
			case r.CurrentVersionID.Valid && r.CurrentVersionID.String == v:
				servedAs = "current"
			case r.RetiringVersionID.Valid && r.RetiringVersionID.String == v && r.RotationDeadline.Valid && r.RotationDeadline.Int64 > now:
				servedAs = "retiring"
			}
			served := servedAs != nil
			state := "not-served"
			switch {
			case r.ConfirmedAt.Valid:
				state = "revocation-confirmed"
			case served:
				state = "served"
			}
			var retiringUntil, because, confirmation, hint any
			if servedAs == "retiring" {
				retiringUntil = audit.ISOTime(r.RotationDeadline.Int64)
			}
			if !served {
				switch {
				case !known:
					because = "unknown"
				case r.EnvDeleted.Valid:
					because = "environment-deleted"
				case deleted:
					because = "value-deleted"
				default:
					because = "replaced"
				}
			}
			if r.ConfirmedAt.Valid {
				confirmation = jsvalue.Object{{Key: "confirmedAt", Value: audit.ISOTime(r.ConfirmedAt.Int64)}, {Key: "actorIdentityId", Value: nullStringJS(r.ConfirmedBy)}}
			}
			if r.ProjectID.Valid {
				if h, ok := hints[[2]string{r.ProjectID.String, r.ItemName}]; ok {
					hint = h
				}
			}
			received[v] = jsvalue.Object{
				{Key: "itemName", Value: r.ItemName}, {Key: "versionId", Value: v}, {Key: "owningEnvironmentId", Value: nullStringJS(r.OwnerEnv)},
				{Key: "projectId", Value: nullStringJS(r.ProjectID)}, {Key: "state", Value: state}, {Key: "servedAs", Value: servedAs},
				{Key: "retiringUntil", Value: retiringUntil}, {Key: "notServedBecause", Value: because}, {Key: "served", Value: served},
				{Key: "confirmation", Value: confirmation}, {Key: "rotationHint", Value: hint},
			}
			order = append(order, v)
		}
		receipts[v] = append(receipts[v], jsvalue.Object{{Key: "environmentId", Value: r.EnvironmentID}, {Key: "way", Value: r.Way},
			{Key: "firstAt", Value: audit.ISOTime(r.FirstAt)}, {Key: "lastAt", Value: audit.ISOTime(r.LastAt)}})
	}
	versions := make([]any, len(order))
	for i, v := range order {
		versions[i] = append(received[v], jsvalue.Member{Key: "receipts", Value: receipts[v]})
	}

	authority, err := authorityAtRemoval(ctx, q, organizationID, identityID)
	if err != nil {
		return nil, err
	}
	coverage, err := backfillCoverage(ctx, db)
	if err != nil {
		return nil, err
	}
	indirect, err := MemberReview(ctx, db, rootKEK, organizationID, identityID, now)
	if err != nil {
		return nil, err
	}
	var role any = member.Role
	if member.RemovedAt.Valid {
		role = nil
	}
	return jsvalue.Object{
		{Key: "member", Value: jsvalue.Object{{Key: "identityId", Value: member.ID}, {Key: "name", Value: member.Name}, {Key: "role", Value: role},
			{Key: "removedAt", Value: iso(member.RemovedAt)}}},
		{Key: "coverage", Value: coverage},
		{Key: "received", Value: versions},
		{Key: "authorityAtRemoval", Value: authority},
		{Key: "indirect", Value: indirect},
	}, nil
}

// authorityAtRemoval is the snapshot a removal recorded: per environment,
// each action with its sources, and the Requirements reading values there
// was conditional on (copies); nil for a current member.
func authorityAtRemoval(ctx context.Context, q *query.Queries, organizationID, identityID string) (any, error) {
	removal, err := q.RemovalOf(ctx, query.RemovalOfParams{OrganizationID: organizationID, IdentityID: identityID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows, err := q.RemovalAuthorityRows(ctx, removal.ID)
	if err != nil {
		return nil, err
	}
	type action struct {
		name    string
		sources []any
	}
	type env struct {
		id          string
		actions     []*action
		conditionOn []any
	}
	var envs []*env
	byID := map[string]*env{}
	for _, a := range rows {
		e := byID[a.EnvironmentID]
		if e == nil {
			e = &env{id: a.EnvironmentID, conditionOn: []any{}}
			byID[a.EnvironmentID] = e
			envs = append(envs, e)
		}
		var act *action
		for _, x := range e.actions {
			if x.name == a.Action {
				act = x
			}
		}
		if act == nil {
			act = &action{name: a.Action}
			e.actions = append(e.actions, act)
		}
		act.sources = append(act.sources, jsvalue.Object{{Key: "source", Value: a.Source}, {Key: "role", Value: nullStringJS(a.Role)},
			{Key: "grantId", Value: nullStringJS(a.GrantID)}, {Key: "viaGroupId", Value: nullStringJS(a.ViaGroupID)}, {Key: "roleId", Value: nullStringJS(a.RoleID)}})
	}
	conditions, err := q.RemovalConditionRows(ctx, removal.ID)
	if err != nil {
		return nil, err
	}
	for _, c := range conditions {
		if e := byID[c.EnvironmentID]; e != nil {
			e.conditionOn = append(e.conditionOn, c.RequirementID)
		}
	}
	reqs, err := q.RemovalRequirementRows(ctx, removal.ID)
	if err != nil {
		return nil, err
	}
	requirements := make([]any, len(reqs))
	for i, r := range reqs {
		target, err := jsvalue.Parse([]byte(r.Target))
		if err != nil {
			return nil, err
		}
		selector, err := jsvalue.Parse([]byte(r.Selector))
		if err != nil {
			return nil, err
		}
		var version any
		if r.RequirementVersion.Valid {
			version = r.RequirementVersion.Int64
		}
		requirements[i] = jsvalue.Object{{Key: "requirementId", Value: r.RequirementID}, {Key: "requirementVersion", Value: version},
			{Key: "target", Value: jsvalue.Jsonb(target)}, {Key: "selector", Value: jsvalue.Jsonb(selector)}}
	}
	environments := make([]any, len(envs))
	for i, e := range envs {
		actions := make([]any, len(e.actions))
		for j, a := range e.actions {
			actions[j] = jsvalue.Object{{Key: "action", Value: a.name}, {Key: "sources", Value: a.sources}}
		}
		environments[i] = jsvalue.Object{{Key: "environmentId", Value: e.id}, {Key: "actions", Value: actions}, {Key: "conditionalOn", Value: e.conditionOn}}
	}
	return jsvalue.Object{
		{Key: "removalId", Value: removal.ID}, {Key: "removedAt", Value: audit.ISOTime(removal.RemovedAt)}, {Key: "role", Value: removal.Role},
		{Key: "left", Value: removal.ActorIdentityID == identityID}, {Key: "environments", Value: environments}, {Key: "requirements", Value: requirements},
	}, nil
}

// backfillCoverage is the report's coverage: complete once the TypeScript
// backfill finished (a Go installation starts finished); otherwise the
// period still being indexed.
func backfillCoverage(ctx context.Context, db query.DBTX) (any, error) {
	var finished, from, to sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT b.finished_at,
		(SELECT a.occurred_at FROM audit_events a WHERE a.event_order > b.cursor ORDER BY a.event_order LIMIT 1),
		(SELECT a.occurred_at FROM audit_events a WHERE a.event_order = b.until_order)
		FROM exposure_backfill b WHERE b.singleton = 1`).Scan(&finished, &from, &to)
	if errors.Is(err, sql.ErrNoRows) || err == nil && finished.Valid {
		return jsvalue.Object{{Key: "complete", Value: true}}, nil
	}
	if err != nil {
		return nil, err
	}
	return jsvalue.Object{{Key: "complete", Value: false}, {Key: "from", Value: iso(from)}, {Key: "to", Value: iso(to)}}, nil
}

// ExposedVersion is exposedVersion: the value owning an exposed version,
// and whether it, its environment and its Project are live; nil when the
// version is not in the person's exposure.
type ExposedVersion struct {
	ItemName      string
	EnvironmentID sql.NullString
	ProjectID     sql.NullString
	Live          bool
}

// ReadExposedVersion reads it.
func ReadExposedVersion(ctx context.Context, db query.DBTX, organizationID, identityID, versionID string) (*ExposedVersion, error) {
	if err := pgText(identityID, versionID); err != nil {
		return nil, err
	}
	r, err := query.New(db).ExposedVersion(ctx, query.ExposedVersionParams{OrganizationID: organizationID, IdentityID: identityID, VersionID: versionID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	live, _ := r.Live.(int64)
	return &ExposedVersion{ItemName: r.ItemName, EnvironmentID: r.EnvironmentID, ProjectID: r.ProjectID, Live: live == 1}, nil
}

// ConfirmRevocation is confirmRevocation: that an exposed version was
// revoked or rotated at its provider, once per version, audited as
// exposure.revocation_confirmed. The caller has checked the permission; a
// repeated confirmation answers the first (created false).
func ConfirmRevocation(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, identityID, versionID string, v ExposedVersion, now func() time.Time) (jsvalue.Object, bool, []auth.PendingReport, error) {
	actor := p.Identity.ID
	var out jsvalue.Object
	var created bool
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(actor, write.Shared), write.Person(identityID, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID}); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		q := query.New(tx)
		inserted, err := q.InsertConfirmation(ctx, query.InsertConfirmationParams{OrganizationID: organizationID, VersionID: versionID,
			IdentityID: identityID, ActorIdentityID: actor, ConfirmedAt: now().UnixMicro()})
		if err != nil {
			return err
		}
		var at int64
		var by string
		if created = len(inserted) > 0; created {
			at, by = inserted[0].ConfirmedAt, inserted[0].ActorIdentityID
			if _, err := audit.Record(ctx, tx, audit.Event{Type: "exposure.revocation_confirmed", Decision: audit.Info, ActorIdentityID: &actor,
				OrganizationID: &organizationID, Resource: jsvalue.Object{{Key: "identityId", Value: identityID}, {Key: "versionId", Value: versionID},
					{Key: "itemName", Value: v.ItemName}, {Key: "environmentId", Value: nullStringJS(v.EnvironmentID)}}}); err != nil {
				return err
			}
		} else {
			row, err := q.ConfirmationOf(ctx, query.ConfirmationOfParams{OrganizationID: organizationID, VersionID: versionID})
			if err != nil {
				return err
			}
			at, by = row.ConfirmedAt, row.ActorIdentityID
		}
		out = jsvalue.Object{{Key: "versionId", Value: versionID}, {Key: "confirmedAt", Value: audit.ISOTime(at)}, {Key: "actorIdentityId", Value: by}}
		return nil
	})
	if err != nil {
		return nil, false, nil, err
	}
	return out, created, reports, nil
}

// NotExposed is the confirmation's refusal of a version the person never
// received.
func NotExposed() error {
	return domainerr.New("RESOURCE_NOT_FOUND", "That version is not in this member's exposure")
}
