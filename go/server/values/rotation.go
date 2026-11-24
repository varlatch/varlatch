// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"database/sql"

	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/totp"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/contracts"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// Dual-phase rotation (ADR-0027; domain/values.ts beginRotation and
// completeRotation; ADR-0059 step 4.2). Beginning one writes a new
// primary version and keeps the prior one retiring until a deadline: the
// read path delivers both until then (values.go). Completing it drops the
// retiring version early. A plain write or a deletion supersedes a
// rotation in flight (SetCurrentValueVersion, DeleteLiveValue). Each is
// one job behind the Organization's and the requester's shared gates, in
// the TypeScript order.

const (
	// DefaultRotationGraceSeconds is the overlap when neither the request
	// nor the Contract names one (contracts.ts DEFAULT_ROTATION_GRACE_SECONDS).
	DefaultRotationGraceSeconds = 24 * 60 * 60
	// MaxRotationGraceSeconds bounds any overlap (MAX_ROTATION_GRACE_SECONDS).
	MaxRotationGraceSeconds = 30 * 24 * 60 * 60
)

// RotationInput is beginRotation's body as its zod schema leaves it.
type RotationInput struct {
	Value string
	// Seed, when set, is the new primary instead of Value (ADR-0061): until
	// the rotation ends an exercise gives the codes of both seeds, which is
	// what enrolling anew at the issuer needs.
	Seed *totp.Seed
	// ExpectedVersionID and GraceSeconds are nil when absent.
	ExpectedVersionID *string
	GraceSeconds      *int64
}

// rotationGrace is rotationGraceOf: the Contract's advisory per-item hint
// (ADR-0053), else the default; the request's own grace first, all
// bounded by the maximum.
func rotationGrace(c *contract.Contract, item string, requested *int64) int64 {
	grace := int64(DefaultRotationGraceSeconds)
	if requested != nil {
		grace = *requested
	} else if c != nil {
		for _, it := range c.Items {
			if it.Name == item {
				if it.RotationGraceSeconds != nil {
					grace = *it.RotationGraceSeconds
				}
				break
			}
		}
	}
	return min(grace, MaxRotationGraceSeconds)
}

// sensitiveIn is sensitivityOf on a parsed Contract: an item it does not
// name, or no Contract, is sensitive.
func sensitiveIn(c *contract.Contract, item string) bool {
	if c == nil {
		return true
	}
	for _, it := range c.Items {
		if it.Name == item {
			return it.Sensitive
		}
	}
	return true
}

// rotationRow is the item's value row, or nil.
func rotationRow(ctx context.Context, q *query.Queries, environmentID, item string) (*query.ValueRotationOfRow, error) {
	rows, err := q.ValueRotationOf(ctx, query.ValueRotationOfParams{EnvironmentID: environmentID, ItemName: item})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// BeginRotation is POST …/values/{item}/rotations (beginRotation). In the
// TypeScript order: the item's name, the environment's expiry, the
// Organization's KEK, the active Contract (the item's sensitivity and its
// grace hint); then in the job the writer's checks, the live value with a
// current version (RESOURCE_NOT_FOUND) before the checkpoint (existence
// first, ADR-0054 Decision 7), a rotation already in flight
// (ROTATION_IN_PROGRESS; one past its deadline is over), the expected
// version (VERSION_CONFLICT); the new version sealed, the row pointed at
// it with the prior one retiring until the deadline, and
// value.rotation_started. The answer is the route's body, 201.
func BeginRotation(ctx context.Context, w *write.Writer, rootKEK []byte, p *auth.Principal, t Target, item string, in RotationInput, now Clock) (jsvalue.Object, []auth.PendingReport, error) {
	if err := checkItemName(item); err != nil {
		return nil, nil, err
	}
	if err := checkNotExpired(t.Env, now().UnixMicro()); err != nil {
		return nil, nil, err
	}
	var (
		reports []auth.PendingReport
		answer  jsvalue.Object
	)
	gates := []write.Gate{write.Organization(t.OrganizationID, write.Shared), write.Person(p.Identity.ID, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		orgKEK, err := orgKEKIn(ctx, tx, rootKEK, t.OrganizationID)
		if err != nil {
			return err
		}
		active, err := contracts.Active(ctx, tx, t.Project.ID, t.Project.ActiveContractRevisionID)
		if err != nil {
			return err
		}
		sensitive := sensitiveIn(active, item)
		grace := rotationGrace(active, item, in.GraceSeconds)
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: t.OrganizationID, ProjectID: t.Project.ID, EnvironmentIDs: []string{t.Env.ID}}); err != nil {
			return err
		}
		q := query.New(tx)
		row, err := rotationRow(ctx, q, t.Env.ID, item)
		if err != nil {
			return err
		}
		if row == nil || deleted(row.DeletedAt, row.Seed) || !row.CurrentVersionID.Valid {
			return domainerr.New("RESOURCE_NOT_FOUND", "No current value to rotate")
		}
		if reports, err = write.Checkpoint(ctx, tx, p, t.OrganizationID); err != nil {
			return err
		}
		at := now()
		// new Date(rotation_deadline).getTime() > Date.now(): milliseconds.
		if row.RetiringVersionID.Valid && row.RotationDeadline.Valid && row.RotationDeadline.Int64/1000 > at.UnixMilli() {
			return domainerr.New("ROTATION_IN_PROGRESS", "A rotation is already in progress for this item; complete it before starting another")
		}
		if in.ExpectedVersionID != nil && row.CurrentVersionID.String != *in.ExpectedVersionID {
			return &domainerr.Error{
				Code: "VERSION_CONFLICT", Message: "The value changed since the expected version",
				Details: jsvalue.Object{{Key: "currentVersionId", Value: row.CurrentVersionID.String}},
			}
		}
		if in.Seed != nil && row.Seed == kindValue {
			// Both versions are delivered until the rotation ends, and only
			// one kind of them at a time can be.
			return &domainerr.Error{Code: "VALIDATION_FAILED", Details: jsvalue.Object{{Key: "reason", Value: "one-time-code"}},
				Message: item + " holds a value: a rotation to the seed of a one-time code needs a seed to rotate from. Set the seed instead"}
		}
		if err := checkKind(item, row.Seed, in.Seed, sensitive); err != nil {
			return err
		}
		versionID := ids.New("ver")
		if in.Seed != nil {
			err = insertSeed(ctx, q, orgKEK, t.OrganizationID, row.ID, versionID, *in.Seed, row.CurrentVersionID, p.Identity.ID, at.UnixMicro())
		} else {
			err = insertVersion(ctx, q, orgKEK, t.OrganizationID, row.ID, versionID, in.Value, row.CurrentVersionID, p.Identity.ID, at.UnixMicro())
		}
		if err != nil {
			return err
		}
		// new Date(Date.now() + grace * 1000).toISOString(): milliseconds.
		deadline := (at.UnixMilli() + grace*1000) * 1000
		if err := q.BeginValueRotation(ctx, query.BeginValueRotationParams{
			CurrentVersionID: sql.NullString{String: versionID, Valid: true}, RetiringVersionID: row.CurrentVersionID,
			RotationDeadline: sql.NullInt64{Int64: deadline, Valid: true}, RotationStartedAt: sql.NullInt64{Int64: at.UnixMicro(), Valid: true},
			ID: row.ID,
		}); err != nil {
			return err
		}
		actor, action := p.Identity.ID, "config.value.write"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "value.rotation_started", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &t.OrganizationID, Action: &action,
			Resource: jsvalue.Object{
				{Key: "projectId", Value: t.Project.ID}, {Key: "environmentId", Value: t.Env.ID}, {Key: "itemName", Value: item},
				{Key: "versionId", Value: versionID}, {Key: "previousVersionId", Value: row.CurrentVersionID.String},
			},
			Metadata: ofSeed(jsvalue.Object{
				{Key: "sensitive", Value: sensitive}, {Key: "retiring", Value: item + "@" + row.CurrentVersionID.String},
				{Key: "deadline", Value: audit.ISOTime(deadline)},
			}, in.Seed),
		}); err != nil {
			return err
		}
		answer = jsvalue.Object{
			{Key: "itemName", Value: item}, {Key: "environmentId", Value: t.Env.ID}, {Key: "primaryVersionId", Value: versionID},
			{Key: "retiringVersionId", Value: row.CurrentVersionID.String}, {Key: "rotationDeadline", Value: audit.ISOTime(deadline)},
			{Key: "sensitive", Value: sensitive},
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return answer, reports, nil
}

// CompleteRotation is POST …/values/{item}/rotations/complete
// (completeRotation): the environment's expiry first; then in the job the
// writer's checks, the live value with a current version
// (RESOURCE_NOT_FOUND) before the checkpoint, and, when a retiring
// version is pinned (its deadline passed or not), the rotation cleared and
// value.rotation_completed. Completing an item not rotating changes
// nothing and succeeds. The item's name is not checked: a name no value
// has is not found. The answer is the route's body, 200.
func CompleteRotation(ctx context.Context, w *write.Writer, p *auth.Principal, t Target, item string, now Clock) (jsvalue.Object, []auth.PendingReport, error) {
	if err := checkNotExpired(t.Env, now().UnixMicro()); err != nil {
		return nil, nil, err
	}
	var (
		reports []auth.PendingReport
		answer  jsvalue.Object
	)
	gates := []write.Gate{write.Organization(t.OrganizationID, write.Shared), write.Person(p.Identity.ID, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: t.OrganizationID, ProjectID: t.Project.ID, EnvironmentIDs: []string{t.Env.ID}}); err != nil {
			return err
		}
		q := query.New(tx)
		row, err := rotationRow(ctx, q, t.Env.ID, item)
		if err != nil {
			return err
		}
		if row == nil || deleted(row.DeletedAt, row.Seed) || !row.CurrentVersionID.Valid {
			return domainerr.New("RESOURCE_NOT_FOUND", "No value to complete rotation for")
		}
		if reports, err = write.Checkpoint(ctx, tx, p, t.OrganizationID); err != nil {
			return err
		}
		if row.RetiringVersionID.Valid {
			if err := q.CompleteValueRotation(ctx, row.ID); err != nil {
				return err
			}
			actor, action := p.Identity.ID, "config.value.write"
			if _, err := audit.Record(ctx, tx, audit.Event{
				Type: "value.rotation_completed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &t.OrganizationID, Action: &action,
				Resource: jsvalue.Object{
					{Key: "projectId", Value: t.Project.ID}, {Key: "environmentId", Value: t.Env.ID}, {Key: "itemName", Value: item},
					{Key: "versionId", Value: row.CurrentVersionID.String},
				},
				Metadata: jsvalue.Object{{Key: "retired", Value: item + "@" + row.RetiringVersionID.String}},
			}); err != nil {
				return err
			}
		}
		active, err := contracts.Active(ctx, tx, t.Project.ID, t.Project.ActiveContractRevisionID)
		if err != nil {
			return err
		}
		answer = jsvalue.Object{
			{Key: "itemName", Value: item}, {Key: "environmentId", Value: t.Env.ID},
			{Key: "primaryVersionId", Value: row.CurrentVersionID.String}, {Key: "sensitive", Value: sensitiveIn(active, item)},
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return answer, reports, nil
}
