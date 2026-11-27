// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"database/sql"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/totp"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/contracts"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// What an entry link needs of values (ADR-0063, server/entry): what an item
// is now, and the one write, in the job that uses the link up.

// Current is what an item is in an environment: its own value, or else the
// one its parent gives it.
type Current struct {
	// VersionID is "" when it has no value at all.
	VersionID string
	// Rotating is whether a rotation's window is open.
	Rotating bool
	seed     int64
}

// CurrentOf reads what item is in an environment, at now.
func CurrentOf(ctx context.Context, db query.DBTX, env query.LiveEnvironmentRow, item string, now int64) (Current, error) {
	environments := []string{env.ID}
	if env.ParentEnvironmentID.Valid {
		environments = append(environments, env.ParentEnvironmentID.String)
	}
	for _, id := range environments {
		rows, err := query.New(db).ValueRotationOf(ctx, query.ValueRotationOfParams{EnvironmentID: id, ItemName: item})
		if err != nil {
			return Current{}, err
		}
		for _, r := range rows {
			if deleted(r.DeletedAt, r.Seed) || !r.CurrentVersionID.Valid {
				continue
			}
			return Current{VersionID: r.CurrentVersionID.String, seed: r.Seed,
				Rotating: r.RetiringVersionID.Valid && r.RotationDeadline.Valid && r.RotationDeadline.Int64 > now}, nil
		}
	}
	return Current{}, nil
}

// Enterable refuses what cannot be entered through a link: an item that is
// no Secret, an OAuth connection (a person connects one in the dashboard),
// a value where a seed is, and an item that is being rotated. seed is
// whether the link takes the seed of a one-time code. undeclared is whether
// the item may be one the active Contract does not name: an item no one
// expects reaches every process that gets the environment, and a name such as
// NODE_OPTIONS means something to it.
func Enterable(ctx context.Context, db query.DBTX, t Target, item string, seed, undeclared bool, now int64) (Current, error) {
	if err := checkItemName(item); err != nil {
		return Current{}, err
	}
	if err := checkNotExpired(t.Env, now); err != nil {
		return Current{}, err
	}
	active, err := contracts.Active(ctx, db, t.Project.ID, t.Project.ActiveContractRevisionID)
	if err != nil {
		return Current{}, err
	}
	declared, sensitive := active == nil, true
	if active != nil {
		for _, it := range active.Items {
			if it.Name == item {
				declared, sensitive = true, it.Sensitive
			}
		}
	}
	if !declared && !undeclared {
		return Current{}, &domainerr.Error{Code: "VALIDATION_FAILED", Details: jsvalue.Object{{Key: "reason", Value: "not-in-contract"}},
			Message: item + " is not in the Contract: an identity without config.value.write asks for what the Contract names"}
	}
	if !sensitive {
		return Current{}, &domainerr.Error{Code: "VALIDATION_FAILED", Details: jsvalue.Object{{Key: "reason", Value: "not-sensitive"}},
			Message: item + " is not sensitive in the Contract: only a Secret's value is entered through a link"}
	}
	current, err := CurrentOf(ctx, db, t.Env, item, now)
	if err != nil {
		return Current{}, err
	}
	if current.seed == kindConnection {
		return Current{}, &domainerr.Error{Code: "VALIDATION_FAILED", Details: jsvalue.Object{{Key: "reason", Value: "oauth-connection"}},
			Message: item + " is an OAuth connection: a person who may write values here connects it in the dashboard, in their own session"}
	}
	// checkKind's rules, for what an inherited value is too.
	var s *totp.Seed
	if seed {
		s = &totp.Seed{}
	}
	if err := checkKind(item, current.seed, s, true); err != nil {
		return Current{}, err
	}
	if current.Rotating {
		return Current{}, domainerr.New("ROTATION_IN_PROGRESS", item+" is being rotated: complete the rotation first")
	}
	return current, nil
}

// CheckEntered refuses a value that is not what it says: one that holds
// ${NAME}, which is replaced by another item's value wherever this one is
// used, so that whoever may write this one would have that one sent where
// this one goes, or $${NAME}, which is used as something else than was
// entered.
func CheckEntered(value string) error {
	if token.MatchString(value) {
		return &domainerr.Error{Code: "VALIDATION_FAILED", Details: jsvalue.Object{{Key: "reason", Value: "reference"}},
			Message: "value: it holds ${…}, which Varlatch would replace by another value: somebody who may write values here has to set this one"}
	}
	return nil
}

// Enter writes what was entered through a link: a version, and
// value.written with metadata added, by actor, or by nobody known when it is
// "" (a link open to anyone). The caller has checked everything in this job.
func Enter(ctx context.Context, tx *storage.Tx, rootKEK []byte, t Target, item, value string, seed *totp.Seed, actor string, requestID string, metadata jsvalue.Object, at int64) error {
	orgKEK, err := orgKEKIn(ctx, tx, rootKEK, t.OrganizationID)
	if err != nil {
		return err
	}
	defer clear(orgKEK)
	q := query.New(tx)
	rows, err := q.ValueRowsOfItems(ctx, query.ValueRowsOfItemsParams{EnvironmentID: t.Env.ID, ItemNames: []string{item}})
	if err != nil {
		return err
	}
	var row valueRow
	if len(rows) > 0 {
		row = rows[0]
	} else {
		row = valueRow{ID: ids.New("val"), ItemName: item}
		if err := q.InsertValueRow(ctx, query.InsertValueRowParams{ID: row.ID, EnvironmentID: t.Env.ID, ItemName: item, CreatedAt: at}); err != nil {
			return err
		}
	}
	previous := row.CurrentVersionID
	if deleted(row.DeletedAt, row.Seed) {
		previous = sql.NullString{}
	}
	versionID := ids.New("ver")
	if err := writeVersion(ctx, q, orgKEK, t.OrganizationID, row.ID, versionID, value, seed, previous, actor, at); err != nil {
		return err
	}
	action := "config.value.write"
	event := audit.Event{
		Type: "value.written", Decision: audit.Info, OrganizationID: &t.OrganizationID, Action: &action, RequestID: &requestID,
		Resource: jsvalue.Object{
			{Key: "projectId", Value: t.Project.ID}, {Key: "environmentId", Value: t.Env.ID}, {Key: "itemName", Value: item},
			{Key: "versionId", Value: versionID}, {Key: "previousVersionId", Value: nullable(previous)},
		},
		Metadata: append(ofSeed(jsvalue.Object{{Key: "sensitive", Value: true}}, seed), metadata...),
	}
	if actor != "" {
		event.ActorIdentityID = &actor
	}
	_, err = audit.Record(ctx, tx, event)
	return err
}
