// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/totp"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/contracts"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/environments"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// The writes of values (domain/values.ts setValue, deleteValue and
// applyChangeSet; ADR-0059 step 4.1d): each one job of the single writer
// behind the Organization's and the requester's shared gates, in the
// TypeScript order, with the writer's checks (the Organization, the
// Project and the environment live) and the passkey-verification
// checkpoint inside it. setValue and applyChangeSet run under an
// Idempotency-Key when the request has one (write.Idempotent): the claim,
// the write and the stored response are the same job.

// Target is the environment a write is for, as the route entered it.
type Target struct {
	OrganizationID string
	Project        query.LiveProjectRow
	Env            query.LiveEnvironmentRow
}

var itemName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// checkItemName is assertItemName.
func checkItemName(name string) error {
	if !itemName.MatchString(name) {
		return domainerr.New("VALIDATION_FAILED", "Invalid Config Item name: "+name)
	}
	if slices.Contains(contract.ReservedItemNames, name) {
		return domainerr.New("VALIDATION_FAILED", name+" is reserved for launcher metadata and cannot be stored")
	}
	return nil
}

// checkNotExpired is assertNotExpired (ADR-0020): an expired environment
// takes no writes.
func checkNotExpired(env query.LiveEnvironmentRow, now int64) error {
	if environments.Expired(env, now) {
		return domainerr.New("ENVIRONMENT_EXPIRED",
			"This environment has expired; retrieval and mutation are disabled until it is deleted or its expiry is changed")
	}
	return nil
}

// orgKEKIn is orgKekOf, read in db: a deleted Organization's KEK is
// destroyed (ADR-0051 Decision 6), so it fails closed.
func orgKEKIn(ctx context.Context, db query.DBTX, rootKEK []byte, organizationID string) ([]byte, error) {
	org, err := query.New(db).RetrievalOrganization(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	if !org.WrappedOrgKek.Valid {
		return nil, domainerr.New("ORGANIZATION_DELETED", "This Organization was deleted: its key is destroyed")
	}
	var wrapped envelope.Envelope
	if err := json.Unmarshal([]byte(org.WrappedOrgKek.String), &wrapped); err != nil {
		return nil, err
	}
	return envelope.UnwrapOrgKEK(rootKEK, wrapped, organizationID)
}

// sensitivity is sensitivityOf on the Project's active Contract as the
// route read the Project: an item it does not name is sensitive.
func sensitivity(ctx context.Context, db query.DBTX, project query.LiveProjectRow) (func(string) bool, error) {
	active, err := contracts.Active(ctx, db, project.ID, project.ActiveContractRevisionID)
	if err != nil {
		return nil, err
	}
	return func(name string) bool {
		if active == nil {
			return true
		}
		for _, it := range active.Items {
			if it.Name == name {
				return it.Sensitive
			}
		}
		return true
	}, nil
}

// nodeUTF8 is Buffer.from(s, "utf8"): a lone surrogate (kept as WTF-8 by
// jsvalue) is written as U+FFFD, as Node encodes it. A value is sealed,
// never stored as text, so U+0000 stays.
func nodeUTF8(s string) []byte {
	if utf8.ValidString(s) {
		return []byte(s)
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n <= 1 {
			if i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
				n = 3
			}
			out = utf8.AppendRune(out, utf8.RuneError)
			i += max(n, 1)
			continue
		}
		out = append(out, s[i:i+n]...)
		i += n
	}
	return out
}

// valueRow is a row of env_values as lockValueRows reads it.
type valueRow = query.ValueRowsOfItemsRow

// What a live value row holds (ValueRowsOfItems' seed).
const (
	kindValue      = 0
	kindSeed       = 1
	kindConnection = 2
)

// deleted is whether a value row holds nothing: a seed of one-time codes
// and an OAuth connection have a deleted_at and are live (ADR-0061,
// ADR-0062).
func deleted(at sql.NullInt64, seed int64) bool { return at.Valid && seed == 0 }

// checkKind refuses, for a live value row, a value where a seed is, a value or
// a seed where an OAuth connection is, and a seed for an item that is no
// Secret.
func checkKind(item string, holds int64, seed *totp.Seed, sensitive bool) error {
	switch {
	case holds == kindConnection:
		return &domainerr.Error{Code: "VALIDATION_FAILED", Details: jsvalue.Object{{Key: "reason", Value: "oauth-connection"}},
			Message: item + " is an OAuth connection: delete it before setting a value"}
	case seed == nil && holds == kindSeed:
		return &domainerr.Error{Code: "VALIDATION_FAILED", Details: jsvalue.Object{{Key: "reason", Value: "one-time-code"}},
			Message: item + " holds the seed of a one-time code: give another seed (otpauth), or delete it before setting a value"}
	case seed != nil && !sensitive:
		return &domainerr.Error{Code: "VALIDATION_FAILED", Details: jsvalue.Object{{Key: "reason", Value: "not-sensitive"}},
			Message: item + " is not sensitive in the Contract, and a seed is always a Secret: mark the item sensitive first"}
	}
	return nil
}

// writeVersion writes a new version of a value row, a value or a seed, and
// points the row at it.
func writeVersion(ctx context.Context, q *query.Queries, orgKEK []byte, organizationID, valueID, versionID, value string, seed *totp.Seed, previous sql.NullString, actor string, at int64) error {
	if seed == nil {
		return sealVersion(ctx, q, orgKEK, organizationID, valueID, versionID, value, previous, actor, at)
	}
	if err := insertSeed(ctx, q, orgKEK, organizationID, valueID, versionID, *seed, previous, actor, at); err != nil {
		return err
	}
	return q.SetCurrentSeedVersion(ctx, query.SetCurrentSeedVersionParams{Version: sql.NullString{String: versionID, Valid: true},
		Now: sql.NullInt64{Int64: at, Valid: true}, ID: valueID})
}

// ofSeed is a write's audit metadata, when it wrote a seed.
func ofSeed(md jsvalue.Object, seed *totp.Seed) jsvalue.Object {
	if seed != nil {
		md = append(md, jsvalue.Member{Key: "totp", Value: true})
	}
	return md
}

// sealVersion writes a new version of a value row: sealed under the
// Organization's KEK, its predecessor named, the row pointed at it (a plain
// write supersedes any rotation in flight).
func sealVersion(ctx context.Context, q *query.Queries, orgKEK []byte, organizationID, valueID, versionID, value string, previous sql.NullString, actor string, at int64) error {
	if err := insertVersion(ctx, q, orgKEK, organizationID, valueID, versionID, value, previous, actor, at); err != nil {
		return err
	}
	return q.SetCurrentValueVersion(ctx, query.SetCurrentValueVersionParams{CurrentVersionID: sql.NullString{String: versionID, Valid: true}, ID: valueID})
}

// insertVersion writes a new version of a value row, sealed under the
// Organization's KEK, its predecessor named; the row is left as it is.
func insertVersion(ctx context.Context, q *query.Queries, orgKEK []byte, organizationID, valueID, versionID, value string, previous sql.NullString, actor string, at int64) error {
	sealed, err := SealValue(orgKEK, organizationID, valueID, versionID, nodeUTF8(value))
	if err != nil {
		return err
	}
	payload, err := json.Marshal(sealed.Payload)
	if err != nil {
		return err
	}
	dek, err := json.Marshal(sealed.WrappedDEK)
	if err != nil {
		return err
	}
	return q.InsertValueVersion(ctx, query.InsertValueVersionParams{
		ID: versionID, ValueID: valueID, Payload: sql.NullString{String: string(payload), Valid: true},
		WrappedDek: sql.NullString{String: string(dek), Valid: true}, PreviousVersionID: previous,
		CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: at,
	})
}

// SetInput is setValue's body as its zod schema leaves it.
type SetInput struct {
	Value string
	// Seed, when set, is written instead of Value (ADR-0061).
	Seed *totp.Seed
	// ExpectedVersionID is nil when absent.
	ExpectedVersionID *string
}

// Clock is the time a write reads, in the job.
type Clock func() time.Time

// SetValue is PUT …/values/{item} (setValue under withIdempotency): the
// claim's job, or a plain job without a key. In the job, in the TypeScript
// order: the item's name, the environment's expiry, the Organization's
// KEK, the item's sensitivity from the active Contract; the writer's checks
// (the environment included) and the checkpoint; the value row (made when
// the item has none, deleted ones reused); the expected version
// (VERSION_CONFLICT with the current one); then the sealed version, the
// row pointed at it, and value.written. The answer is the route's.
func SetValue(ctx context.Context, w *write.Writer, rootKEK []byte, p *auth.Principal, t Target, item string, in SetInput, claim write.Claim, now Clock) (write.Response, bool, []auth.PendingReport, error) {
	var reports []auth.PendingReport
	resp, replayed, err := idempotentJob(ctx, w, p, t.OrganizationID, claim, &reports, func(ctx context.Context, tx *storage.Tx) (write.Response, error) {
		at := now().UnixMicro()
		if err := checkItemName(item); err != nil {
			return write.Response{}, err
		}
		if err := checkNotExpired(t.Env, at); err != nil {
			return write.Response{}, err
		}
		orgKEK, err := orgKEKIn(ctx, tx, rootKEK, t.OrganizationID)
		if err != nil {
			return write.Response{}, err
		}
		sensitive, err := sensitivity(ctx, tx, t.Project)
		if err != nil {
			return write.Response{}, err
		}
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: t.OrganizationID, ProjectID: t.Project.ID, EnvironmentIDs: []string{t.Env.ID}}); err != nil {
			return write.Response{}, err
		}
		if reports, err = write.Checkpoint(ctx, tx, p, t.OrganizationID); err != nil {
			return write.Response{}, err
		}
		q := query.New(tx)
		rows, err := q.ValueRowsOfItems(ctx, query.ValueRowsOfItemsParams{EnvironmentID: t.Env.ID, ItemNames: []string{item}})
		if err != nil {
			return write.Response{}, err
		}
		var row valueRow
		if len(rows) > 0 {
			row = rows[0]
		} else {
			row = valueRow{ID: ids.New("val"), ItemName: item}
			if err := q.InsertValueRow(ctx, query.InsertValueRowParams{ID: row.ID, EnvironmentID: t.Env.ID, ItemName: item, CreatedAt: at}); err != nil {
				return write.Response{}, err
			}
		}
		if in.ExpectedVersionID != nil && (!row.CurrentVersionID.Valid || row.CurrentVersionID.String != *in.ExpectedVersionID) {
			return write.Response{}, &domainerr.Error{
				Code: "VERSION_CONFLICT", Message: "The value changed since the expected version",
				Details: jsvalue.Object{{Key: "currentVersionId", Value: nullable(row.CurrentVersionID)}},
			}
		}
		if err := checkKind(item, row.Seed, in.Seed, sensitive(item)); err != nil {
			return write.Response{}, err
		}
		versionID := ids.New("ver")
		if err := writeVersion(ctx, q, orgKEK, t.OrganizationID, row.ID, versionID, in.Value, in.Seed, row.CurrentVersionID, p.Identity.ID, at); err != nil {
			return write.Response{}, err
		}
		actor, action := p.Identity.ID, "config.value.write"
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "value.written", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &t.OrganizationID, Action: &action,
			Resource: jsvalue.Object{
				{Key: "projectId", Value: t.Project.ID}, {Key: "environmentId", Value: t.Env.ID}, {Key: "itemName", Value: item},
				{Key: "versionId", Value: versionID}, {Key: "previousVersionId", Value: nullable(row.CurrentVersionID)},
			},
			Metadata: ofSeed(jsvalue.Object{{Key: "sensitive", Value: sensitive(item)}}, in.Seed),
		}); err != nil {
			return write.Response{}, err
		}
		answer := jsvalue.Object{
			{Key: "versionId", Value: versionID}, {Key: "itemName", Value: item}, {Key: "environmentId", Value: t.Env.ID},
			{Key: "sensitive", Value: sensitive(item)}, {Key: "previousVersionId", Value: nullable(row.CurrentVersionID)},
			{Key: "createdAt", Value: audit.ISOTime(now().UnixMicro())},
		}
		if in.Seed != nil {
			answer = append(answer, jsvalue.Member{Key: "totp", Value: ParamsJS(in.Seed.Params)})
		}
		return write.Response{Status: 200, Payload: answer}, nil
	})
	return resp, replayed, reports, err
}

// idempotentJob takes the Organization's and the requester's gates
// shared, then runs job as write.Idempotent does under claim; a replay
// runs the requester's checkpoint first (requireOrganizationAccess).
func idempotentJob(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID string, claim write.Claim, reports *[]auth.PendingReport, job func(context.Context, *storage.Tx) (write.Response, error)) (write.Response, bool, error) {
	ctx, release, err := w.Gates.Acquire(ctx, write.Organization(organizationID, write.Shared), write.Person(p.Identity.ID, write.Shared))
	if err != nil {
		return write.Response{}, false, err
	}
	defer release()
	return write.Idempotent(ctx, w.Store, claim,
		func(tx *storage.Tx) error {
			var err error
			*reports, err = write.Checkpoint(ctx, tx, p, organizationID)
			return err
		},
		func(tx *storage.Tx) (write.Response, error) { return job(ctx, tx) })
}

// DeleteValue is DELETE …/values/{item} (deleteValue): the environment's
// expiry first; then in one job the writer's checks, the live value
// (RESOURCE_NOT_FOUND "Value not found") before the checkpoint (existence
// first, ADR-0054 Decision 7), the tombstone (its rotation cleared), and
// value.deleted. The item's name is not checked: a name no value has is
// not found.
func DeleteValue(ctx context.Context, w *write.Writer, p *auth.Principal, t Target, item string, now Clock) ([]auth.PendingReport, error) {
	if err := checkNotExpired(t.Env, now().UnixMicro()); err != nil {
		return nil, err
	}
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(t.OrganizationID, write.Shared), write.Person(p.Identity.ID, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: t.OrganizationID, ProjectID: t.Project.ID, EnvironmentIDs: []string{t.Env.ID}}); err != nil {
			return err
		}
		q := query.New(tx)
		live, err := q.LiveValueCount(ctx, query.LiveValueCountParams{EnvironmentID: t.Env.ID, ItemName: item})
		if err != nil {
			return err
		}
		if live == 0 {
			return domainerr.New("RESOURCE_NOT_FOUND", "Value not found")
		}
		if reports, err = write.Checkpoint(ctx, tx, p, t.OrganizationID); err != nil {
			return err
		}
		if _, err := q.DeleteLiveValue(ctx, query.DeleteLiveValueParams{
			DeletedAt: sql.NullInt64{Int64: now().UnixMicro(), Valid: true}, EnvironmentID: t.Env.ID, ItemName: item,
		}); err != nil {
			return err
		}
		// A connection's tokens go with it (ADR-0062).
		if err := q.ForgetDeadOAuthConnectionsOf(ctx, query.ForgetDeadOAuthConnectionsOfParams{EnvironmentID: t.Env.ID, ItemName: item}); err != nil {
			return err
		}
		actor, action := p.Identity.ID, "config.value.write"
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "value.deleted", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &t.OrganizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "projectId", Value: t.Project.ID}, {Key: "environmentId", Value: t.Env.ID}, {Key: "itemName", Value: item}},
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return reports, nil
}

// Change is one change of a change set, as its zod schema leaves it.
type Change struct {
	Op    string // "set" or "delete"
	Item  string
	Value string // for "set"
	// Seed, for "set", is written instead of Value (ADR-0061).
	Seed *totp.Seed
	// ExpectedVersionID is nil when absent.
	ExpectedVersionID *string
}

// ApplyChangeSet is POST …/changes (applyChangeSet under withIdempotency,
// dashboard design R2): one reviewed save is one all-or-nothing job. In
// the TypeScript order: the environment's expiry; every item's name and no
// item twice, in the set's order; the Organization's KEK and the active
// Contract; the writer's checks and the checkpoint; then every expected
// version (for sets and deletes; a delete of a value that is not live
// without one) is checked before anything is written, and any conflict
// refuses the whole set (VERSION_CONFLICT with every conflict); then each
// change in order, and the audit events after every row, each carrying
// the set's changeSetId and the request's id.
func ApplyChangeSet(ctx context.Context, w *write.Writer, rootKEK []byte, p *auth.Principal, t Target, changes []Change, requestID string, claim write.Claim, now Clock) (write.Response, bool, []auth.PendingReport, error) {
	var reports []auth.PendingReport
	resp, replayed, err := idempotentJob(ctx, w, p, t.OrganizationID, claim, &reports, func(ctx context.Context, tx *storage.Tx) (write.Response, error) {
		at := now().UnixMicro()
		if err := checkNotExpired(t.Env, at); err != nil {
			return write.Response{}, err
		}
		if len(changes) == 0 {
			return write.Response{}, domainerr.New("VALIDATION_FAILED", "Change set is empty")
		}
		seen := map[string]bool{}
		names := make([]string, 0, len(changes))
		for _, c := range changes {
			if err := checkItemName(c.Item); err != nil {
				return write.Response{}, err
			}
			if seen[c.Item] {
				return write.Response{}, domainerr.New("VALIDATION_FAILED", "Duplicate Config Item in change set: "+c.Item)
			}
			seen[c.Item] = true
			names = append(names, c.Item)
		}
		orgKEK, err := orgKEKIn(ctx, tx, rootKEK, t.OrganizationID)
		if err != nil {
			return write.Response{}, err
		}
		sensitive, err := sensitivity(ctx, tx, t.Project)
		if err != nil {
			return write.Response{}, err
		}
		changeSetID := "cs_" + strings.TrimPrefix(ids.New("ver"), "ver_")
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: t.OrganizationID, ProjectID: t.Project.ID, EnvironmentIDs: []string{t.Env.ID}}); err != nil {
			return write.Response{}, err
		}
		if reports, err = write.Checkpoint(ctx, tx, p, t.OrganizationID); err != nil {
			return write.Response{}, err
		}
		q := query.New(tx)
		existing, err := q.ValueRowsOfItems(ctx, query.ValueRowsOfItemsParams{EnvironmentID: t.Env.ID, ItemNames: names})
		if err != nil {
			return write.Response{}, err
		}
		rows := map[string]valueRow{}
		for _, r := range existing {
			rows[r.ItemName] = r
		}
		// Phase 1: every guard before any write.
		var conflicts []any
		conflict := func(item string, current any) {
			conflicts = append(conflicts, jsvalue.Object{{Key: "item", Value: item}, {Key: "currentVersionId", Value: current}})
		}
		for _, c := range changes {
			row, ok := rows[c.Item]
			var current any
			if ok && !deleted(row.DeletedAt, row.Seed) && row.CurrentVersionID.Valid {
				current = row.CurrentVersionID.String
			}
			if c.ExpectedVersionID != nil && current != any(*c.ExpectedVersionID) {
				conflict(c.Item, current)
			}
			if c.Op == "delete" && (current == nil || ok && deleted(row.DeletedAt, row.Seed)) && c.ExpectedVersionID == nil {
				conflict(c.Item, nil)
			}
		}
		if len(conflicts) > 0 {
			return write.Response{}, &domainerr.Error{
				Code: "VERSION_CONFLICT", Message: "One or more values changed since they were reviewed; nothing was written",
				Details: jsvalue.Object{{Key: "conflicts", Value: conflicts}},
			}
		}
		for _, c := range changes {
			if c.Op == "set" {
				if err := checkKind(c.Item, rows[c.Item].Seed, c.Seed, sensitive(c.Item)); err != nil {
					return write.Response{}, err
				}
			}
		}
		// Phase 2: every change, then the audit events.
		actor, action := p.Identity.ID, "config.value.write"
		var events []audit.Event
		var results []any
		for _, c := range changes {
			row, ok := rows[c.Item]
			resource := jsvalue.Object{{Key: "projectId", Value: t.Project.ID}, {Key: "environmentId", Value: t.Env.ID}, {Key: "itemName", Value: c.Item}}
			if c.Op == "set" {
				if !ok {
					row = valueRow{ID: ids.New("val"), ItemName: c.Item}
					if err := q.InsertValueRow(ctx, query.InsertValueRowParams{ID: row.ID, EnvironmentID: t.Env.ID, ItemName: c.Item, CreatedAt: at}); err != nil {
						return write.Response{}, err
					}
				}
				previous := row.CurrentVersionID
				if deleted(row.DeletedAt, row.Seed) {
					previous = sql.NullString{}
				}
				versionID := ids.New("ver")
				if err := writeVersion(ctx, q, orgKEK, t.OrganizationID, row.ID, versionID, c.Value, c.Seed, previous, actor, at); err != nil {
					return write.Response{}, err
				}
				events = append(events, audit.Event{
					Type: "value.written", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &t.OrganizationID, Action: &action,
					Resource:  append(resource, jsvalue.Member{Key: "versionId", Value: versionID}, jsvalue.Member{Key: "previousVersionId", Value: nullable(previous)}),
					RequestID: &requestID,
					Metadata:  ofSeed(jsvalue.Object{{Key: "sensitive", Value: sensitive(c.Item)}, {Key: "changeSetId", Value: changeSetID}}, c.Seed),
				})
				results = append(results, jsvalue.Object{{Key: "item", Value: c.Item}, {Key: "op", Value: "set"}, {Key: "versionId", Value: versionID}})
				continue
			}
			if err := q.DeleteValueRow(ctx, query.DeleteValueRowParams{DeletedAt: sql.NullInt64{Int64: at, Valid: true}, ID: row.ID}); err != nil {
				return write.Response{}, err
			}
			if err := q.ForgetOAuthConnection(ctx, row.ID); err != nil {
				return write.Response{}, err
			}
			events = append(events, audit.Event{
				Type: "value.deleted", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &t.OrganizationID, Action: &action,
				Resource: resource, RequestID: &requestID,
				Metadata: jsvalue.Object{{Key: "changeSetId", Value: changeSetID}},
			})
			results = append(results, jsvalue.Object{{Key: "item", Value: c.Item}, {Key: "op", Value: "delete"}, {Key: "versionId", Value: nil}})
		}
		for _, e := range events {
			if _, err := audit.Record(ctx, tx, e); err != nil {
				return write.Response{}, err
			}
		}
		return write.Response{Status: 200, Payload: jsvalue.Object{{Key: "changeSetId", Value: changeSetID}, {Key: "results", Value: results}}}, nil
	})
	return resp, replayed, reports, err
}
