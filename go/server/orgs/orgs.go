// SPDX-License-Identifier: AGPL-3.0-or-later

// Package orgs is Organizations' writes and the reads that go with them
// (the TypeScript domain/orgs.ts and freeze.ts currentFreeze; ADR-0059 step
// 4.1a): creating an Organization with its KEK and its first admin, and
// renaming it. Each write is one job of the single writer, its gates taken
// before (go/server/write).
package orgs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// Org is an Organization as the API shows it.
type Org struct {
	ID, Slug, Name string
	// CreatedAt is in microseconds since the epoch.
	CreatedAt int64
}

// JS is serialize.org: id, slug, name, createdAt.
func (o Org) JS() jsvalue.Object {
	return jsvalue.Object{{Key: "id", Value: o.ID}, {Key: "slug", Value: o.Slug}, {Key: "name", Value: o.Name}, {Key: "createdAt", Value: audit.ISOTime(o.CreatedAt)}}
}

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Create is createOrganization: any authenticated person may create an
// Organization and becomes its Organization Admin (ADR-0010 §6). The slug
// is checked first; then, in one job, its uniqueness (across deleted
// Organizations too, as the column's constraint), the Organization with
// its wrapped KEK, the admin membership, and organization.created.
func Create(ctx context.Context, w *write.Writer, rootKEK []byte, actorID, slug, name string) (Org, error) {
	if !slugPattern.MatchString(slug) {
		return Org{}, domainerr.New("VALIDATION_FAILED", "Invalid organization slug")
	}
	var org Org
	// The creator at step 2 of the TypeScript order, shared: the new
	// Organization is the job's own row.
	err := w.Job(ctx, []write.Gate{write.Person(actorID, write.Shared)}, func(ctx context.Context, tx *storage.Tx) error {
		// The name as PostgreSQL takes it: U+0000 fails the insert (before
		// its unique check) with 500 INTERNAL, a lone surrogate is stored
		// as U+FFFD (write.Text).
		stored, err := write.Text(name)
		if err != nil {
			return err
		}
		q := query.New(tx)
		taken, err := q.OrganizationSlugTaken(ctx, slug)
		if err != nil {
			return err
		}
		if taken > 0 {
			return domainerr.New("VALIDATION_FAILED", "Organization slug already exists")
		}
		id := ids.New("org")
		kek, wrapped, err := envelope.WrapOrgKEK(rootKEK, id)
		if err != nil {
			return err
		}
		clear(kek)
		b, err := json.Marshal(wrapped)
		if err != nil {
			return err
		}
		if err := q.InsertOrganization(ctx, query.InsertOrganizationParams{ID: id, Slug: slug, Name: stored, WrappedOrgKek: sql.NullString{String: string(b), Valid: true}}); err != nil {
			return err
		}
		if err := q.InsertOrganizationAdmin(ctx, query.InsertOrganizationAdminParams{OrganizationID: id, IdentityID: actorID}); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "organization.created", Decision: audit.Info, ActorIdentityID: &actorID, OrganizationID: &id,
			Resource: jsvalue.Object{{Key: "organizationSlug", Value: slug}},
		}); err != nil {
			return err
		}
		org, err = read(ctx, q, id)
		return err
	})
	return org, err
}

// Rename is renameOrganization: the display name only; the slug, which the
// CLI, URLs and configuration use, never changes. In one job: the
// writer's checks (the Organization live, no deletion open, no incident
// freeze), the requester's passkey-verification checkpoint, the update,
// and organization.renamed with both names. name is already trimmed and
// checked (the route's zod schema). It returns the report counts to record
// once the request succeeds.
func Rename(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, name string) (Org, []auth.PendingReport, error) {
	var org Org
	var reports []auth.PendingReport
	gates := []write.Gate{write.Organization(organizationID, write.Shared), write.Person(p.Identity.ID, write.Shared)}
	err := w.Job(ctx, gates, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: organizationID}); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, p, organizationID); err != nil {
			return err
		}
		q := query.New(tx)
		prev, err := read(ctx, q, organizationID)
		if err != nil {
			return err
		}
		// U+0000 fails the update; a lone surrogate is stored as U+FFFD,
		// and then fails in the audit event's jsonb metadata, which holds
		// the name as sent (both 500 INTERNAL, as PostgreSQL fails them).
		stored, err := write.Text(name)
		if err != nil {
			return err
		}
		if err := q.RenameOrganization(ctx, query.RenameOrganizationParams{Name: stored, ID: organizationID}); err != nil {
			return err
		}
		action, actor := "organization.manage", p.Identity.ID
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "organization.renamed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID, Action: &action,
			Resource: jsvalue.Object{{Key: "organizationSlug", Value: prev.Slug}},
			Metadata: jsvalue.Object{{Key: "previousName", Value: prev.Name}, {Key: "name", Value: name}},
		}); err != nil {
			return err
		}
		org, err = read(ctx, q, organizationID)
		return err
	})
	if err != nil {
		return Org{}, nil, err
	}
	return org, reports, nil
}

func read(ctx context.Context, q *query.Queries, id string) (Org, error) {
	row, err := q.OrganizationNames(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Org{}, domainerr.NotFound("Organization")
	}
	if err != nil {
		return Org{}, err
	}
	return Org{ID: id, Slug: row.Slug, Name: row.Name, CreatedAt: row.CreatedAt}, nil
}

// CurrentFreeze is currentFreeze (domain/freeze.ts): the Organization's
// open incident freeze as members see it, or nil.
func CurrentFreeze(ctx context.Context, db query.DBTX, organizationID string) (any, error) {
	f, err := query.New(db).CurrentFreeze(ctx, organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var liftedAt, liftedBy any
	if f.LiftedAt.Valid {
		liftedAt = audit.ISOTime(f.LiftedAt.Int64)
	}
	if f.LiftedBy.Valid {
		var name any
		if f.LiftedByName.Valid {
			name = f.LiftedByName.String
		}
		liftedBy = jsvalue.Object{{Key: "id", Value: f.LiftedBy.String}, {Key: "name", Value: name}}
	}
	var method any
	if f.LiftMethod.Valid {
		method = f.LiftMethod.String
	}
	return jsvalue.Object{
		{Key: "id", Value: f.ID},
		{Key: "frozenAt", Value: audit.ISOTime(f.FrozenAt)},
		{Key: "frozenBy", Value: jsvalue.Object{{Key: "id", Value: f.FrozenBy}, {Key: "name", Value: f.FrozenByName}}},
		{Key: "reason", Value: f.Reason},
		{Key: "liftedAt", Value: liftedAt},
		{Key: "liftedBy", Value: liftedBy},
		{Key: "liftMethod", Value: method},
	}, nil
}
