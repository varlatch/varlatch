// SPDX-License-Identifier: AGPL-3.0-or-later

package orgdeletion

import (
	"context"
	"database/sql"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// The audit-access tombstone (ADR-0016 §6, ADR-0051 Decision 8): a deleted
// Organization's audit log, for the readers fixed at its deletion while
// their identity stays enabled. Nothing else bypasses the live checks.
// Installation Admins see that a tombstone exists and who may read it, and
// can remove a reader; never add one, nor read the events.

// RequireReader is requireTombstoneReader: the principal reads the deleted
// Organization's audit log, or learns nothing (not found).
func RequireReader(ctx context.Context, db query.DBTX, p *auth.Principal, organizationID string) error {
	n, err := query.New(db).IsTombstoneReader(ctx, query.IsTombstoneReaderParams{OrganizationID: organizationID, IdentityID: p.Identity.ID})
	if err != nil {
		return err
	}
	if n == 0 || p.Identity.Disabled {
		return domainerr.New("RESOURCE_NOT_FOUND", "Not found")
	}
	return nil
}

func requireInstallationAdmin(p *auth.Principal) error {
	if !p.Identity.InstallationAdmin {
		return domainerr.New("PERMISSION_DENIED", "Installation Admin required")
	}
	return nil
}

// ListDeleted is GET /v1/installation/deleted-organizations: the deleted
// Organizations, newest first, each with its readers (removed ones too,
// with when), never the events.
func ListDeleted(ctx context.Context, db query.DBTX, p *auth.Principal) (jsvalue.Object, error) {
	if err := requireInstallationAdmin(p); err != nil {
		return nil, err
	}
	q := query.New(db)
	orgs, err := q.DeletedOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	readers, err := q.TombstoneReaders(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]any, 0, len(orgs))
	for _, o := range orgs {
		rs := []any{}
		for _, r := range readers {
			if r.OrganizationID != o.ID {
				continue
			}
			rs = append(rs, jsvalue.Object{{Key: "identityId", Value: r.IdentityID}, {Key: "name", Value: r.Name}, {Key: "removedAt", Value: isoOrNull(r.RemovedAt)}})
		}
		items = append(items, jsvalue.Object{{Key: "id", Value: o.ID}, {Key: "slug", Value: o.Slug}, {Key: "name", Value: o.Name},
			{Key: "deletedAt", Value: isoOrNull(o.DeletedAt)}, {Key: "readers", Value: rs}})
	}
	return jsvalue.Object{{Key: "items", Value: items}}, nil
}

// RemoveReader is DELETE /v1/installation/deleted-organizations/
// {organization}/readers/{identity}: an Installation Admin removes a
// reader, recorded as audit_tombstone.reader_removed. The remover's gate.
func RemoveReader(ctx context.Context, w *write.Writer, p *auth.Principal, organizationID, identityID string, now func() time.Time) error {
	if err := requireInstallationAdmin(p); err != nil {
		return err
	}
	actor := p.Identity.ID
	return w.Job(ctx, []write.Gate{write.Person(actor, write.Shared)}, func(ctx context.Context, tx *storage.Tx) error {
		n, err := query.New(tx).RemoveTombstoneReader(ctx, query.RemoveTombstoneReaderParams{Now: sql.NullInt64{Int64: now().UnixMicro(), Valid: true},
			RemovedBy: sql.NullString{String: actor, Valid: true}, OrganizationID: organizationID, IdentityID: identityID})
		if err != nil {
			return err
		}
		if n == 0 {
			return domainerr.New("RESOURCE_NOT_FOUND", "Reader not found")
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Type: "audit_tombstone.reader_removed", Decision: audit.Info, ActorIdentityID: &actor, OrganizationID: &organizationID,
			Resource: jsvalue.Object{{Key: "identityId", Value: identityID}},
		})
		return err
	})
}
