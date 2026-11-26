// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities

import (
	"context"
	"database/sql"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// repairWindow is how far back RevokeOfRetired looks for retirements: a
// Capability lives a day at most, so one still unexpired was issued
// within the last day, and the retirement that ends it came at most a day
// before it.
const repairWindow = 2 * MaxTTLSeconds * time.Second

// RevokeOfRetired is revokeCapabilitiesOfRetiredIdentities
// (domain/capabilityrepair.ts), an upgrade's repair run at start before
// varlatchd serves: before retirement revoked an identity's Capabilities,
// and before issuance checked its Broker inside the write job, a
// retirement could leave Capabilities live, and a reactivation made them
// work again.
//
// In one write job, it revokes each unexpired Capability that a
// retirement of its Agent or its Broker ends, by the audit log's history
// of that identity: an identity.retired after the Capability was issued,
// or one before it with no identity.reactivated in between. A suspension
// by an Organization's deletion records no identity.retired, so it keeps
// its Capabilities, as cancelling the deletion restores the identity.
// Each revocation is audited as retirement's own (capability.revoked,
// reason identity-retired), with no actor. Finds nothing once repaired.
// It returns how many it revoked.
func RevokeOfRetired(ctx context.Context, w *write.Writer, now func() time.Time) (int, error) {
	revoked := 0
	ctx = audit.WithClock(ctx, now)
	err := w.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
		revoked = 0
		at := now()
		since := at.Add(-repairWindow).UnixMicro()
		q := query.New(tx)
		candidates, err := q.RecentlyRetiredIdentities(ctx, since)
		if err != nil {
			return err
		}
		useAction := "secret.use"
		for _, c := range candidates {
			ended, err := q.CapabilitiesEndedByRetirement(ctx, query.CapabilitiesEndedByRetirementParams{
				OrganizationID: c.OrganizationID, IdentityID: c.IdentityID, Now: at.UnixMicro(), Since: since,
			})
			if err != nil {
				return err
			}
			organizationID := c.OrganizationID
			for _, id := range ended {
				if _, err := q.RevokeCapability(ctx, query.RevokeCapabilityParams{
					Now: sql.NullInt64{Int64: at.UnixMicro(), Valid: true}, ID: id, OrganizationID: organizationID,
				}); err != nil {
					return err
				}
				if _, err := audit.Record(ctx, tx, audit.Event{
					Type: "capability.revoked", Decision: audit.Info, OrganizationID: &organizationID,
					Action: &useAction, Resource: jsvalue.Object{{Key: "capabilityId", Value: id}},
					Metadata: jsvalue.Object{{Key: "reason", Value: "identity-retired"}, {Key: "identityId", Value: c.IdentityID}},
				}); err != nil {
					return err
				}
				revoked++
			}
		}
		return nil
	})
	return revoked, err
}
