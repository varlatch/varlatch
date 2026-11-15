// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/security"
)

// The security report's counts (domain/securityreport.ts) that the read
// path makes: an export under admin-step-up's report mode, counted in the
// disclosure's audit job, and passkey-verification's report counts, queued
// after the response.

// WouldBlock is one attempt a control in report mode would have refused
// (go/server/security).
type WouldBlock = security.WouldBlock

// countWouldBlockInLiveOrganization counts only while the Organization is
// live: its deletion may have run since the snapshot.
func countWouldBlockInLiveOrganization(ctx context.Context, db query.DBTX, organizationID string, attempts []WouldBlock, at int64, now func() time.Time) error {
	return security.CountWouldBlockInLiveOrganization(ctx, db, organizationID, attempts, at, now)
}

// queueCount is queueAccessCount: passkey-verification's count, run after
// the response in a write job of its own (countWouldBlockAfter), only while
// the Organization is live and the person still a member; dropped when too
// many wait, and its errors logged, never answered.
func (s *Service) queueCount(r auth.PendingReport, operation string, at int64) {
	select {
	case s.pending <- struct{}{}:
	default:
		s.log.Error("security report: the access count queue is full; a count was dropped")
		return
	}
	s.counts.Add(1)
	go func() {
		defer s.counts.Done()
		defer func() { <-s.pending }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := s.store.Write(ctx, func(tx *storage.Tx) error {
			q := query.New(tx)
			if live, err := q.LiveOrganizationExists(ctx, r.OrganizationID); err != nil || live == 0 {
				return err
			}
			member, err := q.LiveMembershipExists(ctx, query.LiveMembershipExistsParams{OrganizationID: r.OrganizationID, IdentityID: r.ActorIdentityID})
			if err != nil || member == 0 {
				return err
			}
			return security.CountWouldBlock(ctx, tx, r.OrganizationID, []WouldBlock{{
				Control: "passkey-verification", ConfigVersion: r.ConfigVersion, Operation: operation, ActorIdentityID: r.ActorIdentityID, Reason: r.Reason,
			}}, at, s.now)
		})
		if err != nil {
			s.log.Error("security report: a passkey-verification count was dropped", "error", err)
		}
	}()
}

// QueueAccessCount is queueAccessCount for a request served outside the
// read path (an Organization route): passkey-verification's report count
// of a request that succeeded, under the first action it was authorized
// for, after the response. Settled waits for it too.
func (s *Service) QueueAccessCount(r auth.PendingReport, operation string, at int64) {
	s.queueCount(r, operation, at)
}
