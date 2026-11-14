// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
)

// The security report's counts (domain/securityreport.ts) that the read
// path makes: an export under admin-step-up's report mode, counted in the
// disclosure's audit job, and passkey-verification's report counts, queued
// after the response.

// WouldBlock is one attempt a control in report mode would have refused.
type WouldBlock struct {
	Control         string
	ConfigVersion   int64
	Operation       string
	ActorIdentityID string
	Reason          string
}

const hour = int64(time.Hour / time.Microsecond)

// countWouldBlock is countWouldBlock: the attempts merged by key, in key
// order, each added to the hour of at; an hour already summarized counts in
// the current one instead.
func countWouldBlock(ctx context.Context, db query.DBTX, organizationID string, attempts []WouldBlock, at int64, now func() time.Time) error {
	type entry struct {
		key   string
		a     WouldBlock
		count int64
	}
	merged := map[string]*entry{}
	for _, a := range attempts {
		key := strings.Join([]string{organizationID, a.Control, padVersion(a.ConfigVersion), a.Operation, a.ActorIdentityID, a.Reason}, "\x00")
		if e, ok := merged[key]; ok {
			e.count++
		} else {
			merged[key] = &entry{key: key, a: a, count: 1}
		}
	}
	ordered := make([]*entry, 0, len(merged))
	for _, e := range merged {
		ordered = append(ordered, e)
	}
	sort.Slice(ordered, func(i, j int) bool { return utf16Less(ordered[i].key, ordered[j].key) })
	q := query.New(db)
	for _, e := range ordered {
		seen := now().UnixMicro()
		params := query.CountWouldBlockParams{
			OrganizationID: organizationID, Control: e.a.Control, ConfigVersion: e.a.ConfigVersion, Operation: e.a.Operation,
			ActorIdentityID: e.a.ActorIdentityID, Reason: e.a.Reason, BucketHour: at - at%hour, Count: e.count, Seen: seen,
		}
		rows, err := q.CountWouldBlock(ctx, params)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			continue
		}
		params.BucketHour = seen - seen%hour
		if rows, err = q.CountWouldBlock(ctx, params); err != nil {
			return err
		}
		if len(rows) == 0 {
			// The current hour cannot have been summarized yet; losing a
			// count never changes the operation's outcome.
			continue
		}
	}
	return nil
}

// padVersion is String(v).padStart(10, "0").
func padVersion(v int64) string {
	s := strconv.FormatInt(v, 10)
	if len(s) < 10 {
		s = strings.Repeat("0", 10-len(s)) + s
	}
	return s
}

// countWouldBlockInLiveOrganization counts only while the Organization is
// live: its deletion may have run since the snapshot.
func countWouldBlockInLiveOrganization(ctx context.Context, db query.DBTX, organizationID string, attempts []WouldBlock, at int64, now func() time.Time) error {
	if len(attempts) == 0 {
		return nil
	}
	live, err := query.New(db).LiveOrganizationExists(ctx, organizationID)
	if err != nil || live == 0 {
		return err
	}
	return countWouldBlock(ctx, db, organizationID, attempts, at, now)
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
			return countWouldBlock(ctx, tx, r.OrganizationID, []WouldBlock{{
				Control: "passkey-verification", ConfigVersion: r.ConfigVersion, Operation: operation, ActorIdentityID: r.ActorIdentityID, Reason: r.Reason,
			}}, at, s.now)
		})
		if err != nil {
			s.log.Error("security report: a passkey-verification count was dropped", "error", err)
		}
	}()
}
