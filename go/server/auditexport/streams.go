// SPDX-License-Identifier: AGPL-3.0-or-later

package auditexport

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Stream restarts (Decision 2).

// newStream gives a live export, held in the caller's job, a new stream
// at its committed cursor: the generation incremented and the lease
// cleared, its manifest planned. The caller deleted the pending plan.
func newStream(ctx context.Context, db query.DBTX, r query.AuditExport, reason, cause string, o *overlap, now time.Time) (audit.Event, error) {
	streamID := ids.New(ids.AuditExportStream)
	updated, err := query.New(db).RestartAuditExportStream(ctx, query.RestartAuditExportStreamParams{ID: r.ID, StreamID: streamID, At: now.UnixMicro()})
	if err != nil {
		return audit.Event{}, err
	}
	previous := r.StreamID
	m := manifestPlan(manifest{prefix: updated.Prefix, organizationID: updated.OrganizationID, streamID: streamID, startOrder: updated.CursorOrder,
		previous: &previous, reason: reason, cause: cause, possibleOverlap: o, plannedAt: now})
	if err := insertPlan(ctx, db, r.ID, updated.Version, streamID, updated.Generation, m, retentionOf(updated), now); err != nil {
		return audit.Event{}, err
	}
	return streamStarted(updated.OrganizationID, r.ID, streamID, &previous, reason, cause, nil, nil, o), nil
}

// restartStream is restartStream, after a plan that can no longer be
// uploaded as planned. One job under the export's gate: the plan must
// still be the pending one (another lease holder may have committed or
// restarted first: then nothing happens, so the restart is audited once);
// the plan deleted, the committed cursor kept, a new stream whose
// manifest records the dropped batch's range as a possible overlap.
// reason is "plan_expired" or "plan_discarded" (cause "expired" or
// "unsupported-format"). Whether this call restarted it.
func (s *Service) restartStream(ctx context.Context, exportID, planID, reason, cause string) (bool, error) {
	restarted := false
	err := s.job(ctx, exportID, func(ctx context.Context, tx *storage.Tx) error {
		locked, err := exportByID(ctx, tx, exportID)
		if err != nil || locked == nil || !live(*locked) {
			return err
		}
		plan, err := planOf(ctx, tx, exportID)
		if err != nil || plan == nil || plan.ID != planID {
			return err
		}
		now := msTime(s.now())
		if reason == "plan_expired" && !planExpired(*plan, now) {
			return nil
		}
		if err := query.New(tx).DeleteAuditExportPlan(ctx, plan.ID); err != nil {
			return err
		}
		var o *overlap
		if plan.Kind == "batch" {
			o = &overlap{firstOrder: plan.FirstOrder.Int64, lastOrder: plan.LastOrder.Int64}
		}
		event, err := newStream(ctx, tx, *locked, reason, cause, o, now)
		if err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, event); err != nil {
			return err
		}
		restarted = true
		return nil
	})
	return restarted, err
}

// DiscardPlan is discardPlan, `varlatchd admin audit-export discard-plan
// --export <id> --reason <expired|unsupported-format>`: the host's escape
// hatch. The same restart, refused when the pending plan is neither
// expired nor in a format this release cannot upload, so it never skips
// events. The new stream's id.
func (s *Service) DiscardPlan(ctx context.Context, exportID, reason string) (string, error) {
	ctx = s.clocked(ctx)
	if reason != "expired" && reason != "unsupported-format" {
		return "", invalid("--reason: expired or unsupported-format")
	}
	plan, err := planOf(ctx, s.store().Reader(), exportID)
	if err != nil {
		return "", err
	}
	if plan == nil {
		return "", domainerr.New("RESOURCE_NOT_FOUND", "This audit export has no pending plan")
	}
	if reason == "expired" && !planExpired(*plan, s.now()) {
		return "", invalid("The pending plan's retention has not expired; it can still be uploaded, so it is not discarded")
	}
	if reason == "unsupported-format" && uploadableFormats[plan.FormatVersion] {
		return "", invalid(fmt.Sprintf("The pending plan is in format %d, which this release uploads; it is not discarded", plan.FormatVersion))
	}
	restarted, err := s.restartStream(ctx, exportID, plan.ID, "plan_discarded", reason)
	if err != nil {
		return "", err
	}
	if !restarted {
		return "", domainerr.New("STATE_CHANGED", "The pending plan changed meanwhile (committed, or another restart); nothing was discarded")
	}
	r, err := exportByID(ctx, s.store().Reader(), exportID)
	if err != nil || r == nil {
		return "", err
	}
	return r.StreamID, nil
}

// Restore (Decision 5).

// RecordRestore is recordRestore, in the restore's job (varlatchd
// stopped): every live export gets a new stream at its restored cursor,
// its generation incremented and its pending plan deleted, and
// audit_export.stream_started (reason "restored") is recorded after
// restored (installation.restored). The old streams' objects stay at
// their destinations: they hold events the restore removed, which is
// evidence.
func RecordRestore(ctx context.Context, db query.DBTX, restored audit.Event, now time.Time) error {
	now = msTime(now)
	q := query.New(db)
	rows, err := q.LiveAuditExports(ctx)
	if err != nil {
		return err
	}
	events := []audit.Event{restored}
	for _, r := range rows {
		if err := q.DeleteAuditExportPlanOf(ctx, r.ID); err != nil {
			return err
		}
		e, err := newStream(ctx, db, r, "restored", "", nil, now)
		if err != nil {
			return err
		}
		events = append(events, e)
	}
	_, err = audit.Record(ctx, db, events...)
	return err
}

// Organization deletion (Decision 10).

// RewrapForDrain is rewrapForDrain, in the deletion's finalization job
// (step 4.12), before the Organization KEK is destroyed and before its
// audit inserts: the live export's key sealed again under the Root KEK
// (purpose audit-export-drain), its state draining, its generation
// incremented, and a fixed deadline 30 days from now. Only this key: the
// Organization KEK is never kept. The pending plan stays; it holds its
// bytes. The export drained, "" for none.
func (s *Service) RewrapForDrain(ctx context.Context, db query.DBTX, organizationID string) (string, error) {
	r, err := liveExport(ctx, db, organizationID)
	if err != nil || r == nil || r.State != "active" {
		return "", err
	}
	kek, err := s.orgKEK(ctx, db, organizationID)
	if err != nil {
		return "", err
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(r.CredentialEnvelope.String), &env); err != nil {
		return "", err
	}
	plain, err := envelope.Open(kek, env, envelope.AuditExportCredentialContext(organizationID, r.ID))
	if err != nil {
		return "", err
	}
	drained, err := envelope.Seal(s.RootKEK, plain, envelope.AuditExportDrainContext(organizationID, r.ID))
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(drained)
	if err != nil {
		return "", err
	}
	now := s.now()
	return r.ID, query.New(db).DrainAuditExport(ctx, query.DrainAuditExportParams{
		ID: r.ID, CredentialEnvelope: nullStr(string(b), true), DrainDeadline: nullInt(now.Add(DrainTime).UnixMicro(), true), At: now.UnixMicro(),
	})
}

// drainExpired: r is a drain whose deadline has passed.
func drainExpired(r query.AuditExport, now time.Time) bool {
	return r.State == "draining" && r.DrainDeadline.Valid && r.DrainDeadline.Int64 <= now.UnixMicro()
}

// abandonLocked is abandonLocked, for drains past their deadline that the
// caller's job just read: their plans, then the rows (key cleared,
// generation incremented, so no lease holder can commit), then
// audit_export.abandoned, once each.
func abandonLocked(ctx context.Context, db query.DBTX, rows []query.AuditExport, now time.Time) error {
	q := query.New(db)
	events := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		if err := q.DeleteAuditExportPlanOf(ctx, r.ID); err != nil {
			return err
		}
		if err := q.AbandonAuditExport(ctx, query.AbandonAuditExportParams{ID: r.ID, At: now.UnixMicro()}); err != nil {
			return err
		}
		org := r.OrganizationID
		events = append(events, audit.Event{Type: "audit_export.abandoned", Decision: audit.Info, OrganizationID: &org,
			Resource: jsvalue.Object{{Key: "exportId", Value: r.ID}},
			Metadata: jsvalue.Object{{Key: "streamId", Value: r.StreamID}, {Key: "cursor", Value: strconv.FormatInt(r.CursorOrder, 10)},
				{Key: "drainDeadline", Value: nullTime(r.DrainDeadline)}}})
	}
	_, err := audit.Record(ctx, db, events...)
	return err
}

// abandonIfExpired is abandonIfExpired: the worker's side of the drain's
// bound. An export it may not lease, or is about to upload for, that is a
// drain past its deadline is abandoned now, not delivered. Whether this
// call abandoned it.
func (s *Service) abandonIfExpired(ctx context.Context, exportID string) (bool, error) {
	abandoned := false
	err := s.job(ctx, exportID, func(ctx context.Context, tx *storage.Tx) error {
		locked, err := exportByID(ctx, tx, exportID)
		now := s.now()
		if err != nil || locked == nil || !drainExpired(*locked, now) {
			return err
		}
		abandoned = true
		return abandonLocked(ctx, tx, []query.AuditExport{*locked}, now)
	})
	return abandoned, err
}

// AbandonExpiredDrains is abandonExpiredDrains, in the deletion loop
// (step 4.12) whatever the host switch says: a drain not completed by its
// deadline loses its key, becomes abandoned and records
// audit_export.abandoned. The worker abandons one it reaches first. Found
// on a read connection first, so an installation without one queues no
// job. The exports abandoned.
func (s *Service) AbandonExpiredDrains(ctx context.Context) ([]string, error) {
	ctx = s.clocked(ctx)
	due, err := query.New(s.store().Reader()).ExpiredAuditExportDrains(ctx, nullInt(s.now().UnixMicro(), true))
	if err != nil || len(due) == 0 {
		return nil, err
	}
	var out []string
	for _, d := range due {
		abandoned, err := s.abandonIfExpired(ctx, d.ID)
		if err != nil {
			return out, err
		}
		if abandoned {
			out = append(out, d.ID)
		}
	}
	return out, nil
}
