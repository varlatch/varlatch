// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// Lifecycle is an identity's identity.retired or identity.reactivated
// event, by audit order.
type Lifecycle struct {
	EventType  string
	EventOrder int64
}

// EndedByRetirement is endedByRetirement (domain/capabilityrepair.ts):
// whether a retirement of one of a Capability's identities (its Agent, its
// Broker, or the issuer that issued it for another Broker) ends it. The audit log's order decides, never timestamps: an
// identity retired now ends it; one with no identity.retired in its history
// keeps it (a suspension by an Organization's deletion records none, and
// reactivating an already-enabled identity is no retirement); otherwise,
// with its latest identity.retired at latestRetired,
// the Capability is ended when its capability.issued is not found (issued
// == nil), precedes latestRetired, or has identity.retired as the
// identity's latest lifecycle event at or before issued (atIssuance).
func EndedByRetirement(retiredNow bool, latestRetired *int64, issued *int64, atIssuance *Lifecycle) bool {
	if retiredNow {
		return true
	}
	if latestRetired == nil {
		return false
	}
	if issued == nil || *issued < *latestRetired {
		return true
	}
	return atIssuance != nil && atIssuance.EventType == "identity.retired"
}

// RepairBatch is how many Capabilities one write job of RevokeOfRetired
// repairs at most.
const RepairBatch = 200

// afterBatch, when set (tests), is told how many Capabilities each batch
// read.
var afterBatch func(n int)

// RevokeOfRetired is revokeCapabilitiesOfRetiredIdentities
// (domain/capabilityrepair.ts), the repair Repair runs before Capabilities
// are admitted: before retirement revoked an identity's Capabilities, and
// before issuance checked its Broker inside the write job, a retirement
// could leave Capabilities live, and a reactivation made them work again.
//
// In write jobs of at most RepairBatch Capabilities each, by Organization
// and id, so the single writer is never held for long, it revokes each
// unexpired, unrevoked Capability that a retirement of its Agent, its
// Broker or, issued for another Broker, its issuer (ADR-0060) ends
// (EndedByRetirement), so also what a release that revoked no issuer's at
// retirement left live, by the identity's whole audit history,
// not a window: an imported Capability may outlive a day, and a retirement
// may be older than what it ends. Its reads go by the indexes of schema
// version 3. Each revocation is audited as retirement's own
// (capability.revoked, reason identity-retired), with no actor. A
// Capability this release issued is never ended unless a retirement
// already revoked it (only a retirement bracketing the issuance ends it,
// never a redundant identity.reactivated), so it is
// safe to run again; batches are safe one after another, since no
// Capability is issued until the repair has run, a retirement since
// revokes its identity's Capabilities itself, and a reactivation since
// commits after the issuance and cannot clear a retirement before or at
// issuance. It returns how many it revoked.
func RevokeOfRetired(ctx context.Context, w *write.Writer, now func() time.Time) (int, error) {
	return RevokeOfRetiredInBatches(ctx, w, now, RepairBatch)
}

// RevokeOfRetiredInBatches is RevokeOfRetired with batch Capabilities per
// write job.
func RevokeOfRetiredInBatches(ctx context.Context, w *write.Writer, now func() time.Time, batch int) (int, error) {
	ctx = audit.WithClock(ctx, now)
	revoked := 0
	afterOrg, afterID := "", ""
	for {
		n, full := 0, false
		var lastOrg, lastID string
		err := w.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
			var err error
			n, lastOrg, lastID, full, err = repairBatch(ctx, tx, now().UnixMicro(), afterOrg, afterID, batch)
			return err
		})
		if err != nil {
			return revoked, err
		}
		revoked += n
		if !full {
			return revoked, nil
		}
		afterOrg, afterID = lastOrg, lastID
	}
}

// repairBatch repairs the next at most batch live Capabilities after
// (afterOrg, afterID): how many it revoked, the last one read, and whether
// the batch was full (more may follow).
func repairBatch(ctx context.Context, tx *storage.Tx, at int64, afterOrg, afterID string, batch int) (revoked int, lastOrg, lastID string, full bool, err error) {
	q := query.New(tx)
	caps, err := q.LiveCapabilitiesForRepair(ctx, query.LiveCapabilitiesForRepairParams{Now: at, AfterOrg: afterOrg, AfterID: afterID, Batch: int64(batch)})
	if err != nil {
		return 0, "", "", false, err
	}
	if afterBatch != nil {
		afterBatch(len(caps))
	}
	if len(caps) == 0 {
		return 0, "", "", false, nil
	}
	last := caps[len(caps)-1]
	full = len(caps) == batch
	type key struct{ org, identity string }
	retiredNow := map[string]bool{}
	latestRetired := map[key]*int64{}
	identity := func(org, id string) (bool, *int64, error) {
		if _, ok := retiredNow[id]; !ok {
			n, err := q.IdentityRetiredNow(ctx, id)
			if err != nil {
				return false, nil, err
			}
			retiredNow[id] = n > 0
		}
		if retiredNow[id] {
			return true, nil, nil
		}
		k := key{org, id}
		if _, ok := latestRetired[k]; !ok {
			order, err := q.LatestIdentityRetirement(ctx, query.LatestIdentityRetirementParams{
				OrganizationID: sql.NullString{String: org, Valid: true}, IdentityID: sql.NullString{String: id, Valid: true},
			})
			switch {
			case errors.Is(err, sql.ErrNoRows):
				latestRetired[k] = nil
			case err != nil:
				return false, nil, err
			default:
				latestRetired[k] = &order
			}
		}
		return false, latestRetired[k], nil
	}
	useAction := "secret.use"
	for _, c := range caps {
		var issued *int64
		issuedRead := false
		ended := ""
		ids := []string{c.AgentIdentityID, c.BrokerIdentityID}
		if c.CreatedBy != c.BrokerIdentityID {
			ids = append(ids, c.CreatedBy)
		}
		for _, id := range ids {
			retired, retiredOrder, err := identity(c.OrganizationID, id)
			if err != nil {
				return 0, "", "", false, err
			}
			var atIssuance *Lifecycle
			if !retired && retiredOrder != nil {
				if !issuedRead {
					issuedRead = true
					order, err := q.CapabilityIssuedOrder(ctx, query.CapabilityIssuedOrderParams{
						OrganizationID: sql.NullString{String: c.OrganizationID, Valid: true},
						CapabilityID:   sql.NullString{String: c.ID, Valid: true},
					})
					if err != nil && !errors.Is(err, sql.ErrNoRows) {
						return 0, "", "", false, err
					}
					if err == nil {
						issued = &order
					}
				}
				if issued != nil && *issued >= *retiredOrder {
					row, err := q.LatestIdentityLifecycleAt(ctx, query.LatestIdentityLifecycleAtParams{
						OrganizationID: sql.NullString{String: c.OrganizationID, Valid: true},
						IdentityID:     sql.NullString{String: id, Valid: true},
						AtOrder:        *issued,
					})
					if err != nil && !errors.Is(err, sql.ErrNoRows) {
						return 0, "", "", false, err
					}
					if err == nil {
						atIssuance = &Lifecycle{EventType: row.EventType, EventOrder: row.EventOrder}
					}
				}
			}
			if EndedByRetirement(retired, retiredOrder, issued, atIssuance) {
				ended = id
				break
			}
		}
		if ended == "" {
			continue
		}
		organizationID := c.OrganizationID
		if _, err := q.RevokeCapability(ctx, query.RevokeCapabilityParams{
			Now: sql.NullInt64{Int64: at, Valid: true}, ID: c.ID, OrganizationID: organizationID,
		}); err != nil {
			return 0, "", "", false, err
		}
		resource := jsvalue.Object{{Key: "capabilityId", Value: c.ID}}
		if c.CreatedBy != c.BrokerIdentityID {
			resource = append(resource, jsvalue.Member{Key: "brokerIdentityId", Value: c.BrokerIdentityID},
				jsvalue.Member{Key: "issuedByIdentityId", Value: c.CreatedBy})
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Type: "capability.revoked", Decision: audit.Info, OrganizationID: &organizationID,
			Action: &useAction, Resource: resource,
			Metadata: jsvalue.Object{{Key: "reason", Value: "identity-retired"}, {Key: "identityId", Value: ended}},
		}); err != nil {
			return 0, "", "", false, err
		}
		revoked++
	}
	return revoked, last.OrganizationID, last.ID, full, nil
}

// Repair is whether RevokeOfRetired has run on the database varlatchd
// serves: until it has, Capabilities are neither issued nor exercised
// (Require answers 503 MAINTENANCE), so a repair that fails, or that a
// maintenance gate or an upgrade's hold keeps back, fails closed. It
// starts not ready; a gate (a migration's transfer brings rows in) makes it
// not ready again (Invalidate). The repair runs inside the maintenance
// admission, as a request does.
type Repair struct {
	mu         sync.Mutex
	repaired   bool
	generation uint64
	running    bool
	// Run is the repair; RevokeOfRetired when nil.
	Run func(ctx context.Context, w *write.Writer, now func() time.Time) (int, error)
}

// Ready reports whether the repair has run since varlatchd started, or
// since the last Invalidate. No Repair (nil) waits for nothing.
func (r *Repair) Ready() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.repaired
}

// Invalidate makes Capabilities wait for the repair again; an attempt begun
// before it does not count.
func (r *Repair) Invalidate() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.generation++
	r.repaired = false
}

// Require refuses Capabilities until the repair has run.
func (r *Repair) Require() error {
	if r.Ready() {
		return nil
	}
	return domainerr.New("MAINTENANCE", "Capabilities are unavailable until varlatchd has revoked the Capabilities of retired identities; retry later")
}

// Attempt runs the repair once, unless it has run or one is running, inside
// enter (the maintenance admission): false when enter refuses or the
// repair fails, which is logged.
func (r *Repair) Attempt(ctx context.Context, w *write.Writer, enter func() (func(), bool), now func() time.Time, log *slog.Logger) bool {
	r.mu.Lock()
	if r.repaired {
		r.mu.Unlock()
		return true
	}
	if r.running {
		r.mu.Unlock()
		return false
	}
	leave, ok := enter()
	if !ok {
		r.mu.Unlock()
		return false
	}
	r.running = true
	generation := r.generation
	r.mu.Unlock()
	defer leave()
	run := r.Run
	if run == nil {
		run = RevokeOfRetired
	}
	n, err := run(ctx, w, now)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	if err != nil {
		log.Error("cannot revoke the Capabilities of retired identities; Capabilities answer 503 MAINTENANCE until it succeeds, tried again shortly", "error", err)
		return false
	}
	if n > 0 {
		log.Info("revoked the Capabilities of retired identities", "capabilities", n)
	}
	if generation != r.generation {
		return false
	}
	r.repaired = true
	return true
}

// Loop is Attempt at once, then every interval until ctx ends: invalidates
// (a non-capture gate open, an unreadable gate, or an upgrade's hold)
// makes it not ready first, since a restore or migration behind a gate may
// replace or bring in rows the repair has not seen; nothing changes behind
// a backup capture. varlatchd runs it once its listener serves, so a long
// repair never holds the start: Capabilities answer 503 until it has run,
// and everything else is served meanwhile.
func (r *Repair) Loop(ctx context.Context, every time.Duration, w *write.Writer, enter func() (func(), bool), invalidates func() bool, now func() time.Time, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if invalidates() {
			r.Invalidate()
		} else {
			r.Attempt(ctx, w, enter, now, log)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
