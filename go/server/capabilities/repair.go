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

// Lifecycle is an identity's latest identity.retired or
// identity.reactivated, by audit order; nil when it has neither.
type Lifecycle struct {
	EventType  string
	EventOrder int64
}

// EndedByRetirement is endedByRetirement (domain/capabilityrepair.ts):
// whether a retirement of one of a Capability's identities (its Agent or
// its Broker) ends it. The audit log's order decides, never timestamps: an
// identity retired now ends it; one with no retirement or reactivation in
// its history keeps it (a suspension by an Organization's deletion records
// neither); otherwise it is kept only when the identity's latest such event
// is a reactivation that precedes the Capability's capability.issued
// (issued, nil when not found).
func EndedByRetirement(retiredNow bool, latest *Lifecycle, issued *int64) bool {
	if retiredNow {
		return true
	}
	if latest == nil {
		return false
	}
	if latest.EventType == "identity.retired" {
		return true
	}
	return issued == nil || *issued < latest.EventOrder
}

// issuedMargin is how far around a Capability's created_at its
// capability.issued is looked for (the same job; the margin only bounds
// the read).
const issuedMargin = 24 * time.Hour

// RevokeOfRetired is revokeCapabilitiesOfRetiredIdentities
// (domain/capabilityrepair.ts), the repair Repair runs before Capabilities
// are admitted: before retirement revoked an identity's Capabilities, and
// before issuance checked its Broker inside the write job, a retirement
// could leave Capabilities live, and a reactivation made them work again.
//
// In one write job, it revokes each unexpired, unrevoked Capability that a
// retirement of its Agent or its Broker ends (EndedByRetirement), by the
// identity's whole audit history, not a window: an imported Capability may
// outlive a day, and a retirement may be older than what it ends. Each
// revocation is audited as retirement's own (capability.revoked, reason
// identity-retired), with no actor. A Capability this release issued is
// never ended unless a retirement already revoked it, so it is safe to
// run again. It returns how many it revoked.
func RevokeOfRetired(ctx context.Context, w *write.Writer, now func() time.Time) (int, error) {
	revoked := 0
	ctx = audit.WithClock(ctx, now)
	err := w.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
		revoked = 0
		at := now().UnixMicro()
		q := query.New(tx)
		caps, err := q.LiveCapabilitiesForRepair(ctx, at)
		if err != nil {
			return err
		}
		type key struct{ org, identity string }
		retiredNow := map[string]bool{}
		latest := map[key]*Lifecycle{}
		identity := func(org, id string) (bool, *Lifecycle, error) {
			if _, ok := retiredNow[id]; !ok {
				n, err := q.IdentityRetiredNow(ctx, id)
				if err != nil {
					return false, nil, err
				}
				retiredNow[id] = n > 0
			}
			k := key{org, id}
			if _, ok := latest[k]; !ok {
				row, err := q.LatestIdentityLifecycle(ctx, query.LatestIdentityLifecycleParams{
					OrganizationID: sql.NullString{String: org, Valid: true}, IdentityID: sql.NullString{String: id, Valid: true},
				})
				switch {
				case errors.Is(err, sql.ErrNoRows):
					latest[k] = nil
				case err != nil:
					return false, nil, err
				default:
					latest[k] = &Lifecycle{EventType: row.EventType, EventOrder: row.EventOrder}
				}
			}
			return retiredNow[id], latest[k], nil
		}
		useAction := "secret.use"
		for _, c := range caps {
			var issued *int64
			issuedRead := false
			ended := ""
			for _, id := range []string{c.AgentIdentityID, c.BrokerIdentityID} {
				now, last, err := identity(c.OrganizationID, id)
				if err != nil {
					return err
				}
				if !issuedRead && !now && last != nil && last.EventType == "identity.reactivated" {
					issuedRead = true
					order, err := q.CapabilityIssuedOrder(ctx, query.CapabilityIssuedOrderParams{
						OrganizationID: sql.NullString{String: c.OrganizationID, Valid: true},
						FromAt:         c.CreatedAt - issuedMargin.Microseconds(), ToAt: c.CreatedAt + issuedMargin.Microseconds(),
						CapabilityID: sql.NullString{String: c.ID, Valid: true},
					})
					if err != nil && !errors.Is(err, sql.ErrNoRows) {
						return err
					}
					if err == nil {
						issued = &order
					}
				}
				if EndedByRetirement(now, last, issued) {
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
				return err
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Type: "capability.revoked", Decision: audit.Info, OrganizationID: &organizationID,
				Action: &useAction, Resource: jsvalue.Object{{Key: "capabilityId", Value: c.ID}},
				Metadata: jsvalue.Object{{Key: "reason", Value: "identity-retired"}, {Key: "identityId", Value: ended}},
			}); err != nil {
				return err
			}
			revoked++
		}
		return nil
	})
	return revoked, err
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

// Loop is Attempt every interval until ctx ends: isolated (a gate open, an
// upgrade's hold) makes it not ready first, since a migration's transfer
// behind a gate brings rows the repair has not seen.
func (r *Repair) Loop(ctx context.Context, every time.Duration, w *write.Writer, enter func() (func(), bool), isolated func() bool, now func() time.Time, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if isolated() {
				r.Invalidate()
				continue
			}
			r.Attempt(ctx, w, enter, now, log)
		}
	}
}
