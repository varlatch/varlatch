// SPDX-License-Identifier: AGPL-3.0-or-later

package write

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Writer is what the write path writes with: the storage engine's single
// writer and the process's gates.
type Writer struct {
	Store *storage.DB
	Gates *Gates
}

// Job runs fn as one write job with gates held: taken in the order before
// the job is queued, released once it has its answer. A plain write takes
// its people and its Organization shared, as the TypeScript code locks
// them for share or for key share, so it waits for an exclusive holder (an
// effect consuming its requester's approval, a freeze) as that code waits
// for the row lock. fn gets a context that records the gates.
func (w *Writer) Job(ctx context.Context, gates []Gate, fn func(ctx context.Context, tx *storage.Tx) error) error {
	ctx, release, err := w.Gates.Acquire(ctx, gates...)
	if err != nil {
		return err
	}
	defer release()
	return w.Store.Write(ctx, func(tx *storage.Tx) error { return fn(ctx, tx) })
}

// EffectDeadline is how long an external effect may make outbound calls
// while passkey-verification is at report or enforce for its Organization
// (EXTERNAL_EFFECT_LIMITS.deadlineMs). A variable for tests.
var EffectDeadline = 90 * time.Second

// ErrEffectDeadline is externalEffectDeadline: the effect's call took
// longer than its deadline, and nothing of it was kept.
func ErrEffectDeadline() *domainerr.Error {
	return &domainerr.Error{
		Code: "STATE_CHANGED",
		Message: "The call outside Varlatch took longer than 90 seconds, so it was stopped and Varlatch's own changes for this request were rolled back. " +
			"What the call already did outside Varlatch may have happened (a GitHub code it already exchanged, say): check there before you try again.",
		Details: jsvalue.Object{{Key: "retryable", Value: true}, {Key: "reason", Value: "external-effect-deadline"}},
	}
}

// Effect is one protected external effect (ADR-0054 Decision 7, the
// TypeScript withExternalEffect), run in decision 4's five parts by
// RunEffect. C is what the call returns, R the effect's result.
type Effect[C, R any] struct {
	// OrganizationID is the Organization the effect acts in: its gate is
	// held shared for the effect's whole life.
	OrganizationID string
	// People are the effect's person gates (Person), as the TypeScript
	// code locks them: shared, or exclusive for a requester whose request
	// carries an approval it may consume. Resources are the resource gates
	// held across the call (Resource).
	People, Resources []Gate
	// Principal is the requester, whose passkey-verification checkpoint
	// runs in part 2; nil for none.
	Principal *auth.Principal
	// Check is part 2's own checks, in the snapshot, after the
	// Organization's: the people, the resource's state, the approval
	// precheck. It may capture what the call needs (a claim's eligibility
	// and its time, part 3: the claim itself is written in Final). nil
	// checks nothing more.
	Check func(ctx context.Context, tx *sql.Tx) error
	// Call is part 4, the outbound call. Its context ends at the deadline
	// while passkey-verification is active; EffectAlive says whether
	// another request may start.
	Call func(ctx context.Context) (C, error)
	// Final is part 5, in one write job after the Organization is checked
	// again: re-read what the call may have raced with (a resource's
	// version), consume an approval, write the outcome and its audit
	// events. It does not run when the call failed or the deadline fired.
	Final func(ctx context.Context, tx *storage.Tx, called C) (R, error)
}

type effectKey struct{}

type effectState struct {
	mu       sync.Mutex
	refusals []audit.Event
	deadline time.Time // zero: none
}

// NoteRefusal keeps an outbound refusal's audit event for the effect ctx
// runs in (noteEffectRefusal): written with the final job, or alone when
// the effect fails. Outside an effect it reports false and the caller
// writes the event itself.
func NoteRefusal(ctx context.Context, e audit.Event) bool {
	st, _ := ctx.Value(effectKey{}).(*effectState)
	if st == nil {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.refusals = append(st.refusals, e)
	return true
}

// EffectAlive is guardEffectFetch's check, made before each outbound
// request of an effect: once the deadline passed, no request starts.
func EffectAlive(ctx context.Context) error {
	st, _ := ctx.Value(effectKey{}).(*effectState)
	if st != nil && !st.deadline.IsZero() && !time.Now().Before(st.deadline) {
		return ErrEffectDeadline()
	}
	return nil
}

// RunEffect runs e:
//
//  1. its gates, in the order, before anything is read: the Organization
//     shared, the people, the resources;
//  2. the authoritative checks in one read snapshot taken while the gates
//     are held: the Organization (CheckLive), Check, then the requester's
//     passkey-verification checkpoint, and whether passkey-verification is
//     active (which sets the deadline). Every mutation that could change
//     what they read takes an exclusive gate this effect holds a share of,
//     so they stay true until the gates are released;
//  3. a claim (only completeRegistration's): held by its resource gate,
//     written by Final;
//  4. the call, conflicting writers waiting on the gates meanwhile;
//  5. the final job.
//
// It returns the result and the report counts to record once the request
// succeeds. The gates are released when it returns.
func RunEffect[C, R any](ctx context.Context, w *Writer, e Effect[C, R]) (R, []auth.PendingReport, error) {
	var zero R
	gates := append([]Gate{Organization(e.OrganizationID, Shared)}, e.People...)
	gates = append(gates, e.Resources...)
	ctx, release, err := w.Gates.Acquire(ctx, gates...)
	if err != nil {
		return zero, nil, err
	}
	defer release()

	scope := Scope{OrganizationID: e.OrganizationID}
	var reports []auth.PendingReport
	active := false
	err = func() error {
		tx, err := w.Store.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if err := CheckLive(ctx, tx, scope); err != nil {
			return err
		}
		if e.Check != nil {
			if err := e.Check(ctx, tx); err != nil {
				return err
			}
		}
		if reports, err = Checkpoint(ctx, tx, e.Principal, e.OrganizationID); err != nil {
			return err
		}
		active, err = passkeyVerificationActive(ctx, tx, e.OrganizationID)
		return err
	}()
	if err != nil {
		return zero, nil, err
	}

	st := &effectState{}
	callCtx := context.WithValue(ctx, effectKey{}, st)
	if active {
		st.deadline = time.Now().Add(EffectDeadline)
		var cancel context.CancelFunc
		callCtx, cancel = context.WithDeadline(callCtx, st.deadline)
		defer cancel()
	}
	called, err := e.Call(callCtx)
	expired := st.expired()
	if err == nil && expired {
		err = ErrEffectDeadline()
	}
	if err != nil {
		// Nothing of the effect is kept but its refusals, written alone.
		if werr := writeRefusals(ctx, w, st); werr != nil {
			return zero, nil, errors.Join(err, werr)
		}
		if expired {
			// Whatever the call made of being stopped, the answer is the deadline.
			return zero, nil, ErrEffectDeadline()
		}
		return zero, nil, err
	}

	// The final job checks the deadline again before it writes anything and
	// once the outcome is written, as the TypeScript effect checks its
	// signal after the whole callback, inside its transaction: a final job
	// that waited for the writer, or ran, past the deadline keeps nothing
	// (its savepoint rolls back), and the refusals are written alone.
	var out R
	err = w.Store.Write(ctx, func(tx *storage.Tx) error {
		if st.expired() {
			return ErrEffectDeadline()
		}
		for _, ev := range st.refusals {
			if _, err := audit.Record(ctx, tx, ev); err != nil {
				return err
			}
		}
		if err := CheckLive(ctx, tx, scope); err != nil {
			return err
		}
		var err error
		if out, err = e.Final(ctx, tx, called); err != nil {
			return err
		}
		if st.expired() {
			return ErrEffectDeadline()
		}
		return nil
	})
	if err != nil {
		// Rolled back: whatever failed, once the deadline passed the answer
		// is the deadline's, as the TypeScript effect answers any error it
		// catches after its signal fired.
		if st.expired() {
			err = ErrEffectDeadline()
		}
		if werr := writeRefusals(ctx, w, st); werr != nil {
			return zero, nil, errors.Join(err, werr)
		}
		return zero, nil, err
	}
	return out, reports, nil
}

// expired reports whether the effect has a deadline and it passed.
func (st *effectState) expired() bool {
	return !st.deadline.IsZero() && !time.Now().Before(st.deadline)
}

func writeRefusals(ctx context.Context, w *Writer, st *effectState) error {
	if len(st.refusals) == 0 {
		return nil
	}
	return w.Store.Write(ctx, func(tx *storage.Tx) error {
		for _, ev := range st.refusals {
			if _, err := audit.Record(ctx, tx, ev); err != nil {
				return err
			}
		}
		return nil
	})
}

// passkeyVerificationActive is passkeyVerificationActive: whether the
// Organization's passkey-verification is at report or enforce.
func passkeyVerificationActive(ctx context.Context, tx *sql.Tx, organizationID string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM security_controls WHERE organization_id = ? AND control = 'passkey-verification' AND mode IN ('report', 'enforce')`,
		organizationID).Scan(&n)
	return n > 0, err
}
