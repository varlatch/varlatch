// SPDX-License-Identifier: AGPL-3.0-or-later

package write

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// blockingCall is a fake provider: each call reports that it started and
// waits until the test releases it (or the effect's context ends).
type blockingCall struct {
	started  chan struct{}
	release  chan struct{}
	calls    atomic.Int32
	deadline atomic.Bool
}

func newBlockingCall() *blockingCall {
	return &blockingCall{started: make(chan struct{}, 8), release: make(chan struct{})}
}

func (b *blockingCall) call(ctx context.Context) (string, error) {
	b.calls.Add(1)
	_, has := ctx.Deadline()
	b.deadline.Store(has)
	b.started <- struct{}{}
	select {
	case <-b.release:
		return "done", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// recordOutcome is a final job: the effect's outcome as an audit event.
func recordOutcome(ctx context.Context, tx *storage.Tx, called string) (string, error) {
	_, err := audit.Record(ctx, tx, audit.Event{Type: "organization.renamed", Decision: audit.Info, OrganizationID: ptr("org_a"),
		Metadata: jsvalue.Object{{Key: "outcome", Value: called}}})
	return called, err
}

func outcomes(t *testing.T, w *Writer) int {
	return count(t, w.Store, `SELECT count(*) FROM audit_events WHERE event_type = 'organization.renamed'`)
}

// While an effect's call is blocked, the writers that take its gates
// exclusively wait, and then see its outcome: a change of the requester
// (retirement, member removal, an approval consumed: the person gate) and
// an Organization transition (a Security Control change, a freeze, a
// deletion scheduled: the Organization gate). A writer that takes no gate
// of the effect is not held up.
func TestEffectHoldsItsGatesAcrossTheCall(t *testing.T) {
	w := newWriter(t)
	fake := newBlockingCall()
	done := make(chan error, 1)
	go func() {
		_, _, err := RunEffect(context.Background(), w, Effect[string, string]{
			OrganizationID: "org_a", People: []Gate{Person("idn_a", Shared)}, Call: fake.call, Final: recordOutcome,
		})
		done <- err
	}()
	<-fake.started
	if fake.deadline.Load() {
		t.Error("a deadline with passkey-verification off")
	}
	type waiter struct {
		name string
		gate Gate
	}
	seen := make(chan string, 4)
	for _, wt := range []waiter{{"person", Person("idn_a", Exclusive)}, {"organization", Organization("org_a", Exclusive)}} {
		go func() {
			ctx, release, err := w.Gates.Acquire(context.Background(), wt.gate)
			if err != nil {
				t.Error(err)
				return
			}
			defer release()
			var n int
			_ = w.Store.Write(ctx, func(tx *storage.Tx) error {
				return tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE event_type = 'organization.renamed'`).Scan(&n)
			})
			if n != 1 {
				t.Errorf("%s ran before the effect's outcome", wt.name)
			}
			seen <- wt.name
		}()
	}
	// Unrelated work goes on meanwhile: another person, another Organization.
	_, r, err := w.Gates.Acquire(context.Background(), Organization("org_b", Exclusive), Person("idn_b", Exclusive))
	if err != nil {
		t.Fatal(err)
	}
	r()
	select {
	case s := <-seen:
		t.Fatalf("%s did not wait", s)
	case <-time.After(50 * time.Millisecond):
	}
	close(fake.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-seen
	<-seen
}

// Two effects on one resource (two completions of one registration): one
// reaches the provider; the other waits for the resource's gate, then its
// checks read the first one's committed outcome and refuse as the
// TypeScript server does after its row lock.
func TestEffectResourceGateSerializes(t *testing.T) {
	w := newWriter(t)
	fake := newBlockingCall()
	consumed := func(ctx context.Context, tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE event_type = 'organization.renamed'`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return domainerr.New("CONSUMED", "already completed")
		}
		return nil
	}
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			_, _, err := RunEffect(context.Background(), w, Effect[string, string]{
				OrganizationID: "org_a", Resources: []Gate{Resource("github-app-registration", "ghr_1")},
				Check: consumed, Call: fake.call, Final: recordOutcome,
			})
			errs <- err
		}()
	}
	<-fake.started
	// The second effect is waiting for the resource's gate before the first
	// is let go: otherwise it could arrive after the first had finished and
	// refuse without ever having waited.
	for deadline := time.Now().Add(10 * time.Second); len(w.Gates.Waiting()) != 1; {
		if time.Now().After(deadline) {
			t.Fatalf("the second effect never waited for the gate: %v", w.Gates.Waiting())
		}
		time.Sleep(time.Millisecond)
	}
	close(fake.release)
	// Either may report first: the first effect releases the gate before
	// it hands back its result, so the second can refuse and report before
	// the first has.
	first, second := <-errs, <-errs
	if first != nil {
		first, second = second, first
	}
	if first != nil || code(second) != "CONSUMED" || fake.calls.Load() != 1 || outcomes(t, w) != 1 {
		t.Errorf("%v, %v, %d calls", first, second, fake.calls.Load())
	}
}

// Part 2 refuses before any call: a frozen Organization, a requester's
// failed checkpoint (here the Organization unknown).
func TestEffectChecksBeforeTheCall(t *testing.T) {
	w := newWriter(t)
	exec(t, w.Store, `INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ('ofz_1', 'org_a', 'idn_a', 1, 'drill')`)
	fake := newBlockingCall()
	_, _, err := RunEffect(context.Background(), w, Effect[string, string]{OrganizationID: "org_a", Call: fake.call, Final: recordOutcome})
	var frozen *authz.FrozenError
	if !errors.As(err, &frozen) || fake.calls.Load() != 0 {
		t.Errorf("frozen: %v", err)
	}
	_, _, err = RunEffect(context.Background(), w, Effect[string, string]{OrganizationID: "org_x", Call: fake.call, Final: recordOutcome})
	if code(err) != "RESOURCE_NOT_FOUND" || fake.calls.Load() != 0 {
		t.Errorf("unknown: %v", err)
	}
}

// With passkey-verification at report or enforce, the call has a deadline:
// when it fires mid-call nothing of the effect is kept but its outbound
// refusals, and the answer is the deadline's, whatever the call made of
// being stopped. EffectAlive refuses a request after it.
func TestEffectDeadline(t *testing.T) {
	w := newWriter(t)
	exec(t, w.Store, `INSERT INTO security_controls (organization_id, control, mode, version, changed_by) VALUES ('org_a', 'passkey-verification', 'report', 1, 'idn_a')`)
	defer func(d time.Duration) { EffectDeadline = d }(EffectDeadline)
	EffectDeadline = 50 * time.Millisecond
	var alive error
	_, _, err := RunEffect(context.Background(), w, Effect[string, string]{
		OrganizationID: "org_a",
		Call: func(ctx context.Context) (string, error) {
			NoteRefusal(ctx, audit.Event{Type: "outbound.refused", Decision: audit.Deny, OrganizationID: ptr("org_a")})
			<-ctx.Done()
			alive = EffectAlive(ctx)
			return "", errors.New("unreachable") // what the effect's code made of it
		},
		Final: recordOutcome,
	})
	var de *domainerr.Error
	if !errors.As(err, &de) || de.Code != "STATE_CHANGED" || string(jsvalue.Stringify(de.Details)) != `{"retryable":true,"reason":"external-effect-deadline"}` {
		t.Errorf("deadline: %v", err)
	}
	if code(alive) != "STATE_CHANGED" {
		t.Errorf("EffectAlive after the deadline: %v", alive)
	}
	if outcomes(t, w) != 0 || count(t, w.Store, `SELECT count(*) FROM audit_events WHERE event_type = 'outbound.refused'`) != 1 {
		t.Error("the outcome was kept, or the refusal lost")
	}
	// Within the deadline, refusals are written with the outcome.
	EffectDeadline = 10 * time.Second
	_, _, err = RunEffect(context.Background(), w, Effect[string, string]{
		OrganizationID: "org_a",
		Call: func(ctx context.Context) (string, error) {
			if err := EffectAlive(ctx); err != nil {
				return "", err
			}
			NoteRefusal(ctx, audit.Event{Type: "outbound.refused", Decision: audit.Deny, OrganizationID: ptr("org_a")})
			return "ok", nil
		},
		Final: recordOutcome,
	})
	if err != nil || outcomes(t, w) != 1 || count(t, w.Store, `SELECT count(*) FROM audit_events WHERE event_type = 'outbound.refused'`) != 2 {
		t.Errorf("within the deadline: %v", err)
	}
}

// The final job checks the Organization again: one deleted by a writer
// that took no gate (none should exist) refuses the outcome.
func TestEffectFinalChecksAgain(t *testing.T) {
	w := newWriter(t)
	_, _, err := RunEffect(context.Background(), w, Effect[string, string]{
		OrganizationID: "org_a",
		Call: func(ctx context.Context) (string, error) {
			exec(t, w.Store, `UPDATE organizations SET deleted_at = 1, wrapped_org_kek = NULL, org_kek_destroyed_at = 1 WHERE id = 'org_a'`)
			return "ok", nil
		},
		Final: recordOutcome,
	})
	if code(err) != "RESOURCE_NOT_FOUND" || outcomes(t, w) != 0 {
		t.Errorf("%v", err)
	}
}

// The deadline also binds the final job: one that waited for the writer
// past it, or whose own work ran past it, keeps nothing, and answers the
// deadline; the outbound refusals are still written, alone.
func TestEffectDeadlineBindsTheFinalJob(t *testing.T) {
	defer func(d time.Duration) { EffectDeadline = d }(EffectDeadline)
	EffectDeadline = 20 * time.Millisecond
	for _, c := range []string{"final runs past the deadline", "final waits for the writer past it"} {
		t.Run(c, func(t *testing.T) {
			w := newWriter(t)
			exec(t, w.Store, `INSERT INTO security_controls (organization_id, control, mode, version, changed_by) VALUES ('org_a', 'passkey-verification', 'enforce', 1, 'idn_a')`)
			release := make(chan struct{})
			busy := make(chan struct{})
			_, _, err := RunEffect(context.Background(), w, Effect[string, string]{
				OrganizationID: "org_a",
				Call: func(ctx context.Context) (string, error) {
					NoteRefusal(ctx, audit.Event{Type: "outbound.refused", Decision: audit.Deny, OrganizationID: ptr("org_a")})
					if c == "final waits for the writer past it" {
						// Another job holds the writer until after the deadline.
						go func() {
							_ = w.Store.Write(context.Background(), func(*storage.Tx) error {
								close(busy)
								<-release
								return nil
							})
						}()
						<-busy
						go func() { time.Sleep(60 * time.Millisecond); close(release) }()
					}
					return "ok", nil
				},
				Final: func(ctx context.Context, tx *storage.Tx, called string) (string, error) {
					if c == "final runs past the deadline" {
						time.Sleep(60 * time.Millisecond)
					}
					return recordOutcome(ctx, tx, called)
				},
			})
			if code(err) != "STATE_CHANGED" {
				t.Fatalf("%v", err)
			}
			if outcomes(t, w) != 0 || count(t, w.Store, `SELECT count(*) FROM audit_events WHERE event_type = 'outbound.refused'`) != 1 {
				t.Error("the outcome was kept, or the refusal lost")
			}
		})
	}
}

// A final job that fails once the deadline passed answers the deadline,
// not its own error, and keeps nothing: its savepoint rolled back what it
// wrote before failing; the refusals are written alone.
func TestEffectFinalFailingAfterTheDeadline(t *testing.T) {
	defer func(d time.Duration) { EffectDeadline = d }(EffectDeadline)
	EffectDeadline = 20 * time.Millisecond
	w := newWriter(t)
	exec(t, w.Store, `INSERT INTO security_controls (organization_id, control, mode, version, changed_by) VALUES ('org_a', 'passkey-verification', 'report', 1, 'idn_a')`)
	own := domainerr.New("VERSION_CONFLICT", "the App changed")
	_, _, err := RunEffect(context.Background(), w, Effect[string, string]{
		OrganizationID: "org_a",
		Call: func(ctx context.Context) (string, error) {
			NoteRefusal(ctx, audit.Event{Type: "outbound.refused", Decision: audit.Deny, OrganizationID: ptr("org_a")})
			return "ok", nil
		},
		Final: func(ctx context.Context, tx *storage.Tx, called string) (string, error) {
			if _, err := recordOutcome(ctx, tx, called); err != nil {
				return "", err
			}
			time.Sleep(40 * time.Millisecond)
			return "", own
		},
	})
	if errors.Is(err, own) || code(err) != "STATE_CHANGED" {
		t.Fatalf("%v", err)
	}
	if outcomes(t, w) != 0 || count(t, w.Store, `SELECT count(*) FROM audit_events WHERE event_type = 'outbound.refused'`) != 1 {
		t.Error("the outcome was kept, or the refusal lost")
	}
	// Before the deadline, the final job's own error is the answer.
	EffectDeadline = 10 * time.Second
	_, _, err = RunEffect(context.Background(), w, Effect[string, string]{
		OrganizationID: "org_a",
		Call:           func(context.Context) (string, error) { return "ok", nil },
		Final:          func(context.Context, *storage.Tx, string) (string, error) { return "", own },
	})
	if !errors.Is(err, own) {
		t.Errorf("before the deadline: %v", err)
	}
}
