// SPDX-License-Identifier: AGPL-3.0-or-later

package db

// Regression tests for the four guarantees PostgreSQL's triggers gave
// (ADR-0059 Decision 2), ported from the TypeScript server's tests and run
// against schema.sql through lib/storage:
//
//   - commit-ordered audit positions (migration 0017): migrate.test.ts
//     "upgrades existing audit history", postgres-concurrency.test.ts
//     "cannot advance delivery past an uncommitted audit event";
//   - forward-only passkey counters (0040): passkey-evidence-postgres.test.ts,
//     the counter tests;
//   - a session's end revoking its browser credentials in the same
//     transaction (0043): session-end-revocation.test.ts;
//   - GitHub App registrations' pending material written once (0050):
//     migrate.test.ts "stages GitHub App registrations".

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db/query"
)

var errAbort = errors.New("the job gives up")

func insertEvent(ctx context.Context, q *query.Queries, id, eventType string) (int64, error) {
	return q.InsertAuditEvent(ctx, query.InsertAuditEventParams{ID: id, EventType: eventType, Decision: "info"})
}

func auditIDs(t *testing.T, s *storage.DB) []string {
	t.Helper()
	events, err := query.New(s.Reader()).ListAuditEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i, e := range events {
		if e.EventOrder != int64(i+1) {
			t.Fatalf("event %s has position %d, want %d: positions have a gap", e.ID, e.EventOrder, i+1)
		}
		ids = append(ids, e.ID)
	}
	return ids
}

// --- Audit positions (PostgreSQL migration 0017) ---------------------------

func TestAuditPositionsFollowInsertOrder(t *testing.T) {
	s := openDB(t)
	write(t, s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		for _, id := range []string{"older", "newer"} {
			if _, err := insertEvent(ctx, q, id, "test"); err != nil {
				return err
			}
		}
		return nil
	})
	var latest int64
	write(t, s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) (err error) {
		latest, err = insertEvent(ctx, q, "latest", "test")
		return err
	})
	if latest != 3 {
		t.Fatalf("the latest event has position %d, want 3", latest)
	}
	if got := auditIDs(t, s); !slices.Equal(got, []string{"older", "newer", "latest"}) {
		t.Fatalf("events by position: %v", got)
	}
	pos, err := query.New(s.Reader()).LastAuditPosition(context.Background())
	if err != nil || pos != 3 {
		t.Fatalf("LastAuditPosition = %d, %v", pos, err)
	}
}

// An insert cannot choose its position: only the next one is accepted.
func TestAuditPositionsAreAssignedByTheDatabase(t *testing.T) {
	s := openDB(t)
	write(t, s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		_, err := insertEvent(ctx, q, "first", "test")
		return err
	})
	for _, pos := range []int64{1, 3, 1000, 0, -5} {
		err := tryWrite(s, func(ctx context.Context, _ *query.Queries, tx *storage.Tx) error {
			_, err := tx.ExecContext(ctx, "INSERT INTO audit_events (event_order, id, event_type, decision) VALUES (?, ?, 'test', 'info')", pos, fmt.Sprint("chosen", pos))
			return err
		})
		if pos == 1 { // taken: refused before SQLite's own unique check
			refusedBy(t, err, "audit_events_no_replace")
		} else {
			refusedBy(t, err, "audit_events_position")
		}
	}
	// Naming exactly the next position is the same as naming none.
	exec(t, s, "INSERT INTO audit_events (event_order, id, event_type, decision) VALUES (2, 'second', 'test', 'info')")
	if got := auditIDs(t, s); !slices.Equal(got, []string{"first", "second"}) {
		t.Fatalf("events: %v", got)
	}
}

// PostgreSQL withheld UPDATE and DELETE on audit_events from the runtime
// role (migration 0003); here triggers refuse them.
func TestAuditEventsAreAppendOnly(t *testing.T) {
	s := openDB(t)
	write(t, s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		_, err := insertEvent(ctx, q, "kept", "test")
		return err
	})
	refusedBy(t, tryWrite(s, func(ctx context.Context, _ *query.Queries, tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE audit_events SET event_type = 'rewritten'")
		return err
	}), "audit_events_no_update")
	refusedBy(t, tryWrite(s, func(ctx context.Context, _ *query.Queries, tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM audit_events")
		return err
	}), "audit_events_no_delete")
	if got := auditIDs(t, s); !slices.Equal(got, []string{"kept"}) {
		t.Fatalf("events: %v", got)
	}
}

// postgres-concurrency.test.ts "cannot advance delivery past an uncommitted
// audit event": while one write holds an uncommitted event, a reader sees
// neither it nor any event written after it; both become visible together,
// in the order they were written.
func TestAuditPositionNeverOvertakesAnUncommittedOne(t *testing.T) {
	s := openDB(t)
	ctx := context.Background()
	reader := query.New(s.Reader())
	last := func() int64 {
		t.Helper()
		pos, err := reader.LastAuditPosition(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return pos
	}
	write(t, s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		_, err := insertEvent(ctx, q, "before", "test")
		return err
	})

	inserted, release := make(chan struct{}), make(chan struct{})
	slow := make(chan error, 1)
	go func() {
		slow <- tryWrite(s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
			if _, err := insertEvent(ctx, q, "slow", "test.slow"); err != nil {
				return err
			}
			close(inserted)
			<-release
			return nil
		})
	}()
	<-inserted
	fast := make(chan error, 1)
	go func() {
		fast <- tryWrite(s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
			_, err := insertEvent(ctx, q, "fast", "test.fast")
			return err
		})
	}()
	// The fast write waits for the writer; nothing new is visible.
	time.Sleep(50 * time.Millisecond)
	if got := last(); got != 1 {
		t.Fatalf("a reader sees position %d before the slow write committed", got)
	}
	select {
	case err := <-fast:
		t.Fatalf("the fast write finished before the slow one released the writer: %v", err)
	default:
	}
	close(release)
	if err := <-slow; err != nil {
		t.Fatal(err)
	}
	if err := <-fast; err != nil {
		t.Fatal(err)
	}
	if got := auditIDs(t, s); !slices.Equal(got, []string{"before", "slow", "fast"}) {
		t.Fatalf("events by position: %v", got)
	}
}

// Many writers, some of whose jobs fail after inserting events, while
// readers watch: a reader only ever sees positions 1..n with no gap, n
// never goes back, and in the end exactly the committed events hold
// positions 1..n. A job rolled back to its savepoint gives its positions
// back before the next job runs.
func TestAuditPositionsHaveNoGapsUnderConcurrentWrites(t *testing.T) {
	s := openDB(t)
	ctx := context.Background()
	const writers, jobsEach = 8, 40
	var committed sync.Map
	var stop atomic.Bool
	var readerErr atomic.Pointer[string]
	var readers sync.WaitGroup
	for range 2 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			var prev int64
			for !stop.Load() {
				var n, max int64
				if err := s.Reader().QueryRowContext(ctx, "SELECT count(*), coalesce(max(event_order), 0) FROM audit_events").Scan(&n, &max); err != nil {
					msg := err.Error()
					readerErr.Store(&msg)
					return
				}
				if n != max || max < prev {
					msg := fmt.Sprintf("a reader saw %d events with the highest position %d (previously %d)", n, max, prev)
					readerErr.Store(&msg)
					return
				}
				prev = max
			}
		}()
	}
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(w), 7))
			for j := range jobsEach {
				events := 1 + rng.IntN(3)
				fail := rng.IntN(4) == 0
				var ids []string
				err := tryWrite(s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
					ids = ids[:0]
					for e := range events {
						id := fmt.Sprintf("w%d-j%d-e%d", w, j, e)
						if _, err := insertEvent(ctx, q, id, "test"); err != nil {
							return err
						}
						ids = append(ids, id)
					}
					if fail {
						return errAbort
					}
					return nil
				})
				switch {
				case fail && errors.Is(err, errAbort):
				case !fail && err == nil:
					for _, id := range ids {
						committed.Store(id, true)
					}
				default:
					t.Errorf("job w%d-j%d (fail %v): %v", w, j, fail, err)
				}
			}
		}()
	}
	wg.Wait()
	stop.Store(true)
	readers.Wait()
	if msg := readerErr.Load(); msg != nil {
		t.Fatal(*msg)
	}
	got := auditIDs(t, s) // fails on a gap
	want := 0
	committed.Range(func(any, any) bool { want++; return true })
	if len(got) != want {
		t.Fatalf("%d events stored, %d committed", len(got), want)
	}
	for _, id := range got {
		if _, ok := committed.Load(id); !ok {
			t.Fatalf("event %s is stored but its job failed", id)
		}
	}
	m := s.Metrics()
	t.Logf("%d batches, %d jobs, largest batch %d, %d failed alone", m.Batches, m.Jobs, m.MaxBatch, m.JobErrors)
}

// --- Passkey counters (PostgreSQL migration 0040) --------------------------

func passkeyFixture(t *testing.T, s *storage.DB, counter int64) {
	t.Helper()
	write(t, s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		if err := q.CreateAuthUser(ctx, query.CreateAuthUserParams{ID: "bau_p", Name: "P", Email: "p@varlatch.placeholder.invalid"}); err != nil {
			return err
		}
		return q.CreatePasskey(ctx, query.CreatePasskeyParams{
			ID: "pk_1", PublicKey: "k", UserID: "bau_p", CredentialID: "cred-1",
			Counter: counter, DeviceType: "singleDevice", BackedUp: false,
		})
	})
}

func setCounter(s *storage.DB, n int64) error {
	return tryWrite(s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		return q.SetPasskeyCounter(ctx, query.SetPasskeyCounterParams{Counter: n, ID: "pk_1"})
	})
}

func counterOf(t *testing.T, s *storage.DB) int64 {
	t.Helper()
	n, err := query.New(s.Reader()).GetPasskeyCounter(context.Background(), "pk_1")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPasskeyCounterOnlyMovesForward(t *testing.T) {
	for _, tc := range []struct {
		name          string
		stored, write int64
		ok            bool
	}{
		{"greater", 1, 2, true},
		{"from zero", 0, 5, true},
		{"zero over zero (an authenticator without a counter)", 0, 0, true},
		{"equal", 2, 2, false},
		{"lower (the late write of two concurrent sign-ins)", 2, 1, false},
		{"back to zero", 2, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openDB(t)
			passkeyFixture(t, s, tc.stored)
			err := setCounter(s, tc.write)
			want := tc.write
			if tc.ok {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				// The refusal is the job's own error: the batch and every
				// other job in it go on.
				refusedBy(t, err, "passkey_counter_forward")
				want = tc.stored
			}
			if got := counterOf(t, s); got != want {
				t.Fatalf("counter %d, want %d", got, want)
			}
		})
	}
}

// passkey-evidence-postgres.test.ts: the authenticator signs counter 1,
// then 2; the write of 2 commits first, and the late write of 1 is
// refused, so the counter never goes back. An authenticator without a
// counter signs in any number of times.
func TestPasskeyCounterRaces(t *testing.T) {
	s := openDB(t)
	passkeyFixture(t, s, 0)
	if err := setCounter(s, 2); err != nil {
		t.Fatal(err)
	}
	refusedBy(t, setCounter(s, 1), "passkey_counter_forward")
	if got := counterOf(t, s); got != 2 {
		t.Fatalf("counter %d, want 2", got)
	}

	z := openDB(t)
	passkeyFixture(t, z, 0)
	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := range errs {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = setCounter(z, 0) }()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("sign-in %d with counter 0: %v", i, err)
		}
	}
	if got := counterOf(t, z); got != 0 {
		t.Fatalf("counter %d, want 0", got)
	}
}

// An UPDATE that does not set the counter (renaming a passkey) is not
// checked.
func TestPasskeyRenameIsNotACounterWrite(t *testing.T) {
	s := openDB(t)
	passkeyFixture(t, s, 7)
	write(t, s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		return q.RenamePasskey(ctx, query.RenamePasskeyParams{Name: ns("laptop"), ID: "pk_1"})
	})
	if got := counterOf(t, s); got != 7 {
		t.Fatalf("counter %d, want 7", got)
	}
}

// --- A session's end revokes its browser credentials (migration 0043) -------

type sessionFixture struct {
	s      *storage.DB
	person string
	org    string
	n      int
}

func newSessionFixture(t *testing.T) *sessionFixture {
	t.Helper()
	f := &sessionFixture{s: openDB(t), person: "idn_person", org: "org_a"}
	write(t, f.s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		if err := q.CreateIdentity(ctx, query.CreateIdentityParams{ID: f.person, Kind: "human", Name: "Jeremy"}); err != nil {
			return err
		}
		if err := q.CreateOrganization(ctx, query.CreateOrganizationParams{ID: f.org, Slug: "acme", Name: "Acme", WrappedOrgKek: ns("{}")}); err != nil {
			return err
		}
		if err := q.CreateIdentity(ctx, query.CreateIdentityParams{ID: "idn_machine", Kind: "service", Name: "prod-api", OrganizationID: ns(f.org)}); err != nil {
			return err
		}
		if err := q.CreateAuthUser(ctx, query.CreateAuthUserParams{ID: "bau_p", Name: "Jeremy", Email: "p@varlatch.placeholder.invalid"}); err != nil {
			return err
		}
		return q.LinkAuthUser(ctx, query.LinkAuthUserParams{BetterAuthUserID: "bau_p", IdentityID: f.person})
	})
	f.session(t, "ses_a")
	f.session(t, "ses_b")
	return f
}

func (f *sessionFixture) session(t *testing.T, id string) {
	t.Helper()
	write(t, f.s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		return q.CreateAuthSession(ctx, query.CreateAuthSessionParams{
			ID: id, ExpiresAt: time.Now().Add(7 * 24 * time.Hour).UnixMicro(), TokenHash: "hash-" + id, UserID: "bau_p",
		})
	})
}

// credential issues one; minutes is its lifetime (negative: already
// expired), session the auth_session_id it carries ("" for none).
func (f *sessionFixture) credential(t *testing.T, identity, kind, session string, minutes int) string {
	t.Helper()
	f.n++
	id := fmt.Sprintf("crd_%02d", f.n)
	params := query.CreateCredentialParams{ID: id, IdentityID: identity, Kind: kind, TokenHash: "token-" + id}
	if minutes != 0 {
		params.ExpiresAt = ni(time.Now().Add(time.Duration(minutes) * time.Minute).UnixMicro())
	}
	if session != "" {
		params.AuthSessionID = ns(session)
	}
	write(t, f.s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		return q.CreateCredential(ctx, params)
	})
	return id
}

func (f *sessionFixture) browser(t *testing.T, session string) string {
	return f.credential(t, f.person, "browser", session, 15)
}

func (f *sessionFixture) cred(t *testing.T, id string) query.Credential {
	t.Helper()
	c, err := query.New(f.s.Reader()).GetCredential(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *sessionFixture) live(t *testing.T, id string) bool { return !f.cred(t, id).RevokedAt.Valid }

func (f *sessionFixture) revocations(t *testing.T) []query.AuditEvent {
	t.Helper()
	events, err := query.New(f.s.Reader()).ListAuditEventsOfType(context.Background(), "credential.revoked")
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func (f *sessionFixture) endSession(t *testing.T, id string) {
	t.Helper()
	write(t, f.s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		n, err := q.DeleteAuthSession(ctx, id)
		if err == nil && n != 1 {
			err = fmt.Errorf("deleted %d sessions", n)
		}
		return err
	})
}

// The shape of the TypeScript server's ids (db/ids.ts): evt_ and 128
// random bits in lowercase base32, the last character carrying 3 of them.
var eventID = regexp.MustCompile(`^evt_[a-z2-7]{25}[aeimquy4]$`)

func jsonEqual(t *testing.T, got sql.NullString, want map[string]any) {
	t.Helper()
	var v map[string]any
	if !got.Valid || json.Unmarshal([]byte(got.String), &v) != nil || !reflect.DeepEqual(v, want) {
		t.Fatalf("JSON %v, want %v", got, want)
	}
}

func TestSessionEndRevokesItsBrowserCredentials(t *testing.T) {
	f := newSessionFixture(t)
	a1, a2 := f.browser(t, "ses_a"), f.browser(t, "ses_a")
	b := f.browser(t, "ses_b")
	// A CLI credential from the browser hand-off carries the session too;
	// it outlives it (ADR-0024).
	handoff := f.credential(t, f.person, "cli", "ses_a", 12*60)
	cli := f.credential(t, f.person, "cli", "", 0)
	service := f.credential(t, "idn_machine", "service", "", 0)
	before := len(f.revocations(t))

	f.endSession(t, "ses_a")

	for _, id := range []string{a1, a2} {
		if f.live(t, id) {
			t.Fatalf("browser credential %s of the ended session is live", id)
		}
	}
	for _, id := range []string{b, handoff, cli, service} {
		if !f.live(t, id) {
			t.Fatalf("credential %s was revoked", id)
		}
	}
	lines := f.revocations(t)[before:]
	var ids []string
	seen := map[string]bool{}
	for _, l := range lines {
		ids = append(ids, l.CredentialID.String)
		if l.ActorIdentityID.Valid || l.OrganizationID.Valid || l.Decision != "info" || l.SchemaVersion != 1 {
			t.Fatalf("event %+v: want no actor, no organization, decision info, schema version 1", l)
		}
		jsonEqual(t, l.Resource, map[string]any{"identityId": f.person})
		jsonEqual(t, l.Metadata, map[string]any{"kind": "browser", "reason": "session-ended"})
		if !eventID.MatchString(l.ID) || seen[l.ID] {
			t.Fatalf("event id %q: not of the TypeScript server's shape, or repeated", l.ID)
		}
		seen[l.ID] = true
		if c := f.cred(t, l.CredentialID.String); c.RevokedAt.Int64 != l.OccurredAt {
			t.Fatalf("credential revoked at %d, its event at %d", c.RevokedAt.Int64, l.OccurredAt)
		}
	}
	if want := []string{a1, a2}; !slices.Equal(ids, want) {
		t.Fatalf("revocation events for %v, want %v (in credential id order)", ids, want)
	}
}

func TestSessionEndLeavesEndedCredentialsAlone(t *testing.T) {
	f := newSessionFixture(t)
	expired := f.credential(t, f.person, "browser", "ses_a", -1)
	revoked := f.browser(t, "ses_a")
	revokedAt := time.Now().Add(-time.Minute).UnixMicro()
	write(t, f.s, func(ctx context.Context, _ *query.Queries, tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE credentials SET revoked_at = ? WHERE id = ?", revokedAt, revoked)
		return err
	})
	before := len(f.revocations(t))
	f.endSession(t, "ses_a")
	if c := f.cred(t, expired); c.RevokedAt.Valid {
		t.Fatal("the expired credential was revoked")
	}
	if c := f.cred(t, revoked); c.RevokedAt.Int64 != revokedAt {
		t.Fatalf("the revoked credential's revoked_at changed to %d", c.RevokedAt.Int64)
	}
	if n := len(f.revocations(t)); n != before {
		t.Fatalf("%d revocation events written for credentials that had ended", n-before)
	}
}

func TestSessionWithoutCredentialsEndsWithoutAuditLine(t *testing.T) {
	f := newSessionFixture(t)
	f.endSession(t, "ses_b")
	if ids := auditIDs(t, f.s); len(ids) != 0 {
		t.Fatalf("audit events written: %v", ids)
	}
}

// Bulk deletes (Better Auth's revoke-sessions) and the cascade from a
// deleted user: one line per credential.
func TestSessionEndCoversBulkDeletesAndTheUserCascade(t *testing.T) {
	f := newSessionFixture(t)
	tokens := []string{f.browser(t, "ses_a"), f.browser(t, "ses_b"), f.browser(t, "ses_b")}
	write(t, f.s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		n, err := q.DeleteAuthSessionsOfUser(ctx, "bau_p")
		if err == nil && n != 2 {
			err = fmt.Errorf("deleted %d sessions", n)
		}
		return err
	})
	var got []string
	for _, l := range f.revocations(t) {
		got = append(got, l.CredentialID.String)
	}
	// Session by session (SQLite's row triggers), each in credential id
	// order; PostgreSQL wrote one statement's in credential id order. The
	// set is the same.
	if !slices.Equal(slices.Sorted(slices.Values(got)), tokens) {
		t.Fatalf("revocation events for %v, want %v", got, tokens)
	}
	for _, id := range tokens {
		if f.live(t, id) {
			t.Fatalf("%s is live", id)
		}
	}

	f.session(t, "ses_c")
	c := f.browser(t, "ses_c")
	write(t, f.s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		_, err := q.DeleteAuthUser(ctx, "bau_p")
		return err
	})
	if f.live(t, c) {
		t.Fatal("the credential of a session removed by the user's deletion is live")
	}
	lines := f.revocations(t)
	if last := lines[len(lines)-1]; last.CredentialID.String != c {
		t.Fatalf("the last revocation is of %s, want %s", last.CredentialID.String, c)
	} else {
		jsonEqual(t, last.Metadata, map[string]any{"kind": "browser", "reason": "session-ended"})
	}
}

// The revocation is part of the deleting transaction: a job that ends a
// session and then fails leaves the session, its credentials and the audit
// log as they were.
func TestSessionEndIsInTheDeletingTransaction(t *testing.T) {
	f := newSessionFixture(t)
	a := f.browser(t, "ses_a")
	err := tryWrite(f.s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		if _, err := q.DeleteAuthSession(ctx, "ses_a"); err != nil {
			return err
		}
		return errAbort
	})
	if !errors.Is(err, errAbort) {
		t.Fatalf("the job: %v", err)
	}
	if !f.live(t, a) {
		t.Fatal("the credential was revoked although the session's deletion rolled back")
	}
	if ids := auditIDs(t, f.s); len(ids) != 0 {
		t.Fatalf("audit events survived the rollback: %v", ids)
	}
	var n int
	if err := f.s.Reader().QueryRow("SELECT count(*) FROM auth_sessions WHERE id = 'ses_a'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("the session: %d rows, %v", n, err)
	}
}

// The public-URL change revokes every browser credential with its own
// reason before it deletes the sessions; each credential is recorded once.
func TestSessionEndAfterAnotherRevocationRecordsOnce(t *testing.T) {
	f := newSessionFixture(t)
	a, b := f.browser(t, "ses_a"), f.browser(t, "ses_b")
	write(t, f.s, func(ctx context.Context, q *query.Queries, tx *storage.Tx) error {
		now := time.Now().UnixMicro()
		for _, id := range []string{a, b} {
			if _, err := tx.ExecContext(ctx, "UPDATE credentials SET revoked_at = ? WHERE id = ?", now, id); err != nil {
				return err
			}
			if _, err := q.InsertAuditEvent(ctx, query.InsertAuditEventParams{
				ID: "evt_" + id, EventType: "credential.revoked", Decision: "info", CredentialID: ns(id),
				Metadata: ns(`{"reason":"public-url-changed"}`),
			}); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, "DELETE FROM auth_sessions")
		return err
	})
	lines := f.revocations(t)
	if len(lines) != 2 {
		t.Fatalf("%d revocation events, want 2", len(lines))
	}
	for _, l := range lines {
		jsonEqual(t, l.Metadata, map[string]any{"reason": "public-url-changed"})
	}
}

// --- GitHub App registrations' pending material (migration 0050) -----------

type registrationFixture struct {
	s   *storage.DB
	now int64
}

func newRegistration(t *testing.T) *registrationFixture {
	t.Helper()
	f := &registrationFixture{s: openDB(t), now: time.Now().UnixMicro()}
	write(t, f.s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		for _, org := range []string{"org_a", "org_b"} {
			if err := q.CreateOrganization(ctx, query.CreateOrganizationParams{ID: org, Slug: org, Name: org, WrappedOrgKek: ns("{}")}); err != nil {
				return err
			}
		}
		for _, id := range []string{"idn_admin", "idn_other"} {
			if err := q.CreateIdentity(ctx, query.CreateIdentityParams{ID: id, Kind: "human", Name: id}); err != nil {
				return err
			}
		}
		id, err := q.CreateGitHubAppRegistration(ctx, query.CreateGitHubAppRegistrationParams{
			StateHash: "inflight", OrganizationID: "org_a", ActorIdentityID: "idn_admin",
			AccountLogin: "acme-gh", AccountType: "organization", CreatedAt: f.now, ExpiresAt: f.now + time.Hour.Microseconds(),
		})
		if err == nil && !regexp.MustCompile(`^ghr_[0-9a-f]{26}$`).MatchString(id) {
			err = fmt.Errorf("the default registration id %q", id)
		}
		return err
	})
	return f
}

func (f *registrationFixture) update(set string, args ...any) error {
	return tryWrite(f.s, func(ctx context.Context, _ *query.Queries, tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE github_app_registrations SET "+set+" WHERE state_hash = 'inflight'", args...)
		return err
	})
}

func (f *registrationFixture) convert(t *testing.T) {
	t.Helper()
	write(t, f.s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		_, err := q.ConvertGitHubAppRegistration(ctx, query.ConvertGitHubAppRegistrationParams{
			ConvertedAt: ni(f.now), PendingExpiresAt: ni(f.now + time.Hour.Microseconds()),
			PendingGithubAppID: ni(5254113), PendingSlug: ns("varlatch-acme"), PendingClientID: ns("Iv1.x"),
			PendingOwnerLogin: ns("acme-gh"), PendingOwnerID: ni(7), PendingOwnerType: ns("organization"),
			PendingKeyEnvelope: ns(`{"k":1}`), StateHash: "inflight",
		})
		return err
	})
}

func TestGitHubAppRegistrationPendingMaterialIsWrittenOnce(t *testing.T) {
	f := newRegistration(t)

	// Before a conversion, the row changes freely.
	if err := f.update("account_login = 'acme-gh2'"); err != nil {
		t.Fatal(err)
	}
	// A conversion is complete or absent.
	refusedBy(t, f.update("consumed_at = ?, converted_at = ?", f.now, f.now), "github_app_registrations_conversion_complete")
	f.convert(t)

	// Written once: no pending field changes, to another value or to NULL.
	guarded := map[string]any{
		"id": "ghr_00000000000000000000000000", "state_hash": "other", "organization_id": "org_b",
		"actor_identity_id": "idn_other", "consumed_at": f.now + 1, "converted_at": f.now + 1,
		"pending_expires_at": f.now + 2*time.Hour.Microseconds(), "pending_github_app_id": int64(5254114),
		"pending_slug": "other", "pending_client_id": "Iv1.y", "pending_owner_login": "other-gh",
		"pending_owner_id": int64(8), "pending_owner_type": "user", "pending_key_envelope": `{"k":2}`,
	}
	for col, v := range guarded {
		refusedBy(t, f.update(col+" = ?", v), "github_app_registrations_pending_once")
		// Deleting the key is how a registration ends (below).
		if col != "pending_key_envelope" {
			refusedBy(t, f.update(col+" = NULL"), "github_app_registrations_pending_once")
		}
	}
	// The same key in another spelling is another text.
	refusedBy(t, f.update(`pending_key_envelope = '{ "k": 1 }'`), "github_app_registrations_pending_once")
	// Writing a field's own value back is no change.
	if err := f.update("pending_slug = pending_slug, pending_key_envelope = pending_key_envelope"); err != nil {
		t.Fatal(err)
	}
	// What the trigger does not guard in PostgreSQL stays unguarded.
	if err := f.update("account_login = 'acme-gh3', account_type = 'user', expires_at = expires_at + 1"); err != nil {
		t.Fatal(err)
	}
	// The key exists only while the registration is pending: deleting it
	// alone breaks that rule; ending the registration deletes it.
	refusedBy(t, f.update("pending_key_envelope = NULL"), "github_app_registrations_key_while_pending")
	write(t, f.s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		_, err := q.EndGitHubAppRegistration(ctx, query.EndGitHubAppRegistrationParams{EndedAt: ni(f.now + 5), EndReason: ns("discarded"), StateHash: "inflight"})
		return err
	})
	// An end never changes, and no key comes back.
	refusedBy(t, f.update("end_reason = 'attached'"), "github_app_registrations_pending_once")
	refusedBy(t, f.update("ended_at = ?", f.now+6), "github_app_registrations_pending_once")
	refusedBy(t, f.update(`pending_key_envelope = '{"k":1}'`), "github_app_registrations_pending_once")

	r, err := query.New(f.s.Reader()).GetGitHubAppRegistration(context.Background(), "inflight")
	if err != nil {
		t.Fatal(err)
	}
	if r.PendingSlug.String != "varlatch-acme" || r.PendingKeyEnvelope.Valid || r.EndReason.String != "discarded" || r.AccountLogin != "acme-gh3" {
		t.Fatalf("registration: %+v", r)
	}
}

// --- REPLACE ---------------------------------------------------------------
//
// SQLite carries out INSERT OR REPLACE (and UPDATE OR REPLACE) by deleting
// the conflicting row without firing its delete triggers (recursive_triggers
// is off in lib/storage). The *_no_replace triggers refuse the collision
// first, so no guarantee above can be bypassed that way.

// The review's reproduction: insert a and b, replace a. Without the guard
// all three succeed, leaving (2, b), (3, a): the original a gone, and a gap.
func TestAuditEventsCannotBeReplaced(t *testing.T) {
	s := openDB(t)
	write(t, s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		for _, id := range []string{"a", "b"} {
			if _, err := insertEvent(ctx, q, id, "original"); err != nil {
				return err
			}
		}
		return nil
	})
	for _, stmt := range []string{
		"INSERT OR REPLACE INTO audit_events (id, event_type, decision) VALUES ('a', 'replaced', 'info')",
		"REPLACE INTO audit_events (id, event_type, decision) VALUES ('a', 'replaced', 'info')",
		"INSERT OR REPLACE INTO audit_events (event_order, id, event_type, decision) VALUES (1, 'c', 'replaced', 'info')",
		"INSERT INTO audit_events (id, event_type, decision) VALUES ('a', 'x', 'info') ON CONFLICT (id) DO UPDATE SET event_type = 'replaced'",
		"INSERT OR IGNORE INTO audit_events (id, event_type, decision) VALUES ('a', 'replaced', 'info')",
	} {
		refusedBy(t, tryExec(s, stmt), "audit_events_no_replace")
	}
	refusedBy(t, tryExec(s, "UPDATE OR REPLACE audit_events SET id = 'a' WHERE id = 'b'"), "audit_events_no_update")
	events, err := query.New(s.Reader()).ListAuditEvents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].ID != "a" || events[1].ID != "b" || events[0].EventType != "original" || events[1].EventType != "original" {
		t.Fatalf("events: %+v", events)
	}
}

func TestSessionsCannotBeReplaced(t *testing.T) {
	f := newSessionFixture(t)
	a := f.browser(t, "ses_a")
	refusedBy(t, tryExec(f.s, "INSERT OR REPLACE INTO auth_sessions (id, expires_at, token_hash, user_id) VALUES ('ses_a', 1, 'hash-new', 'bau_p')"),
		"auth_sessions_no_replace")
	refusedBy(t, tryExec(f.s, "INSERT OR REPLACE INTO auth_sessions (id, expires_at, token_hash, user_id) VALUES ('ses_new', 1, 'hash-ses_a', 'bau_p')"),
		"auth_sessions_no_replace")
	refusedBy(t, tryExec(f.s, "UPDATE OR REPLACE auth_sessions SET token_hash = 'hash-ses_a' WHERE id = 'ses_b'"), "auth_sessions_no_replace")
	refusedBy(t, tryExec(f.s, "UPDATE OR REPLACE auth_sessions SET id = 'ses_a' WHERE id = 'ses_b'"), "auth_sessions_no_replace")
	if !f.live(t, a) {
		t.Fatal("the session's credential was revoked")
	}
	var n int
	if err := f.s.Reader().QueryRow("SELECT count(*) FROM auth_sessions WHERE (id, token_hash) IN (VALUES ('ses_a', 'hash-ses_a'), ('ses_b', 'hash-ses_b'))").Scan(&n); err != nil || n != 2 {
		t.Fatalf("sessions: %d, %v", n, err)
	}
	// Ordinary updates go through, the keys included when they collide with nothing.
	exec(t, f.s, "UPDATE auth_sessions SET expires_at = expires_at + 1, token_hash = 'hash-rotated' WHERE id = 'ses_b'")
	// And ending a session still revokes.
	f.endSession(t, "ses_a")
	if f.live(t, a) {
		t.Fatal("the ended session's credential is live")
	}
}

func TestPasskeysCannotBeReplaced(t *testing.T) {
	s := openDB(t)
	passkeyFixture(t, s, 5)
	write(t, s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		return q.CreatePasskey(ctx, query.CreatePasskeyParams{ID: "pk_2", PublicKey: "k2", UserID: "bau_p", CredentialID: "cred-2", DeviceType: "singleDevice"})
	})
	for _, stmt := range []string{
		// A new row for the same passkey, its counter back at 0.
		"INSERT OR REPLACE INTO passkeys (id, public_key, user_id, credential_id, counter, device_type, backed_up) VALUES ('pk_1', 'k', 'bau_p', 'cred-1', 0, 'singleDevice', 0)",
		"INSERT OR REPLACE INTO passkeys (id, public_key, user_id, credential_id, counter, device_type, backed_up) VALUES ('pk_9', 'k', 'bau_p', 'cred-1', 0, 'singleDevice', 0)",
		"UPDATE OR REPLACE passkeys SET credential_id = 'cred-1' WHERE id = 'pk_2'",
		"UPDATE OR REPLACE passkeys SET id = 'pk_1' WHERE id = 'pk_2'",
	} {
		refusedBy(t, tryExec(s, stmt), "passkeys_no_replace")
	}
	if got := counterOf(t, s); got != 5 {
		t.Fatalf("counter %d, want 5", got)
	}
}

func TestGitHubAppRegistrationsCannotBeReplaced(t *testing.T) {
	f := newRegistration(t)
	f.convert(t)
	write(t, f.s, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		_, err := q.CreateGitHubAppRegistration(ctx, query.CreateGitHubAppRegistrationParams{
			StateHash: "second", OrganizationID: "org_a", ActorIdentityID: "idn_admin",
			AccountLogin: "acme-gh", AccountType: "organization", CreatedAt: f.now, ExpiresAt: f.now + time.Hour.Microseconds(),
		})
		return err
	})
	first, err := query.New(f.s.Reader()).GetGitHubAppRegistration(context.Background(), "inflight")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		fmt.Sprintf(`INSERT OR REPLACE INTO github_app_registrations (state_hash, organization_id, actor_identity_id, account_login, account_type, created_at, expires_at)
			VALUES ('inflight', 'org_a', 'idn_admin', 'acme-gh', 'organization', %d, %d)`, f.now, f.now+1),
		fmt.Sprintf(`INSERT OR REPLACE INTO github_app_registrations (state_hash, organization_id, actor_identity_id, account_login, account_type, created_at, expires_at, id)
			VALUES ('third', 'org_a', 'idn_admin', 'acme-gh', 'organization', %d, %d, '%s')`, f.now, f.now+1, first.ID),
		"UPDATE OR REPLACE github_app_registrations SET state_hash = 'inflight' WHERE state_hash = 'second'",
		fmt.Sprintf("UPDATE OR REPLACE github_app_registrations SET id = '%s' WHERE state_hash = 'second'", first.ID),
	} {
		refusedBy(t, tryExec(f.s, stmt), "github_app_registrations_no_replace")
	}
	again, err := query.New(f.s.Reader()).GetGitHubAppRegistration(context.Background(), "inflight")
	if err != nil || again != first {
		t.Fatalf("the converted registration changed: %+v, %v", again, err)
	}
}

// A REPLACE of a session's parent (its user) needs no guard: the foreign
// key cascade from the replaced row deletes the sessions through
// session_end_revokes_browser_credentials, though recursive_triggers is
// off. This test holds SQLite to that.
func TestReplacingAUserStillEndsItsSessions(t *testing.T) {
	f := newSessionFixture(t)
	a, b := f.browser(t, "ses_a"), f.browser(t, "ses_b")
	exec(t, f.s, "INSERT OR REPLACE INTO auth_users (id, name, email) VALUES ('bau_p', 'Jeremy', 'p@varlatch.placeholder.invalid')")
	for _, id := range []string{a, b} {
		if f.live(t, id) {
			t.Fatalf("%s is live after its user was replaced", id)
		}
	}
	var got []string
	for _, l := range f.revocations(t) {
		got = append(got, l.CredentialID.String)
		jsonEqual(t, l.Metadata, map[string]any{"kind": "browser", "reason": "session-ended"})
	}
	if !slices.Equal(slices.Sorted(slices.Values(got)), []string{a, b}) {
		t.Fatalf("revocation events for %v", got)
	}
}
