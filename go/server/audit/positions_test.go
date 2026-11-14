// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Audit positions under group commit (ADR-0059 Decision 2): Record's
// positions are contiguous and in commit order when jobs share a batch,
// when a job fails and rolls back to its savepoint, and when a whole batch
// fails.

func openStore(t *testing.T) *storage.DB {
	t.Helper()
	s, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := db.Init(context.Background(), s, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	return s
}

// batch runs jobs as concurrently queued writes behind a gate job, so the
// writer finds them queued together, and returns each job's result and
// whether they all went into one write transaction. The writer takes jobs
// in the order they reached its queue, which the goroutines do not fix;
// the tests compare positions with the order the jobs ran in.
func batch(t *testing.T, s *storage.DB, jobs []func(*storage.Tx) error) ([]error, bool) {
	t.Helper()
	before := s.Metrics()
	entered, release := make(chan struct{}), make(chan struct{})
	gate := make(chan error, 1)
	go func() {
		gate <- s.Write(context.Background(), func(*storage.Tx) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	results := make([]error, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Go(func() { results[i] = s.Write(context.Background(), j) })
	}
	// The goroutines only have to reach the queue; give them time to.
	time.Sleep(100 * time.Millisecond)
	close(release)
	if err := <-gate; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	after := s.Metrics()
	return results, after.Batches-before.Batches == 2 && after.MaxBatch >= len(jobs)
}

type ran struct {
	seq       int64
	ids       []string
	positions []int64
}

func event(id string) Event {
	return Event{ID: id, Type: "value.written", Decision: Info}
}

var errAbort = errors.New("abort")

func lastPosition(t *testing.T, s *storage.DB) int64 {
	t.Helper()
	p, err := query.New(s.Reader()).LastAuditPosition(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func stored(t *testing.T, s *storage.DB, id string) (int64, bool) {
	t.Helper()
	e, err := query.New(s.Reader()).GetAuditEvent(context.Background(), id)
	if err != nil {
		return 0, false
	}
	return e.EventOrder, true
}

// TestPositionsInOneBatch: jobs in one batch, some failing on their own
// after recording, get contiguous positions in the order they ran; a
// failed job's positions go to the next job; a reader never sees a
// position without its predecessors.
func TestPositionsInOneBatch(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	var stop atomic.Bool
	readerErr := make(chan error, 1)
	go func() {
		var prev int64
		for !stop.Load() {
			var n, max int64
			if err := s.Reader().QueryRowContext(ctx, "SELECT count(*), coalesce(max(event_order), 0) FROM audit_events").Scan(&n, &max); err != nil {
				readerErr <- err
				return
			}
			if n != max || max < prev {
				readerErr <- fmt.Errorf("a reader saw %d events up to position %d (before: %d)", n, max, prev)
				return
			}
			prev = max
			time.Sleep(time.Millisecond)
		}
		readerErr <- nil
	}()

	batched := false
	for round := range 5 {
		base := lastPosition(t, s)
		var seq atomic.Int64
		var mu sync.Mutex
		var ok, failed []ran
		var jobs []func(*storage.Tx) error
		for j := range 24 {
			fail := j%5 == 2
			jobs = append(jobs, func(tx *storage.Tx) error {
				r := ran{seq: seq.Add(1)}
				for e := range 1 + j%3 {
					id := fmt.Sprintf("r%d-j%d-e%d", round, j, e)
					rec, err := Record(ctx, tx, event(id))
					if err != nil {
						return err
					}
					r.ids = append(r.ids, id)
					r.positions = append(r.positions, rec[0].Position)
				}
				mu.Lock()
				defer mu.Unlock()
				if fail {
					failed = append(failed, r)
					return errAbort
				}
				ok = append(ok, r)
				return nil
			})
		}
		results, one := batch(t, s, jobs)
		batched = batched || one
		for i, err := range results {
			if want := i%5 == 2; want != errors.Is(err, errAbort) || (!want && err != nil) {
				t.Fatalf("round %d job %d: %v", round, i, err)
			}
		}
		// The jobs that committed, in the order they ran, hold base+1 to
		// base+n, without a gap, each job's positions together.
		slices.SortFunc(ok, func(a, b ran) int { return int(a.seq - b.seq) })
		next := base + 1
		for _, r := range ok {
			for i, p := range r.positions {
				if p != next {
					t.Fatalf("round %d: job %d's event %d at position %d, want %d", round, r.seq, i, p, next)
				}
				if got, found := stored(t, s, r.ids[i]); !found || got != p {
					t.Fatalf("round %d: %s stored at %d (%v), recorded at %d", round, r.ids[i], got, found, p)
				}
				next++
			}
		}
		if last := lastPosition(t, s); last != next-1 {
			t.Fatalf("round %d: last position %d, want %d", round, last, next-1)
		}
		// A failed job's positions were given back: its events are gone,
		// and the job that ran after it took the same positions.
		for _, r := range failed {
			for _, id := range r.ids {
				if _, found := stored(t, s, id); found {
					t.Fatalf("round %d: %s of a failed job is stored", round, id)
				}
			}
			for _, o := range ok {
				if o.seq == r.seq+1 && len(r.positions) > 0 && o.positions[0] != r.positions[0] {
					t.Fatalf("round %d: the job after a failed one starts at %d, the failed one started at %d", round, o.positions[0], r.positions[0])
				}
			}
		}
	}
	stop.Store(true)
	if err := <-readerErr; err != nil {
		t.Fatal(err)
	}
	if !batched {
		t.Fatal("the jobs never shared a write transaction in five rounds: group commit was not exercised")
	}
}

// TestPositionsAfterAFailedBatch: when a batch fails as a whole, none of
// its jobs' events are stored, every job gets the batch's error, and the
// next write takes the position right after the last committed one.
func TestPositionsAfterAFailedBatch(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	write := func(id string) {
		t.Helper()
		if err := s.Write(ctx, func(tx *storage.Tx) error { _, err := Record(ctx, tx, event(id)); return err }); err != nil {
			t.Fatal(err)
		}
	}
	write("before-1")
	write("before-2")
	if err := s.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_taken', 'taken', 'Taken', '{}')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	recordJob := func(ids ...string) func(*storage.Tx) error {
		return func(tx *storage.Tx) error {
			for _, id := range ids {
				if _, err := Record(ctx, tx, event(id)); err != nil {
					return err
				}
			}
			return nil
		}
	}
	// INSERT OR ROLLBACK rolls back the whole transaction: no job's own
	// error, so the batch fails.
	failing := func(tx *storage.Tx) error {
		if _, err := Record(ctx, tx, event("in-failing")); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT OR ROLLBACK INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_taken', 'taken2', 'T', '{}')`)
		return err
	}
	ids := []string{"a-1", "a-2", "b-1", "in-failing", "d-1"}
	for attempt := 0; ; attempt++ {
		results, one := batch(t, s, []func(*storage.Tx) error{recordJob("a-1", "a-2"), recordJob("b-1"), failing, recordJob("d-1")})
		if !one {
			// Some job committed apart from the failing one: inconclusive.
			if attempt == 4 {
				t.Fatal("the jobs never shared a write transaction in five attempts")
			}
			s = openStore(t)
			write("before-1")
			write("before-2")
			if err := s.Write(ctx, func(tx *storage.Tx) error {
				_, err := tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_taken', 'taken', 'Taken', '{}')`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		for i, err := range results {
			var be *storage.BatchError
			if !errors.As(err, &be) {
				t.Fatalf("job %d: %v, want the batch's error", i, err)
			}
		}
		break
	}
	for _, id := range ids {
		if _, found := stored(t, s, id); found {
			t.Fatalf("%s of the failed batch is stored", id)
		}
	}
	if last := lastPosition(t, s); last != 2 {
		t.Fatalf("last position %d after the failed batch, want 2", last)
	}
	var rec []Recorded
	if err := s.Write(ctx, func(tx *storage.Tx) error {
		var err error
		rec, err = Record(ctx, tx, event("after-1"), event("after-2"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if rec[0].Position != 3 || rec[1].Position != 4 {
		t.Fatalf("positions after the failed batch: %+v, want 3 and 4", rec)
	}
}

// Record refuses an event type AUDIT_EVENT_TYPES does not list, and a
// decision other than allow, deny and info, before writing anything.
func TestRecordRefusesUnknownTypes(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	for _, e := range []Event{{Type: "made.up", Decision: Info}, {Type: "value.written", Decision: "maybe"}} {
		err := s.Write(ctx, func(tx *storage.Tx) error {
			_, err := Record(ctx, tx, event("ok"), e)
			return err
		})
		if err == nil {
			t.Fatalf("%+v recorded", e)
		}
	}
	if last := lastPosition(t, s); last != 0 {
		t.Fatalf("%d events stored", last)
	}
}

// Attribution: only the acting identity's events take the request's
// credential, client, listener and tailnet; a caller's value, null
// included, wins.
func TestAttribution(t *testing.T) {
	client := "varlatch CLI"
	a := Attribution{IdentityID: "idn_a", CredentialID: "crd_a", Client: &client, Listener: "tailnet", Tailnet: jsvalue.Object{{Key: "nodeId", Value: "n1"}}}
	ctx := WithAttribution(context.Background(), a)
	actor, other := "idn_a", "idn_b"
	got := Row(ctx, Event{Type: "value.written", Decision: Info, ActorIdentityID: &actor})
	if got.CredentialID.String != "crd_a" || got.Client.String != client || got.Listener.String != "tailnet" || !got.Tailnet.Valid {
		t.Fatalf("not attributed: %+v", got)
	}
	got = Row(ctx, Event{Type: "value.written", Decision: Info, ActorIdentityID: &other})
	if got.CredentialID.Valid || got.Client.Valid || got.Listener.Valid || got.Tailnet.Valid {
		t.Fatalf("someone else's event attributed: %+v", got)
	}
	got = Row(ctx, Event{Type: "value.written", Decision: Info, ActorIdentityID: &actor, CredentialID: Null[string](), Client: Value("mine")})
	if got.CredentialID.Valid || got.Client.String != "mine" || got.Listener.String != "tailnet" {
		t.Fatalf("the caller's values lost: %+v", got)
	}
	got = Row(context.Background(), Event{Type: "value.written", Decision: Info, ActorIdentityID: &actor})
	if got.CredentialID.Valid || got.Listener.Valid {
		t.Fatalf("attributed outside a request: %+v", got)
	}
}
