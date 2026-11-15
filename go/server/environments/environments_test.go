// SPDX-License-Identifier: AGPL-3.0-or-later

package environments

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/projects"
	"github.com/varlatch/varlatch/go/server/write"
)

// What PostgreSQL stores for an expiresAt zod accepted, and what the API
// answers for it (go-timestamp-vectors.test.ts): the fraction rounded to
// microseconds half to even, year 0 refused, years past 9999 answered as
// toISOString writes them.
func TestPostgresTimestampVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/pg-timestamps.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Input, Micros, ISO string
			Refused            bool
		}
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) < 20 {
		t.Fatalf("%d vectors", len(f.Vectors))
	}
	for _, v := range f.Vectors {
		got, err := PostgresTimestamp(v.Input)
		if v.Refused {
			if !errors.Is(err, ErrTimestamp) {
				t.Errorf("%s: %d %v, want a refusal", v.Input, got, err)
			}
			continue
		}
		want, _ := strconv.ParseInt(v.Micros, 10, 64)
		if err != nil || got != want || audit.ISOTime(got) != v.ISO {
			t.Errorf("%s: %d %s %v, want %d %s", v.Input, got, audit.ISOTime(got), err, want, v.ISO)
		}
	}
}

// An Organization with one Project, written by idn_a.
func setup(t *testing.T) (*write.Writer, string, projects.Project) {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := db.Init(ctx, store, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'A')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	org, err := orgs.Create(ctx, w, envelope.GenerateKey(), "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := projects.Create(ctx, w, alice(), org.ID, "api", "API", "git", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return w, org.ID, p
}

func alice() *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: "idn_a", Kind: "human"}, Credential: auth.Credential{ID: "crd_a", Kind: auth.KindCLI}}
}

func root(name, tier string) Input { return Input{Name: name, Tier: &tier} }

func count(t *testing.T, w *write.Writer, query string, args ...any) int64 {
	t.Helper()
	return paritytest.Rows(t, w.Store, query, args...)[0]["n"].(int64)
}

// tx-nesting's guarantees as they apply here. The TypeScript writers join
// the transaction they are handed (withTx on a client), so what one
// transaction does commits or rolls back whole; here the writes' bodies
// run in the job they are handed: an environment created and another
// removed in one job, which then fails, leave nothing, events included;
// the same job that succeeds keeps both.
func TestWritesJoinTheirJob(t *testing.T) {
	w, orgID, p := setup(t)
	ctx := context.Background()
	staging, _, err := Create(ctx, w, alice(), orgID, p.ID, root("staging", "staging"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	events := func() int64 {
		return count(t, w, `SELECT count(*) AS n FROM audit_events WHERE event_type LIKE 'environment.%'`)
	}
	before := events()
	refused := errors.New("refused")
	both := func(fail bool) error {
		return w.Job(ctx, []write.Gate{write.Organization(orgID, write.Shared), write.Person("idn_a", write.Shared)}, func(ctx context.Context, tx *storage.Tx) error {
			if _, _, err := create(ctx, tx, alice(), orgID, p.ID, root("qa", "staging"), time.Now().UnixMicro()); err != nil {
				return err
			}
			if _, err := remove(ctx, tx, alice(), orgID, p.ID, staging, time.Now().UnixMicro()); err != nil {
				return err
			}
			// Each read in the job sees what the job wrote.
			if _, err := Get(ctx, tx, p.ID, "qa"); err != nil {
				return err
			}
			if _, err := Get(ctx, tx, p.ID, "staging"); !isNotFound(err) {
				return errors.New("the job does not see its own removal")
			}
			if fail {
				return refused
			}
			return nil
		})
	}
	if err := both(true); !errors.Is(err, refused) {
		t.Fatal(err)
	}
	if n := count(t, w, `SELECT count(*) AS n FROM environments WHERE deleted_at IS NULL`); n != 1 || events() != before {
		t.Fatalf("a failed job left %d live environments and %d events", n, events()-before)
	}
	if err := both(false); err != nil {
		t.Fatal(err)
	}
	if n := count(t, w, `SELECT count(*) AS n FROM environments WHERE deleted_at IS NULL AND name = 'qa'`); n != 1 || events() != before+2 {
		t.Fatalf("the job kept %d environments and %d events", n, events()-before)
	}
}

// A write started from inside a job (the TypeScript code's nested withTx
// that would open a transaction of its own) is refused, never queued
// behind the job it is inside, which would deadlock the writer.
func TestNestedWriteRefused(t *testing.T) {
	w, orgID, p := setup(t)
	ctx := context.Background()
	err := w.Job(ctx, []write.Gate{write.Organization(orgID, write.Shared), write.Person("idn_a", write.Shared)}, func(ctx context.Context, tx *storage.Tx) error {
		_, _, err := Create(ctx, w, alice(), orgID, p.ID, root("inner", "development"), time.Now)
		return err
	})
	var order *write.OrderError
	if !errors.As(err, &order) {
		t.Fatalf("a job inside a job: %v", err)
	}
	if n := count(t, w, `SELECT count(*) AS n FROM environments`); n != 0 {
		t.Errorf("%d environments", n)
	}
}

// Removing an environment while one is created under it, at once: either
// the derived one is created first, and the removal is refused for it, or
// the removal is first, and the creation finds no parent. Never a live
// derived environment under a removed root.
func TestRemovalAndDerivedCreation(t *testing.T) {
	for range 20 {
		w, orgID, p := setup(t)
		ctx := context.Background()
		dev, _, err := Create(ctx, w, alice(), orgID, p.ID, root("development", "development"), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		parent := dev.ID
		errs := make(chan error, 2)
		go func() {
			_, _, err := Create(ctx, w, alice(), orgID, p.ID, Input{Name: "development/alice", ParentEnvironmentID: &parent}, time.Now)
			errs <- err
		}()
		go func() { _, err := Delete(ctx, w, w.Store.Reader(), alice(), orgID, p, dev, time.Now); errs <- err }()
		a, b := <-errs, <-errs
		orphans := count(t, w, `SELECT count(*) AS n FROM environments c JOIN environments r ON r.id = c.parent_environment_id
			WHERE c.deleted_at IS NULL AND r.deleted_at IS NOT NULL`)
		if orphans != 0 {
			t.Fatalf("a live derived environment under a removed root (%v, %v)", a, b)
		}
		if (a == nil) == (b == nil) {
			t.Fatalf("both or neither succeeded: %v, %v", a, b)
		}
	}
}

func isNotFound(err error) bool {
	var de *domainerr.Error
	return errors.As(err, &de) && de.Code == "RESOURCE_NOT_FOUND"
}
