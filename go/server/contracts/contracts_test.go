// SPDX-License-Identifier: AGPL-3.0-or-later

package contracts_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/contracts"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/write"
)

// An Organization with one Project, written by idn_a.
func setup(t *testing.T) (w *write.Writer, orgID, projectID string) {
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
	err = store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'A')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	w = &write.Writer{Store: store, Gates: write.NewGates()}
	org, err := orgs.Create(ctx, w, envelope.GenerateKey(), "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	err = store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO projects (id, organization_id, slug, name, contract_authority) VALUES ('prj_api', ?, 'api', 'API', 'git')`, org.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return w, org.ID, "prj_api"
}

func alice() *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: "idn_a", Kind: "human"}, Credential: auth.Credential{ID: "crd_a", Kind: auth.KindCLI}}
}

// A Contract of items named by names, as varlatchd's reader holds a body.
func contractOf(names ...string) any {
	items := make([]any, 0, len(names))
	for _, n := range names {
		items = append(items, jsvalue.Object{{Key: "name", Value: n}, {Key: "required", Value: jsvalue.Object{{Key: "kind", Value: "always"}}},
			{Key: "sensitive", Value: false}, {Key: "type", Value: "string"}})
	}
	return jsvalue.Object{{Key: "schemaVersion", Value: 1.0}, {Key: "items", Value: items}}
}

// Concurrent pushes of one Contract (the TypeScript push holds the Project
// row, so they serialize): one revision, every push answered with it, one
// audit event.
func TestConcurrentPushesMakeOneRevision(t *testing.T) {
	w, orgID, projectID := setup(t)
	ctx := context.Background()
	ids := make([]string, 16)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Go(func() {
			rev, _, err := contracts.Push(ctx, w, alice(), orgID, projectID, contractOf("B", "A"), nil)
			if err != nil {
				t.Error(err)
				return
			}
			ids[i] = rev.ID
		})
	}
	wg.Wait()
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("two revisions: %s and %s", ids[0], id)
		}
	}
	if n := paritytest.Rows(t, w.Store, `SELECT count(*) AS n FROM contract_revisions`)[0]["n"]; n != int64(1) {
		t.Errorf("%v revisions", n)
	}
	if n := paritytest.Rows(t, w.Store, `SELECT count(*) AS n FROM audit_events WHERE event_type = 'contract.revision_pushed'`)[0]["n"]; n != int64(1) {
		t.Errorf("%v push events", n)
	}
}

// Concurrent activations each diff against the revision they replace (the
// TypeScript activation reads the active revision under the Project's
// lock). Revisions of 1, 2 and 4 items, each holding the smaller ones'
// items, so an event's itemsAdded and itemsRemoved name the pair it
// activated: in commit order the events form one chain from the first
// active revision, and the Project ends on the last event's revision.
func TestConcurrentActivationsDiffWhatTheyReplace(t *testing.T) {
	w, orgID, projectID := setup(t)
	ctx := context.Background()
	sizes := map[string]int{}
	var revs []string
	for _, names := range [][]string{{"P"}, {"P", "Q"}, {"P", "Q", "R", "S"}} {
		rev, _, err := contracts.Push(ctx, w, alice(), orgID, projectID, contractOf(names...), nil)
		if err != nil {
			t.Fatal(err)
		}
		revs = append(revs, rev.ID)
		sizes[rev.ID] = len(names)
	}
	if _, _, err := contracts.Activate(ctx, w, alice(), orgID, projectID, revs[0]); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 30 {
		wg.Go(func() {
			if _, _, err := contracts.Activate(ctx, w, alice(), orgID, projectID, revs[(i+1)%3]); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	events := paritytest.Rows(t, w.Store, `SELECT resource, metadata FROM audit_events WHERE event_type = 'contract.activated' ORDER BY event_order`)
	if len(events) != 31 {
		t.Fatalf("%d activations recorded", len(events))
	}
	active := ""
	for i, e := range events {
		var res struct{ ContractRevisionID string }
		var m struct {
			Initial                  bool
			ItemsAdded, ItemsRemoved int
		}
		if err := json.Unmarshal([]byte(e["resource"].(string)), &res); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(e["metadata"].(string)), &m); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if !m.Initial || res.ContractRevisionID != revs[0] {
				t.Fatalf("the first activation: %+v %s", m, res.ContractRevisionID)
			}
		} else {
			from, to := sizes[active], sizes[res.ContractRevisionID]
			if m.Initial || m.ItemsAdded != max(to-from, 0) || m.ItemsRemoved != max(from-to, 0) {
				t.Fatalf("event %d diffs %+v, replacing %d items with %d", i, m, from, to)
			}
		}
		active = res.ContractRevisionID
	}
	if got := paritytest.Rows(t, w.Store, `SELECT active_contract_revision_id AS id FROM projects WHERE id = ?`, projectID)[0]["id"]; got != active {
		t.Errorf("the Project's active revision is %v, the last event's %s", got, active)
	}
}

// A push takes the Organization's gate shared: it waits for a transition
// holding it exclusively (a freeze), then sees its outcome and refuses,
// having written nothing.
func TestPushWaitsForAFreeze(t *testing.T) {
	w, orgID, projectID := setup(t)
	ctx := context.Background()
	gctx, release, err := w.Gates.Acquire(ctx, write.Organization(orgID, write.Exclusive))
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan write.Gate, 1)
	w.Gates.Observe(func(event string, g write.Gate) {
		if event == "waiting" {
			waiting <- g
		}
	})
	done := make(chan error, 1)
	go func() {
		_, _, err := contracts.Push(ctx, w, alice(), orgID, projectID, contractOf("A"), nil)
		done <- err
	}()
	select {
	case g := <-waiting:
		if g != write.Organization(orgID, write.Shared) {
			t.Fatalf("waiting for %s", g)
		}
	case err := <-done:
		t.Fatalf("the push did not wait: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the push never reached its gate")
	}
	err = w.Store.Write(gctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(gctx, `INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ('ofz_1', ?, 'idn_a', 1, 'drill')`, orgID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	release()
	var frozen *authz.FrozenError
	select {
	case err := <-done:
		if !errors.As(err, &frozen) {
			t.Fatalf("after the freeze: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the push did not finish after the freeze")
	}
	if n := paritytest.Rows(t, w.Store, `SELECT count(*) AS n FROM contract_revisions`)[0]["n"]; n != int64(0) {
		t.Errorf("%v revisions written", n)
	}
}
