// SPDX-License-Identifier: AGPL-3.0-or-later

package orgs_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/write"
)

func newWriter(t *testing.T) (*write.Writer, []byte) {
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
		_, err := tx.ExecContext(ctx, `INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'A'), ('idn_b', 'human', 'B')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return &write.Writer{Store: store, Gates: write.NewGates()}, envelope.GenerateKey()
}

func principal(id string) *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: id, Kind: "human"}, Credential: auth.Credential{ID: "crd_" + id, Kind: auth.KindCLI}}
}

// organization-rename's invariant (the TypeScript rename takes the
// Organization FOR NO KEY UPDATE, so renames serialize): concurrent renames
// lose no update. Their audit events, in commit order, form one chain from
// the first name, each previousName the name before it, and the
// Organization ends with the last event's name. Creating Organizations
// meanwhile, by the same person, is not held up.
func TestConcurrentRenamesLoseNoUpdate(t *testing.T) {
	w, rootKEK := newWriter(t)
	ctx := context.Background()
	org, err := orgs.Create(ctx, w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, _, err := orgs.Rename(ctx, w, principal("idn_a"), org.ID, fmt.Sprintf("Acme %02d", i)); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := orgs.Create(ctx, w, rootKEK, "idn_a", fmt.Sprintf("other-%02d", i), "Other"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	events := paritytest.Rows(t, w.Store, `SELECT metadata FROM audit_events WHERE event_type = 'organization.renamed' ORDER BY event_order`)
	if len(events) != 24 {
		t.Fatalf("%d renames recorded", len(events))
	}
	name := "Acme"
	seen := map[string]bool{}
	for _, e := range events {
		var m struct{ PreviousName, Name string }
		if err := json.Unmarshal([]byte(e["metadata"].(string)), &m); err != nil {
			t.Fatal(err)
		}
		if m.PreviousName != name || seen[m.Name] {
			t.Fatalf("the chain breaks: %q after %q", m.PreviousName, name)
		}
		seen[m.Name] = true
		name = m.Name
	}
	final := paritytest.Rows(t, w.Store, `SELECT name FROM organizations WHERE id = ?`, org.ID)
	if final[0]["name"] != name {
		t.Errorf("the Organization is named %q, the last rename %q", final[0]["name"], name)
	}
	if n := paritytest.Rows(t, w.Store, `SELECT count(*) AS n FROM organizations`)[0]["n"]; n != int64(25) {
		t.Errorf("%v Organizations", n)
	}
}

// A rename takes the Organization's gate shared: it waits for a transition
// that holds it exclusively (a freeze: the TypeScript freeze holds the
// Organization row FOR UPDATE), then sees its outcome and refuses.
func TestRenameWaitsForAFreeze(t *testing.T) {
	w, rootKEK := newWriter(t)
	ctx := context.Background()
	org, err := orgs.Create(ctx, w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	gctx, release, err := w.Gates.Acquire(ctx, write.Organization(org.ID, write.Exclusive))
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
		_, _, err := orgs.Rename(ctx, w, principal("idn_a"), org.ID, "Renamed")
		done <- err
	}()
	// The rename reached its gate and waits there.
	select {
	case g := <-waiting:
		if g != write.Organization(org.ID, write.Shared) {
			t.Fatalf("waiting for %s", g)
		}
	case err := <-done:
		t.Fatalf("the rename did not wait: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the rename never reached its gate")
	}
	err = w.Store.Write(gctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(gctx, `INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ('ofz_1', ?, 'idn_a', 1, 'drill')`, org.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("the rename finished while the freeze held its gate: %v", err)
	default:
	}
	release()
	var frozen *authz.FrozenError
	select {
	case err := <-done:
		if !errors.As(err, &frozen) {
			t.Fatalf("after the freeze: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the rename did not finish after the freeze")
	}
	if n := paritytest.Rows(t, w.Store, `SELECT count(*) AS n FROM audit_events WHERE event_type = 'organization.renamed'`)[0]["n"]; n != int64(0) {
		t.Errorf("%v renames recorded", n)
	}
}

// A slug is unique across every Organization, a deleted one included, as
// the column's constraint: checked in the job, before the insert.
func TestCreateSlugTaken(t *testing.T) {
	w, rootKEK := newWriter(t)
	ctx := context.Background()
	org, err := orgs.Create(ctx, w, rootKEK, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	err = w.Store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE organizations SET deleted_at = 1, wrapped_org_kek = NULL, org_kek_destroyed_at = 1 WHERE id = ?`, org.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var de *domainerr.Error
	if _, err := orgs.Create(ctx, w, rootKEK, "idn_b", "acme", "Again"); !errors.As(err, &de) || de.Message != "Organization slug already exists" {
		t.Errorf("%v", err)
	}
}
