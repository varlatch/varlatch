// SPDX-License-Identifier: AGPL-3.0-or-later

package projects_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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
	"github.com/varlatch/varlatch/go/server/projects"
	"github.com/varlatch/varlatch/go/server/write"
)

func setup(t *testing.T) (*write.Writer, string) {
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
	return w, org.ID
}

func alice() *auth.Principal {
	return &auth.Principal{Identity: auth.Identity{ID: "idn_a", Kind: "human"}, Credential: auth.Credential{ID: "crd_a", Kind: auth.KindCLI}}
}

// project-rename's guarantees, under concurrency (the TypeScript rename
// takes the Project FOR NO KEY UPDATE, so renames serialize): the slug
// never changes, no rename is lost, and the audit events, in commit order,
// form one chain from the first name, each previousName the name before
// it, the Project ending with the last event's name. Projects created
// meanwhile by the same person are not held up.
func TestConcurrentRenamesLoseNoUpdate(t *testing.T) {
	w, orgID := setup(t)
	ctx := context.Background()
	p, _, err := projects.Create(ctx, w, alice(), orgID, "gateway", "--org", "git", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Go(func() {
			if _, _, err := projects.Rename(ctx, w, alice(), orgID, p.ID, fmt.Sprintf("Gateway %02d", i)); err != nil {
				t.Error(err)
			}
		})
		wg.Go(func() {
			if _, _, err := projects.Create(ctx, w, alice(), orgID, fmt.Sprintf("other-%02d", i), "Other", "git", time.Now); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	events := paritytest.Rows(t, w.Store, `SELECT resource, metadata FROM audit_events WHERE event_type = 'project.renamed' ORDER BY event_order`)
	if len(events) != 24 {
		t.Fatalf("%d renames recorded", len(events))
	}
	name := "--org"
	seen := map[string]bool{}
	for _, e := range events {
		var res struct{ ProjectID, ProjectSlug string }
		var m struct{ PreviousName, Name string }
		if err := json.Unmarshal([]byte(e["resource"].(string)), &res); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(e["metadata"].(string)), &m); err != nil {
			t.Fatal(err)
		}
		if res.ProjectID != p.ID || res.ProjectSlug != "gateway" {
			t.Fatalf("event for %+v", res)
		}
		if m.PreviousName != name || seen[m.Name] {
			t.Fatalf("the chain breaks: %q after %q", m.PreviousName, name)
		}
		seen[m.Name] = true
		name = m.Name
	}
	got, err := projects.Get(ctx, w.Store.Reader(), orgID, "gateway")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != name || got.Slug != "gateway" || got.ID != p.ID {
		t.Errorf("the Project is %+v, the last rename %q", got, name)
	}
	all, err := projects.List(ctx, w.Store.Reader(), orgID)
	if err != nil || len(all) != 25 {
		t.Fatalf("%d Projects: %v", len(all), err)
	}
}

// Creating Projects in a row lists them in that order: created_at has the
// clock's microseconds, not the column default's milliseconds, so
// listProjects' ORDER BY created_at, id is creation order as in
// PostgreSQL, however fast they come.
func TestListInCreationOrder(t *testing.T) {
	w, orgID := setup(t)
	ctx := context.Background()
	var want []string
	for i := range 40 {
		slug := fmt.Sprintf("p%02d", i)
		if _, _, err := projects.Create(ctx, w, alice(), orgID, slug, slug, "git", time.Now); err != nil {
			t.Fatal(err)
		}
		want = append(want, slug)
	}
	all, err := projects.List(ctx, w.Store.Reader(), orgID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range all {
		got = append(got, p.Slug)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("listed %v", got)
	}
}

// The same slug created twice at once: one Project, the other refused as
// the unique index refuses it there.
func TestConcurrentCreateOneSlug(t *testing.T) {
	w, orgID := setup(t)
	ctx := context.Background()
	errs := make([]error, 8)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() { _, _, errs[i] = projects.Create(ctx, w, alice(), orgID, "twice", "Twice", "git", time.Now) })
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		var de *domainerr.Error
		switch {
		case err == nil:
			ok++
		case errors.As(err, &de) && de.Message == "Project slug already exists in this organization":
		default:
			t.Error(err)
		}
	}
	if ok != 1 {
		t.Errorf("%d created", ok)
	}
}

// A rename takes the Organization's gate shared: it waits for a freeze
// holding it exclusively, then refuses, having written nothing.
func TestRenameWaitsForAFreeze(t *testing.T) {
	w, orgID := setup(t)
	ctx := context.Background()
	p, _, err := projects.Create(ctx, w, alice(), orgID, "api", "API", "git", time.Now)
	if err != nil {
		t.Fatal(err)
	}
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
	go func() { _, _, err := projects.Rename(ctx, w, alice(), orgID, p.ID, "Renamed"); done <- err }()
	select {
	case g := <-waiting:
		if g != write.Organization(orgID, write.Shared) {
			t.Fatalf("waiting for %s", g)
		}
	case err := <-done:
		t.Fatalf("the rename did not wait: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the rename never reached its gate")
	}
	if err := w.Store.Write(gctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(gctx, `INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason) VALUES ('ofz_1', ?, 'idn_a', 1, 'drill')`, orgID)
		return err
	}); err != nil {
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
		t.Fatal("the rename did not finish after the freeze")
	}
	if got, _ := projects.Get(ctx, w.Store.Reader(), orgID, "api"); got.Name != "API" {
		t.Errorf("renamed to %q", got.Name)
	}
}
