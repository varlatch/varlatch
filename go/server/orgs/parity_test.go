// SPDX-License-Identifier: AGPL-3.0-or-later

package orgs_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// coreTables are the tables of core-v0.22.0.json (go-core-fixture.test.ts).
var coreTables = []string{"installation", "identities", "user", "auth_user_links", "credentials", "organizations", "org_memberships",
	"grants", "requirements", "security_controls", "organization_freezes", "organization_deletions", "projects", "contract_revisions",
	"environments", "env_values", "capabilities"}

type server struct {
	handler *httpserver.Server
	store   *storage.DB
	values  *values.Service
	rootKEK []byte
}

func newServer(t *testing.T, f paritytest.Fixture) *server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, coreTables); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	vs := values.New(store, rootKEK, values.Options{Log: log})
	h, err := httpserver.New(httpserver.Options{
		// The TypeScript server's SERVER_VERSION, which the installation
		// release read reports.
		Version: strings.TrimPrefix(f.Ref, "v"), Backend: daemon.NewBackend(store, rootKEK), Log: log,
		Auth: auth.New(store, auth.Options{Log: log, RootKEK: rootKEK}), Values: vs,
		Writer: &write.Writer{Store: store, Gates: write.NewGates()}, RootKEK: rootKEK,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	return &server{handler: h, store: store, values: vs, rootKEK: rootKEK}
}

// The core fixture's operations give the TypeScript server's answers: the
// Organization operations (step 4.1a), the Contract operations (4.1b), and
// the Projects, environments and installation reads (4.1c). Every request,
// its audit events, the side rows it wrote (Organizations, memberships,
// Projects, Contract revisions, environments, values, Capabilities), the
// report counts; every response valid against the OpenAPI document. Every Organization the
// requests created has a KEK that opens with the installation's Root KEK.
func TestTypeScriptFixture(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("core-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 50 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	s := newServer(t, f)
	paritytest.Replay(t, s.target(t, f), f)
	known := map[string]bool{}
	for _, o := range f.Rows["organizations"] {
		known[o["id"].(string)] = true
	}
	created := 0
	for _, r := range paritytest.Rows(t, s.store, "SELECT id, wrapped_org_kek FROM organizations") {
		id := r["id"].(string)
		if known[id] {
			continue
		}
		created++
		var wrapped envelope.Envelope
		if err := json.Unmarshal([]byte(r["wrapped_org_kek"].(string)), &wrapped); err != nil {
			t.Fatal(err)
		}
		if _, err := envelope.UnwrapOrgKEK(s.rootKEK, wrapped, id); err != nil {
			t.Errorf("%s: the Organization KEK does not open: %v", id, err)
		}
	}
	want := 0
	for _, r := range f.Requests {
		want += len(r.Side["organizations"]["inserted"])
	}
	if created != want || want < 8 {
		t.Errorf("%d Organizations created, the fixture %d", created, want)
	}
}

// fillPath is go-core-fixture.test.ts's: {orgId} and {goneId}, acme's
// live {project:SLUG} and {env:PROJECT/NAME}, and {rev:KEY}, the revision
// holding an item named KEY.
func fillPath(t testing.TB, f paritytest.Fixture) func(string) string {
	idOf := func(slug string) string {
		for _, o := range f.Rows["organizations"] {
			if o["slug"] == slug {
				return o["id"].(string)
			}
		}
		return ""
	}
	acme := idOf("acme")
	pairs := []string{"{orgId}", acme, "{goneId}", idOf("gone")}
	live := map[string]string{} // acme's live Projects: id to slug
	for _, p := range f.Rows["projects"] {
		if p["organization_id"] == acme && p["deleted_at"] == nil {
			live[p["id"].(string)] = p["slug"].(string)
			pairs = append(pairs, "{project:"+p["slug"].(string)+"}", p["id"].(string))
		}
	}
	for _, e := range f.Rows["environments"] {
		if slug, ok := live[e["project_id"].(string)]; ok && e["deleted_at"] == nil {
			pairs = append(pairs, "{env:"+slug+"/"+e["name"].(string)+"}", e["id"].(string))
		}
	}
	for _, r := range f.Rows["contract_revisions"] {
		items, _ := r["contract"].(map[string]any)["items"].([]any)
		for _, it := range items {
			pairs = append(pairs, "{rev:"+it.(map[string]any)["name"].(string)+"}", r["id"].(string))
		}
	}
	paths := strings.NewReplacer(pairs...)
	return func(p string) string {
		out := paths.Replace(p)
		if strings.Contains(out, "{rev:") || strings.Contains(out, "{project:") || strings.Contains(out, "{env:") {
			t.Fatalf("%s: a placeholder the rows do not fill", p)
		}
		return out
	}
}

func (s *server) target(t testing.TB, f paritytest.Fixture) paritytest.Target {
	return paritytest.Target{
		Handler: s.handler, Store: s.store, Settled: s.values.Settled,
		Path: fillPath(t, f),
		// Responses only: some requests are outside the document on
		// purpose, as the TypeScript fixture runs the unchecked app.
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}
}

// failures records what a replay reports, without failing the test.
type failures struct {
	testing.TB
	mu   sync.Mutex
	errs []string
}

func (f *failures) Errorf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs = append(f.errs, fmt.Sprintf(format, args...))
}

// The replay notices what a request changed that it should not have: a
// rename that also removes an unrelated membership (a deleted side row),
// or that changes another Organization (an updated one), fails it.
func TestReplayNoticesUnintendedChanges(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("core-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sabotage := range []string{
		`DELETE FROM org_memberships WHERE role = 'member'`,
		`UPDATE organizations SET name = 'Tampered' WHERE slug = 'frozen'`,
	} {
		s := newServer(t, f)
		target := s.target(t, f)
		real := target.Handler
		target.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			real.ServeHTTP(w, r)
			if r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/acme") {
				if err := s.store.Write(r.Context(), func(tx *storage.Tx) error { _, err := tx.ExecContext(r.Context(), sabotage); return err }); err != nil {
					t.Error(err)
				}
			}
		})
		target.Check = nil
		rec := &failures{TB: t}
		paritytest.Replay(rec, target, f)
		found := false
		for _, e := range rec.errs {
			if strings.Contains(e, "PATCH rename: side tables") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: not noticed (%d other differences)", sabotage, len(rec.errs))
		}
	}
}
