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
	"grants", "requirements", "security_controls", "organization_freezes", "organization_deletions"}

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
		Version: "test", Backend: daemon.NewBackend(store, rootKEK), Log: log,
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

// The Organization operations give the TypeScript server's answers
// (step 4.1a's part of the core fixture): every request, its audit events,
// the Organizations and memberships it wrote, the report counts; every
// response valid against the OpenAPI document. Every Organization the
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
	paritytest.Replay(t, s.target(f), f)
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

func (s *server) target(f paritytest.Fixture) paritytest.Target {
	idOf := func(slug string) string {
		for _, o := range f.Rows["organizations"] {
			if o["slug"] == slug {
				return o["id"].(string)
			}
		}
		return ""
	}
	paths := strings.NewReplacer("{orgId}", idOf("acme"), "{goneId}", idOf("gone"))
	return paritytest.Target{
		Handler: s.handler, Store: s.store, Settled: s.values.Settled,
		Path: paths.Replace,
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
		target := s.target(f)
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
