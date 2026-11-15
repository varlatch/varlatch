// SPDX-License-Identifier: AGPL-3.0-or-later

package orgs_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	orgID := ""
	for _, o := range f.Rows["organizations"] {
		if o["slug"] == "acme" {
			orgID = o["id"].(string)
		}
	}
	paritytest.Replay(t, paritytest.Target{
		Handler: s.handler, Store: s.store, Settled: s.values.Settled,
		Path: func(p string) string { return strings.ReplaceAll(p, "{orgId}", orgID) },
		// Responses only: some requests are outside the document on
		// purpose, as the TypeScript fixture runs the unchecked app.
		Check: func(t *testing.T, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}, f)
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
	if created != 6 {
		t.Errorf("%d Organizations created", created)
	}
}
