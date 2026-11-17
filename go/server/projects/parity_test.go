// SPDX-License-Identifier: AGPL-3.0-or-later

package projects_test

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// deletionTables are the tables of project-deletion-v0.22.0.json
// (go-project-deletion-fixture.test.ts).
var deletionTables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "groups", "grants",
	"projects", "team_projects", "contract_revisions", "environments", "env_values", "value_versions", "capabilities",
	"platform_connections", "sync_targets", "security_controls", "approval_intents", "organization_freezes", "organization_deletions",
	"audit_events"}

// fillPath is go-project-deletion-fixture.test.ts's: beta's Project web,
// acme's Project empty and acme's Team core, by the file's rows.
func fillPath(f paritytest.Fixture) func(string) string {
	find := func(table string, match func(paritytest.Row) bool) string {
		for _, r := range f.Rows[table] {
			if match(r) {
				return r["id"].(string)
			}
		}
		return ""
	}
	org := func(slug string) string {
		return find("organizations", func(r paritytest.Row) bool { return r["slug"] == slug })
	}
	project := func(orgSlug, slug string) string {
		o := org(orgSlug)
		return find("projects", func(r paritytest.Row) bool {
			return r["organization_id"] == o && r["slug"] == slug && r["deleted_at"] == nil
		})
	}
	acme := org("acme")
	r := strings.NewReplacer(
		"{betaWebId}", project("beta", "web"),
		"{emptyId}", project("acme", "empty"),
		"{coreTeamId}", find("groups", func(r paritytest.Row) bool { return r["organization_id"] == acme && r["name"] == "core" }),
	)
	return r.Replace
}

// TestTypeScriptFixture replays the table against varlatchd on the file's
// rows: every answer, audit event and changed row the same.
func TestTypeScriptFixture(t *testing.T) {
	path := paritytest.Path("project-deletion-v0.22.0.json")
	f, err := paritytest.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 20 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	db := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(db, f.Rows, deletionTables); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: db})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := url.Parse("http://127.0.0.1:8686")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	now := paritytest.HourClock()
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PublicURL: public, PersonGate: w.Gates.PersonGate, Now: now})
	vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates, Now: now})
	h, err := httpserver.New(httpserver.Options{
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: public,
		Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vs.Settled)
	paritytest.Replay(t, paritytest.Target{
		Handler: h, Store: store, Settled: vs.Settled, Path: fillPath(f), Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}, f)
}
