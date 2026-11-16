// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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

// capabilitiesTables are the tables of capabilities-v0.22.0.json
// (go-capabilities-fixture.test.ts).
var capabilitiesTables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "grants", "requirements",
	"organization_freezes", "organization_deletions", "projects", "contract_revisions", "environments", "env_values", "value_versions",
	"capabilities", "audit_events"}

type digests map[string]struct {
	StateDigest  string            `json:"stateDigest"`
	StateDigests map[string]string `json:"stateDigests"`
}

var placeholder = regexp.MustCompile(`\{(idn|cap|grant|project|env|digest):([^}]+)\}`)

// fillPath is go-capabilities-fixture.test.ts's: identities by name,
// Capabilities by run id, an identity's Grant, cap's Project api and its
// environments, and the state digests the file keeps.
func fillPath(f paritytest.Fixture, d digests) func(string) string {
	find := func(table, key string, match func(paritytest.Row) bool) string {
		for _, r := range f.Rows[table] {
			if match(r) {
				return r[key].(string)
			}
		}
		return ""
	}
	org := find("organizations", "id", func(r paritytest.Row) bool { return r["slug"] == "cap" })
	project := find("projects", "id", func(r paritytest.Row) bool { return r["organization_id"] == org && r["slug"] == "api" })
	return func(p string) string {
		return placeholder.ReplaceAllStringFunc(p, func(m string) string {
			parts := placeholder.FindStringSubmatch(m)
			kind, arg := parts[1], parts[2]
			switch kind {
			case "idn":
				return find("identities", "id", func(r paritytest.Row) bool { return r["name"] == arg })
			case "cap":
				return find("capabilities", "id", func(r paritytest.Row) bool { return r["run_id"] == "known-"+arg })
			case "grant":
				subject := find("identities", "id", func(r paritytest.Row) bool { return r["name"] == arg })
				return find("grants", "id", func(r paritytest.Row) bool { return r["subject_identity_id"] == subject })
			case "project":
				return project
			case "env":
				return find("environments", "id", func(r paritytest.Row) bool { return r["project_id"] == project && r["name"] == arg })
			}
			env, category, has := strings.Cut(arg, ":")
			if has {
				return d[env].StateDigests[category]
			}
			return d[env].StateDigest
		})
	}
}

// TestTypeScriptFixture replays the table against varlatchd on the file's
// rows: every answer, audit event and Capability row the same.
func TestTypeScriptFixture(t *testing.T) {
	path := paritytest.Path("capabilities-v0.22.0.json")
	f, err := paritytest.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var x struct {
		Digests digests `json:"digests"`
	}
	if err := json.Unmarshal(b, &x); err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 140 || len(x.Digests) != 2 {
		t.Fatalf("%d requests, %d digests: the fixture is incomplete", len(f.Requests), len(x.Digests))
	}
	db := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(db, f.Rows, capabilitiesTables); err != nil {
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
		Handler: h, Store: store, Settled: vs.Settled, Path: fillPath(f, x.Digests), Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}, f)
}
