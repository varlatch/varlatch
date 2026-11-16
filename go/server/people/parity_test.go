// SPDX-License-Identifier: AGPL-3.0-or-later

package people_test

import (
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// peopleTables are the tables of people-v0.22.0.json
// (go-people-fixture.test.ts).
var peopleTables = []string{"installation", "identities", "user", "auth_user_links", "credentials", "setup_grants", "organizations",
	"org_memberships", "projects", "environments", "roles", "groups", "group_members", "grants", "requirements", "platform_connections",
	"sync_targets", "member_integrations", "webhooks", "oidc_bindings", "membership_removals", "removal_authority", "removal_requirements",
	"removal_conditions", "security_controls", "security_control_counters", "approval_intents", "organization_freezes", "organization_deletions"}

var placeholder = regexp.MustCompile(`\{(org|idn|inv):([^}]+)\}`)

// fillPath is go-people-fixture.test.ts's: rows named by what they are.
func fillPath(t *testing.T, f paritytest.Fixture) func(string) string {
	find := func(table string, match func(paritytest.Row) bool) string {
		for _, r := range f.Rows[table] {
			if match(r) {
				return r["id"].(string)
			}
		}
		t.Fatalf("no %s row for a placeholder", table)
		return ""
	}
	org := func(slug string) string {
		return find("organizations", func(r paritytest.Row) bool { return r["slug"] == slug })
	}
	return func(p string) string {
		return placeholder.ReplaceAllStringFunc(p, func(m string) string {
			sub := placeholder.FindStringSubmatch(m)
			a, b, _ := strings.Cut(sub[2], ":")
			switch sub[1] {
			case "org":
				return org(a)
			case "idn":
				return find("identities", func(r paritytest.Row) bool { return r["name"] == a })
			}
			return find("setup_grants", func(r paritytest.Row) bool { return r["invite_organization_id"] == org(a) && r["invite_name"] == b })
		})
	}
}

// The people fixture's operations give the TypeScript server's answers
// (step 4.5a): invitations listed (every status, limit and cursor form),
// issued and revoked in every state; members reviewed, promoted, demoted,
// removed (the authority snapshot, the review) and leaving, the last-admin
// rule and the admin check's audited refusal; the profile; each control
// off, at report and at enforce with approvals; U+0000 where it reaches a
// query. Every request, its audit events, the side rows it wrote, the
// report counts; every response valid against the OpenAPI document.
func TestTypeScriptFixture(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("people-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 100 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, peopleTables); err != nil {
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
	public, _ := url.Parse("http://127.0.0.1:8686")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	// Its report counts are kept per hour: the replay runs in one.
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
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	paritytest.Replay(t, paritytest.Target{
		Handler: h, Store: store, Settled: vs.Settled, Path: fillPath(t, f), Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}, f)
}
