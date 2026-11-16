// SPDX-License-Identifier: AGPL-3.0-or-later

package people_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

// exposureTables are the tables of exposure-v0.22.0.json
// (go-exposure-fixture.test.ts).
var exposureTables = []string{"installation", "identities", "user", "auth_user_links", "credentials", "organizations", "org_memberships",
	"projects", "environments", "contract_revisions", "env_values", "value_versions", "grants", "requirements", "membership_removals",
	"removal_authority", "removal_requirements", "removal_conditions", "member_exposure", "exposure_confirmations", "organization_freezes"}

var placeholder = regexp.MustCompile(`\{(org|idn|inv|ver):([^}]+)\}`)

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
			case "ver":
				return version(t, f, org("exp"), sub[2])
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
	replay(t, f, peopleTables)
}

// The exposure fixture's operations give the TypeScript server's answers
// (step 4.5b): the report for current, former and other members, with
// versions current, replaced, retiring, past their deadline, of a deleted
// value or environment, and unknown here, the authority at a removal, and
// a confirmation; confirmations of every kind (where the value lives, by
// an admin once it is gone, again, refused).
func TestExposureFixture(t *testing.T) {
	f, err := paritytest.Read(paritytest.Path("exposure-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 30 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	replay(t, f, exposureTables)
}

// replay runs a fixture's requests against varlatchd on its rows.
func replay(t *testing.T, f paritytest.Fixture, tables []string) {
	t.Helper()
	// An intended difference: an issued invitation's answer, which carries
	// its token, is Cache-Control: no-store here; the TypeScript route sets
	// none.
	for i, c := range f.Requests {
		if c.Method == http.MethodPost && strings.HasSuffix(c.Path, "/invitations") && c.Expect.Status == http.StatusCreated {
			if f.Requests[i].Expect.Headers == nil {
				f.Requests[i].Expect.Headers = map[string]string{}
			}
			f.Requests[i].Expect.Headers["Cache-Control"] = "no-store"
		}
	}
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, tables); err != nil {
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

// version is {ver:ENV/ITEM/N}: the N-th version, oldest first, of the
// exp Organization's api value at ENV/ITEM.
func version(t *testing.T, f paritytest.Fixture, org, arg string) string {
	parts := strings.Split(arg, "/")
	env, item, n := parts[0], parts[1], parts[2]
	var project, environment, value string
	for _, r := range f.Rows["projects"] {
		if r["organization_id"] == org && r["slug"] == "api" {
			project, _ = r["id"].(string)
		}
	}
	for _, r := range f.Rows["environments"] {
		if r["project_id"] == project && r["name"] == env {
			environment, _ = r["id"].(string)
		}
	}
	for _, r := range f.Rows["env_values"] {
		if r["environment_id"] == environment && r["item_name"] == item {
			value, _ = r["id"].(string)
		}
	}
	var versions []paritytest.Row
	for _, r := range f.Rows["value_versions"] {
		if r["value_id"] == value {
			versions = append(versions, r)
		}
	}
	sort.SliceStable(versions, func(i, j int) bool {
		return fmt.Sprint(versions[i]["created_at"]) < fmt.Sprint(versions[j]["created_at"])
	})
	i, err := strconv.Atoi(n)
	if err != nil || i < 1 || i > len(versions) {
		t.Fatalf("no version %s", arg)
	}
	id, _ := versions[i-1]["id"].(string)
	return id
}
