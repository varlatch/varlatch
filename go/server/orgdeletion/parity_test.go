// SPDX-License-Identifier: AGPL-3.0-or-later

package orgdeletion_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auditexport"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgdeletion"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// deletionTables are the tables of org-deletion-v0.22.0.json
// (go-org-deletion-fixture.test.ts).
var deletionTables = []string{"installation", "identities", "credentials", "setup_grants", "organizations", "org_memberships", "roles",
	"groups", "group_members", "grants", "projects", "contract_revisions", "environments", "env_values", "value_versions", "capabilities",
	"github_apps", "github_app_registrations", "platform_connections", "sync_targets", "webhooks", "oidc_bindings", "audit_exports",
	"security_controls", "security_control_counters", "approval_intents", "organization_freezes", "organization_deletions", "audit_events"}

// runPath is the fixture's due run (RUN_PATH): answered by the test, not
// the server.
const runPath = "/__fixture/run-due-deletions"

var (
	tombstonePage   = regexp.MustCompile(`^/v1/deleted-organizations/[^/]+/audit-events$`)
	tombstoneExport = regexp.MustCompile(`^/v1/deleted-organizations/[^/]+/audit-events/export$`)
)

// fillPath is go-org-deletion-fixture.test.ts's: the deletions of acme,
// beta and icy, acme's and beta's ids, erin and bob, by the file's rows.
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
	deletion := func(slug string) string {
		o := org(slug)
		return find("organization_deletions", func(r paritytest.Row) bool { return r["organization_id"] == o })
	}
	person := func(name string) string {
		return find("identities", func(r paritytest.Row) bool { return r["name"] == name && r["kind"] == "human" })
	}
	r := strings.NewReplacer("{acmeDeletion}", deletion("acme"), "{betaDeletion}", deletion("beta"), "{icyDeletion}", deletion("icy"),
		"{acmeId}", org("acme"), "{betaId}", org("beta"), "{erinId}", person("erin"), "{bobId}", person("bob"))
	return r.Replace
}

// masked is an event with its request id masked (maskRequestId).
func masked(v any) any {
	e, ok := v.(jsvalue.Object)
	if !ok {
		return v
	}
	if id, has := e.Get("requestId"); has && id != nil {
		return e.Set("requestId", "{requestId}")
	}
	return e
}

// tiesInOrder is the fixture's: a tombstone page with every event's
// request id masked, and the events of one time ordered by type, then the
// identity they name; the rest kept newest first.
func tiesInOrder(t testing.TB, body []byte) []byte {
	v, err := jsvalue.Parse(body)
	if err != nil {
		t.Fatalf("a tombstone page: %v", err)
	}
	page, _ := v.(jsvalue.Object)
	raw, _ := page.Get("items")
	items, ok := raw.([]any)
	if !ok {
		return body
	}
	str := func(e any, k string) string {
		o, _ := e.(jsvalue.Object)
		s, _ := o.Get(k)
		out, _ := s.(string)
		return out
	}
	key := func(e any) string {
		o, _ := e.(jsvalue.Object)
		res, _ := o.Get("resource")
		return str(e, "eventType") + "\x00" + str(res, "identityId")
	}
	group := make([]int, len(items))
	for i := range items {
		group[i] = i
		if i > 0 && str(items[i], "occurredAt") == str(items[i-1], "occurredAt") {
			group[i] = group[i-1]
		}
	}
	type entry struct {
		group int
		key   string
		item  any
	}
	es := make([]entry, len(items))
	for i, it := range items {
		es[i] = entry{group[i], key(it), masked(it)}
	}
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].group != es[j].group {
			return es[i].group < es[j].group
		}
		return es[i].key < es[j].key
	})
	out := make([]any, len(es))
	for i, e := range es {
		out[i] = e.item
	}
	return jsvalue.Stringify(page.Set("items", out))
}

// exportMasked is the fixture's: an export with every event's request id
// masked.
func exportMasked(t testing.TB, body []byte) []byte {
	lines := strings.Split(string(body), "\n")
	for i, l := range lines {
		if l == "" {
			continue
		}
		v, err := jsvalue.Parse([]byte(l))
		if err != nil {
			t.Fatalf("an export line: %v", err)
		}
		lines[i] = string(jsvalue.Stringify(masked(v)))
	}
	return []byte(strings.Join(lines, "\n"))
}

// outcomeJS is a FinalizeOutcome as the fixture's run answers it.
func outcomeJS(o orgdeletion.Outcome) jsvalue.Object {
	return jsvalue.Object{
		{Key: "deletionId", Value: o.DeletionID}, {Key: "organizationId", Value: o.OrganizationID},
		{Key: "members", Value: o.Members}, {Key: "readers", Value: o.Readers}, {Key: "projects", Value: o.Projects},
		{Key: "versionsErased", Value: o.VersionsErased}, {Key: "targetsRevoked", Value: o.TargetsRevoked},
		{Key: "identitiesRetired", Value: o.IdentitiesRetired}, {Key: "credentialsRevoked", Value: o.CredentialsRevoked},
		{Key: "webhooksRemoved", Value: o.WebhooksRemoved}, {Key: "connectionsRevoked", Value: o.ConnectionsRevoked},
		{Key: "githubAppRemoved", Value: o.GitHubAppRemoved},
	}
}

// TestTypeScriptFixture replays the table against varlatchd on the file's
// rows, the due run through the deletion loop's own pass: every answer,
// audit event and changed row the same.
func TestTypeScriptFixture(t *testing.T) { replayFixture(t, time.Now) }

// TestFixtureLaterDate: the replay does not depend on the date it runs on.
// With the date outside 30 days after today (past the rows' invitations,
// valid a week, and the scheduled deletions' run_after), it gives the same
// answers.
func TestFixtureLaterDate(t *testing.T) {
	replayFixture(t, func() time.Time { return time.Now().Add(30 * 24 * time.Hour) })
}

// replayFixture replays the fixture on the recording's clock
// (paritytest.RecordedClock), wall being the date outside.
func replayFixture(t *testing.T, wall func() time.Time) {
	path := paritytest.Path("org-deletion-v0.22.0.json")
	f, err := paritytest.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 50 {
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
	now, err := paritytest.RecordedClock(f.Rows, wall)
	if err != nil {
		t.Fatal(err)
	}
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
	drains := &auditexport.Service{Writer: w, Approvals: approvals, RootKEK: rootKEK, Now: now, Log: log}
	deletions := &orgdeletion.Service{Writer: w, Approvals: approvals, Drains: drains, Now: now, Log: log}
	handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == runPath:
			var body struct{ Age []string }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			at := now()
			err := store.Write(r.Context(), func(tx *storage.Tx) error {
				for _, slug := range body.Age {
					if _, err := tx.ExecContext(r.Context(), `UPDATE organization_deletions SET scheduled_at = scheduled_at - ?, run_after = ?
						WHERE cancelled_at IS NULL AND completed_at IS NULL AND organization_id = (SELECT id FROM organizations WHERE slug = ?)`,
						(40 * 24 * time.Hour).Microseconds(), at.Add(-time.Second).UnixMicro(), slug); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			done := []any{}
			for _, o := range deletions.RunDue(r.Context()) {
				done = append(done, outcomeJS(o))
			}
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write(jsvalue.Stringify(jsvalue.Object{{Key: "deletions", Value: done}}))
		case tombstonePage.MatchString(r.URL.Path), tombstoneExport.MatchString(r.URL.Path):
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			body := rec.Body.Bytes()
			if rec.Code == http.StatusOK {
				if tombstonePage.MatchString(r.URL.Path) {
					body = tiesInOrder(t, body)
				} else {
					body = exportMasked(t, body)
				}
			}
			for k, vs := range rec.Header() {
				rw.Header()[k] = vs
			}
			rw.WriteHeader(rec.Code)
			_, _ = io.Copy(rw, bytes.NewReader(body))
		default:
			h.ServeHTTP(rw, r)
		}
	})
	paritytest.Replay(t, paritytest.Target{
		Handler: handler, Store: store, Settled: vs.Settled, Path: fillPath(f), Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			if req.URL.Path != runPath {
				openapicheck.Recorder{T: t}.Exchange(req, body, rec)
			}
		},
	}, f)
}
