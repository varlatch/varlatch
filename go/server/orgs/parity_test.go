// SPDX-License-Identifier: AGPL-3.0-or-later

package orgs_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/varlatch/varlatch/go/server/jsvalue"
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
	"environments", "env_values", "capabilities", "value_versions", "idempotency_keys"}

type server struct {
	opts    httpserver.Options
	mu      sync.Mutex
	handler *httpserver.Server
	store   *storage.DB
	values  *values.Service
	rootKEK []byte
}

// current is the server answering now.
func (s *server) current() *httpserver.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handler
}

// restart starts a fresh server on the same database and services: a new
// request window (paritytest.WindowBatch).
func (s *server) restart(t testing.TB) {
	h, err := httpserver.New(s.opts)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = h
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
	opts := httpserver.Options{
		// The TypeScript server's SERVER_VERSION, which the installation
		// release read reports.
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log,
		Auth: auth.New(store, auth.Options{Log: log, RootKEK: rootKEK}), Values: vs,
		Writer: &write.Writer{Store: store, Gates: write.NewGates()}, RootKEK: rootKEK,
	}
	h, err := httpserver.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	return &server{opts: opts, handler: h, store: store, values: vs, rootKEK: rootKEK}
}

// The core fixture's operations give the TypeScript server's answers: the
// Organization operations (step 4.1a), the Contract operations (4.1b), and
// the Projects, environments and installation reads (4.1c). Every request,
// its audit events, the side rows it wrote (Organizations, memberships,
// Projects, Contract revisions, environments, values, Capabilities), the
// report counts; every response valid against the OpenAPI document. Every Organization the
// requests created has a KEK that opens with the installation's Root KEK.
// TestTypeScriptFixture replays both core files: core-v0.22.0.json, the
// rows as v0.22.0 sealed them, and core-v0.21.0.json, the same rows with
// every envelope sealed by v0.21.0 (a v0.21.0 installation after its
// upgrade). Both hold Idempotency-Key claims the TypeScript server stored,
// which the migration copies (step 7): a replay answers from them.
func TestTypeScriptFixture(t *testing.T) {
	for _, name := range []string{"core-v0.22.0.json", "core-v0.21.0.json"} {
		t.Run(name, func(t *testing.T) { replayCoreFile(t, name) })
	}
}

func replayCoreFile(t *testing.T, name string) {
	f, err := paritytest.Read(paritytest.Path(name))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 50 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	if want := "v" + strings.TrimSuffix(strings.TrimPrefix(name, "core-v"), ".json"); f.Ref != want {
		t.Fatalf("ref %q, want %q", f.Ref, want)
	}
	if n := len(f.Rows["idempotency_keys"]); n < 2 {
		t.Fatalf("%d stored Idempotency-Key claims: the fixture has none to replay", n)
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
	checkWrittenValues(t, s, f)
	checkRotationWindows(t, s)
}

// checkRotationWindows checks the grace each rotation the requests began in
// acme/rotate was given, which the fixture holds only as {time}: the
// Contract's hint (HINTED, 3600 s), the request's own (GRACED, 120 s), the
// default (DEFAULTED, a day) and the longest (MAXED, 30 days). The deadline
// is the start's millisecond plus the grace (new Date(Date.now() + grace *
// 1000)).
func checkRotationWindows(t *testing.T, s *server) {
	t.Helper()
	want := map[string]int64{"HINTED": 3600, "GRACED": 120, "DEFAULTED": 86_400, "MAXED": 2_592_000}
	rows := paritytest.Rows(t, s.store, `SELECT v.item_name, v.rotation_deadline, v.rotation_started_at FROM env_values v
		JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id
		WHERE p.slug = 'rotate' AND e.name = 'development' AND v.rotation_deadline IS NOT NULL`)
	seen := 0
	for _, r := range rows {
		grace, ok := want[r["item_name"].(string)]
		if !ok {
			continue
		}
		seen++
		deadline, started := r["rotation_deadline"].(int64), r["rotation_started_at"].(int64)
		if deadline != (started/1000+grace*1000)*1000 {
			t.Errorf("%s: deadline %d, started %d: not a grace of %d s", r["item_name"], deadline, started, grace)
		}
	}
	if seen != len(want) {
		t.Errorf("%d of %d rotations in flight in acme/rotate", seen, len(want))
	}
}

// checkWrittenValues opens every value version the requests wrote with
// its Organization's KEK: each holds a value one of the requests sent
// (JSON-decoded as Node decodes it: a lone surrogate is U+FFFD), and as
// many were written as the fixture's side rows say.
func checkWrittenValues(t *testing.T, s *server, f paritytest.Fixture) {
	t.Helper()
	sent := map[string]bool{}
	var collect func(v any)
	collect = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if s, ok := e.(string); ok && k == "value" {
					sent[s] = true
				}
				collect(e)
			}
		case []any:
			for _, e := range x {
				collect(e)
			}
		}
	}
	want := 0
	for _, r := range f.Requests {
		var raw []byte
		switch {
		case r.RawBody != nil:
			raw = []byte(*r.RawBody)
		case r.Body != nil:
			raw = *r.Body
		}
		var v any
		if json.Unmarshal(raw, &v) == nil {
			collect(v)
		}
		want += len(r.Side["value_versions"]["inserted"])
	}
	known := map[string]bool{}
	for _, v := range f.Rows["value_versions"] {
		known[v["id"].(string)] = true
	}
	rows := paritytest.Rows(t, s.store, `SELECT vv.id, vv.value_id, vv.payload, vv.wrapped_dek, o.id AS org, o.wrapped_org_kek
		FROM value_versions vv JOIN env_values ev ON ev.id = vv.value_id JOIN environments e ON e.id = ev.environment_id
		JOIN projects p ON p.id = e.project_id JOIN organizations o ON o.id = p.organization_id`)
	written := 0
	for _, r := range rows {
		id := r["id"].(string)
		if known[id] {
			continue
		}
		written++
		var wrapped envelope.Envelope
		var sealed envelope.EncryptedValue
		if json.Unmarshal([]byte(r["wrapped_org_kek"].(string)), &wrapped) != nil ||
			json.Unmarshal([]byte(r["payload"].(string)), &sealed.Payload) != nil ||
			json.Unmarshal([]byte(r["wrapped_dek"].(string)), &sealed.WrappedDEK) != nil {
			t.Fatalf("%s: unreadable envelopes", id)
		}
		org := r["org"].(string)
		kek, err := envelope.UnwrapOrgKEK(s.rootKEK, wrapped, org)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := envelope.DecryptValue(kek, org, r["value_id"].(string), id, sealed)
		if err != nil {
			t.Errorf("%s: does not open: %v", id, err)
			continue
		}
		if !sent[string(plain)] {
			t.Errorf("%s holds %q, which no request sent", id, plain)
		}
	}
	// A concurrent request's side rows are everything its answers wrote.
	if written != want || want < 200 {
		t.Errorf("%d value versions written, the fixture %d", written, want)
	}
}

// fillPath is go-core-fixture.test.ts's, for a request's path and body:
// {orgId} and {goneId}, acme's live {project:SLUG}, {env:PROJECT/NAME} and
// {ver:PROJECT/ENVIRONMENT/ITEM} (the value's current version), and
// {rev:KEY}, the revision holding an item named KEY.
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
	envs := map[string]string{} // acme's live environments: id to PROJECT/NAME
	for _, e := range f.Rows["environments"] {
		if slug, ok := live[e["project_id"].(string)]; ok && e["deleted_at"] == nil {
			envs[e["id"].(string)] = slug + "/" + e["name"].(string)
			pairs = append(pairs, "{env:"+slug+"/"+e["name"].(string)+"}", e["id"].(string))
		}
	}
	for _, v := range f.Rows["env_values"] {
		if env, ok := envs[v["environment_id"].(string)]; ok && v["current_version_id"] != nil {
			pairs = append(pairs, "{ver:"+env+"/"+v["item_name"].(string)+"}", v["current_version_id"].(string))
		}
	}
	for _, r := range f.Rows["contract_revisions"] {
		items, _ := r["contract"].(map[string]any)["items"].([]any)
		for _, it := range items {
			pairs = append(pairs, "{rev:"+it.(map[string]any)["name"].(string)+"}", r["id"].(string))
		}
	}
	// {cursor:PROJECT/ITEM}: a search cursor after that hit, as
	// encodeCursor writes it.
	projectOf := map[string]string{}
	for _, e := range f.Rows["environments"] {
		projectOf[e["id"].(string)] = e["project_id"].(string)
	}
	cursors := map[string]bool{}
	for _, v := range f.Rows["env_values"] {
		project := projectOf[v["environment_id"].(string)]
		slug, ok := live[project]
		key := "{cursor:" + slug + "/" + v["item_name"].(string) + "}"
		if !ok || cursors[key] {
			continue
		}
		cursors[key] = true
		pairs = append(pairs, key, base64.RawURLEncoding.EncodeToString(jsvalue.Stringify([]any{slug, v["item_name"], project})))
	}
	paths := strings.NewReplacer(pairs...)
	return func(p string) string {
		out := paths.Replace(p)
		if strings.Contains(out, "{rev:") || strings.Contains(out, "{project:") || strings.Contains(out, "{env:") || strings.Contains(out, "{ver:") || strings.Contains(out, "{cursor:") {
			t.Fatalf("%s: a placeholder the rows do not fill", p)
		}
		return out
	}
}

func (s *server) target(t testing.TB, f paritytest.Fixture) paritytest.Target {
	return paritytest.Target{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.current().ServeHTTP(w, r) }),
		Store:   s.store, Settled: s.values.Settled, Restart: func() { s.restart(t) },
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
