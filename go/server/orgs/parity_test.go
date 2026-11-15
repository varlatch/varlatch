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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

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
	target := s.target(t, f)
	begins := 0
	target.Inspect = rotationDeadlines(&begins)
	paritytest.Replay(t, target, f)
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
	if want := beginsIn(f); begins != want || want < 12 {
		t.Errorf("%d begun rotations checked, the file has %d", begins, want)
	}
}

// rotationHints are the Contract hints on the fixture's rotated items
// (acme/rotate's HINTED), as go-core-fixture.test.ts holds them.
var rotationHints = map[string]int64{"rotate/HINTED": 3600}

// rotationDeadlines checks what the file holds only as {time}: for every
// rotation a request began, the answer's rotationDeadline,
// value.rotation_started's metadata.deadline and the stored
// rotation_deadline are the same instant, the request's time plus its
// grace (the request's own, else the Contract's hint, else a day; at most
// 30 days). begins counts the rotations it checked.
func rotationDeadlines(begins *int) func(testing.TB, paritytest.Recorded, paritytest.Raw) {
	return func(t testing.TB, c paritytest.Recorded, raw paritytest.Raw) {
		if c.Method != http.MethodPost || !strings.HasSuffix(c.Path, "/rotations") {
			return
		}
		segments := strings.Split(c.Path, "/")
		grace := int64(86_400)
		var body struct{ GraceSeconds *float64 }
		if c.Body != nil && json.Unmarshal(*c.Body, &body) == nil && body.GraceSeconds != nil {
			grace = int64(*body.GraceSeconds)
		} else if hint, ok := rotationHints[segments[5]+"/"+segments[9]]; ok {
			grace = hint
		}
		grace = min(grace, 2_592_000)
		for i, status := range raw.Statuses {
			if status != http.StatusCreated {
				continue
			}
			*begins++
			var answer struct{ PrimaryVersionID, RotationDeadline string }
			if err := json.Unmarshal(raw.Bodies[i], &answer); err != nil {
				t.Errorf("%s: %v", c.Name, err)
				continue
			}
			var audited, stored any
			for _, e := range raw.Audit {
				resource, _ := e["resource"].(map[string]any)
				metadata, _ := e["metadata"].(map[string]any)
				if e["event_type"] == "value.rotation_started" && resource["versionId"] == answer.PrimaryVersionID {
					audited = metadata["deadline"]
				}
			}
			for _, r := range raw.Side["env_values"] {
				if r["current_version_id"] == answer.PrimaryVersionID {
					stored = r["rotation_deadline"]
				}
			}
			if audited != answer.RotationDeadline || stored != answer.RotationDeadline {
				t.Errorf("%s: the answer's, the audit event's and the stored deadline differ: %q %v %v", c.Name, answer.RotationDeadline, audited, stored)
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, answer.RotationDeadline)
			low, high := raw.Sent.Add(time.Duration(grace)*time.Second).Truncate(time.Millisecond), raw.Done.Add(time.Duration(grace)*time.Second)
			if err != nil || at.Before(low) || at.After(high) {
				t.Errorf("%s: deadline %s is not the request's time plus %d s", c.Name, answer.RotationDeadline, grace)
			}
		}
	}
}

// beginsIn counts the rotations the file's requests begin (answers of 201).
func beginsIn(f paritytest.Fixture) int {
	n := 0
	for _, r := range f.Requests {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.Path, "/rotations") {
			continue
		}
		if len(r.Answers) == 0 && r.Expect.Status == http.StatusCreated {
			n++
		}
		for _, a := range r.Answers {
			if a.Status == http.StatusCreated {
				n++
			}
		}
	}
	return n
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
	if raceDetector {
		t.Skip("checks the replay's checks, not concurrency: run without the race detector (a replay takes minutes under it)")
	}
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

// The deadline check notices a begun rotation's deadline changed in the
// answer or in the audit event, which the normalized comparison cannot
// (both read {time} there). The answer is changed on the wire; the audit
// event, append-only, on its way to the check.
func TestReplayNoticesWrongRotationDeadlines(t *testing.T) {
	if raceDetector {
		t.Skip("checks the replay's checks, not concurrency: run without the race detector (a replay takes minutes under it)")
	}
	f, err := paritytest.Read(paritytest.Path("core-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	shifted := regexp.MustCompile(`"rotationDeadline":"([^"]+)"`)
	later := func(iso string) string {
		at, _ := time.Parse(time.RFC3339Nano, iso)
		return at.Add(time.Second).UTC().Format("2006-01-02T15:04:05.000Z")
	}
	// One replay (a replay is minutes under the race detector): the
	// answer changed on HINTED's begin, the audit event on GRACED's.
	s := newServer(t, f)
	target := s.target(t, f)
	real := target.Handler
	target.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/values/HINTED/rotations") {
			real.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		real.ServeHTTP(rec, r)
		body := shifted.ReplaceAllFunc(rec.Body.Bytes(), func(m []byte) []byte {
			return []byte(`"rotationDeadline":"` + later(string(shifted.FindSubmatch(m)[1])) + `"`)
		})
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body)
	})
	target.Check = nil
	begins := 0
	check := rotationDeadlines(&begins)
	// Audit events are append-only: the audited deadline is changed on
	// its way to the check, as a server that audited another would.
	target.Inspect = func(t testing.TB, c paritytest.Recorded, raw paritytest.Raw) {
		if strings.Contains(c.Path, "/GRACED/rotations") {
			for _, e := range raw.Audit {
				if m, ok := e["metadata"].(map[string]any); ok && e["event_type"] == "value.rotation_started" {
					m["deadline"] = later(m["deadline"].(string))
				}
			}
		}
		check(t, c, raw)
	}
	rec := &failures{TB: t}
	paritytest.Replay(rec, target, f)
	for _, want := range []string{
		"begin a rotation, the Contract's grace: the answer's, the audit event's and the stored deadline differ",
		"begin a rotation, its own grace: the answer's, the audit event's and the stored deadline differ",
	} {
		found := false
		for _, e := range rec.errs {
			found = found || strings.Contains(e, want)
		}
		if !found {
			t.Errorf("not noticed: %s (%d other differences)", want, len(rec.errs))
		}
	}
}
