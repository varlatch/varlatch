// SPDX-License-Identifier: AGPL-3.0-or-later

package values_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/values/valuestest"
)

// The read path's parity with the TypeScript server, and G3 for the values
// a database holds. testdata/values-v0.22.0.json and values-v0.21.0.json
// are written by services/varlatchd/test/go-values-fixture.test.ts: a
// database the TypeScript server built through its own /v1 API (its rows,
// as PostgreSQL holds them), a table of requests, and the TypeScript
// server's answer to each, with the audit events, exposure rows and report
// counts it wrote. The v0.21.0 file's envelopes were sealed by that
// release's crypto code. Here the rows are loaded through the schema
// mapping (../db/mapping.json), as the migration will copy them, the same
// requests run against the Go server, and every answer must be the same:
// status, headers, the body byte for byte (the request id aside), and what
// was written.

var writeGoSealed = flag.String("write-go-sealed", "", "write the v0.22.0 fixture with every Organization KEK and value sealed again by Go to this path")

type row = valuestest.Row

type fixture = valuestest.Fixture

func readFixture(t *testing.T, path string) fixture {
	t.Helper()
	f, err := valuestest.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type server struct {
	t       *testing.T
	store   *storage.DB
	handler *httpserver.Server
	values  *values.Service
	rootKEK []byte
}

func newServer(t *testing.T, f fixture) *server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := valuestest.Prepare(path, f); err != nil {
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
		// The Backend serve uses: readiness opens the installation's
		// canary with the Root KEK (G3 at the database level).
		Version: "test", Backend: daemon.NewBackend(store, rootKEK), Log: log,
		Auth:   auth.New(store, auth.Options{Log: log, RootKEK: rootKEK}),
		Values: vs,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	return &server{t: t, store: store, handler: h, values: vs, rootKEK: rootKEK}
}

// canonical parses JSON text or a value into plain Go values, so two
// objects compare without their member order (jsonb's differs from ours).
func canonical(v any) any {
	if s, ok := v.(string); ok && (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) {
		var out any
		if json.Unmarshal([]byte(s), &out) == nil {
			return out
		}
	}
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

var auditColumns = []string{"event_type", "actor_identity_id", "credential_id", "organization_id", "action", "resource", "decision",
	"authz", "tailnet", "listener", "request_id", "metadata", "client", "schema_version"}

func (s *server) rows(q string, args ...any) []row {
	s.t.Helper()
	rs, err := s.store.Reader().Query(q, args...)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rs.Close()
	cols, _ := rs.Columns()
	var out []row
	for rs.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rs.Scan(ptrs...); err != nil {
			s.t.Fatal(err)
		}
		r := row{}
		for i, c := range cols {
			r[c] = vals[i]
		}
		out = append(out, r)
	}
	return out
}

func (s *server) lastAudit() int64 {
	var n sql.NullInt64
	if err := s.store.Reader().QueryRow("SELECT max(event_order) FROM audit_events").Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n.Int64
}

func exposureKey(r row) string {
	return fmt.Sprint(r["identity_id"], "|", r["version_id"], "|", r["environment_id"], "|", r["way"])
}

// replay runs every request of f against the Go server and compares.
func replay(t *testing.T, f fixture) {
	s := newServer(t, f)
	var orgID, projectID string
	for _, o := range f.Rows["organizations"] {
		if o["slug"] == "acme" {
			orgID = o["id"].(string)
		}
	}
	for _, p := range f.Rows["projects"] {
		if p["organization_id"] == orgID && p["slug"] == "api" {
			projectID = p["id"].(string)
		}
	}
	for _, c := range f.Requests {
		before := s.lastAudit()
		seen := map[string]bool{}
		for _, r := range s.rows("SELECT identity_id, version_id, environment_id, way FROM member_exposure") {
			seen[exposureKey(r)] = true
		}
		path := strings.NewReplacer("{orgId}", orgID, "{projectId}", projectID).Replace(c.Path)
		var body io.Reader
		switch {
		case c.RawBody != nil:
			body = strings.NewReader(*c.RawBody)
		case c.Body != nil:
			b, _ := json.Marshal(*c.Body)
			body = bytes.NewReader(b)
		}
		req := httptest.NewRequest(c.Method, path, body)
		req.Header.Set("Content-Type", "application/json")
		ua := c.UserAgent
		if ua == "" {
			ua = valuestest.CLIAgent
		}
		req.Header.Set("User-Agent", ua)
		if c.Credential != "none" {
			req.Header.Set("Authorization", "Bearer "+f.Tokens[c.Credential])
		}
		rec := httptest.NewRecorder()
		s.handler.ServeHTTP(rec, req)
		s.values.Settled()
		// Every answer against the OpenAPI document (responses only: some
		// requests are outside it on purpose).
		openapicheck.Recorder{T: t}.Exchange(req, nil, rec)
		id := rec.Header().Get("X-Request-Id")
		got := strings.ReplaceAll(rec.Body.String(), id, "{requestId}")
		name := c.Method + " " + c.Name
		if rec.Code != c.Expect.Status || got != c.Expect.Body {
			t.Errorf("%s: %d %s\n want %d %s", name, rec.Code, got, c.Expect.Status, c.Expect.Body)
		}
		for _, h := range []string{"Cache-Control", "Retry-After", "Content-Type", "Varlatch-Credential-Expires"} {
			if g, w := rec.Header().Get(h), c.Expect.Headers[h]; g != w {
				t.Errorf("%s: %s %q, want %q", name, h, g, w)
			}
		}
		var audit []any
		for _, r := range s.rows("SELECT "+strings.Join(auditColumns, ", ")+" FROM audit_events WHERE event_order > ? ORDER BY event_order", before) {
			if r["request_id"] == id {
				r["request_id"] = "{requestId}"
			}
			for _, k := range []string{"resource", "authz", "tailnet", "metadata"} {
				if r[k] != nil {
					r[k] = canonical(r[k])
				}
			}
			audit = append(audit, canonical(r))
		}
		var want []any
		for _, r := range c.Audit {
			want = append(want, canonical(r))
		}
		if !reflect.DeepEqual(audit, want) {
			gb, _ := json.Marshal(audit)
			wb, _ := json.Marshal(want)
			t.Errorf("%s: audit\n  %s\n want %s", name, gb, wb)
		}
		var exposure []any
		for _, r := range s.rows("SELECT organization_id, identity_id, version_id, item_name, environment_id, way FROM member_exposure ORDER BY identity_id, version_id, environment_id, way") {
			if !seen[exposureKey(r)] {
				exposure = append(exposure, canonical(r))
			}
		}
		var wantExposure []any
		for _, r := range c.Exposure {
			wantExposure = append(wantExposure, canonical(r))
		}
		if !reflect.DeepEqual(exposure, wantExposure) {
			t.Errorf("%s: exposure %v, want %v", name, exposure, wantExposure)
		}
	}
	var counters []any
	for _, r := range s.rows("SELECT organization_id, control, config_version, operation, actor_identity_id, reason, count FROM security_control_counters ORDER BY organization_id, control, operation, actor_identity_id, reason") {
		counters = append(counters, canonical(r))
	}
	var wantCounters []any
	for _, r := range f.Counters {
		wantCounters = append(wantCounters, canonical(r))
	}
	if !reflect.DeepEqual(counters, wantCounters) {
		t.Errorf("counters %v, want %v", counters, wantCounters)
	}
}

// TestTypeScriptFixtures: every answer of the TypeScript server, on both
// releases' envelopes (G3: values the TypeScript server sealed open in Go).
func TestTypeScriptFixtures(t *testing.T) {
	for _, file := range []string{"testdata/values-v0.22.0.json", "testdata/values-v0.21.0.json"} {
		t.Run(filepath.Base(file), func(t *testing.T) {
			f := readFixture(t, file)
			if len(f.Requests) < 50 {
				t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
			}
			replay(t, f)
		})
	}
}

// goSealed is the v0.22.0 fixture with every Organization KEK and value
// sealed again by this code (values.SealValue, which the server's writes
// use): its answers must stay the same, here and in the TypeScript server
// (go.yml runs go-values-fixture.test.ts on the file -write-go-sealed
// writes).
func goSealed(t *testing.T) fixture {
	f := readFixture(t, "testdata/values-v0.22.0.json")
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	// The Root KEK canary, as varlatchd writes it on first start.
	for _, inst := range f.Rows["installation"] {
		canary, err := envelope.NewCanary(rootKEK, inst["id"].(string))
		if err != nil {
			t.Fatal(err)
		}
		inst["kek_canary"] = envelopeValue(t, canary)
	}
	kekOf := map[string][]byte{}
	for _, o := range f.Rows["organizations"] {
		id := o["id"].(string)
		kek, wrapped, err := envelope.WrapOrgKEK(rootKEK, id)
		if err != nil {
			t.Fatal(err)
		}
		kekOf[id] = kek
		o["wrapped_org_kek"] = envelopeValue(t, wrapped)
	}
	env := map[any]row{}
	for _, e := range f.Rows["environments"] {
		env[e["id"]] = e
	}
	project := map[any]row{}
	for _, p := range f.Rows["projects"] {
		project[p["id"]] = p
	}
	value := map[any]row{}
	for _, v := range f.Rows["env_values"] {
		value[v["id"]] = v
	}
	for _, v := range f.Rows["value_versions"] {
		val := value[v["value_id"]]
		org := project[env[val["environment_id"]]["project_id"]]["organization_id"].(string)
		plaintext, ok := f.Plaintexts[v["id"].(string)]
		if !ok {
			t.Fatalf("no plaintext for %s", v["id"])
		}
		sealed, err := values.SealValue(kekOf[org], org, val["id"].(string), v["id"].(string), []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		v["payload"], v["wrapped_dek"] = envelopeValue(t, sealed.Payload), envelopeValue(t, sealed.WrappedDEK)
	}
	f.Comment = "Written by the Go tests (go test ./server/values -run TestGoSealedFixture -args -write-go-sealed=<file>): the v0.22.0 fixture with the Root KEK canary and every Organization KEK and value sealed again by Go; services/varlatchd/test/go-values-fixture.test.ts opens it with the TypeScript server."
	f.Ref = "go"
	return f
}

func envelopeValue(t *testing.T, e envelope.Envelope) map[string]any {
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestGoSealedFixture: values Go sealed open through the Go read path with
// the TypeScript server's answers; with -write-go-sealed, the file for the
// TypeScript side.
func TestGoSealedFixture(t *testing.T) {
	f := goSealed(t)
	replay(t, f)
	if *writeGoSealed == "" {
		return
	}
	var raw map[string]json.RawMessage
	b, err := os.ReadFile("testdata/values-v0.22.0.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]any{"comment": f.Comment, "ref": f.Ref, "rows": f.Rows} {
		enc, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		raw[k] = enc
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(*writeGoSealed, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
