// SPDX-License-Identifier: AGPL-3.0-or-later

package security_test

import (
	"cmp"
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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// securityTables are the tables of security-v0.22.0.json
// (go-security-fixture.test.ts).
var securityTables = []string{"installation", "identities", "user", "auth_user_links", "passkey", "passkey_provenance", "credentials",
	"organizations", "org_memberships", "projects", "contract_revisions", "environments", "env_values", "value_versions", "security_controls", "security_control_counters", "approval_intents", "organization_freezes",
	"organization_deletions"}

// publicURL is the public URL both servers answer with (approvals need one).
const publicURL = "http://127.0.0.1:8686"

// summaries is the file's record of the summary worker's pass.
type summaries struct {
	Emitted  int              `json:"emitted"`
	Deleted  int              `json:"deleted"`
	Audit    []paritytest.Row `json:"audit"`
	Counters []paritytest.Row `json:"counters"`
}

func readFixture(t *testing.T) (paritytest.Fixture, summaries) {
	t.Helper()
	path := paritytest.Path("security-v0.22.0.json")
	f, err := paritytest.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var extra struct {
		Summaries summaries `json:"summaries"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&extra); err != nil {
		t.Fatal(err)
	}
	return f, extra.Summaries
}

type server struct {
	handler *httpserver.Server
	store   *storage.DB
	values  *values.Service
	writer  *write.Writer
}

func newServer(t *testing.T, f paritytest.Fixture) *server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, securityTables); err != nil {
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
	public, _ := url.Parse(publicURL)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PublicURL: public, PersonGate: w.Gates.PersonGate})
	vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates})
	h, err := httpserver.New(httpserver.Options{
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: public,
		Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	return &server{handler: h, store: store, values: vs, writer: w}
}

func fillPath(f paritytest.Fixture) func(string) string {
	sec := ""
	for _, o := range f.Rows["organizations"] {
		if o["slug"] == "sec" {
			sec = o["id"].(string)
		}
	}
	return func(p string) string { return strings.ReplaceAll(p, "{secId}", sec) }
}

// The security fixture's operations give the TypeScript server's answers
// (step 4.3a): listSecurityControls, changeSecurityControl (tightening,
// loosening without an approval, with approvals approved, pending, used,
// asked for by another credential or another person, every refusal and
// every zod issue), securityControlReport and securityApprovalKeys. Every
// request, its audit events, the side rows it wrote (controls, the
// security epoch, report counters, approval intents), the report counts;
// every response valid against the OpenAPI document.
func TestTypeScriptFixture(t *testing.T) {
	f, _ := readFixture(t)
	if len(f.Requests) < 100 {
		t.Fatalf("%d requests: the fixture is incomplete", len(f.Requests))
	}
	s := newServer(t, f)
	paritytest.Replay(t, paritytest.Target{
		Handler: s.handler, Store: s.store, Settled: s.values.Settled, Path: fillPath(f),
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
	}, f)
}

// The summary worker's pass over the file's rows writes the TypeScript
// worker's security_control.would_block events, for the due rows of live
// Organizations in key order, and leaves the same counter rows: the due
// ones marked emitted, the ones past retention and the deleted
// Organization's gone.
func TestTypeScriptSummaries(t *testing.T) {
	f, want := readFixture(t)
	if want.Emitted == 0 || want.Deleted == 0 {
		t.Fatalf("the fixture's summaries cover nothing: %+v", want)
	}
	s := newServer(t, f)
	emitted, deleted, err := security.RunWorker(context.Background(), s.writer, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if emitted != want.Emitted || deleted != want.Deleted {
		t.Errorf("emitted %d and deleted %d, want %d and %d", emitted, deleted, want.Emitted, want.Deleted)
	}
	norm := paritytest.NewNormalizer(f.Rows)
	var audit []any
	for _, r := range paritytest.PGAudit(t, s.store, "security_control.would_block") {
		audit = append(audit, norm.Value(map[string]any(r), ""))
	}
	if !paritytest.Same(audit, want.Audit) {
		t.Errorf("audit\n  %s\n want %s", paritytest.Canonical(audit), paritytest.Canonical(want.Audit))
	}
	rows := paritytest.PGRows(t, s.store, "security_control_counters")
	// ORDER BY organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour.
	slices.SortFunc(rows, func(a, b paritytest.Row) int {
		for _, k := range []string{"organization_id", "control", "config_version", "operation", "actor_identity_id", "reason", "bucket_hour"} {
			if c := cmp.Compare(paritytest.Canonical(a[k]), paritytest.Canonical(b[k])); c != 0 {
				return c
			}
		}
		return 0
	})
	var counters []any
	for _, r := range rows {
		counters = append(counters, norm.Value(map[string]any(r), ""))
	}
	if !paritytest.Same(counters, want.Counters) {
		t.Errorf("counters\n  %s\n want %s", paritytest.Canonical(counters), paritytest.Canonical(want.Counters))
	}
}
