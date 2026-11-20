// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/check"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
	"github.com/varlatch/varlatch/go/server/migration/migrate"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
)

// The seeded migration every test holds a damaged copy of: migrationtest's
// source (the v0.22.0 parity fixtures, 47 tables with rows, every
// encryption class), its digests computed from the source's rows (as the
// TypeScript export computes them, not by the code under test), its
// decision table, and the database an import built from it.
type seeded struct {
	source migrationtest.Source
	runKey []byte
	bundle []byte
	db     string // the imported varlatch.db
	// secrets are what no report may hold: every plaintext, the Root KEK,
	// the run key, every digest.
	secrets [][]byte
}

var (
	once    sync.Once
	seed    seeded
	seedErr string
	tmp     string
)

func TestMain(m *testing.M) {
	var err error
	tmp, err = os.MkdirTemp("", "varlatch-check-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

// setUp builds the seeded migration once.
func setUp(t *testing.T) seeded {
	t.Helper()
	once.Do(func() { build(t) })
	if seedErr != "" {
		t.Fatal(seedErr)
	}
	return seed
}

func build(t *testing.T) {
	fail := func(format string, a ...any) { seedErr = fmt.Sprintf(format, a...) }
	s := migrationtest.Load(t)
	runKey := make([]byte, 32)
	_, _ = rand.Read(runKey)
	digests := migrationtest.Digests(t, s, runKey)
	// The decision table: the tuples evaluated on a first import (the
	// TypeScript evaluator's table arrives with its export, slice 7.2).
	first := filepath.Join(tmp, "first")
	if err := os.Mkdir(first, 0o700); err != nil {
		fail("%v", err)
		return
	}
	plain := migrationtest.Bundle(t, s, migrationtest.Options{Sections: &migrationtest.Sections{Digests: digests}})
	if _, err := migrate.Import(context.Background(), bytes.NewReader(plain), migrate.Options{DataDir: first, RootKEK: s.RootKEK, Release: "0.50.0-test"}); err != nil {
		fail("the first import: %v", err)
		return
	}
	db := openRO(t, filepath.Join(first, config.DatabaseFile))
	at := time.Now().UnixMicro()
	var decisions []bundle.Decision
	for _, d := range tuples(t, db) {
		got, err := check.Evaluate(context.Background(), db, d)
		if err != nil {
			fail("evaluating a tuple: %v", err)
			return
		}
		decisions = append(decisions, got)
	}
	db.Close()
	b := migrationtest.Bundle(t, s, migrationtest.Options{Sections: &migrationtest.Sections{Digests: digests, Decisions: decisions, At: at}})
	dir := filepath.Join(tmp, "imported")
	if err := os.Mkdir(dir, 0o700); err != nil {
		fail("%v", err)
		return
	}
	if _, err := migrate.Import(context.Background(), bytes.NewReader(b), migrate.Options{DataDir: dir, RootKEK: s.RootKEK, Release: "0.50.0-test"}); err != nil {
		fail("the import: %v", err)
		return
	}
	secrets := append(slices.Clone(s.Secrets), runKey)
	for _, d := range digests {
		secrets = append(secrets, []byte(d.HMAC))
	}
	seed = seeded{source: s, runKey: runKey, bundle: b, db: filepath.Join(dir, config.DatabaseFile), secrets: secrets}
}

func openRO(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// tuples is the decision table's questions: every credential of an
// identity with a Grant, a role or a machine identity's Organization,
// asking every action on the Organization, and the environment actions on
// each environment of each Project there; active, and for a few, expired
// and revoked; with no Tailnet Context, and for the actions Requirements
// constrain, with one too.
func tuples(t *testing.T, db *sql.DB) []bundle.Decision {
	t.Helper()
	rows, err := db.Query(`SELECT c.id, o.organization_id FROM credentials c
		JOIN (SELECT identity_id, organization_id FROM org_memberships WHERE removed_at IS NULL
		      UNION SELECT subject_identity_id, organization_id FROM grants WHERE subject_identity_id IS NOT NULL
		      UNION SELECT id, organization_id FROM identities WHERE organization_id IS NOT NULL) o ON o.identity_id = c.identity_id
		WHERE c.revoked_at IS NULL ORDER BY c.id, o.organization_id`)
	if err != nil {
		t.Fatal(err)
	}
	type pair struct{ credential, org string }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.credential, &p.org); err != nil {
			t.Fatal(err)
		}
		pairs = append(pairs, p)
	}
	rows.Close()
	type env struct{ project, id string }
	envs := map[string][]env{}
	rows, err = db.Query(`SELECT p.organization_id, p.id, e.id FROM environments e JOIN projects p ON p.id = e.project_id
		WHERE e.deleted_at IS NULL AND p.deleted_at IS NULL ORDER BY e.id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var org string
		var e env
		if err := rows.Scan(&org, &e.project, &e.id); err != nil {
			t.Fatal(err)
		}
		envs[org] = append(envs[org], e)
	}
	rows.Close()
	// On an environment, the actions that decide on one: reading,
	// writing and revealing values (those Requirements constrain among
	// them), and managing it.
	onEnvironments := []string{"environment.read", "environment.manage", "config.value.read", "config.value.write", "secret.reveal", "secret.use"}
	tailnet := &bundle.Tailnet{Tailnet: "example.ts.net", NodeID: "nCheck", Tags: []string{"tag:ci"}}
	var out []bundle.Decision
	for i, p := range pairs {
		if raceDetector && i%4 != 0 {
			continue
		}
		for _, a := range authz.Actions {
			out = append(out, bundle.Decision{Credential: p.credential, State: bundle.Active, Organization: p.org, Action: a})
			if !slices.Contains(onEnvironments, a) {
				continue
			}
			for _, e := range envs[p.org] {
				d := bundle.Decision{Credential: p.credential, State: bundle.Active, Organization: p.org, Project: e.project, Environment: e.id, Action: a}
				out = append(out, d)
				if a == "secret.reveal" || a == "config.value.read" || a == "secret.use" {
					d.Tailnet = tailnet
					out = append(out, d)
				}
			}
			if i%10 == 0 {
				out = append(out, bundle.Decision{Credential: p.credential, State: bundle.Expired, Organization: p.org, Action: a},
					bundle.Decision{Credential: p.credential, State: bundle.Revoked, Organization: p.org, Action: a})
			}
		}
	}
	return out
}

// copyDB is a writable copy of the imported database.
func copyDB(t *testing.T, s seeded) string {
	t.Helper()
	b, err := os.ReadFile(s.db)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), config.DatabaseFile)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// damage runs statements on a copy, its triggers dropped first (the audit
// log's append-only ones would refuse a damage), foreign keys off.
func damage(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.Query("SELECT name FROM sqlite_schema WHERE type = 'trigger'")
	if err != nil {
		t.Fatal(err)
	}
	var triggers []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		triggers = append(triggers, n)
	}
	rows.Close()
	for _, n := range triggers {
		if _, err := db.Exec(`DROP TRIGGER "` + n + `"`); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range stmts {
		res, err := db.Exec(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if n, _ := res.RowsAffected(); n == 0 && !strings.HasPrefix(q, "CREATE") && !strings.HasPrefix(q, "DROP") {
			t.Fatalf("%s: no row changed", q)
		}
	}
}

// run runs the checks on path against the seeded bundle.
func run(t *testing.T, s seeded, path string, runKey []byte) check.Report {
	t.Helper()
	db := openRO(t, path)
	defer db.Close()
	rep, err := check.Run(context.Background(), db, bytes.NewReader(s.bundle), check.Options{RootKEK: s.source.RootKEK, RunKey: runKey})
	if err != nil {
		t.Fatal(err)
	}
	noSecrets(t, s, rep)
	return rep
}

// noSecrets fails when the report, as JSON or as text, holds a secret: a
// plaintext, a key or a digest, as bytes, hex or base64.
func noSecrets(t *testing.T, s seeded, rep check.Report) {
	t.Helper()
	j, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	scan(t, s, "the report", append(j, rep.Text()...))
}

func scan(t *testing.T, s seeded, what string, out []byte) {
	t.Helper()
	for _, secret := range s.secrets {
		if len(secret) < 8 {
			continue
		}
		for _, form := range [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(secret)),
			[]byte(base64.RawURLEncoding.EncodeToString(secret)), []byte(base64.RawStdEncoding.EncodeToString(secret))} {
			if bytes.Contains(out, form) {
				t.Fatalf("%s holds a secret", what)
			}
		}
	}
}

// failed is the report's faults by check.
func failed(rep check.Report) map[string][]check.Failure {
	out := map[string][]check.Failure{}
	for _, c := range rep.Checks {
		if !c.Passed {
			out[c.Name] = c.Failures
		}
	}
	return out
}

// A seeded installation imports, and every check passes: each reads
// something, every class is held, and the report holds no secret.
func TestASeededImportPasses(t *testing.T) {
	s := setUp(t)
	rep := run(t, s, s.db, s.runKey)
	if !rep.Passed {
		t.Fatalf("the checks failed:\n%s", rep.Text())
	}
	t.Logf("\n%s", rep.Text())
	for _, n := range check.Names {
		if r := rep.Result(n); !r.Passed || r.Checked == 0 {
			t.Errorf("%s: %+v", n, r)
		}
	}
	classes := map[string]bool{}
	for _, it := range migrationtest.Items(t, s.source) {
		classes[it.Class] = true
	}
	for _, c := range check.ClassNames {
		if !classes[c] {
			t.Errorf("the seed holds no %s item", c)
		}
	}
	var allowed, denied int
	r, _ := bundleDecisions(t, s.bundle)
	for _, d := range r {
		if d.Allowed {
			allowed++
		} else {
			denied++
		}
	}
	if allowed == 0 || denied == 0 {
		t.Errorf("the decision table: %d allowed, %d denied", allowed, denied)
	}
	t.Logf("%d decisions: %d allowed, %d denied", len(r), allowed, denied)
}

func bundleDecisions(t *testing.T, b []byte) ([]bundle.Decision, int) {
	t.Helper()
	m := loadManifest(t)
	r, err := bundle.NewReader(bytes.NewReader(b), m)
	if err != nil {
		t.Fatal(err)
	}
	for range bundle.Tables(m) {
		_, n, err := r.NextTable()
		if err != nil {
			t.Fatal(err)
		}
		for range n {
			if _, err := r.Row(); err != nil {
				t.Fatal(err)
			}
		}
	}
	n, err := r.Digests()
	if err != nil {
		t.Fatal(err)
	}
	for range n {
		if _, err := r.Digest(); err != nil {
			t.Fatal(err)
		}
	}
	k, _, err := r.Decisions()
	if err != nil {
		t.Fatal(err)
	}
	var out []bundle.Decision
	for range k {
		d, err := r.Decision()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out, n
}

// flip changes one ciphertext byte of the envelope in column of the
// table's row where: the envelope stays well formed, its ciphertext not.
func flip(t *testing.T, path, table, column, where string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	var rowid int64
	if err := db.QueryRow(`SELECT rowid, "`+column+`" FROM "`+table+`" WHERE `+where+` ORDER BY rowid LIMIT 1`).Scan(&rowid, &raw); err != nil {
		db.Close()
		t.Fatalf("%s.%s: %v", table, column, err)
	}
	db.Close()
	var e map[string]any
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}
	ct, err := base64.StdEncoding.DecodeString(e["ciphertext"].(string))
	if err != nil || len(ct) == 0 {
		t.Fatalf("%s.%s: the ciphertext: %v", table, column, err)
	}
	ct[0] ^= 1
	e["ciphertext"] = base64.StdEncoding.EncodeToString(ct)
	b, _ := json.Marshal(e)
	damage(t, path, fmt.Sprintf(`UPDATE "%s" SET "%s" = '%s' WHERE rowid = %d`, table, column, strings.ReplaceAll(string(b), "'", "''"), rowid))
}

// One changed ciphertext byte per encryption class fails the class check,
// naming the class.
func TestAChangedCiphertextByteFailsItsClass(t *testing.T) {
	s := setUp(t)
	for _, c := range []struct{ class, table, column, where string }{
		{envelope.PurposeKEKCanary, "installation", "kek_canary", "1"},
		{envelope.PurposeOrgKEK, "organizations", "wrapped_org_kek", "wrapped_org_kek IS NOT NULL AND org_kek_destroyed_at IS NULL"},
		{envelope.PurposeDEK, "value_versions", "wrapped_dek", "erased_at IS NULL"},
		{envelope.PurposeValue, "value_versions", "payload", "erased_at IS NULL"},
		{envelope.PurposeWebhookSecret, "webhooks", "secret_envelope", "secret_envelope IS NOT NULL AND organization_id IN (SELECT id FROM organizations WHERE org_kek_destroyed_at IS NULL)"},
		{envelope.PurposePlatformCredential, "platform_connections", "credential_envelope", "credential_envelope IS NOT NULL AND organization_id IN (SELECT id FROM organizations WHERE org_kek_destroyed_at IS NULL)"},
		{envelope.PurposeGitHubAppKey, "github_apps", "key_envelope", "key_envelope IS NOT NULL"},
		{envelope.PurposeAuditExportCredential, "audit_exports", "credential_envelope", "state <> 'draining'"},
		{envelope.PurposeAuditExportDrain, "audit_exports", "credential_envelope", "state = 'draining'"},
		{envelope.PurposeJWTSigningKey, "signing_keys", "private_key_wrapped", "1"},
	} {
		t.Run(c.class, func(t *testing.T) {
			t.Parallel()
			path := copyDB(t, s)
			flip(t, path, c.table, c.column, c.where)
			rep := run(t, s, path, s.runKey)
			named := false
			for _, f := range failed(rep)[check.Classes] {
				named = named || f.Class == c.class
			}
			if !named {
				t.Fatalf("the class check does not name %s:\n%s", c.class, rep.Text())
			}
		})
	}
}

// Each damage fails at its own check, naming its table.
func TestEachDamageFailsAtItsCheck(t *testing.T) {
	s := setUp(t)
	// A machine identity's Grant: its credentials' answers rest on it.
	// One whose credential the decision table asks about.
	var grant string
	{
		asked := map[string]bool{}
		decisions, _ := bundleDecisions(t, s.bundle)
		for _, d := range decisions {
			asked[d.Credential] = true
		}
		db := openRO(t, s.db)
		rows, err := db.Query(`SELECT g.id, c.id FROM grants g JOIN identities i ON i.id = g.subject_identity_id
			JOIN credentials c ON c.identity_id = i.id AND c.revoked_at IS NULL
			WHERE g.revoked_at IS NULL AND i.kind <> 'human' ORDER BY g.id, c.id`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() && grant == "" {
			var g, c string
			if err := rows.Scan(&g, &c); err != nil {
				t.Fatal(err)
			}
			if asked[c] {
				grant = g
			}
		}
		rows.Close()
		db.Close()
		if grant == "" {
			t.Fatal("no machine identity's Grant the decision table asks about")
		}
	}
	// What the report says, where it says more than the table.
	says := map[string]string{
		"a requirements row out of physical order": "requirements: the target holds the source's rows out of the source's physical order, from row 1",
		"a changed grant":                          "denies (PERMISSION_DENIED)",
		"a reordered audit position":               "position 2 holds",
		"a moved cursor":                           "the cursor moved (cursor_order)",
		"a missing row":                            "member_integrations: the source's row 1 is missing",
		"an extra row":                             "idempotency_keys: a row the source does not have",
	}
	for _, c := range []struct {
		name, check, table string
		stmts              []string
	}{
		{"a missing row", check.Rows, "member_integrations",
			[]string{"DELETE FROM member_integrations WHERE rowid = (SELECT min(rowid) FROM member_integrations)"}},
		{"an extra row", check.Rows, "idempotency_keys", []string{
			"CREATE TEMP TABLE extra AS SELECT * FROM idempotency_keys WHERE rowid = (SELECT min(rowid) FROM idempotency_keys)",
			"UPDATE extra SET idempotency_key = idempotency_key || '-extra'",
			"INSERT INTO idempotency_keys SELECT * FROM extra"}},
		{"a reordered audit position", check.Audit, "audit_events", []string{
			"UPDATE audit_events SET event_order = -1 WHERE event_order = 2",
			"UPDATE audit_events SET event_order = 2 WHERE event_order = 3",
			"UPDATE audit_events SET event_order = 3 WHERE event_order = -1"}},
		{"a moved cursor", check.Audit, "webhooks",
			[]string{"UPDATE webhooks SET cursor_order = cursor_order + 1 WHERE id = (SELECT min(id) FROM webhooks)"}},
		{"a changed grant", check.Authorization, "",
			[]string{"UPDATE grants SET revoked_at = 1795000000000000 WHERE id = '" + grant + "'"}},
		{"a changed passkey counter", check.Authentication, "passkey",
			[]string{"UPDATE passkeys SET counter = counter + 1 WHERE id = (SELECT min(id) FROM passkeys)"}},
		{"a changed passkey flag", check.Authentication, "passkey",
			[]string{"UPDATE passkeys SET backed_up = 1 - backed_up WHERE id = (SELECT min(id) FROM passkeys)"}},
		{"a changed credential expiry", check.Authentication, "credentials",
			[]string{"UPDATE credentials SET expires_at = expires_at + 1000000 WHERE rowid = (SELECT min(rowid) FROM credentials WHERE expires_at IS NOT NULL)"}},
		{"a requirements row out of physical order", check.Rows, "requirements", []string{
			"CREATE TEMP TABLE moved AS SELECT * FROM requirements WHERE rowid = (SELECT min(rowid) FROM requirements)",
			"DELETE FROM requirements WHERE id = (SELECT id FROM moved)",
			"INSERT INTO requirements SELECT * FROM moved"}},
		{"a session kept", check.Authentication, "session", []string{
			"INSERT INTO auth_sessions (id, expires_at, token_hash, created_at, updated_at, user_id) VALUES ('ses_kept', 1895000000000000, 'kept', 1795000000000000, 1795000000000000, 'usr_migration')"}},
		{"a table the manifest does not account for", check.Rows, "unaccounted",
			[]string{"CREATE TABLE unaccounted (x INTEGER)"}},
		{"a browser credential of an ended session left live", check.Authentication, "credentials",
			[]string{"UPDATE credentials SET revoked_at = NULL WHERE id = 'crd_migration_browser'"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			path := copyDB(t, s)
			damage(t, path, c.stmts...)
			rep := run(t, s, path, s.runKey)
			got := failed(rep)
			fs, ok := got[c.check]
			if !ok {
				t.Fatalf("the %s check passed:\n%s", c.check, rep.Text())
			}
			named := c.table == ""
			for _, f := range fs {
				named = named || f.Table == c.table
			}
			if why := says[c.name]; !strings.Contains(rep.Text(), why) {
				t.Fatalf("the report does not say %q:\n%s", why, rep.Text())
			}
			if !named {
				t.Fatalf("the %s check does not name %s:\n%s", c.check, c.table, rep.Text())
			}
			t.Logf("\n%s", rep.Text())
		})
	}
}

// The wrong run key: every digest differs, and the class check says so
// without a digest or the key in the report.
func TestAnotherRunKey(t *testing.T) {
	s := setUp(t)
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	rep := run(t, s, s.db, other)
	if _, ok := failed(rep)[check.Classes]; !ok || len(failed(rep)) != 1 {
		t.Fatalf("another run key:\n%s", rep.Text())
	}
	scan(t, seeded{secrets: [][]byte{other}}, "the report", []byte(rep.Text()))
}

// An audit export that ended holds no credential: no item of either
// audit-export class, and nothing for the class check to fault. The same
// export in the source and the target (a seed export ended in both).
func TestAnEndedAuditExportHoldsNoItem(t *testing.T) {
	s := setUp(t)
	src := s.source
	src.Rows = map[string][]jsvalue.Object{}
	for k, v := range s.source.Rows {
		src.Rows[k] = v
	}
	var ended []jsvalue.Object
	for _, r := range s.source.Rows["audit_exports"] {
		r = slices.Clone(r)
		if st, _ := r.Get("state"); st == "active" && len(ended) == 0 {
			r = r.Set("state", "completed").Set("credential_envelope", nil).Set("drain_deadline", "2026-11-17T08:05:00.000Z")
		}
		ended = append(ended, r)
	}
	src.Rows["audit_exports"] = ended
	b := migrationtest.Bundle(t, src, migrationtest.Options{Sections: &migrationtest.Sections{Digests: migrationtest.Digests(t, src, s.runKey)}})
	dir := t.TempDir()
	if _, err := migrate.Import(context.Background(), bytes.NewReader(b), migrate.Options{DataDir: dir, RootKEK: src.RootKEK, Release: "0.50.0-test"}); err != nil {
		t.Fatal(err)
	}
	db := openRO(t, filepath.Join(dir, config.DatabaseFile))
	defer db.Close()
	rep, err := check.Run(context.Background(), db, bytes.NewReader(b), check.Options{RootKEK: src.RootKEK, RunKey: s.runKey})
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Result(check.Classes); !r.Passed {
		t.Fatalf("an ended audit export:\n%s", rep.Text())
	}
}

// A bundle without its decision table fails the authorization check: a
// table that holds nothing is no pass.
func TestNoDecisionTable(t *testing.T) {
	s := setUp(t)
	empty := migrationtest.Bundle(t, s.source, migrationtest.Options{Sections: &migrationtest.Sections{Digests: migrationtest.Digests(t, s.source, s.runKey)}})
	db := openRO(t, s.db)
	defer db.Close()
	rep, err := check.Run(context.Background(), db, bytes.NewReader(empty), check.Options{RootKEK: s.source.RootKEK, RunKey: s.runKey})
	if err != nil {
		t.Fatal(err)
	}
	if f := failed(rep); len(f) != 1 || len(f[check.Authorization]) != 1 || !strings.Contains(f[check.Authorization][0].What, "no decision table") {
		t.Fatalf("no decision table:\n%s", rep.Text())
	}
}

// A bundle whose rows are not in the manifest's order is named so: the
// rows check matches rows by key, in that order.
func TestABundleOutOfOrder(t *testing.T) {
	s := setUp(t)
	lines := bytes.SplitAfter(s.bundle, []byte("\n"))
	swapped := false
	for i, l := range lines {
		if bytes.HasPrefix(l, []byte(`{"table":"grants","rows":`)) {
			lines[i+1], lines[i+2] = lines[i+2], lines[i+1]
			swapped = true
			break
		}
	}
	if !swapped {
		t.Fatal("no grants in the bundle")
	}
	b := migrationtest.Reseal(t, bytes.Join(lines, nil))
	db := openRO(t, s.db)
	defer db.Close()
	rep, err := check.Run(context.Background(), db, bytes.NewReader(b), check.Options{RootKEK: s.source.RootKEK, RunKey: s.runKey})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.Text(), "grants: the bundle's row 2 is out of the manifest's order") {
		t.Fatalf("a bundle out of order:\n%s", rep.Text())
	}
}

// What a run refuses: a run key that is not 32 bytes, a damaged bundle, a
// reverse bundle.
func TestRunRefusals(t *testing.T) {
	s := setUp(t)
	db := openRO(t, s.db)
	defer db.Close()
	runWith := func(b []byte, key []byte) error {
		_, err := check.Run(context.Background(), db, bytes.NewReader(b), check.Options{RootKEK: s.source.RootKEK, RunKey: key})
		return err
	}
	if err := runWith(s.bundle, s.runKey[:16]); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("a short run key: %v", err)
	}
	d := slices.Clone(s.bundle)
	d[len(d)/2] ^= 1
	if err := runWith(d, s.runKey); err == nil {
		t.Error("a damaged bundle")
	}
	var rev bytes.Buffer
	dir := t.TempDir()
	if _, err := migrate.Import(context.Background(), bytes.NewReader(s.bundle), migrate.Options{DataDir: dir, RootKEK: s.source.RootKEK, Release: "0.50.0-test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.ExportReverse(context.Background(), &rev, migrate.Options{DataDir: dir, Release: "0.50.0-test"}); err != nil {
		t.Fatal(err)
	}
	if err := runWith(rev.Bytes(), s.runKey); err == nil || !strings.Contains(err.Error(), "reverse bundle") {
		t.Errorf("a reverse bundle: %v", err)
	}
}

func loadManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
	}
	return m
}
