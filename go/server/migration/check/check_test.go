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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/totp"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/check"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
	"github.com/varlatch/varlatch/go/server/migration/migrate"
	"github.com/varlatch/varlatch/go/server/migration/migrationtest"
	"github.com/varlatch/varlatch/go/server/oauth/oauthparams"
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

// tuples is the decision table's questions (migrationtest.Tuples), every
// fourth pair under the race detector, so that run stays within its time.
func tuples(t *testing.T, db *sql.DB) []bundle.Decision {
	t.Helper()
	every := 1
	if raceDetector {
		every = 4
	}
	return migrationtest.Tuples(t, db, every)
}

func copyDB(t *testing.T, s seeded) string { return migrationtest.CopyDB(t, s.db) }

func damage(t *testing.T, path string, stmts ...string) { migrationtest.Damage(t, path, stmts...) }

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

// One changed ciphertext byte per encryption class fails the class check,
// naming the class; each other damage of G5's list fails at its own check,
// naming its table (migrationtest's catalog, which the G5 gate holds the
// varlatchd binary to as well).
func TestEachDamageFailsAtItsCheck(t *testing.T) {
	s := setUp(t)
	db := openRO(t, s.db)
	decisions, _ := bundleDecisions(t, s.bundle)
	grant := migrationtest.AskedGrant(t, db, decisions)
	db.Close()
	for _, f := range append(migrationtest.ClassFaults(), migrationtest.TargetFaults(grant)...) {
		t.Run(f.Name, func(t *testing.T) {
			t.Parallel()
			path := copyDB(t, s)
			f.Apply(t, path)
			rep := run(t, s, path, s.runKey)
			fs, ok := failed(rep)[f.Check]
			if !ok {
				t.Fatalf("the %s check passed:\n%s", f.Check, rep.Text())
			}
			named := f.Table == "" && f.Class == ""
			for _, x := range fs {
				named = named || (f.Table != "" && x.Table == f.Table) || (f.Class != "" && x.Class == f.Class)
			}
			if !named || !strings.Contains(rep.Text(), f.Says) {
				t.Fatalf("the %s check does not name %s%s or say %q:\n%s", f.Check, f.Table, f.Class, f.Says, rep.Text())
			}
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

// check.Evaluate held to answers written by hand, not drawn from itself:
// a person who is an Organization's admin may manage it; a revoked credential is
// refused before authorization; a machine identity outside its own
// Organization finds nothing; and the tailnet fixture's Requirement
// refuses a reveal without a Tailnet Context, whatever the Grant allows.
func TestEvaluateAgainstWrittenAnswers(t *testing.T) {
	s := setUp(t)
	db := openRO(t, s.db)
	defer db.Close()
	one := func(q string, args ...any) []string {
		t.Helper()
		var a, b string
		if err := db.QueryRow(q, args...).Scan(&a, &b); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return []string{a, b}
	}
	admin := one(`SELECT c.id, m.organization_id FROM credentials c JOIN identities i ON i.id = c.identity_id
		JOIN org_memberships m ON m.identity_id = i.id AND m.role = 'admin' AND m.removed_at IS NULL
		WHERE i.kind = 'human' AND c.revoked_at IS NULL ORDER BY c.id LIMIT 1`)
	machine := one(`SELECT c.id, i.organization_id FROM credentials c JOIN identities i ON i.id = c.identity_id
		WHERE i.kind <> 'human' AND i.organization_id IS NOT NULL AND c.revoked_at IS NULL ORDER BY c.id LIMIT 1`)
	other := one(`SELECT id, slug FROM organizations WHERE id <> ? ORDER BY id LIMIT 1`, machine[1])
	// The requirements fixture: the service credential's Grant allows
	// secret.use on this development environment, and the active
	// Requirement req_dcuzcxot4dkbxvsqtgecn6tfiq targets it: without a
	// Tailnet Context, TAILNET_CONTEXT_REQUIRED.
	reveal := one(`SELECT c.id, e.id FROM credentials c, environments e
		WHERE c.id = 'crd_ovjf3vcoae6nkrsmbcywzmqnva' AND e.id = 'env_5tzcue6ry5edzdhgrqlxparw3a'`)
	envOrg := one(`SELECT p.organization_id, p.id FROM environments e JOIN projects p ON p.id = e.project_id WHERE e.id = ?`, reveal[1])
	for _, c := range []struct {
		name    string
		d       bundle.Decision
		allowed bool
		code    string
	}{
		{"an admin manages its Organization", bundle.Decision{Credential: admin[0], State: bundle.Active, Organization: admin[1], Action: "organization.manage"}, true, ""},
		{"a revoked credential", bundle.Decision{Credential: admin[0], State: bundle.Revoked, Organization: admin[1], Action: "organization.read"}, false, "UNAUTHENTICATED"},
		{"an expired credential", bundle.Decision{Credential: admin[0], State: bundle.Expired, Organization: admin[1], Action: "organization.read"}, false, "UNAUTHENTICATED"},
		{"a machine identity in another Organization", bundle.Decision{Credential: machine[0], State: bundle.Active, Organization: other[0], Action: "organization.read"}, false, "RESOURCE_NOT_FOUND"},
		{"a reveal without the Tailnet Context a Requirement asks", bundle.Decision{Credential: reveal[0], State: bundle.Active, Organization: envOrg[0],
			Project: envOrg[1], Environment: reveal[1], Action: "secret.use"}, false, "TAILNET_CONTEXT_REQUIRED"},
	} {
		got, err := check.Evaluate(context.Background(), db, c.d)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got.Allowed != c.allowed || got.Code != c.code {
			t.Errorf("%s: allowed %v (%s), want %v (%s)", c.name, got.Allowed, got.Code, c.allowed, c.code)
		}
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

// What ADR-0060 limits (an exercise-only credential and its binding, a
// single-use Capability, a token exchanged once, a capability.issue Grant)
// is in the copied tables in a form the TypeScript server's columns hold:
// the reverse checks pass, the reverse bundle carries each row as it is
// (where it matches no token and no secret), and varlatchd's own two tables
// stay behind.
func TestTheReverseChecksWithLimits(t *testing.T) {
	s := setUp(t)
	path := copyDB(t, s)
	const broker = "(SELECT id FROM identities WHERE kind = 'broker' ORDER BY id LIMIT 1)"
	const org = "(SELECT organization_id FROM identities WHERE kind = 'broker' ORDER BY id LIMIT 1)"
	for _, q := range []string{
		`INSERT INTO oidc_bindings (id, identity_id, organization_id, issuer, audience, subject, claims, created_at)
		 VALUES ('oib_limited', ` + broker + `, ` + org + `, 'https://issuer.example', 'varlatch', 'machine:*',
		 '{"varlatch:limits": "{\"v\":1,\"exerciseOnly\":true,\"singleExchange\":true}"}', 1000)`,
		`INSERT INTO credentials (id, identity_id, kind, token_hash, created_at, expires_at)
		 VALUES ('crd_limited', ` + broker + `, 'oidc', 'exercise:' || printf('%064d', 7), 1000, 2000)`,
		`INSERT INTO exercise_credentials (credential_id, oidc_binding_id, run_id) VALUES ('crd_limited', 'oib_limited', 'run-left-behind')`,
		`INSERT INTO oidc_token_uses (token_key, used_at, expires_at) VALUES (printf('%064d', 1), 1, 2)`,
		`INSERT INTO grants (id, organization_id, subject_identity_id, scope, actions, created_at)
		 VALUES ('grt_issue', ` + org + `, ` + broker + `, '{"kind": "organization"}', '["capability.issue"]', 1000)`,
		`UPDATE capabilities SET secret_hash = 'for:once:' || secret_hash, created_by = (SELECT id FROM identities WHERE kind = 'service' ORDER BY id LIMIT 1)
		 WHERE id = (SELECT min(id) FROM capabilities)`,
		`UPDATE capabilities SET secret_hash = 'used:' || secret_hash WHERE id = (SELECT max(id) FROM capabilities)`,
	} {
		damage(t, path, q)
	}
	keep := filepath.Join(t.TempDir(), "keep")
	var rev bytes.Buffer
	if _, err := migrate.ExportReverse(context.Background(), &rev, migrate.Options{DataDir: filepath.Dir(path), Keep: keep, Release: "0.50.0-check"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"oib_limited", "varlatch:limits", "crd_limited", "exercise:", "grt_issue", "for:once:", "used:"} {
		if !bytes.Contains(rev.Bytes(), []byte(want)) {
			t.Errorf("the reverse bundle has no %s", want)
		}
	}
	if bytes.Contains(rev.Bytes(), []byte("run-left-behind")) || bytes.Contains(rev.Bytes(), []byte("oidc_token_uses")) {
		t.Error("the reverse bundle carries varlatchd's own tables")
	}
	rebuilt := migrationtest.FromReverse(t, rev.Bytes(), s.source.RootKEK)
	db := openRO(t, filepath.Join(keep, config.DatabaseFile))
	defer db.Close()
	decisions := []bundle.Decision{}
	for _, d := range tuples(t, db) {
		got, err := check.Evaluate(context.Background(), db, d)
		if err != nil {
			t.Fatal(err)
		}
		decisions = append(decisions, got)
	}
	b := migrationtest.Bundle(t, rebuilt, migrationtest.Options{Sections: &migrationtest.Sections{Digests: migrationtest.Digests(t, rebuilt, s.runKey), Decisions: decisions, At: 1}})
	rep, err := check.Run(context.Background(), db, bytes.NewReader(b), check.Options{RootKEK: s.source.RootKEK, RunKey: s.runKey, Reverse: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Passed {
		t.Fatalf("the reverse checks:\n%s", rep.Text())
	}
}

// sealSeed stores a seed of one-time codes, sealed as varlatchd seals one,
// in place of a value, and a step given for it.
func sealSeed(t *testing.T, s seeded, path string) {
	t.Helper()
	db := openRO(t, path)
	defer db.Close()
	var org, value, version, wrapped string
	if err := db.QueryRow(`SELECT o.id, v.id, v.current_version_id, o.wrapped_org_kek FROM env_values v JOIN value_versions x ON x.id = v.current_version_id
		JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id JOIN organizations o ON o.id = p.organization_id
		WHERE x.erased_at IS NULL AND o.wrapped_org_kek IS NOT NULL AND o.org_kek_destroyed_at IS NULL ORDER BY v.id LIMIT 1`).Scan(&org, &value, &version, &wrapped); err != nil {
		t.Fatal(err)
	}
	var w envelope.Envelope
	if err := json.Unmarshal([]byte(wrapped), &w); err != nil {
		t.Fatal(err)
	}
	kek, err := envelope.UnwrapOrgKEK(s.source.RootKEK, w, org)
	if err != nil {
		t.Fatal(err)
	}
	const params = `{"issuer":"Portal","account":"alice@example.com","algorithm":"SHA1","digits":6,"period":30}`
	sealed, err := envelope.EncryptSeed(kek, org, value, version, params, []byte("otpauth://totp/Portal:alice@example.com?secret=JBSWJBSWJBSWJBSX&issuer=Portal&algorithm=SHA1&digits=6&period=30"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(sealed.Payload)
	dek, _ := json.Marshal(sealed.WrappedDEK)
	damage(t, path,
		"UPDATE value_versions SET payload = json_set('"+string(payload)+"', '$.totp', json('"+params+"')), wrapped_dek = '"+string(dek)+"' WHERE id = '"+version+"'",
		"INSERT INTO one_time_codes_given (version_id, step) VALUES ('"+version+"', 58817400)",
		"UPDATE env_values SET deleted_at = 1795000000000000 WHERE id = '"+value+"'")
}

// A seed of one-time codes (ADR-0061) is in the copied tables in a form the
// TypeScript server's columns hold: the reverse checks pass, every version
// opening on both sides (that export refuses as a whole when one does not),
// the reverse bundle carries the row with deleted_at and current_version_id
// both set, which that server reads as deleted, and the version's own mark;
// the steps given stay behind. A forward import brings the seed back as it
// was.
func TestTheReverseChecksWithSeeds(t *testing.T) {
	s := setUp(t)
	path := copyDB(t, s)
	sealSeed(t, s, path)
	seeds := func(db *sql.DB) (n int, ids string) {
		t.Helper()
		if err := db.QueryRow(`SELECT count(*), coalesce(group_concat(v.id || v.current_version_id || json_extract(x.payload, '$.totp.issuer')), '')
			FROM env_values v JOIN value_versions x ON x.id = v.current_version_id WHERE v.deleted_at IS NOT NULL AND json_type(x.payload, '$.totp') = 'object'`).Scan(&n, &ids); err != nil {
			t.Fatal(err)
		}
		return n, ids
	}
	db := openRO(t, path)
	n, before := seeds(db)
	db.Close()
	if n != 1 {
		t.Fatalf("%d seeds", n)
	}
	keep := filepath.Join(t.TempDir(), "keep")
	var rev bytes.Buffer
	if _, err := migrate.ExportReverse(context.Background(), &rev, migrate.Options{DataDir: filepath.Dir(path), Keep: keep, Release: "0.50.0-check"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rev.Bytes(), []byte("alice@example.com")) || bytes.Contains(rev.Bytes(), []byte("one_time_codes_given")) {
		t.Error("the reverse bundle has no seed, or varlatchd's own table")
	}
	rebuilt := migrationtest.FromReverse(t, rev.Bytes(), s.source.RootKEK)
	db = openRO(t, filepath.Join(keep, config.DatabaseFile))
	defer db.Close()
	decisions := []bundle.Decision{}
	for _, d := range tuples(t, db) {
		got, err := check.Evaluate(context.Background(), db, d)
		if err != nil {
			t.Fatal(err)
		}
		decisions = append(decisions, got)
	}
	b := migrationtest.Bundle(t, rebuilt, migrationtest.Options{Sections: &migrationtest.Sections{Digests: migrationtest.Digests(t, rebuilt, s.runKey), Decisions: decisions, At: 1}})
	rep, err := check.Run(context.Background(), db, bytes.NewReader(b), check.Options{RootKEK: s.source.RootKEK, RunKey: s.runKey, Reverse: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Passed {
		t.Fatalf("the reverse checks:\n%s", rep.Text())
	}
	// Forward again.
	dir := t.TempDir()
	if _, err := migrate.Import(context.Background(), bytes.NewReader(b), migrate.Options{DataDir: dir, RootKEK: s.source.RootKEK, Release: "0.50.0-check"}); err != nil {
		t.Fatal(err)
	}
	again := openRO(t, filepath.Join(dir, config.DatabaseFile))
	defer again.Close()
	if n, after := seeds(again); n != 1 || after != before {
		t.Errorf("after a forward import: %d seeds, %s, want %s", n, after, before)
	}
	var org, value, version, payload, dek, wrapped string
	if err := again.QueryRow(`SELECT p.organization_id, v.id, x.id, x.payload, x.wrapped_dek, o.wrapped_org_kek FROM env_values v JOIN value_versions x ON x.id = v.current_version_id
		JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id JOIN organizations o ON o.id = p.organization_id
		WHERE json_type(x.payload, '$.totp') = 'object'`).Scan(&org, &value, &version, &payload, &dek, &wrapped); err != nil {
		t.Fatal(err)
	}
	// jsonb kept no member order: the readable part is written again as
	// varlatchd writes it, and the seed still opens with it.
	var kekEnvelope envelope.Envelope
	var v envelope.EncryptedValue
	var mark struct{ TOTP totp.Params }
	for text, to := range map[string]any{wrapped: &kekEnvelope, dek: &v.WrappedDEK} {
		if err := json.Unmarshal([]byte(text), to); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(json.Unmarshal([]byte(payload), &v.Payload), json.Unmarshal([]byte(payload), &mark)); err != nil {
		t.Fatal(err)
	}
	kek, err := envelope.UnwrapOrgKEK(s.source.RootKEK, kekEnvelope, org)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(mark.TOTP)
	if got, err := envelope.DecryptSeed(kek, org, value, version, string(params), v); err != nil || !strings.HasPrefix(string(got), "otpauth://totp/Portal:") {
		t.Errorf("the seed after a forward import: %v (%s)", err, payload)
	}
}

// sealConnection stores an OAuth connection, its client secret sealed as
// varlatchd seals one, in place of a value, with tokens.
func sealConnection(t *testing.T, s seeded, path string) oauthparams.Params {
	t.Helper()
	db := openRO(t, path)
	defer db.Close()
	var org, value, version, wrapped string
	if err := db.QueryRow(`SELECT o.id, v.id, v.current_version_id, o.wrapped_org_kek FROM env_values v JOIN value_versions x ON x.id = v.current_version_id
		JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id JOIN organizations o ON o.id = p.organization_id
		WHERE x.erased_at IS NULL AND o.wrapped_org_kek IS NOT NULL AND o.org_kek_destroyed_at IS NULL ORDER BY v.id LIMIT 1`).Scan(&org, &value, &version, &wrapped); err != nil {
		t.Fatal(err)
	}
	var w envelope.Envelope
	if err := json.Unmarshal([]byte(wrapped), &w); err != nil {
		t.Fatal(err)
	}
	kek, err := envelope.UnwrapOrgKEK(s.source.RootKEK, w, org)
	if err != nil {
		t.Fatal(err)
	}
	p := oauthparams.Params{V: oauthparams.Version, Provider: "generic", Issuer: "https://idp.example", AuthorizationEndpoint: "https://idp.example/authorize",
		TokenEndpoint: "https://idp.example/token", AuthMethod: oauthparams.AuthBasic, Grant: oauthparams.AuthorizationCode, ClientID: "client-of-alice",
		Scopes: []string{"openid", "a"}, AuthorizationParams: []oauthparams.Param{{Name: "prompt", Value: "consent"}}, Hosts: []string{"api.example.com:443"}, IdleDays: 90}
	if err := p.Check(); err != nil {
		t.Fatal(err)
	}
	params, _ := p.Text()
	sealed, err := envelope.EncryptOAuthClient(kek, org, value, version, params, []byte("made-up client secret"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(sealed.Payload)
	dek, _ := json.Marshal(sealed.WrappedDEK)
	damage(t, path,
		"UPDATE value_versions SET payload = json_set('"+string(payload)+"', '$.oauth', json('"+params+"')), wrapped_dek = '"+string(dek)+"' WHERE id = '"+version+"'",
		"INSERT INTO oauth_connections (value_id, version_id, status, access_token, refresh_token, account, account_label) VALUES ('"+value+"', '"+version+"', 'connected', '{}', '{}', 'sub-1', 'tokens-of-alice')",
		"INSERT INTO oauth_authorizations SELECT '"+strings.Repeat("0f", 32)+"', '"+org+"', '"+value+"', '"+version+"', id, 'ses', 'n', '{}', 'https://x.example/oauth/callback/idp.example', 0, 1, 2 FROM identities LIMIT 1",
		"UPDATE env_values SET deleted_at = 1795000000000000 WHERE id = '"+value+"'")
	return p
}

// An OAuth connection (ADR-0062) goes back and forth as a seed does: the
// reverse checks pass, the bundle carries what it is in a row the TypeScript
// server reads as deleted, and none of its tokens; a forward import brings it
// back, its client secret opening with its parameters, and not connected.
func TestTheReverseChecksWithConnections(t *testing.T) {
	s := setUp(t)
	path := copyDB(t, s)
	want := sealConnection(t, s, path)
	keep := filepath.Join(t.TempDir(), "keep")
	var rev bytes.Buffer
	if _, err := migrate.ExportReverse(context.Background(), &rev, migrate.Options{DataDir: filepath.Dir(path), Keep: keep, Release: "0.50.0-check"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rev.Bytes(), []byte("client-of-alice")) {
		t.Error("the reverse bundle has no connection")
	}
	for _, kept := range []string{"oauth_connections", "oauth_authorizations", "tokens-of-alice"} {
		if bytes.Contains(rev.Bytes(), []byte(kept)) {
			t.Errorf("the reverse bundle has %s", kept)
		}
	}
	rebuilt := migrationtest.FromReverse(t, rev.Bytes(), s.source.RootKEK)
	db := openRO(t, filepath.Join(keep, config.DatabaseFile))
	defer db.Close()
	decisions := []bundle.Decision{}
	for _, d := range tuples(t, db) {
		got, err := check.Evaluate(context.Background(), db, d)
		if err != nil {
			t.Fatal(err)
		}
		decisions = append(decisions, got)
	}
	b := migrationtest.Bundle(t, rebuilt, migrationtest.Options{Sections: &migrationtest.Sections{Digests: migrationtest.Digests(t, rebuilt, s.runKey), Decisions: decisions, At: 1}})
	rep, err := check.Run(context.Background(), db, bytes.NewReader(b), check.Options{RootKEK: s.source.RootKEK, RunKey: s.runKey, Reverse: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Passed {
		t.Fatalf("the reverse checks:\n%s", rep.Text())
	}
	dir := t.TempDir()
	if _, err := migrate.Import(context.Background(), bytes.NewReader(b), migrate.Options{DataDir: dir, RootKEK: s.source.RootKEK, Release: "0.50.0-check"}); err != nil {
		t.Fatal(err)
	}
	again := openRO(t, filepath.Join(dir, config.DatabaseFile))
	defer again.Close()
	var n int
	if err := again.QueryRow("SELECT (SELECT count(*) FROM oauth_connections) + (SELECT count(*) FROM oauth_authorizations)").Scan(&n); err != nil || n != 0 {
		t.Errorf("%d rows of tokens (%v)", n, err)
	}
	var org, value, version, payload, dek, wrapped, params string
	var deleted sql.NullInt64
	if err := again.QueryRow(`SELECT p.organization_id, v.id, x.id, x.payload, x.wrapped_dek, o.wrapped_org_kek, json_extract(x.payload, '$.oauth'), v.deleted_at
		FROM env_values v JOIN value_versions x ON x.id = v.current_version_id
		JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id JOIN organizations o ON o.id = p.organization_id
		WHERE json_type(x.payload, '$.oauth') = 'object'`).Scan(&org, &value, &version, &payload, &dek, &wrapped, &params, &deleted); err != nil {
		t.Fatal(err)
	}
	if !deleted.Valid {
		t.Error("the row is live")
	}
	// jsonb kept no member order: the parameters are written again in theirs.
	got, ok := oauthparams.Parse(params)
	if !ok {
		t.Fatalf("parameters: %s", params)
	}
	text, _ := got.Text()
	if wanted, _ := want.Text(); text != wanted {
		t.Errorf("parameters: %s, want %s", text, wanted)
	}
	var kekEnvelope envelope.Envelope
	var v envelope.EncryptedValue
	for text, to := range map[string]any{wrapped: &kekEnvelope, dek: &v.WrappedDEK, payload: &v.Payload} {
		if err := json.Unmarshal([]byte(text), to); err != nil {
			t.Fatal(err)
		}
	}
	kek, err := envelope.UnwrapOrgKEK(s.source.RootKEK, kekEnvelope, org)
	if err != nil {
		t.Fatal(err)
	}
	if secret, err := envelope.DecryptOAuthClient(kek, org, value, version, text, v); err != nil || string(secret) != "made-up client secret" {
		t.Errorf("the client secret after a forward import: %v", err)
	}
	// Opened as a value, as the TypeScript server would, it is an envelope.
	if plain, err := envelope.DecryptValue(kek, org, value, version, v); err != nil || bytes.Contains(plain, []byte("made-up")) || !bytes.Contains(plain, []byte("ciphertext")) {
		t.Errorf("opened as a value: %s, %v", plain, err)
	}
}

// Entry links (ADR-0063) stay behind: the reverse checks pass, the bundle
// carries none, and an import brings none back. A value entered through one,
// by nobody known, is a value version and goes both ways.
func TestTheReverseChecksWithEntryLinks(t *testing.T) {
	s := setUp(t)
	path := copyDB(t, s)
	db := openRO(t, path)
	var org, project, env, identity, value, version string
	if err := db.QueryRow(`SELECT p.organization_id, p.id, e.id, (SELECT id FROM identities LIMIT 1), v.id, v.current_version_id FROM env_values v
		JOIN value_versions x ON x.id = v.current_version_id JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id
		WHERE x.erased_at IS NULL AND v.deleted_at IS NULL ORDER BY v.id LIMIT 1`).Scan(&org, &project, &env, &identity, &value, &version); err != nil {
		t.Fatal(err)
	}
	db.Close()
	damage(t, path,
		"INSERT INTO entry_links (id, token_hash, organization_id, project_id, environment_id, item_name, accepts, replaces, restricted_to, description, requested_by, credential_id, created_at, expires_at) VALUES ('enl_kept', '"+
			strings.Repeat("0f", 32)+"', '"+org+"', '"+project+"', '"+env+"', 'A_KEY', 'value', 0, 'anyone', 'words of its maker', '"+identity+"', (SELECT min(id) FROM credentials), 1, 2)",
		"UPDATE value_versions SET created_by = NULL WHERE id = '"+version+"'",
		"INSERT INTO grants (id, organization_id, subject_identity_id, scope, actions, created_at) VALUES ('grt_entry', '"+org+"', '"+identity+
			"', '{\"kind\": \"organization\"}', '[\"entry-link.create\",\"entry-link.create-open\"]', 1000)")
	keep := filepath.Join(t.TempDir(), "keep")
	var rev bytes.Buffer
	if _, err := migrate.ExportReverse(context.Background(), &rev, migrate.Options{DataDir: filepath.Dir(path), Keep: keep, Release: "0.50.0-check"}); err != nil {
		t.Fatal(err)
	}
	for _, kept := range []string{"entry_links", "enl_kept", "words of its maker", strings.Repeat("0f", 32)} {
		if bytes.Contains(rev.Bytes(), []byte(kept)) {
			t.Errorf("the reverse bundle has %s", kept)
		}
	}
	rebuilt := migrationtest.FromReverse(t, rev.Bytes(), s.source.RootKEK)
	kept := openRO(t, filepath.Join(keep, config.DatabaseFile))
	defer kept.Close()
	decisions := []bundle.Decision{}
	for _, d := range tuples(t, kept) {
		got, err := check.Evaluate(context.Background(), kept, d)
		if err != nil {
			t.Fatal(err)
		}
		decisions = append(decisions, got)
	}
	b := migrationtest.Bundle(t, rebuilt, migrationtest.Options{Sections: &migrationtest.Sections{Digests: migrationtest.Digests(t, rebuilt, s.runKey), Decisions: decisions, At: 1}})
	rep, err := check.Run(context.Background(), kept, bytes.NewReader(b), check.Options{RootKEK: s.source.RootKEK, RunKey: s.runKey, Reverse: true})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Passed {
		t.Fatalf("the reverse checks:\n%s", rep.Text())
	}
	dir := t.TempDir()
	if _, err := migrate.Import(context.Background(), bytes.NewReader(b), migrate.Options{DataDir: dir, RootKEK: s.source.RootKEK, Release: "0.50.0-check"}); err != nil {
		t.Fatal(err)
	}
	again := openRO(t, filepath.Join(dir, config.DatabaseFile))
	defer again.Close()
	// The Grants do go there and back: no one asks for such an action there.
	var n, nobodys, grants int
	if err := again.QueryRow("SELECT (SELECT count(*) FROM entry_links), (SELECT count(*) FROM value_versions WHERE id = ? AND created_by IS NULL), (SELECT count(*) FROM grants WHERE id = 'grt_entry' AND actions LIKE '%entry-link.create-open%')",
		version).Scan(&n, &nobodys, &grants); err != nil || n != 0 || nobodys != 1 || grants != 1 {
		t.Errorf("%d links, %d versions by nobody known, %d grants (%v)", n, nobodys, grants, err)
	}
}

// The reverse checks: the transformed copy a reverse export kept, held
// against the stand-in TypeScript release's export of the database it
// rebuilt from the reverse bundle, pass with every check reading
// something; the same pair fails the forward checks (no
// installation.migrated after the frozen point); an event after the frozen
// point in the copy fails the reverse audit check, and a browser session in
// the rebuilt installation the reverse authentication check.
func TestTheReverseChecks(t *testing.T) {
	s := setUp(t)
	keep := filepath.Join(t.TempDir(), "keep")
	var rev bytes.Buffer
	if _, err := migrate.ExportReverse(context.Background(), &rev, migrate.Options{DataDir: filepath.Dir(copyDB(t, s)), Keep: keep, Release: "0.50.0-check"}); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(keep, config.DatabaseFile)
	rebuilt := migrationtest.FromReverse(t, rev.Bytes(), s.source.RootKEK)
	db := openRO(t, kept)
	decisions := []bundle.Decision{}
	for _, d := range tuples(t, db) {
		got, err := check.Evaluate(context.Background(), db, d)
		if err != nil {
			t.Fatal(err)
		}
		decisions = append(decisions, got)
	}
	db.Close()
	reexport := func(o migrationtest.Options) []byte {
		o.Sections = &migrationtest.Sections{Digests: migrationtest.Digests(t, rebuilt, s.runKey), Decisions: decisions, At: 1}
		return migrationtest.Bundle(t, rebuilt, o)
	}
	runOn := func(path string, b []byte, reverse bool) check.Report {
		t.Helper()
		db := openRO(t, path)
		defer db.Close()
		rep, err := check.Run(context.Background(), db, bytes.NewReader(b), check.Options{RootKEK: s.source.RootKEK, RunKey: s.runKey, Reverse: reverse})
		if err != nil {
			t.Fatal(err)
		}
		noSecrets(t, s, rep)
		return rep
	}
	b := reexport(migrationtest.Options{})
	rep := runOn(kept, b, true)
	if !rep.Passed || !rep.Reverse || !strings.HasPrefix(rep.Text(), "The reverse checks passed") {
		t.Fatalf("the reverse checks:\n%s", rep.Text())
	}
	for _, c := range rep.Checks {
		if c.Checked == 0 {
			t.Errorf("%s checked nothing", c.Name)
		}
	}
	if rep := runOn(kept, b, false); rep.Passed || failed(rep)[check.Audit] == nil {
		t.Errorf("the forward checks of the reverse's pair:\n%s", rep.Text())
	}
	// An event after the frozen point.
	extra := migrationtest.CopyDB(t, kept)
	damage(t, extra, `INSERT INTO audit_events (event_order, id, event_type, decision) SELECT max(event_order) + 1, 'evt_after_the_frozen_point', 'installation.migrated', 'info' FROM audit_events`)
	if rep := runOn(extra, b, true); rep.Passed || failed(rep)[check.Audit] == nil || !strings.Contains(rep.Text(), "after the frozen point") {
		t.Errorf("an event after the frozen point:\n%s", rep.Text())
	}
	// A browser session in the rebuilt installation.
	session := migrationtest.ManifestTable(t, "session")
	row := make([]any, len(session.Columns))
	for i, c := range session.Columns {
		switch c.Source {
		case "id":
			row[i] = "ses_rebuilt"
		case "userId":
			row[i] = "usr_migration"
		case "expiresAt", "createdAt", "updatedAt":
			row[i] = int64(1_800_000_000_000_000)
		}
	}
	if rep := runOn(kept, reexport(migrationtest.Options{Extra: map[string][][]any{"session": {row}}}), true); rep.Passed || failed(rep)[check.Authentication] == nil || !strings.Contains(rep.Text(), "starts with none") {
		t.Errorf("a session in the rebuilt installation:\n%s", rep.Text())
	}
}
