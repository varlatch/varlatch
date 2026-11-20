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
