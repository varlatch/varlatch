// SPDX-License-Identifier: AGPL-3.0-or-later

package migrate

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/canonical"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
)

// The source: the TypeScript server's rows of the core parity fixture
// (written by services/varlatchd/test/go-core-fixture.test.ts from a
// seeded v0.22.0 installation), as its export reads PostgreSQL, plus what
// the fixture lacks to exercise the transformations: a person with a live
// browser session, a browser credential minted from it and a CLI hand-off
// credential from the same session, and the finished exposure backfill.

type source struct {
	rootKEK []byte
	rows    map[string][]jsvalue.Object
}

func loadSource(t *testing.T) source {
	t.Helper()
	get := func(o jsvalue.Object, k string) any {
		for _, m := range o {
			if m.Key == k {
				return m.Value
			}
		}
		return nil
	}
	fixture := func(name string) jsvalue.Object {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join("..", "..", "paritytest", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsvalue.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return doc.(jsvalue.Object)
	}
	core := fixture("core-v0.22.0.json")
	kek, err := hex.DecodeString(get(core, "rootKek").(string))
	if err != nil {
		t.Fatal(err)
	}
	s := source{rootKEK: kek, rows: map[string][]jsvalue.Object{}}
	// The v0.22.0 parity fixtures whose rows do not meet (several reuse
	// fixed ids, so not all of them), each written by the TypeScript server
	// from a seeded installation of its own. The installation (the canary
	// under core's Root KEK) is core's, and the audit log org-deletion's, so
	// its positions run 1..n.
	for _, base := range []string{"core", "org-deletion", "audit-export", "converge", "security", "exposure", "capabilities",
		"oidc", "requirements", "outbound", "tailnet", "audit-export-worker"} {
		for _, tm := range get(fixture(base+"-v0.22.0.json"), "rows").(jsvalue.Object) {
			switch {
			case tm.Key == "installation" && base != "core":
				continue
			case tm.Key == "audit_events" && base != "org-deletion":
				continue
			}
			for _, r := range tm.Value.([]any) {
				row := r.(jsvalue.Object)
				// Organization slugs repeat from one fixture to another
				// (acme): each fixture's get its name.
				if tm.Key == "organizations" && base != "core" {
					row = slices.Clone(row)
					for i, m := range row {
						if m.Key == "slug" {
							row[i].Value = m.Value.(string) + "-" + base
						}
					}
				}
				s.rows[tm.Key] = append(s.rows[tm.Key], row)
			}
		}
	}
	// The additions: a person, a live session, its browser credential, an
	// expired browser credential and a CLI hand-off credential from it, a
	// signing key, the backfill finished.
	admin := ""
	for _, id := range s.rows["identities"] {
		if get(id, "installation_admin") == true && admin == "" {
			admin = get(id, "id").(string)
		}
	}
	if admin == "" {
		t.Fatal("no installation admin in the fixtures")
	}
	at := "2026-11-17T08:05:00.000Z"
	random := func(n int) []byte {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		return b
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	s.rows["user"] = append(s.rows["user"], jsvalue.Object{{Key: "id", Value: "usr_migration"}, {Key: "name", Value: "Admin"},
		{Key: "email", Value: "migration-admin@varlatch.test"}, {Key: "emailVerified", Value: false}, {Key: "image", Value: nil},
		{Key: "createdAt", Value: at}, {Key: "updatedAt", Value: at}})
	s.rows["auth_user_links"] = append(s.rows["auth_user_links"], jsvalue.Object{{Key: "better_auth_user_id", Value: "usr_migration"},
		{Key: "identity_id", Value: admin}, {Key: "created_at", Value: at}})
	// The token is null: the export never reads it (BUNDLE.md).
	s.rows["session"] = append(s.rows["session"], jsvalue.Object{{Key: "id", Value: "ses_migration"}, {Key: "expiresAt", Value: "2027-11-17T08:05:00.000Z"},
		{Key: "token", Value: nil}, {Key: "createdAt", Value: at}, {Key: "updatedAt", Value: at},
		{Key: "ipAddress", Value: nil}, {Key: "userAgent", Value: nil}, {Key: "userId", Value: "usr_migration"}})
	cred := func(id, kind, expires string) jsvalue.Object {
		return jsvalue.Object{{Key: "id", Value: id}, {Key: "identity_id", Value: admin}, {Key: "kind", Value: kind}, {Key: "name", Value: kind},
			{Key: "token_hash", Value: hex.EncodeToString(random(32))}, {Key: "created_at", Value: at}, {Key: "expires_at", Value: expires},
			{Key: "revoked_at", Value: nil}, {Key: "max_uses", Value: nil}, {Key: "use_count", Value: float64(0)}, {Key: "last_used_at", Value: nil},
			{Key: "client", Value: nil}, {Key: "auth_session_id", Value: "ses_migration"}, {Key: "issued_by", Value: nil},
			{Key: "evidence_user_verified", Value: nil}, {Key: "evidence_passkey_id", Value: nil}}
	}
	s.rows["credentials"] = append(s.rows["credentials"],
		cred("crd_migration_browser", "browser", "2027-11-17T08:05:00.000Z"),
		cred("crd_migration_expired", "browser", "2026-11-17T08:06:00.000Z"),
		cred("crd_migration_cli", "cli", "2027-11-17T08:05:00.000Z"))
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := make([]byte, 32), make([]byte, 32)
	signer.PublicKey.X.FillBytes(x)
	signer.PublicKey.Y.FillBytes(y)
	s.rows["signing_keys"] = append(s.rows["signing_keys"], jsvalue.Object{{Key: "id", Value: "key_migration"}, {Key: "algorithm", Value: "ES256"},
		{Key: "public_jwk", Value: jsvalue.Object{{Key: "kty", Value: "EC"}, {Key: "crv", Value: "P-256"}, {Key: "x", Value: b64(x)}, {Key: "y", Value: b64(y)}}},
		{Key: "private_key_wrapped", Value: jsvalue.Object{{Key: "nonce", Value: base64.StdEncoding.EncodeToString(random(12))},
			{Key: "authTag", Value: base64.StdEncoding.EncodeToString(random(16))}, {Key: "algorithm", Value: "aes-256-gcm"},
			{Key: "ciphertext", Value: base64.StdEncoding.EncodeToString(random(150))}, {Key: "formatVersion", Value: float64(1)}}},
		{Key: "created_at", Value: at}, {Key: "retired_at", Value: nil}})
	s.rows["exposure_backfill"] = []jsvalue.Object{{{Key: "singleton", Value: true}, {Key: "cursor", Value: float64(0)},
		{Key: "until_order", Value: float64(0)}, {Key: "finished_at", Value: at}}}
	return s
}

// value is a PostgreSQL value as node-postgres gives it, in the form the
// canonical encoder takes.
func value(t *testing.T, ty canonical.Type, v any) any {
	t.Helper()
	if v == nil {
		return nil
	}
	switch ty {
	case canonical.Timestamptz:
		ts, err := time.Parse(time.RFC3339Nano, v.(string))
		if err != nil {
			t.Fatal(err)
		}
		return ts.UnixMicro()
	case canonical.Integer, canonical.Bigint:
		switch x := v.(type) {
		case float64:
			return int64(x)
		case string:
			n, err := strconv.ParseInt(x, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	case canonical.Jsonb:
		return string(jsvalue.Stringify(jsvalue.Jsonb(v)))
	case canonical.Bytea:
		// PostgreSQL's hex output, as the fixtures hold it.
		b, err := hex.DecodeString(strings.TrimPrefix(v.(string), "\\x"))
		if err != nil {
			t.Fatal(err)
		}
		return b
	case canonical.Boolean:
		return v
	case canonical.TextArray:
		return v.([]any)
	}
	return v
}

// compareValues is SQLite's ascending order: NULL first, integers by value,
// text and bytes by their bytes.
func compareValues(a, b any) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	switch x := a.(type) {
	case int64:
		return cmp.Compare(x, b.(int64))
	case string:
		return strings.Compare(x, b.(string))
	case bool:
		return cmp.Compare(boolInt(x), boolInt(b.(bool)))
	}
	return 0
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// sourceBundle is the source's forward bundle, extra rows added by table.
func sourceBundle(t *testing.T, s source, extra map[string][][]any, sequences bool) []byte {
	t.Helper()
	m, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := bundle.NewWriter(&buf, m, bundle.Header{Manifest: m.Version, Encoding: m.Encoding, Direction: bundle.Forward,
		Release: m.Source.Release, FrozenPoint: bundle.FrozenPoint{AuditPosition: 0, Snapshot: "00000003-0000001B-1"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range bundle.Tables(m) {
		var rows [][]any
		for _, r := range s.rows[tb.Source] {
			vals := make([]any, len(tb.Columns))
			for i, c := range tb.Columns {
				for _, mem := range r {
					if mem.Key == c.Source {
						vals[i] = value(t, c.Type, mem.Value)
					}
				}
			}
			rows = append(rows, vals)
		}
		rows = append(rows, extra[tb.Source]...)
		if !tb.PhysicalOrder {
			idx := map[string]int{}
			for i, c := range tb.Columns {
				idx[c.Source] = i
			}
			slices.SortStableFunc(rows, func(a, b []any) int {
				for _, k := range tb.OrderBy {
					if c := compareValues(a[idx[k]], b[idx[k]]); c != 0 {
						return c
					}
				}
				return 0
			})
		}
		if err := w.Table(tb.Source, len(rows)); err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			b, err := canonical.AppendRow(nil, tb.Types(), r)
			if err != nil {
				t.Fatalf("%s: %v", tb.Source, err)
			}
			if err := w.Row(b); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if sequences {
		b = bytes.Replace(b, []byte(`"sequences":[]`), []byte(`"sequences":["s"]`), 1)
	}
	return b
}

// tablesOf reads a bundle into its rows by table.
func tablesOf(t *testing.T, b []byte) map[string][]string {
	t.Helper()
	m, _ := manifest.Load()
	r, err := bundle.NewReader(bytes.NewReader(b), m)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for range bundle.Tables(m) {
		tb, n, err := r.NextTable()
		if err != nil {
			t.Fatal(err)
		}
		out[tb.Source] = []string{}
		for range n {
			row, err := r.Row()
			if err != nil {
				t.Fatal(err)
			}
			out[tb.Source] = append(out[tb.Source], string(row))
		}
	}
	if err := r.End(); err != nil {
		t.Fatal(err)
	}
	return out
}

func importInto(t *testing.T, dir string, b []byte, kek []byte) (Result, error) {
	t.Helper()
	return Import(context.Background(), bytes.NewReader(b), Options{DataDir: dir, RootKEK: kek, Release: "0.50.0-test"})
}

// The round trip: the TypeScript server's rows imported, then exported back
// (the reverse bundle) are the same rows, byte for byte, but for the
// documented transformations: the session ended (its browser credential
// revoked, the CLI credential kept), and the audit log a prefix of the
// reverse bundle's, which appends the revocation and installation.migrated
// (forward and reverse).
func TestRoundTrip(t *testing.T) {
	s := loadSource(t)
	src := sourceBundle(t, s, nil, false)
	// The tables the round trip carries rows of.
	var withData []string
	for table, rows := range tablesOf(t, src) {
		if len(rows) > 0 {
			withData = append(withData, table)
		}
	}
	slices.Sort(withData)
	t.Logf("%d tables with rows: %s", len(withData), strings.Join(withData, ", "))
	for _, want := range []string{"audit_events", "signing_keys", "audit_export_plans", "audit_exports", "webhooks", "platform_connections",
		"sync_cursor", "sync_targets", "passkey", "passkey_provenance", "session", "user", "credentials", "value_versions", "requirements", "exposure_backfill"} {
		if !slices.Contains(withData, want) {
			t.Errorf("%s has no rows in the round trip", want)
		}
	}
	if len(withData) < 45 {
		t.Errorf("only %d tables with rows", len(withData))
	}
	dir := t.TempDir()
	res, err := importInto(t, dir, src, s.rootKEK)
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionsEnded != 1 || res.CredentialsRevoked != 1 || res.InstallationID == "" {
		t.Fatalf("import: %+v", res)
	}
	conn, err := sql.Open("sqlite", "file:"+filepath.Join(dir, config.DatabaseFile)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var browserRevoked, cliRevoked, expiredRevoked sql.NullInt64
	_ = conn.QueryRow("SELECT revoked_at FROM credentials WHERE id = 'crd_migration_browser'").Scan(&browserRevoked)
	_ = conn.QueryRow("SELECT revoked_at FROM credentials WHERE id = 'crd_migration_cli'").Scan(&cliRevoked)
	_ = conn.QueryRow("SELECT revoked_at FROM credentials WHERE id = 'crd_migration_expired'").Scan(&expiredRevoked)
	var revokedEvents int
	_ = conn.QueryRow("SELECT count(*) FROM audit_events WHERE event_type = 'credential.revoked' AND credential_id LIKE 'crd_migration_%'").Scan(&revokedEvents)
	if expiredRevoked.Valid || revokedEvents != 1 {
		t.Fatalf("the expired browser credential: revoked %v; %d credential.revoked events, want 1", expiredRevoked, revokedEvents)
	}
	var sessions int
	_ = conn.QueryRow("SELECT count(*) FROM auth_sessions").Scan(&sessions)
	rows, err := conn.Query("SELECT event_type FROM audit_events ORDER BY event_order DESC LIMIT 2")
	if err != nil {
		t.Fatal(err)
	}
	var last []string
	for rows.Next() {
		var e string
		_ = rows.Scan(&e)
		last = append(last, e)
	}
	rows.Close()
	conn.Close()
	if !browserRevoked.Valid || cliRevoked.Valid || sessions != 0 || !slices.Equal(last, []string{MigratedEvent, "credential.revoked"}) {
		t.Fatalf("browser revoked %v, cli revoked %v, sessions %d, last events %q", browserRevoked, cliRevoked, sessions, last)
	}

	var rev bytes.Buffer
	out, err := ExportReverse(context.Background(), &rev, Options{DataDir: dir, Release: "0.50.0-test"})
	if err != nil {
		t.Fatal(err)
	}
	if out.SessionsEnded != 0 || out.InstallationID != res.InstallationID {
		t.Fatalf("export: %+v", out)
	}
	before, after := tablesOf(t, src), tablesOf(t, rev.Bytes())
	for table, want := range before {
		got := after[table]
		switch table {
		case "audit_events":
			if len(got) != len(want)+3 || !slices.Equal(got[:len(want)], want) {
				t.Errorf("audit_events: %d source events, %d after; the source is not a prefix", len(want), len(got))
			}
			for i, e := range []string{"credential.revoked", MigratedEvent, MigratedEvent} {
				if !strings.Contains(got[len(want)+i], `"`+e+`"`) {
					t.Errorf("appended event %d: %s", i, got[len(want)+i])
				}
			}
		case "session":
			if len(got) != 0 {
				t.Errorf("session: %d rows in the reverse bundle", len(got))
			}
		case "credentials":
			diff := 0
			for i := range want {
				if got[i] != want[i] {
					diff++
					if !strings.Contains(want[i], "crd_migration_browser") {
						t.Errorf("credentials: %s changed", want[i])
					}
				}
			}
			if diff != 1 || len(got) != len(want) {
				t.Errorf("credentials: %d changed of %d", diff, len(want))
			}
		default:
			if !slices.Equal(got, want) {
				t.Errorf("%s: the round trip changed it:\n source %q\n after  %q", table, want, got)
			}
		}
	}
	// The export changed nothing in the database.
	conn, _ = sql.Open("sqlite", "file:"+filepath.Join(dir, config.DatabaseFile)+"?mode=ro")
	defer conn.Close()
	var migrated int
	_ = conn.QueryRow("SELECT count(*) FROM audit_events WHERE event_type = ?", MigratedEvent).Scan(&migrated)
	if migrated != 1 {
		t.Errorf("the export wrote to the database: %d installation.migrated events", migrated)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".migrate-export-*")); len(left) != 0 {
		t.Errorf("the snapshot copy was left: %v", left)
	}
}

// What an import refuses, keeping nothing: a data directory in use, the
// wrong Root KEK, a bundle cut short or damaged, a broken foreign key, a
// row not in canonical form, a sequence, a reverse bundle.
func TestImportRefusals(t *testing.T) {
	s := loadSource(t)
	good := sourceBundle(t, s, nil, false)
	empty := func(t *testing.T) string { return t.TempDir() }
	nothingKept := func(t *testing.T, dir, name string) {
		t.Helper()
		if left, _ := filepath.Glob(filepath.Join(dir, "varlatch.db*")); len(left) != 0 {
			t.Errorf("%s: kept %v", name, left)
		}
	}
	wrongKEK := make([]byte, 32)
	_, _ = rand.Read(wrongKEK)
	m, _ := manifest.Load()
	var membership manifest.Table
	for _, tb := range m.Tables {
		if tb.Source == "org_memberships" {
			membership = tb
		}
	}
	orphan := make([]any, len(membership.Columns))
	for i, c := range membership.Columns {
		switch c.Source {
		case "organization_id":
			orphan[i] = "org_nowhere"
		case "identity_id":
			orphan[i] = "idn_nowhere"
		case "role":
			orphan[i] = "member"
		case "created_at":
			orphan[i] = int64(1)
		case "version":
			orphan[i] = int64(0)
		}
	}
	lines := bytes.SplitAfter(good, []byte("\n"))
	cut := bytes.Join(lines[:len(lines)/2], nil)
	var damaged, notCanonical []byte
	for i, l := range lines {
		if i > 0 && bytes.HasPrefix(lines[i-1], []byte(`{"table":"installation",`)) {
			d := slices.Clone(good)
			off := len(bytes.Join(lines[:i], nil))
			d[off+3] ^= 1
			damaged = d
			// The same row with a space after its first value, the
			// stream sealed again: refused for its form, not its digest.
			ls := slices.Clone(lines)
			ls[i] = bytes.Replace(l, []byte(`",`), []byte(`", `), 1)
			notCanonical = reseal(t, bytes.Join(ls, nil))
			break
		}
	}
	used := t.TempDir()
	if err := os.WriteFile(filepath.Join(used, "notes"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var rev bytes.Buffer
	{
		dir := t.TempDir()
		if _, err := importInto(t, dir, good, s.rootKEK); err != nil {
			t.Fatal(err)
		}
		if _, err := ExportReverse(context.Background(), &rev, Options{DataDir: dir, Release: "0.50.0-test"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name   string
		dir    string
		bundle []byte
		kek    []byte
		why    string
	}{
		{"a data directory in use", used, good, s.rootKEK, "not empty"},
		{"the wrong Root KEK", empty(t), good, wrongKEK, "does not open the installation's canary"},
		{"cut short", empty(t), cut, s.rootKEK, "cut short"},
		{"a damaged byte", empty(t), damaged, s.rootKEK, "damaged"},
		{"a row not in canonical form", empty(t), notCanonical, s.rootKEK, "table installation: row 1: canonical: the row is not in canonical form"},
		{"a broken foreign key", empty(t), sourceBundle(t, s, map[string][][]any{"org_memberships": {orphan}}, false), s.rootKEK, "foreign keys do not hold: org_memberships"},
		{"a sequence", empty(t), sourceBundle(t, s, nil, true), s.rootKEK, "sequences"},
		{"a reverse bundle", empty(t), rev.Bytes(), s.rootKEK, "a reverse bundle"},
		{"a session token carried", empty(t), withToken(t, s), s.rootKEK, "session.token holds a value"},
		{"a leftover that is not an import's", leftover(t, ".migrate-import-x.db"), good, s.rootKEK, "not empty (.migrate-import-x.db)"},
	} {
		_, err := importInto(t, c.dir, c.bundle, c.kek)
		if err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v, want %q", c.name, err, c.why)
		}
		if c.dir != used {
			nothingKept(t, c.dir, c.name)
		}
		if left, _ := filepath.Glob(filepath.Join(c.dir, importPrefix+"*")); len(left) != 0 && c.name != "a leftover that is not an import's" {
			t.Errorf("%s: left %v", c.name, left)
		}
	}
}

// withToken is the source with its session's token carried.
func withToken(t *testing.T, s source) []byte {
	t.Helper()
	carried := source{rootKEK: s.rootKEK, rows: map[string][]jsvalue.Object{}}
	for k, v := range s.rows {
		carried.rows[k] = v
	}
	row := slices.Clone(s.rows["session"][0])
	for i, m := range row {
		if m.Key == "token" {
			row[i].Value = "a token the export never carries"
		}
	}
	carried.rows["session"] = []jsvalue.Object{row}
	return sourceBundle(t, carried, nil, false)
}

// leftover is a data directory holding a file named name.
func leftover(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// An import that was killed leaves its database under the temporary name:
// the next import removes it (that exact pattern only) and builds the
// database, renamed into place; no temporary name is left.
func TestAnInterruptedImportsLeftovers(t *testing.T) {
	s := loadSource(t)
	dir := t.TempDir()
	for _, name := range []string{importPrefix + "0123456789ab.db", importPrefix + "0123456789ab.db-wal", importPrefix + "0123456789ab.db-shm"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("an import cut short"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := importInto(t, dir, sourceBundle(t, s, nil, false), s.rootKEK); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{config.DatabaseFile}) {
		t.Fatalf("the data directory after the import: %q", names)
	}
}

// reseal writes a bundle's end line again for its changed bytes.
func reseal(t *testing.T, b []byte) []byte {
	t.Helper()
	body := b[:bytes.LastIndex(b[:len(b)-1], []byte("\n"))+1]
	end := b[len(body):]
	sum := sha256.Sum256(body)
	i := bytes.Index(end, []byte(`"sha256":"`)) + len(`"sha256":"`)
	out := append(slices.Clone(body), end[:i]...)
	out = append(out, hex.EncodeToString(sum[:])...)
	return append(out, end[i+64:]...)
}
