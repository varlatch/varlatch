// SPDX-License-Identifier: AGPL-3.0-or-later

package migrate

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
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
	raw, err := os.ReadFile(filepath.Join("..", "..", "paritytest", "testdata", "core-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsvalue.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	get := func(o jsvalue.Object, k string) any {
		for _, m := range o {
			if m.Key == k {
				return m.Value
			}
		}
		return nil
	}
	root := doc.(jsvalue.Object)
	kek, err := hex.DecodeString(get(root, "rootKek").(string))
	if err != nil {
		t.Fatal(err)
	}
	s := source{rootKEK: kek, rows: map[string][]jsvalue.Object{}}
	for _, tm := range get(root, "rows").(jsvalue.Object) {
		for _, r := range tm.Value.([]any) {
			s.rows[tm.Key] = append(s.rows[tm.Key], r.(jsvalue.Object))
		}
	}
	// The additions: a person, a live session, its browser credential and
	// a CLI hand-off credential, the backfill finished.
	admin := ""
	for _, id := range s.rows["identities"] {
		if get(id, "installation_admin") == true {
			admin = get(id, "id").(string)
		}
	}
	if admin == "" {
		t.Fatal("no installation admin in the fixture")
	}
	at := "2026-11-17T08:05:00.000Z"
	hash := func() string {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}
	s.rows["user"] = append(s.rows["user"], jsvalue.Object{{Key: "id", Value: "usr_migration"}, {Key: "name", Value: "Admin"},
		{Key: "email", Value: "admin@varlatch.test"}, {Key: "emailVerified", Value: false}, {Key: "image", Value: nil},
		{Key: "createdAt", Value: at}, {Key: "updatedAt", Value: at}})
	s.rows["auth_user_links"] = append(s.rows["auth_user_links"], jsvalue.Object{{Key: "better_auth_user_id", Value: "usr_migration"},
		{Key: "identity_id", Value: admin}, {Key: "created_at", Value: at}})
	s.rows["session"] = append(s.rows["session"], jsvalue.Object{{Key: "id", Value: "ses_migration"}, {Key: "expiresAt", Value: "2027-11-17T08:05:00.000Z"},
		{Key: "token", Value: "a session token the export never carries"}, {Key: "createdAt", Value: at}, {Key: "updatedAt", Value: at},
		{Key: "ipAddress", Value: nil}, {Key: "userAgent", Value: nil}, {Key: "userId", Value: "usr_migration"}})
	cred := func(id, kind string) jsvalue.Object {
		return jsvalue.Object{{Key: "id", Value: id}, {Key: "identity_id", Value: admin}, {Key: "kind", Value: kind}, {Key: "name", Value: kind},
			{Key: "token_hash", Value: hash()}, {Key: "created_at", Value: at}, {Key: "expires_at", Value: "2027-11-17T08:05:00.000Z"},
			{Key: "revoked_at", Value: nil}, {Key: "max_uses", Value: nil}, {Key: "use_count", Value: float64(0)}, {Key: "last_used_at", Value: nil},
			{Key: "client", Value: nil}, {Key: "auth_session_id", Value: "ses_migration"}, {Key: "issued_by", Value: nil},
			{Key: "evidence_user_verified", Value: nil}, {Key: "evidence_passkey_id", Value: nil}}
	}
	s.rows["credentials"] = append(s.rows["credentials"], cred("crd_migration_browser", "browser"), cred("crd_migration_cli", "cli"))
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
			var n int64
			for _, c := range x {
				n = n*10 + int64(c-'0')
			}
			return n
		}
	case canonical.Jsonb:
		return string(jsvalue.Stringify(jsvalue.Jsonb(v)))
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
	var browserRevoked, cliRevoked sql.NullInt64
	_ = conn.QueryRow("SELECT revoked_at FROM credentials WHERE id = 'crd_migration_browser'").Scan(&browserRevoked)
	_ = conn.QueryRow("SELECT revoked_at FROM credentials WHERE id = 'crd_migration_cli'").Scan(&cliRevoked)
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
		if bytes.Contains(l, []byte("inst_")) && bytes.HasPrefix(l, []byte("[")) {
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
	} {
		_, err := importInto(t, c.dir, c.bundle, c.kek)
		if err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v, want %q", c.name, err, c.why)
		}
		if c.dir != used {
			nothingKept(t, c.dir, c.name)
		}
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
