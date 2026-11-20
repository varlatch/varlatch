// SPDX-License-Identifier: AGPL-3.0-or-later

// Package migrationtest is the migration's seeded source for tests (slices
// 7.3a and 7.3b): the TypeScript server's rows of the v0.22.0 parity
// fixtures, as its export reads PostgreSQL, written as a forward bundle.
// It is test support only: nothing but tests imports it.
package migrationtest

import (
	"bytes"
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/canonical"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
)

// Source is the seeded installation: its Root KEK, its rows by PostgreSQL
// table (as node-postgres gives them), and its last audit position.
type Source struct {
	RootKEK       []byte
	Rows          map[string][]jsvalue.Object
	AuditPosition int64
	// Secrets are every plaintext sealed in the rows, and the Root KEK:
	// what a report or a log must never hold.
	Secrets [][]byte
}

// Fixtures are the v0.22.0 parity fixtures whose rows do not meet (several
// reuse fixed ids, so not all of them), each written by the TypeScript
// server from a seeded installation of its own.
var Fixtures = []string{"core", "org-deletion", "audit-export", "converge", "security", "exposure", "capabilities",
	"oidc", "requirements", "outbound", "tailnet", "audit-export-worker"}

func testdata() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "paritytest", "testdata")
}

func get(o jsvalue.Object, k string) any {
	v, _ := o.Get(k)
	return v
}

// Load is the source: the fixtures' rows merged, under core's Root KEK.
// The installation (the canary under core's Root KEK) is core's, and the
// audit log org-deletion's, so its positions run 1..n. Every fixture has a
// Root KEK of its own: each Organization's KEK, and a draining audit
// export's credential, are sealed again under core's, so the whole source
// opens with one Root KEK, as an installation's does. To that come what
// the fixtures lack to exercise the transformations and every encryption
// class: a person with a live browser session, a browser credential minted
// from it, an expired one and a CLI hand-off credential from the same
// session, a signing key, and the finished exposure backfill.
func Load(t testing.TB) Source {
	t.Helper()
	fixture := func(name string) jsvalue.Object {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(testdata(), name))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsvalue.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return doc.(jsvalue.Object)
	}
	kekOf := func(doc jsvalue.Object) []byte {
		k, err := hex.DecodeString(get(doc, "rootKek").(string))
		if err != nil || len(k) != envelope.KeySize {
			t.Fatalf("a fixture's Root KEK: %v", err)
		}
		return k
	}
	core := fixture("core-v0.22.0.json")
	s := Source{RootKEK: kekOf(core), Rows: map[string][]jsvalue.Object{}}
	s.Secrets = append(s.Secrets, s.RootKEK)
	for _, base := range Fixtures {
		doc := fixture(base + "-v0.22.0.json")
		own := kekOf(doc)
		for _, tm := range get(doc, "rows").(jsvalue.Object) {
			switch {
			case tm.Key == "installation" && base != "core":
				continue
			case tm.Key == "audit_events" && base != "org-deletion":
				continue
			}
			for _, r := range tm.Value.([]any) {
				row := slices.Clone(r.(jsvalue.Object))
				switch tm.Key {
				case "organizations":
					// Organization slugs repeat from one fixture to
					// another (acme): each fixture's get its name.
					if base != "core" {
						row = row.Set("slug", get(row, "slug").(string)+"-"+base)
					}
					if w := get(row, "wrapped_org_kek"); w != nil {
						id := get(row, "id").(string)
						orgKEK, err := envelope.UnwrapOrgKEK(own, envelopeOf(t, w), id)
						if err != nil {
							t.Fatalf("%s: organization %s's KEK: %v", base, id, err)
						}
						row = row.Set("wrapped_org_kek", seal(t, s.RootKEK, orgKEK, envelope.OrgKEKContext(id)))
						s.Secrets = append(s.Secrets, orgKEK)
					}
				case "audit_exports":
					if get(row, "state") == "draining" {
						org, id := get(row, "organization_id").(string), get(row, "id").(string)
						plain, err := envelope.Open(own, envelopeOf(t, get(row, "credential_envelope")), envelope.AuditExportDrainContext(org, id))
						if err != nil {
							t.Fatalf("%s: audit export %s's drain credential: %v", base, id, err)
						}
						row = row.Set("credential_envelope", seal(t, s.RootKEK, plain, envelope.AuditExportDrainContext(org, id)))
						s.Secrets = append(s.Secrets, plain)
					}
				case "audit_events":
					if p, ok := get(row, "event_order").(float64); ok && int64(p) > s.AuditPosition {
						s.AuditPosition = int64(p)
					}
				}
				s.Rows[tm.Key] = append(s.Rows[tm.Key], row)
			}
		}
	}
	add(t, &s)
	realize(t, &s)
	for _, it := range Items(t, s) {
		s.Secrets = append(s.Secrets, it.Plaintext)
	}
	return s
}

func envelopeOf(t testing.TB, v any) envelope.Envelope {
	t.Helper()
	var e envelope.Envelope
	if err := json.Unmarshal(jsvalue.Stringify(v), &e); err != nil {
		t.Fatal(err)
	}
	return e
}

// seal is plaintext sealed under key, as a jsonb value of a row.
func seal(t testing.TB, key, plaintext []byte, ctx envelope.Context) any {
	t.Helper()
	e, err := envelope.Seal(key, plaintext, ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsvalue.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// add puts in what the fixtures lack.
func add(t testing.TB, s *Source) {
	t.Helper()
	admin := ""
	for _, id := range s.Rows["identities"] {
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
	s.Rows["user"] = append(s.Rows["user"], jsvalue.Object{{Key: "id", Value: "usr_migration"}, {Key: "name", Value: "Admin"},
		{Key: "email", Value: "migration-admin@varlatch.test"}, {Key: "emailVerified", Value: false}, {Key: "image", Value: nil},
		{Key: "createdAt", Value: at}, {Key: "updatedAt", Value: at}})
	s.Rows["auth_user_links"] = append(s.Rows["auth_user_links"], jsvalue.Object{{Key: "better_auth_user_id", Value: "usr_migration"},
		{Key: "identity_id", Value: admin}, {Key: "created_at", Value: at}})
	// The token is null: the export never reads it (BUNDLE.md).
	s.Rows["session"] = append(s.Rows["session"], jsvalue.Object{{Key: "id", Value: "ses_migration"}, {Key: "expiresAt", Value: "2027-11-17T08:05:00.000Z"},
		{Key: "token", Value: nil}, {Key: "createdAt", Value: at}, {Key: "updatedAt", Value: at},
		{Key: "ipAddress", Value: nil}, {Key: "userAgent", Value: nil}, {Key: "userId", Value: "usr_migration"}})
	cred := func(id, kind, expires string) jsvalue.Object {
		return jsvalue.Object{{Key: "id", Value: id}, {Key: "identity_id", Value: admin}, {Key: "kind", Value: kind}, {Key: "name", Value: kind},
			{Key: "token_hash", Value: hex.EncodeToString(random(32))}, {Key: "created_at", Value: at}, {Key: "expires_at", Value: expires},
			{Key: "revoked_at", Value: nil}, {Key: "max_uses", Value: nil}, {Key: "use_count", Value: float64(0)}, {Key: "last_used_at", Value: nil},
			{Key: "client", Value: nil}, {Key: "auth_session_id", Value: "ses_migration"}, {Key: "issued_by", Value: nil},
			{Key: "evidence_user_verified", Value: nil}, {Key: "evidence_passkey_id", Value: nil}}
	}
	s.Rows["credentials"] = append(s.Rows["credentials"],
		cred("crd_migration_browser", "browser", "2027-11-17T08:05:00.000Z"),
		cred("crd_migration_expired", "browser", "2026-11-17T08:06:00.000Z"),
		cred("crd_migration_cli", "cli", "2027-11-17T08:05:00.000Z"))
	// A signing key, its private key sealed under the Root KEK as the
	// TypeScript server seals it (jwt-signing-key).
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	x, y := make([]byte, 32), make([]byte, 32)
	signer.PublicKey.X.FillBytes(x)
	signer.PublicKey.Y.FillBytes(y)
	s.Rows["signing_keys"] = append(s.Rows["signing_keys"], jsvalue.Object{{Key: "id", Value: "key_migration"}, {Key: "algorithm", Value: "ES256"},
		{Key: "public_jwk", Value: jsvalue.Object{{Key: "kty", Value: "EC"}, {Key: "crv", Value: "P-256"}, {Key: "x", Value: b64(x)}, {Key: "y", Value: b64(y)}}},
		{Key: "private_key_wrapped", Value: seal(t, s.RootKEK, der, envelope.JWTSigningKeyContext("key_migration"))},
		{Key: "created_at", Value: at}, {Key: "retired_at", Value: nil}})
	s.Secrets = append(s.Secrets, der)
	s.Rows["exposure_backfill"] = []jsvalue.Object{{{Key: "singleton", Value: true}, {Key: "cursor", Value: float64(0)},
		{Key: "until_order", Value: float64(0)}, {Key: "finished_at", Value: at}}}
}

// Value is a PostgreSQL value as node-postgres gives it, in the form the
// canonical encoder takes.
func Value(t testing.TB, ty canonical.Type, v any) any {
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

// Options are a bundle's variations.
type Options struct {
	// Extra are rows added by table, in canonical form.
	Extra map[string][][]any
	// Sequences lists a sequence in the header (refused).
	Sequences bool
	// Sections are the check sections; empty when nil.
	Sections *Sections
	// AuditPosition replaces the source's in the header when not 0.
	AuditPosition int64
}

// Sections are a bundle's check sections.
type Sections struct {
	Digests   []bundle.Digest
	Decisions []bundle.Decision
	At        int64
}

// Bundle is the source's forward bundle.
func Bundle(t testing.TB, s Source, o Options) []byte {
	t.Helper()
	m, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
	}
	pos := s.AuditPosition
	if o.AuditPosition != 0 {
		pos = o.AuditPosition
	}
	var buf bytes.Buffer
	w, err := bundle.NewWriter(&buf, m, bundle.Header{Manifest: m.Version, Encoding: m.Encoding, Direction: bundle.Forward,
		Release: m.Source.Release, FrozenPoint: bundle.FrozenPoint{AuditPosition: pos, Snapshot: "00000003-0000001B-1"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range bundle.Tables(m) {
		var rows [][]any
		for _, r := range s.Rows[tb.Source] {
			vals := make([]any, len(tb.Columns))
			for i, c := range tb.Columns {
				if v, ok := r.Get(c.Source); ok {
					vals[i] = Value(t, c.Type, v)
				}
			}
			rows = append(rows, vals)
		}
		rows = append(rows, o.Extra[tb.Source]...)
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
	sec := o.Sections
	if sec == nil {
		sec = &Sections{}
	}
	digests := slices.Clone(sec.Digests)
	slices.SortFunc(digests, bundle.CompareDigests)
	if err := w.Digests(len(digests)); err != nil {
		t.Fatal(err)
	}
	for _, d := range digests {
		if err := w.Digest(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Decisions(len(sec.Decisions), sec.At); err != nil {
		t.Fatal(err)
	}
	for _, d := range sec.Decisions {
		if err := w.Decision(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if o.Sequences {
		b = bytes.Replace(b, []byte(`"sequences":[]`), []byte(`"sequences":["s"]`), 1)
	}
	return b
}

// Reseal writes a bundle's end line again for its changed bytes.
func Reseal(t testing.TB, b []byte) []byte {
	t.Helper()
	body := b[:bytes.LastIndex(b[:len(b)-1], []byte("\n"))+1]
	end := b[len(body):]
	sum := sha256Hex(body)
	i := bytes.Index(end, []byte(`"sha256":"`)) + len(`"sha256":"`)
	out := append(slices.Clone(body), end[:i]...)
	out = append(out, sum...)
	return append(out, end[i+64:]...)
}

func sha256Hex(b []byte) []byte {
	sum := sha256.Sum256(b)
	return []byte(hex.EncodeToString(sum[:]))
}

// Item is one encrypted item of the source, opened: its class, its ids
// (its envelope context without the purpose) and its plaintext.
type Item struct {
	Class     string
	IDs       map[string]string
	Plaintext []byte
}

// Items opens every encrypted item of the source, as the TypeScript
// export does for its digests (decision 7), reading its rows, not a
// database: the classes of server/migration/check/CHECKS.md. An item under
// an Organization KEK that was destroyed is not opened (no key opens it).
func Items(t testing.TB, s Source) []Item {
	t.Helper()
	str := func(o jsvalue.Object, k string) string {
		v, _ := get(o, k).(string)
		return v
	}
	var out []Item
	open := func(class string, key []byte, v any, ctx envelope.Context) []byte {
		t.Helper()
		p, err := envelope.Open(key, envelopeOf(t, v), ctx)
		if err != nil {
			t.Fatalf("%s %v: %v", class, ctx, err)
		}
		ids := map[string]string{}
		for k, x := range ctx {
			if k != "purpose" {
				ids[k] = x.(string)
			}
		}
		out = append(out, Item{Class: class, IDs: ids, Plaintext: p})
		return p
	}
	for _, r := range s.Rows["installation"] {
		open(envelope.PurposeKEKCanary, s.RootKEK, get(r, "kek_canary"), envelope.KEKCanaryContext(str(r, "id")))
	}
	orgKEK := map[string][]byte{}
	for _, r := range s.Rows["organizations"] {
		if w := get(r, "wrapped_org_kek"); w != nil && get(r, "org_kek_destroyed_at") == nil {
			id := str(r, "id")
			orgKEK[id] = open(envelope.PurposeOrgKEK, s.RootKEK, w, envelope.OrgKEKContext(id))
		}
	}
	envOrg := map[string]string{}
	{
		projectOrg := map[string]string{}
		for _, p := range s.Rows["projects"] {
			projectOrg[str(p, "id")] = str(p, "organization_id")
		}
		envProject := map[string]string{}
		for _, e := range s.Rows["environments"] {
			envProject[str(e, "id")] = str(e, "project_id")
		}
		for _, v := range s.Rows["env_values"] {
			envOrg[str(v, "id")] = projectOrg[envProject[str(v, "environment_id")]]
		}
	}
	for _, r := range s.Rows["value_versions"] {
		org, secret, version := envOrg[str(r, "value_id")], str(r, "value_id"), str(r, "id")
		k, ok := orgKEK[org]
		if get(r, "erased_at") != nil || !ok {
			continue
		}
		dek := open(envelope.PurposeDEK, k, get(r, "wrapped_dek"), envelope.DEKContext(org, secret, version))
		open(envelope.PurposeValue, dek, get(r, "payload"), envelope.ValueContext(org, secret, version))
	}
	byOrg := func(table, column, class string, ctx func(org, id string) envelope.Context, when func(jsvalue.Object) bool) {
		for _, r := range s.Rows[table] {
			k, ok := orgKEK[str(r, "organization_id")]
			if v := get(r, column); v != nil && ok && when(r) {
				open(class, k, v, ctx(str(r, "organization_id"), str(r, "id")))
			}
		}
	}
	always := func(jsvalue.Object) bool { return true }
	byOrg("webhooks", "secret_envelope", envelope.PurposeWebhookSecret, envelope.WebhookSecretContext, always)
	byOrg("platform_connections", "credential_envelope", envelope.PurposePlatformCredential, envelope.PlatformCredentialContext, always)
	byOrg("github_apps", "key_envelope", envelope.PurposeGitHubAppKey, envelope.GitHubAppKeyContext, always)
	byOrg("github_app_registrations", "pending_key_envelope", envelope.PurposeGitHubAppKey, envelope.GitHubAppKeyContext, always)
	byOrg("audit_exports", "credential_envelope", envelope.PurposeAuditExportCredential, envelope.AuditExportCredentialContext,
		func(r jsvalue.Object) bool { return get(r, "state") != "draining" })
	for _, r := range s.Rows["audit_exports"] {
		if get(r, "state") == "draining" {
			open(envelope.PurposeAuditExportDrain, s.RootKEK, get(r, "credential_envelope"), envelope.AuditExportDrainContext(str(r, "organization_id"), str(r, "id")))
		}
	}
	for _, r := range s.Rows["signing_keys"] {
		open(envelope.PurposeJWTSigningKey, s.RootKEK, get(r, "private_key_wrapped"), envelope.JWTSigningKeyContext(str(r, "id")))
	}
	return out
}

// Digests are the source's digest section under runKey: each item's
// HMAC-SHA256 over canonical.DigestInput, in the bundle's order.
func Digests(t testing.TB, s Source, runKey []byte) []bundle.Digest {
	t.Helper()
	var out []bundle.Digest
	for _, it := range Items(t, s) {
		in, err := canonical.DigestInput(it.Class, it.IDs, it.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		m := hmac.New(sha256.New, runKey)
		m.Write(in)
		out = append(out, bundle.Digest{Class: it.Class, IDs: it.IDs, HMAC: hex.EncodeToString(m.Sum(nil))})
	}
	slices.SortFunc(out, bundle.CompareDigests)
	return out
}

// realize seals a random secret in place of each envelope that does not
// open: the fixtures hold placeholders ({"fixture": ...}) where a server
// test needed no real ciphertext, and the checks need every item real.
func realize(t testing.TB, s *Source) {
	t.Helper()
	str := func(o jsvalue.Object, k string) string {
		v, _ := get(o, k).(string)
		return v
	}
	opens := func(key []byte, v any, ctx envelope.Context) bool {
		var e envelope.Envelope
		if json.Unmarshal(jsvalue.Stringify(v), &e) != nil {
			return false
		}
		_, err := envelope.Open(key, e, ctx)
		return err == nil
	}
	orgKEK := map[string][]byte{}
	for _, r := range s.Rows["organizations"] {
		if w := get(r, "wrapped_org_kek"); w != nil && get(r, "org_kek_destroyed_at") == nil {
			k, err := envelope.UnwrapOrgKEK(s.RootKEK, envelopeOf(t, w), str(r, "id"))
			if err != nil {
				t.Fatal(err)
			}
			orgKEK[str(r, "id")] = k
		}
	}
	secret := func() []byte {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		return []byte(base64.RawURLEncoding.EncodeToString(b))
	}
	for _, c := range []struct {
		table, column string
		ctx           func(org, id string) envelope.Context
		when          func(jsvalue.Object) bool
	}{
		{"webhooks", "secret_envelope", envelope.WebhookSecretContext, nil},
		{"platform_connections", "credential_envelope", envelope.PlatformCredentialContext, nil},
		{"github_apps", "key_envelope", envelope.GitHubAppKeyContext, nil},
		{"github_app_registrations", "pending_key_envelope", envelope.GitHubAppKeyContext, nil},
		{"audit_exports", "credential_envelope", envelope.AuditExportCredentialContext, func(r jsvalue.Object) bool { return get(r, "state") != "draining" }},
	} {
		for _, r := range s.Rows[c.table] {
			org, id := str(r, "organization_id"), str(r, "id")
			k, ok := orgKEK[org]
			v := get(r, c.column)
			if v == nil || !ok || (c.when != nil && !c.when(r)) || opens(k, v, c.ctx(org, id)) {
				continue
			}
			r.Set(c.column, seal(t, k, secret(), c.ctx(org, id)))
		}
	}
	envOrg := map[string]string{}
	projectOrg := map[string]string{}
	for _, p := range s.Rows["projects"] {
		projectOrg[str(p, "id")] = str(p, "organization_id")
	}
	envProject := map[string]string{}
	for _, e := range s.Rows["environments"] {
		envProject[str(e, "id")] = str(e, "project_id")
	}
	for _, v := range s.Rows["env_values"] {
		envOrg[str(v, "id")] = projectOrg[envProject[str(v, "environment_id")]]
	}
	for _, r := range s.Rows["value_versions"] {
		org, secretID, version := envOrg[str(r, "value_id")], str(r, "value_id"), str(r, "id")
		k, ok := orgKEK[org]
		if get(r, "erased_at") != nil || !ok {
			continue
		}
		var v envelope.EncryptedValue
		pj, wj := jsvalue.Stringify(get(r, "payload")), jsvalue.Stringify(get(r, "wrapped_dek"))
		if json.Unmarshal(pj, &v.Payload) == nil && json.Unmarshal(wj, &v.WrappedDEK) == nil {
			if _, err := envelope.DecryptValue(k, org, secretID, version, v); err == nil {
				continue
			}
		}
		dek := envelope.GenerateKey()
		r.Set("wrapped_dek", seal(t, k, dek, envelope.DEKContext(org, secretID, version)))
		r.Set("payload", seal(t, dek, secret(), envelope.ValueContext(org, secretID, version)))
	}
}

// Manifest is the manifest, loaded.
func Manifest(t testing.TB) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// ManifestTable is the manifest's table of the PostgreSQL table source.
func ManifestTable(t testing.TB, source string) manifest.Table {
	t.Helper()
	tb, ok := Manifest(t).Table(source)
	if !ok {
		t.Fatalf("the manifest has no table %s", source)
	}
	return tb
}
