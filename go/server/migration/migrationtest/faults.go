// SPDX-License-Identifier: AGPL-3.0-or-later

package migrationtest

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
)

// G5's damaged copies (ADR-0059 G5; internal docs/design/go-step7.md 7.3b
// and 7.3c): each fault made on a copy of an imported database, and the
// check it must fail at, with the table or class the report names and,
// where it says more, the words it says. The checks' unit tests
// (server/migration/check) and the G5 gate (server/migration/g5, through
// the varlatchd binary) hold the same list.

// Fault is one damage of an imported database.
type Fault struct {
	Name string
	// Check is the check that must fail (server/migration/check's names).
	Check string
	// Table or Class is what its report names ("" for neither).
	Table, Class string
	// Says is what the report says beyond the name, when it matters.
	Says string
	// Apply makes the damage on the database at path.
	Apply func(t testing.TB, path string)
}

// The checks' names, as server/migration/check reports them.
const (
	CheckRows           = "rows"
	CheckClasses        = "encryption-classes"
	CheckAudit          = "audit"
	CheckAuthorization  = "authorization"
	CheckAuthentication = "authentication"
)

func statements(stmts ...string) func(testing.TB, string) {
	return func(t testing.TB, path string) { Damage(t, path, stmts...) }
}

// ClassFaults are one changed ciphertext byte per encryption class.
func ClassFaults() []Fault {
	liveOrg := "organization_id IN (SELECT id FROM organizations WHERE org_kek_destroyed_at IS NULL)"
	var out []Fault
	for _, c := range []struct{ class, table, column, where string }{
		{envelope.PurposeKEKCanary, "installation", "kek_canary", "1"},
		{envelope.PurposeOrgKEK, "organizations", "wrapped_org_kek", "wrapped_org_kek IS NOT NULL AND org_kek_destroyed_at IS NULL"},
		{envelope.PurposeDEK, "value_versions", "wrapped_dek", "erased_at IS NULL"},
		{envelope.PurposeValue, "value_versions", "payload", "erased_at IS NULL"},
		{envelope.PurposeWebhookSecret, "webhooks", "secret_envelope", "secret_envelope IS NOT NULL AND " + liveOrg},
		{envelope.PurposePlatformCredential, "platform_connections", "credential_envelope", "credential_envelope IS NOT NULL AND " + liveOrg},
		{envelope.PurposeGitHubAppKey, "github_apps", "key_envelope", "key_envelope IS NOT NULL"},
		{envelope.PurposeAuditExportCredential, "audit_exports", "credential_envelope", "credential_envelope IS NOT NULL AND state <> 'draining'"},
		{envelope.PurposeAuditExportDrain, "audit_exports", "credential_envelope", "state = 'draining'"},
		{envelope.PurposeJWTSigningKey, "signing_keys", "private_key_wrapped", "1"},
	} {
		out = append(out, Fault{Name: "a changed " + c.class + " ciphertext byte", Check: CheckClasses, Class: c.class,
			Apply: func(t testing.TB, path string) { FlipCiphertext(t, path, c.table, c.column, c.where) }})
	}
	return out
}

// TargetFaults are the other damages, each at its own check. grant is a
// live Grant of a machine identity whose credential the decision table
// asks about (AskedGrant).
func TargetFaults(grant string) []Fault {
	return []Fault{
		{Name: "a missing row", Check: CheckRows, Table: "member_integrations", Says: "member_integrations: the source's row 1 is missing",
			Apply: statements("DELETE FROM member_integrations WHERE rowid = (SELECT min(rowid) FROM member_integrations)")},
		{Name: "an extra row", Check: CheckRows, Table: "idempotency_keys", Says: "idempotency_keys: a row the source does not have",
			Apply: statements(
				"CREATE TEMP TABLE extra AS SELECT * FROM idempotency_keys WHERE rowid = (SELECT min(rowid) FROM idempotency_keys)",
				"UPDATE extra SET idempotency_key = idempotency_key || '-extra'",
				"INSERT INTO idempotency_keys SELECT * FROM extra")},
		{Name: "a reordered audit position", Check: CheckAudit, Table: "audit_events", Says: "position 2 holds",
			Apply: statements(
				"UPDATE audit_events SET event_order = -1 WHERE event_order = 2",
				"UPDATE audit_events SET event_order = 2 WHERE event_order = 3",
				"UPDATE audit_events SET event_order = 3 WHERE event_order = -1")},
		{Name: "a moved cursor", Check: CheckAudit, Table: "webhooks", Says: "the cursor moved (cursor_order)",
			Apply: statements("UPDATE webhooks SET cursor_order = cursor_order + 1 WHERE id = (SELECT min(id) FROM webhooks)")},
		{Name: "a changed grant", Check: CheckAuthorization, Says: "denies (PERMISSION_DENIED)",
			Apply: statements("UPDATE grants SET revoked_at = 1795000000000000 WHERE id = '" + grant + "'")},
		{Name: "a changed passkey counter", Check: CheckAuthentication, Table: "passkey", Says: "counter changed",
			Apply: statements("UPDATE passkeys SET counter = counter + 1 WHERE id = (SELECT min(id) FROM passkeys)")},
		{Name: "a changed passkey flag", Check: CheckAuthentication, Table: "passkey", Says: "backedUp changed",
			Apply: statements("UPDATE passkeys SET backed_up = 1 - backed_up WHERE id = (SELECT min(id) FROM passkeys)")},
		{Name: "a changed credential expiry", Check: CheckAuthentication, Table: "credentials", Says: "expires_at changed",
			Apply: statements("UPDATE credentials SET expires_at = expires_at + 1000000 WHERE rowid = (SELECT min(rowid) FROM credentials WHERE expires_at IS NOT NULL)")},
		{Name: "a requirements row out of physical order", Check: CheckRows, Table: "requirements",
			Says: "requirements: the target holds the source's rows out of the source's physical order, from row 1",
			Apply: statements(
				"CREATE TEMP TABLE moved AS SELECT * FROM requirements WHERE rowid = (SELECT min(rowid) FROM requirements)",
				"DELETE FROM requirements WHERE id = (SELECT id FROM moved)",
				"INSERT INTO requirements SELECT * FROM moved")},
		{Name: "a session kept", Check: CheckAuthentication, Table: "session", Says: "browser sessions kept",
			Apply: statements("INSERT INTO auth_sessions (id, expires_at, token_hash, created_at, updated_at, user_id) " +
				"VALUES ('ses_kept', 1895000000000000, 'kept', 1795000000000000, 1795000000000000, 'usr_migration')")},
		{Name: "a table the manifest does not account for", Check: CheckRows, Table: "unaccounted",
			Apply: statements("CREATE TABLE unaccounted (x INTEGER)")},
		{Name: "a browser credential of an ended session left live", Check: CheckAuthentication, Table: "credentials", Says: "is not revoked",
			Apply: statements("UPDATE credentials SET revoked_at = NULL WHERE id = 'crd_migration_browser'")},
	}
}

// AskedGrant is a live Grant of a machine identity whose credential the
// decisions ask about: its credentials' answers rest on it.
func AskedGrant(t testing.TB, db *sql.DB, decisions []bundle.Decision) string {
	t.Helper()
	asked := map[string]bool{}
	for _, d := range decisions {
		asked[d.Credential] = true
	}
	rows, err := db.Query(`SELECT g.id, c.id FROM grants g JOIN identities i ON i.id = g.subject_identity_id
		JOIN credentials c ON c.identity_id = i.id AND c.revoked_at IS NULL
		WHERE g.revoked_at IS NULL AND i.kind <> 'human' ORDER BY g.id, c.id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var g, c string
		if err := rows.Scan(&g, &c); err != nil {
			t.Fatal(err)
		}
		if asked[c] {
			return g
		}
	}
	t.Fatal("no machine identity's Grant the decision table asks about")
	return ""
}

// CopyDB is a writable copy of the database at path.
func CopyDB(t testing.TB, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// Damage runs statements on the database at path, its triggers dropped
// first (the audit log's append-only ones would refuse a damage), foreign
// keys off. A statement that is not CREATE must change a row.
func Damage(t testing.TB, path string, stmts ...string) {
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
		if n, _ := res.RowsAffected(); n == 0 && !strings.HasPrefix(q, "CREATE") {
			t.Fatalf("%s: no row changed", q)
		}
	}
}

// FlipCiphertext changes one ciphertext byte of the envelope in column of
// table's first row where: the envelope stays well formed, its ciphertext
// does not open.
func FlipCiphertext(t testing.TB, path, table, column, where string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	var rowid int64
	err = db.QueryRow(`SELECT rowid, "`+column+`" FROM "`+table+`" WHERE `+where+` ORDER BY rowid LIMIT 1`).Scan(&rowid, &raw)
	db.Close()
	if err != nil {
		t.Fatalf("%s.%s: %v", table, column, err)
	}
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
	Damage(t, path, fmt.Sprintf(`UPDATE "%s" SET "%s" = '%s' WHERE rowid = %d`, table, column, strings.ReplaceAll(string(b), "'", "''"), rowid))
}

// Tuples are a decision table's questions: every credential of an identity
// with a Grant, a role or a machine identity's Organization, asking every
// action on the Organization, and the environment actions on each
// environment of each Project there; active, and for every tenth pair,
// expired and revoked too; with no Tailnet Context, and for the actions
// Requirements constrain, with one too. every keeps one pair in every
// (1 for all of them).
func Tuples(t testing.TB, db *sql.DB, every int) []bundle.Decision {
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
		if every > 1 && i%every != 0 {
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

// Forms are a secret's spellings a scan looks for: its bytes, hex and
// base64 (standard and URL, padded or not).
func Forms(secret []byte) [][]byte {
	return [][]byte{secret, []byte(fmt.Sprintf("%x", secret)), []byte(base64.StdEncoding.EncodeToString(secret)),
		[]byte(base64.RawStdEncoding.EncodeToString(secret)), []byte(base64.URLEncoding.EncodeToString(secret)),
		[]byte(base64.RawURLEncoding.EncodeToString(secret))}
}
