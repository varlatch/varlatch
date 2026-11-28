// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !g6fixture

package db

import (
	"context"
	"path/filepath"
	"testing"
)

// Schema version 8 makes the approval tables again with installation.upgrade
// in the operation CHECK (ADR-0065): every intent and challenge a version 7
// database held is still there, a challenge still goes with its intent, the
// new operation is accepted and an unknown one still refused.
func TestVersion8KeepsTheApprovals(t *testing.T) {
	ctx := context.Background()
	older := openFile(t, filepath.Join(t.TempDir(), "v7.db"))
	defer older.Close()
	intent := func(id, operation string) string {
		return "INSERT INTO approval_intents (id, credential_id, identity_id, auth_session_id, operation, target, body_hash, query_hash, summary, origin, created_at, expires_at, poll_interval) " +
			"VALUES ('" + id + "', 'crd_a', 'idn_a', 'ses_a', '" + operation + "', '{}', 'b', 'q', '{}', 'dashboard', 1, 2, 5)"
	}
	exec(t, older, schemaBefore(t, v7Marker),
		"INSERT INTO schema_version (version, compatible_from, created_at, created_by_release, updated_at, updated_by_release) VALUES (7, 1, 1, '0.51.0', 1, '0.51.0')",
		"INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')",
		"INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_a', 'idn_a', 'browser', 'h')",
		intent("apr_one", "passkey.remove"), intent("apr_two", "passkey.remove"),
		"INSERT INTO approval_intent_challenges (id, intent_id, identity_id, auth_session_id, challenge, created_at, expires_at) VALUES ('apc_one', 'apr_one', 'idn_a', 'ses_a', 'c1', 1, 2)",
		"INSERT INTO approval_intent_challenges (id, intent_id, identity_id, auth_session_id, challenge, created_at, expires_at) VALUES ('apc_two', 'apr_two', 'idn_a', 'ses_a', 'c2', 1, 2)",
	)
	if err := tryExec(older, intent("apr_up", "installation.upgrade")); err == nil {
		t.Fatal("version 7 accepted installation.upgrade")
	}
	up, err := Upgrade(ctx, older, testRelease)
	if err != nil || up.From != 7 || up.To != SchemaVersion || up.CompatibleFrom != 1 {
		t.Fatalf("%+v %v", up, err)
	}
	count := func(q string) int {
		var n int
		if err := older.Reader().QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("SELECT count(*) FROM approval_intents") != 2 || count("SELECT count(*) FROM approval_intent_challenges") != 2 {
		t.Fatal("rows lost")
	}
	if count("SELECT count(*) FROM sqlite_schema WHERE name LIKE '%_v7'") != 0 {
		t.Fatal("the old tables are left")
	}
	exec(t, older, intent("apr_up", "installation.upgrade"), "DELETE FROM approval_intents WHERE id = 'apr_one'")
	if count("SELECT count(*) FROM approval_intent_challenges WHERE id = 'apc_one'") != 0 || count("SELECT count(*) FROM approval_intent_challenges") != 1 {
		t.Fatal("the challenge does not go with its intent")
	}
	if err := tryExec(older, intent("apr_bad", "installation.downgrade")); err == nil {
		t.Fatal("an unknown operation was accepted")
	}
}
