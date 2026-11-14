// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

// The CHECK constraints that were regular expressions (~) or LIKE in
// PostgreSQL are GLOB patterns and length checks in schema.sql. Each is
// evaluated here, as schema.sql spells it, on generated strings, and must
// accept exactly what PostgreSQL's pattern accepted (Go's regexp has the
// same semantics for these patterns: anchored, no flags, code-point
// ranges).
func TestRewrittenPatternChecks(t *testing.T) {
	s := openDB(t)
	var tableSQL = map[string]string{}
	rows, err := s.Reader().Query("SELECT name, sql FROM sqlite_schema WHERE type = 'table'")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name, text string
		if err := rows.Scan(&name, &text); err != nil {
			t.Fatal(err)
		}
		tableSQL[name] = text
	}
	rows.Close()

	for _, tc := range []struct {
		table, constraint, column string
		postgres                  string // the PostgreSQL pattern as a Go regexp
		alphabet                  string
		pieces                    []string // fragments that make matches likely
	}{
		{"device_sign_ins", "device_sign_ins_user_code_check", "user_code",
			`^[BCDFGHJKLMNPQRSTVWXZ]{8}$`, "BCDFGHJKLMNPQRSTVWXZAEIOUYbc1 é\n", []string{"BCDFGHJK", "LMNPQRST", "VWXZ"}},
		{"github_app_registrations", "github_app_registrations_account_login_check", "account_login",
			`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`, "aZ09-_. é\n", []string{"acme", "-gh", "a1b2c3d4e5f6g7h8i9j0", "-"}},
		{"audit_export_plans", "audit_export_plans_sha256_check", "sha256",
			`^[0-9a-f]{64}$`, "0123456789abcdefABCDEFg \n", []string{strings.Repeat("0123456789abcdef", 4), strings.Repeat("fedcba9876543210", 4), "f"}},
		{"audit_export_plans", "audit_export_plans_md5_check", "md5",
			`^[0-9a-f]{32}$`, "0123456789abcdefABCDEFg \n", []string{strings.Repeat("0123456789abcdef", 2), strings.Repeat("9a8b7c6d5e4f3210", 2), "a"}},
		{"security_control_counters", "security_control_counters_operation_check", "operation",
			`^[a-z][a-z_-]*(\.[a-z][a-z_-]*)+$`, "az_-.A0 é\n", []string{"secret", ".export", "member.remove", "_", "-", ".", "..", "a.b"}},
		// LIKE 'inst_%': _ is any one character, % any sequence.
		{"installation", "installation_singleton", "id",
			`(?s)^inst.`, "inst_I\n é", []string{"inst_", "inst", "INST_", "ins"}},
	} {
		t.Run(tc.constraint, func(t *testing.T) {
			expr, ok := namedChecks(t, tc.table, tableSQL[tc.table])[tc.constraint]
			if !ok {
				t.Fatalf("%s has no CHECK %s", tc.table, tc.constraint)
			}
			re := regexp.MustCompile(tc.postgres)
			stmt := "SELECT coalesce((" + expr + "), 1) FROM (SELECT ? AS " + tc.column + ")"
			rng := rand.New(rand.NewPCG(1, uint64(len(tc.constraint))))
			alphabet := []rune(tc.alphabet)
			gen := func() string {
				if rng.IntN(3) == 0 { // one fragment alone: often a match
					return tc.pieces[rng.IntN(len(tc.pieces))]
				}
				var b strings.Builder
				for range rng.IntN(8) {
					if rng.IntN(2) == 0 {
						b.WriteString(tc.pieces[rng.IntN(len(tc.pieces))])
					} else {
						b.WriteRune(alphabet[rng.IntN(len(alphabet))])
					}
				}
				return b.String()
			}
			candidates := []string{""}
			for range 4000 {
				c := gen()
				candidates = append(candidates, c)
				if r := []rune(c); len(r) > 0 { // and one character changed
					r[rng.IntN(len(r))] = alphabet[rng.IntN(len(alphabet))]
					candidates = append(candidates, string(r))
				}
			}
			matches := 0
			for _, c := range candidates {
				var got bool
				if err := s.Reader().QueryRowContext(context.Background(), stmt, c).Scan(&got); err != nil {
					t.Fatalf("%q: %v", c, err)
				}
				want := re.MatchString(c)
				if got != want {
					t.Fatalf("%q: SQLite's CHECK says %v, PostgreSQL's pattern %v", c, got, want)
				}
				if want {
					matches++
				}
			}
			if matches < 50 || matches > len(candidates)-50 {
				t.Fatalf("%d of %d candidates match: too few of one kind to compare", matches, len(candidates))
			}
		})
	}
}

// date_trunc('hour', bucket_hour, 'UTC') = bucket_hour, on microseconds.
func TestBucketHourCheck(t *testing.T) {
	s := openDB(t)
	insert := func(bucket int64) error {
		return tryExec(s, `INSERT INTO security_control_counters
			(organization_id, control, config_version, operation, actor_identity_id, reason, bucket_hour, count, first_seen, last_seen)
			VALUES ('org_a', 'admin-step-up', 1, 'member.remove', 'idn_a', 'no-approval', ?, 1, 0, 0)`, bucket)
	}
	const hour = int64(3_600_000_000)
	if err := insert(490_000 * hour); err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{1, 1_000_000, hour / 2, hour - 1} {
		refusedBy(t, insert(490_001*hour+off), "security_control_counters_bucket_hour_check")
	}
}

// The security-controls config check: jsonb_typeof 'number' is SQLite's
// 'integer' or 'real'. The verdicts are PostgreSQL's for the same values.
func TestCredentialLifetimeConfigCheck(t *testing.T) {
	s := openDB(t)
	exec(t, s, "INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'acme', 'Acme', '{}')")
	for _, tc := range []struct {
		config string
		ok     bool
	}{
		{`{"defaultTtlSeconds": 3600, "maxTtlSeconds": 86400}`, true},
		{`{"defaultTtlSeconds": 1.5, "maxTtlSeconds": 1.5}`, true},
		{`{"defaultTtlSeconds": 0, "maxTtlSeconds": 10}`, false},
		{`{"defaultTtlSeconds": 20, "maxTtlSeconds": 10}`, false},
		{`{"defaultTtlSeconds": "3600", "maxTtlSeconds": 86400}`, false},
		// A missing key makes PostgreSQL's expression NULL, which a CHECK
		// accepts (checked on PGlite); SQLite's does the same.
		{`{"maxTtlSeconds": 86400}`, true},
		{`{"defaultTtlSeconds": 5}`, true},
		{`{}`, true},
		{`[3600, 86400]`, false},
		{`not json`, false},
	} {
		err := tryExec(s, `INSERT INTO security_controls (organization_id, control, mode, config, version)
			VALUES ('org_a', 'credential-lifetime', 'report', ?, 1)`, tc.config)
		if err == nil {
			exec(t, s, "DELETE FROM security_controls")
		}
		if tc.ok && err != nil {
			t.Errorf("%s: %v", tc.config, err)
		}
		if !tc.ok {
			refusedBy(t, err, "CHECK constraint failed")
		}
	}
}

// PostgreSQL's integer is 32-bit; SQLite's INTEGER 64. Each widened column
// keeps PostgreSQL's range (int4_<column>), intersected with its own
// checks; bigint stays 64-bit. mapping_test.go checks every column; these
// write through lib/storage at both edges of each class.
func TestIntegerRanges(t *testing.T) {
	s := openDB(t)
	exec(t, s,
		"INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'A')",
		"INSERT INTO auth_users (id, name, email) VALUES ('bau_a', 'A', 'a@varlatch.placeholder.invalid')",
		"INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'acme', 'Acme', '{}')")
	const lo, hi = int64(-2147483648), int64(2147483647)
	n := 0
	passkey := func(counter int64) error {
		n++
		return tryExec(s, `INSERT INTO passkeys (id, public_key, user_id, credential_id, counter, device_type, backed_up)
			VALUES (?, 'k', 'bau_a', ?, ?, 'singleDevice', 0)`, fmt.Sprint("pk_", n), fmt.Sprint("cred-", n), counter)
	}
	credential := func(maxUses int64) error {
		n++
		return tryExec(s, "INSERT INTO credentials (id, identity_id, kind, token_hash, max_uses) VALUES (?, 'idn_a', 'cli', ?, ?)",
			fmt.Sprint("crd_", n), fmt.Sprint("h", n), maxUses)
	}
	// integer with no bound of its own: the whole 32-bit range. A WebAuthn
	// counter (unsigned 32-bit) above it is refused, never stored negative.
	for _, v := range []int64{lo, hi, 0} {
		if err := passkey(v); err != nil {
			t.Fatalf("counter %d: %v", v, err)
		}
	}
	for _, v := range []int64{lo - 1, hi + 1, 4294967295} {
		refusedBy(t, passkey(v), "int4_counter")
	}
	// integer bounded below by PostgreSQL (max_uses > 0): its own lower
	// bound, PostgreSQL's ceiling.
	if err := credential(hi); err != nil {
		t.Fatal(err)
	}
	refusedBy(t, credential(hi+1), "int4_max_uses")
	refusedBy(t, credential(0), "credentials_max_uses_check")
	// integer bounded on both sides by PostgreSQL (requested_ttl between 60
	// and 86400): its own check, no range check.
	for _, v := range []int64{59, 86401, hi + 1} {
		refusedBy(t, tryExec(s, "INSERT INTO device_sign_ins (id, device_code_hash, user_code, requested_ttl, expires_at) VALUES ('dsi_a', 'h', 'BCDFGHJK', ?, 0)", v),
			"device_sign_ins_requested_ttl_check")
	}
	// bigint: SQLite's whole range; beyond it a literal is a REAL, which a
	// STRICT INTEGER column refuses.
	for _, v := range []int64{-9223372036854775808, 9223372036854775807} {
		exec(t, s, fmt.Sprintf("UPDATE organizations SET security_epoch = %d", v))
	}
	refusedBy(t, tryExec(s, "UPDATE organizations SET security_epoch = 9223372036854775808"), "cannot store REAL value in INTEGER column")
}

// text[] columns hold JSON arrays of strings or nulls (PostgreSQL arrays
// allow NULL elements), on insert and on update.
func TestTextArrayElements(t *testing.T) {
	s := openDB(t)
	exec(t, s,
		"INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'A')",
		"INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_a', 'acme', 'Acme', '{}')",
		"INSERT INTO identities (id, kind, name, organization_id) VALUES ('idn_b', 'broker', 'B', 'org_a'), ('idn_g', 'agent', 'G', 'org_a')",
		"INSERT INTO projects (id, organization_id, slug, name, contract_authority) VALUES ('prj_a', 'org_a', 'api', 'API', 'managed')",
		"INSERT INTO environments (id, project_id, name, kind, tier) VALUES ('env_a', 'prj_a', 'dev', 'shared', 'development')")
	n := 0
	inserts := map[string]func(string) error{
		"roles.actions": func(v string) error {
			n++
			return tryExec(s, "INSERT INTO roles (id, organization_id, name, actions) VALUES (?, 'org_a', ?, ?)", fmt.Sprint("rol_", n), fmt.Sprint("r", n), v)
		},
		"grants.actions": func(v string) error {
			n++
			return tryExec(s, "INSERT INTO grants (id, organization_id, subject_identity_id, scope, actions) VALUES (?, 'org_a', 'idn_a', '{}', ?)", fmt.Sprint("grt_", n), v)
		},
		"capabilities.items": func(v string) error {
			n++
			return tryExec(s, `INSERT INTO capabilities (id, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id, items, destinations, secret_hash, expires_at, created_by)
				VALUES (?, 'org_a', 'idn_b', 'idn_g', 'prj_a', 'env_a', ?, '[]', 'h', 0, 'idn_a')`, fmt.Sprint("cap_", n), v)
		},
		"capabilities.destinations": func(v string) error {
			n++
			return tryExec(s, `INSERT INTO capabilities (id, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id, items, destinations, secret_hash, expires_at, created_by)
				VALUES (?, 'org_a', 'idn_b', 'idn_g', 'prj_a', 'env_a', '[]', ?, 'h', 0, 'idn_a')`, fmt.Sprint("cap_", n), v)
		},
		"member_integrations.changes": func(v string) error {
			n++
			return tryExec(s, "INSERT INTO member_integrations (organization_id, identity_id, kind, resource_id, changes, first_at, last_at) VALUES ('org_a', 'idn_a', 'target', ?, ?, 0, 0)", fmt.Sprint("syt_", n), v)
		},
		"webhooks.event_types": func(v string) error {
			n++
			return tryExec(s, "INSERT INTO webhooks (id, organization_id, url, event_types, secret_envelope, cursor_occurred_at) VALUES (?, 'org_a', 'https://h.invalid', ?, '{}', 0)", fmt.Sprint("whk_", n), v)
		},
	}
	good := []string{`[]`, `["secret.use"]`, `["a", null, "b"]`}
	bad := []string{`[1]`, `["a", 2.5]`, `[true]`, `[["a"]]`, `[{"a": "b"}]`}
	for col, insert := range inserts {
		table, column, _ := strings.Cut(col, ".")
		for _, v := range good {
			if err := insert(v); err != nil {
				t.Fatalf("%s = %s: %v", col, v, err)
			}
		}
		for _, v := range bad {
			refusedBy(t, insert(v), table+"_text_arrays")
			refusedBy(t, tryExec(s, fmt.Sprintf("UPDATE %s SET %s = ?", table, column), v), table+"_text_arrays")
		}
		// Not an array at all: the CHECK.
		refusedBy(t, insert(`"a"`), "CHECK constraint failed")
		if err := tryExec(s, fmt.Sprintf("UPDATE %s SET %s = ?", table, column), `["x", null]`); err != nil {
			t.Fatalf("%s: a good update: %v", col, err)
		}
	}
}
