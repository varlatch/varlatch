// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
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
