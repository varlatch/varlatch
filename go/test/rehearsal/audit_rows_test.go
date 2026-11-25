// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// VL_RH_AUDIT_ROWS (VL_RH_ONLY=bundle; off by default) makes the bundle the size
// of an installation that has been used: so many audit events more, of about
// 1.4 kB each in PostgreSQL and 110 bytes in the archive, and with them the
// credentials and the exposure rows such an installation has. The harness's
// SQL, never product code: past the trigger that assigns positions (a row of
// it updated for each event of one transaction), which are given here, in
// order and without gaps.
const (
	auditRowBytes = 1180 // of a row's columns; with its header and the page's
	auditCreds    = 4000
	auditExposure = 2000
)

func auditRows(t *testing.T, in *installation) {
	want := os.Getenv("VL_RH_AUDIT_ROWS")
	if want == "" {
		return
	}
	n, err := strconv.Atoi(want)
	if err != nil || n < 1 {
		t.Fatalf("VL_RH_AUDIT_ROWS=%q: a number", want)
	}
	random := 8
	if v := os.Getenv("VL_RH_AUDIT_RANDOM"); v != "" {
		if random, err = strconv.Atoi(v); err != nil {
			t.Fatal(err)
		}
	}
	began := time.Now()
	const types = `('value.written','value.disclosed','secret.disclosed')`
	one := func(query string) string {
		r := in.psql(query)
		if r.code != 0 {
			t.Fatalf("the audit rows: %s", r)
		}
		return strings.TrimSpace(r.stdout)
	}
	avg, err := strconv.Atoi(one(`SELECT coalesce(round(avg(pg_column_size(e.*))), 0) FROM audit_events e WHERE event_type IN ` + types))
	if err != nil || avg == 0 {
		t.Fatalf("the audit rows: no event to make them after (%d, %v)", avg, err)
	}
	pad := max(auditRowBytes-avg-random-30, 1)
	// A Varlatch id's letters, of random ones.
	const id = `substr(translate(md5(random()::text || clock_timestamp()::text || n), '0189', 'ghij') || translate(md5(random()::text), '0189', 'klmn'), 1, 26)`
	one(fmt.Sprintf(`SELECT value FROM audit_position FOR UPDATE; -- before anything: the server's own writers wait here
SET session_replication_role = replica;
INSERT INTO credentials (id, identity_id, kind, name, token_hash, created_at, expires_at)
  SELECT 'crd_' || %[1]s, (SELECT id FROM identities WHERE kind = 'service' ORDER BY id LIMIT 1), 'agent-run', 'run ' || n,
    md5(random()::text || n) || md5(n || random()::text), now() - interval '60 days' + n * interval '19 minutes', now() - interval '59 days' + n * interval '18 minutes'
  FROM generate_series(1, %[2]d) n;
INSERT INTO member_exposure (organization_id, identity_id, version_id, item_name, environment_id, way, first_at, last_at)
  SELECT p.organization_id, (SELECT id FROM identities WHERE kind = 'human' ORDER BY id LIMIT 1), v.id, e.item_name, e.environment_id, w.way, now() - interval '9 days', now() - interval '1 day'
  FROM value_versions v JOIN env_values e ON e.id = v.value_id JOIN environments x ON x.id = e.environment_id JOIN projects p ON p.id = x.project_id,
    (VALUES ('revealed'), ('delivered'), ('export'), ('written')) w (way)
  ORDER BY v.id, w.way LIMIT %[3]d ON CONFLICT DO NOTHING;
CREATE TEMP TABLE like_these AS SELECT row_number() OVER (ORDER BY event_order) - 1 AS k, e.* FROM audit_events e WHERE event_type IN %[4]s;
CREATE TEMP TABLE creds AS SELECT row_number() OVER (ORDER BY id) - 1 AS k, id FROM credentials;
CREATE UNIQUE INDEX ON like_these (k); CREATE UNIQUE INDEX ON creds (k); ANALYZE like_these; ANALYZE creds;
INSERT INTO audit_events (id, schema_version, event_type, occurred_at, actor_identity_id, authentication_method_id, credential_id, organization_id, action, resource,
    decision, authz, tailnet, listener, request_id, metadata, client, event_order)
  SELECT 'evt_' || %[1]s, l.schema_version, l.event_type, now() - interval '61 days' + n * (interval '60 days' / %[5]d), l.actor_identity_id, l.authentication_method_id, c.id, l.organization_id, l.action, l.resource,
    l.decision, l.authz, l.tailnet, l.listener, 'req_' || %[1]s,
    coalesce(l.metadata, '{}'::jsonb) || jsonb_build_object('rehearsal', substr(md5(random()::text) || md5(n::text || random()::text) || md5(random()::text || 'x') || md5('y' || random()::text) || md5('z' || random()::text), 1, %[6]d),
      'padding', substr(repeat('as an event of an installation that has been used, ', 40), 1, %[7]d)),
    l.client, (SELECT value FROM audit_position) + n
  FROM generate_series(1, %[5]d) n
    JOIN like_these l ON l.k = n %% (SELECT count(*) FROM like_these) JOIN creds c ON c.k = (n * 7) %% (SELECT count(*) FROM creds);
UPDATE audit_position SET value = (SELECT max(event_order) FROM audit_events);`, id, auditCreds, auditExposure, types, n, random, pad))
	got := one(`SELECT count(*) || ' events (position ' || (SELECT value FROM audit_position) || ', ' || count(DISTINCT event_order) || ' positions from ' || min(event_order) || ' to ' || max(event_order) || '), ' ||
 pg_size_pretty(pg_table_size('audit_events')) || ' and ' || pg_size_pretty(pg_indexes_size('audit_events')) || ' of indexes; ' ||
 (SELECT count(*) FROM credentials) || ' credentials, ' || (SELECT count(*) FROM member_exposure) || ' exposure rows; the database ' || pg_size_pretty(pg_database_size('varlatch')) FROM audit_events`)
	record(t, bundleItem, "the size of one that has been used", true, fmt.Sprintf("%s, in %s", got, time.Since(began).Round(time.Second)))
}
