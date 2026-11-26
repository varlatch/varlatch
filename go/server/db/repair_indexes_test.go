// SPDX-License-Identifier: AGPL-3.0-or-later

package db

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
)

// namedQuery is the text of the query called name in queries/file, with
// each sqlc.arg(...) a parameter.
func namedQuery(t *testing.T, file, name string) string {
	t.Helper()
	b, err := os.ReadFile("queries/" + file)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	i := strings.Index(text, "-- name: "+name+" ")
	if i < 0 {
		t.Fatalf("queries/%s has no query %s", file, name)
	}
	text = text[i:]
	if j := strings.Index(text, ";"); j >= 0 {
		text = text[:j]
	}
	return regexp.MustCompile(`sqlc\.arg\(\w+\)`).ReplaceAllString(text, "?")
}

// The repair of Capabilities earlier retirements left live reads an
// identity's latest lifecycle event and a Capability's issuance by the
// indexes of schema version 3, never by a scan of the audit log; and it
// reads the live Capabilities batch by batch along
// capabilities_live_idx, from the cursor on, with no sort of what remains.
func TestRepairQueriesUseTheirIndexes(t *testing.T) {
	s := openDB(t)
	for _, c := range []struct {
		query, index string
		args         []any
	}{
		{"LatestIdentityRetirement", "audit_events_identity_lifecycle_idx", []any{"org_a", "idn_a"}},
		{"LatestIdentityLifecycleAt", "audit_events_identity_lifecycle_idx", []any{"org_a", "idn_a", int64(10)}},
		{"CapabilityIssuedOrder", "audit_events_capability_issued_idx", []any{"org_a", "cap_a"}},
		{"LiveCapabilitiesForRepair", "capabilities_live_idx", []any{int64(1), "org_a", "cap_a", int64(200)}},
	} {
		rows, err := s.Reader().QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+namedQuery(t, "capabilities.sql", c.query), c.args...)
		if err != nil {
			t.Fatalf("%s: %v", c.query, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		joined := strings.Join(plan, "; ")
		if !strings.Contains(joined, "USING INDEX "+c.index) || strings.Contains(joined, "TEMP B-TREE") {
			t.Errorf("%s: %s, want it read by %s with no sort", c.query, joined, c.index)
		}
	}
}
