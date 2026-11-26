// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/varlatch/varlatch/go/server/capabilities"
)

// TestRevokeOfRetired: the upgrade's repair revokes what an earlier
// release's retirement left live (issued before the retirement, or while
// the identity was retired), and keeps what was issued after a
// reactivation, an identity suspended without a retirement (an
// Organization's deletion) and an expired Capability. Each revocation is
// audited with no actor; a second run finds nothing.
func TestRevokeOfRetired(t *testing.T) {
	r := newRetireHarness(t)
	agent, raced, suspended := r.fill("{idn:agent}"), r.fill("{idn:noread}"), r.fill("{idn:nogrant}")
	retireAsBefore := func(identity, id string) {
		t.Helper()
		if code, body := r.call(http.MethodPost, "/v1/organizations/cap/identities/{idn:"+identity+"}/retire", "alice", ""); code != http.StatusOK {
			t.Fatalf("retire %s: %d %s", identity, code, body)
		}
		r.exec("UPDATE capabilities SET revoked_at = NULL WHERE agent_identity_id = ?", id)
	}
	// The Agent's, issued before its retirement, which left them live; the
	// Agent was reactivated since.
	retireAsBefore("agent", agent)
	if code, body := r.call(http.MethodPost, "/v1/organizations/cap/identities/{idn:agent}/reactivate", "alice", ""); code != http.StatusOK {
		t.Fatalf("reactivate the Agent: %d %s", code, body)
	}
	if code, body := r.call(http.MethodPost, exercises, "broker", exercise); code != http.StatusOK {
		t.Fatalf("exercise after reactivation, before the repair: %d %s", code, body)
	}
	now := r.now().UnixMicro()
	before := r.count("SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL AND expires_at > ?", agent, now)
	expired := r.count("SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL AND expires_at <= ?", agent, now)
	if before == 0 || expired == 0 {
		t.Fatalf("the fixture's Agent has %d unexpired and %d expired live Capabilities", before, expired)
	}
	// Issued after the reactivation.
	code, body := r.call(http.MethodPost, issuances, "broker", r.fill(issuance))
	if code != http.StatusCreated {
		t.Fatalf("issue after reactivation: %d %s", code, body)
	}
	var after struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &after); err != nil {
		t.Fatal(err)
	}
	// Issued while its Agent was retired: an issuance that raced the
	// retirement.
	retireAsBefore("noread", raced)
	r.exec("UPDATE capabilities SET created_at = ? WHERE agent_identity_id = ?", r.now().UnixMicro(), raced)
	racedLive := r.count("SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL", raced)
	// An Organization's deletion suspends an identity without retiring it.
	r.exec("UPDATE identities SET disabled = 1 WHERE id = ?", suspended)
	suspendedLive := r.count("SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL", suspended)
	if racedLive == 0 || suspendedLive == 0 {
		t.Fatalf("the fixture's raced and suspended Agents have %d and %d live Capabilities", racedLive, suspendedLive)
	}

	n, err := capabilities.RevokeOfRetired(context.Background(), r.w, r.now)
	if err != nil {
		t.Fatal(err)
	}
	if n != before+racedLive {
		t.Fatalf("revoked %d, want %d", n, before+racedLive)
	}
	if code, body := r.call(http.MethodPost, exercises, "broker", exercise); code != http.StatusForbidden || refusalReason(t, body) != "revoked" {
		t.Fatalf("exercise after the repair: %d %s, want 403 (revoked)", code, body)
	}
	for _, c := range []struct {
		what string
		q    string
		args []any
		want int
	}{
		{"the Agent's live", "SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL AND expires_at > ?", []any{agent, now}, 1},
		{"issued after the reactivation, live", "SELECT count(*) FROM capabilities WHERE id = ? AND revoked_at IS NULL", []any{after.ID}, 1},
		{"the Agent's expired, untouched", "SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL AND expires_at <= ?", []any{agent, now}, expired},
		{"the raced Agent's live", "SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL", []any{raced}, 0},
		{"the suspended Agent's live", "SELECT count(*) FROM capabilities WHERE agent_identity_id = ? AND revoked_at IS NULL", []any{suspended}, suspendedLive},
		{"capability.revoked without an actor", `SELECT count(*) FROM audit_events WHERE event_type = 'capability.revoked' AND actor_identity_id IS NULL
			AND json_extract(metadata, '$.reason') = 'identity-retired'`, nil, n},
	} {
		if got := r.count(c.q, c.args...); got != c.want {
			t.Errorf("%s: %d, want %d", c.what, got, c.want)
		}
	}
	if n, err := capabilities.RevokeOfRetired(context.Background(), r.w, r.now); err != nil || n != 0 {
		t.Fatalf("a second run revoked %d (%v), want 0", n, err)
	}
}
