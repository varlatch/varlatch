// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/capabilities"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/maintenance"
	"github.com/varlatch/varlatch/go/server/write"
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
	r.suspendByDeletion(suspended)
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

// suspendByDeletion disables the identity as an Organization's deletion
// does (here, a deletion since cancelled): suspended, not retired.
func (r *retireHarness) suspendByDeletion(identity string) {
	r.t.Helper()
	r.exec(`INSERT INTO organization_deletions (id, organization_id, requested_by, run_after, approval_required, cancelled_by, cancelled_at)
		SELECT 'odl_test', organization_id, (SELECT id FROM identities WHERE installation_admin = 1 LIMIT 1), ?, 0,
		       (SELECT id FROM identities WHERE installation_admin = 1 LIMIT 1), ?
		FROM identities WHERE id = ?`, time.Now().Add(48*time.Hour).UnixMicro(), time.Now().UnixMicro(), identity)
	r.exec("UPDATE identities SET disabled = 1, suspended_by_deletion = 'odl_test' WHERE id = ?", identity)
}

func (r *retireHarness) retire(identity string) {
	r.t.Helper()
	if code, body := r.call(http.MethodPost, "/v1/organizations/cap/identities/{idn:"+identity+"}/retire", "alice", ""); code != http.StatusOK {
		r.t.Fatalf("retire %s: %d %s", identity, code, body)
	}
}

func (r *retireHarness) reactivate(identity string) {
	r.t.Helper()
	if code, body := r.call(http.MethodPost, "/v1/organizations/cap/identities/{idn:"+identity+"}/reactivate", "alice", ""); code != http.StatusOK {
		r.t.Fatalf("reactivate %s: %d %s", identity, code, body)
	}
}

func (r *retireHarness) issue() string {
	r.t.Helper()
	code, body := r.call(http.MethodPost, issuances, "broker", r.fill(issuance))
	if code != http.StatusCreated {
		r.t.Fatalf("issue: %d %s", code, body)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		r.t.Fatal(err)
	}
	return out.ID
}

// imported copies the Capability from as id, live for days, with no
// capability.issued: an imported row.
func (r *retireHarness) imported(from, id string, days int) {
	r.t.Helper()
	r.exec(`INSERT INTO capabilities (id, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id,
		  items, destinations, secret_hash, run_id, expires_at, revoked_at, created_by, created_at, targets)
		SELECT ?, organization_id, broker_identity_id, agent_identity_id, project_id, environment_id,
		  items, destinations, secret_hash || 'x', run_id, ?, NULL, created_by, ?, targets
		FROM capabilities WHERE id = ?`,
		id, r.now().Add(time.Duration(days)*24*time.Hour).UnixMicro(), r.now().UnixMicro(), from)
}

func (r *retireHarness) live(id string) bool {
	r.t.Helper()
	return r.count("SELECT count(*) FROM capabilities WHERE id = ? AND revoked_at IS NULL", id) == 1
}

// TestRevokeOfRetiredByAuditOrder: an issuance after a reactivation is
// placed by the audit log, not by its row's created_at, which may precede
// the reactivation's time.
func TestRevokeOfRetiredByAuditOrder(t *testing.T) {
	r := newRetireHarness(t)
	r.retire("agent")
	r.reactivate("agent")
	after := r.issue()
	r.exec("UPDATE capabilities SET created_at = created_at - ? WHERE id = ?", time.Hour.Microseconds(), after)
	if n, err := capabilities.RevokeOfRetired(context.Background(), r.w, r.now); err != nil || n != 0 {
		t.Fatalf("revoked %d (%v), want 0", n, err)
	}
	if !r.live(after) {
		t.Fatal("the Capability issued after the reactivation was revoked")
	}
}

// TestRevokeOfRetiredFindsAFarIssuance: an issuance after a reactivation is
// found however far its row's created_at is from its capability.issued (an
// imported Capability's), not only within a window around it.
func TestRevokeOfRetiredFindsAFarIssuance(t *testing.T) {
	r := newRetireHarness(t)
	r.retire("agent")
	r.reactivate("agent")
	after := r.issue()
	r.exec("UPDATE capabilities SET created_at = created_at - ? WHERE id = ?", (3 * 24 * time.Hour).Microseconds(), after)
	if n, err := capabilities.RevokeOfRetired(context.Background(), r.w, r.now); err != nil || n != 0 {
		t.Fatalf("revoked %d (%v), want 0", n, err)
	}
	if !r.live(after) {
		t.Fatal("the Capability issued after the reactivation was revoked")
	}
}

// TestRevokeOfRetiredInBatches: the repair holds the writer for at most a
// batch of Capabilities at a time, and repairs them all.
func TestRevokeOfRetiredInBatches(t *testing.T) {
	r := newRetireHarness(t)
	var ended []string
	for range 5 {
		ended = append(ended, r.issue())
	}
	r.retire("agent")
	r.exec("UPDATE capabilities SET revoked_at = NULL WHERE agent_identity_id = ?", r.fill("{idn:agent}"))
	r.reactivate("agent")
	var kept []string
	for range 3 {
		kept = append(kept, r.issue())
	}
	live := r.count("SELECT count(*) FROM capabilities WHERE revoked_at IS NULL AND expires_at > ?", r.now().UnixMicro())
	var batches []int
	capabilities.SetAfterBatch(func(n int) { batches = append(batches, n) })
	defer capabilities.SetAfterBatch(nil)
	n, err := capabilities.RevokeOfRetiredInBatches(context.Background(), r.w, r.now, 2)
	if err != nil || n < len(ended) {
		t.Fatalf("revoked %d (%v), want at least %d", n, err, len(ended))
	}
	for _, id := range ended {
		if r.live(id) {
			t.Fatalf("%s is live", id)
		}
	}
	for _, id := range kept {
		if !r.live(id) {
			t.Fatalf("%s was revoked", id)
		}
	}
	total := 0
	for _, b := range batches {
		if b > 2 {
			t.Fatalf("a batch of %d (%v)", b, batches)
		}
		total += b
	}
	if total != live || len(batches) != live/2+1 {
		t.Fatalf("batches %v for %d live Capabilities", batches, live)
	}
}

// TestRevokeOfRetiredReadsAllHistory: a retirement older than two days
// still ends a Capability that outlives a day (an imported one).
func TestRevokeOfRetiredReadsAllHistory(t *testing.T) {
	r := newRetireHarness(t)
	id := r.issue()
	r.retire("agent")
	r.exec("UPDATE capabilities SET revoked_at = NULL, expires_at = ? WHERE id = ?", r.now().Add(5*24*time.Hour).UnixMicro(), id)
	r.skew.Add((3 * 24 * time.Hour).Microseconds())
	if n, err := capabilities.RevokeOfRetired(context.Background(), r.w, r.now); err != nil || n != 1 {
		t.Fatalf("revoked %d (%v), want 1", n, err)
	}
	if r.live(id) {
		t.Fatal("the retired Agent's Capability is live")
	}
}

// TestRevokeOfRetiredWithoutIssuance: a Capability whose capability.issued
// is not found is revoked once its identity was ever retired, and kept
// otherwise.
func TestRevokeOfRetiredWithoutIssuance(t *testing.T) {
	r := newRetireHarness(t)
	id := r.issue()
	r.retire("agent")
	r.reactivate("agent")
	r.imported(id, "cap_imported_retired", 3)
	kept := r.fill("{cap:live}")
	r.exec("UPDATE capabilities SET agent_identity_id = ? WHERE id = ?", r.fill("{idn:nogrant}"), kept)
	r.imported(kept, "cap_imported_kept", 3)
	if n, err := capabilities.RevokeOfRetired(context.Background(), r.w, r.now); err != nil || n != 1 {
		t.Fatalf("revoked %d (%v), want 1", n, err)
	}
	if r.live("cap_imported_retired") || !r.live("cap_imported_kept") {
		t.Fatalf("imported: retired Agent's live %v, never-retired Agent's live %v", r.live("cap_imported_retired"), r.live("cap_imported_kept"))
	}
}

// TestRevokeOfRetiredRetiredNow: an identity retired now (disabled, not
// by a deletion) ends its Capabilities whatever its audit history.
func TestRevokeOfRetiredRetiredNow(t *testing.T) {
	r := newRetireHarness(t)
	id := r.issue()
	r.exec("UPDATE identities SET disabled = 1 WHERE id = ?", r.fill("{idn:agent}"))
	if n, err := capabilities.RevokeOfRetired(context.Background(), r.w, r.now); err != nil || n == 0 {
		t.Fatalf("revoked %d (%v), want some", n, err)
	}
	if r.live(id) {
		t.Fatal("the retired Agent's Capability is live")
	}
}

func admitted() (func(), bool) { return func() {}, true }

// TestCapabilitiesWaitForTheRepair: issuance and exercise answer 503
// MAINTENANCE until the repair has run, also after it failed, and again
// once it is invalidated.
func TestCapabilitiesWaitForTheRepair(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	repair := &capabilities.Repair{Run: func(ctx context.Context, w *write.Writer, now func() time.Time) (int, error) {
		if fail.Load() {
			return 0, errors.New("disk I/O error")
		}
		return 0, nil
	}}
	r := newRetireHarnessWith(t, func(o *httpserver.Options) { o.Capabilities = repair })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	refused := func(what string, code int, body string) {
		t.Helper()
		if code != http.StatusServiceUnavailable || !strings.Contains(body, "MAINTENANCE") {
			t.Fatalf("%s: %d %s, want 503 MAINTENANCE", what, code, body)
		}
	}
	code, body := r.call(http.MethodPost, issuances, "broker", r.fill(issuance))
	refused("issue before the repair", code, body)
	code, body = r.call(http.MethodPost, exercises, "broker", exercise)
	refused("exercise before the repair", code, body)
	if repair.Attempt(context.Background(), r.w, admitted, r.now, log) {
		t.Fatal("a failed repair counted")
	}
	code, body = r.call(http.MethodPost, issuances, "broker", r.fill(issuance))
	refused("issue after a failed repair", code, body)
	fail.Store(false)
	if !repair.Attempt(context.Background(), r.w, admitted, r.now, log) {
		t.Fatal("the repair did not count")
	}
	if code, body := r.call(http.MethodPost, issuances, "broker", r.fill(issuance)); code != http.StatusCreated {
		t.Fatalf("issue after the repair: %d %s", code, body)
	}
	if code, body := r.call(http.MethodPost, exercises, "broker", exercise); code != http.StatusOK {
		t.Fatalf("exercise after the repair: %d %s", code, body)
	}
	repair.Invalidate()
	code, body = r.call(http.MethodPost, issuances, "broker", r.fill(issuance))
	refused("issue once invalidated", code, body)
}

// TestRepairLoopStartsAtOnce: the loop attempts the repair when it starts,
// not after its first interval.
func TestRepairLoopStartsAtOnce(t *testing.T) {
	r := newRetireHarness(t)
	repair := &capabilities.Repair{Run: func(ctx context.Context, w *write.Writer, now func() time.Time) (int, error) {
		return 0, nil
	}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		repair.Loop(ctx, time.Hour, r.w, admitted, func() bool { return false }, r.now, log)
	}()
	defer func() { cancel(); <-done }()
	for i := 0; i < 400 && !repair.Ready(); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if !repair.Ready() {
		t.Fatal("the loop waited for its first interval")
	}
}

// TestRepairWaitsForTheAdmission: the repair runs inside the maintenance
// admission: not while an upgrade holds varlatchd, at once when it ends;
// a gate makes it wait and run again.
func TestRepairWaitsForTheAdmission(t *testing.T) {
	r := newRetireHarness(t)
	admission := maintenance.Open(t.TempDir(), nil)
	admission.HoldForUpgrade()
	var runs atomic.Int32
	repair := &capabilities.Repair{Run: func(ctx context.Context, w *write.Writer, now func() time.Time) (int, error) {
		runs.Add(1)
		return 0, nil
	}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if repair.Attempt(context.Background(), r.w, admission.Enter, r.now, log) || runs.Load() != 0 {
		t.Fatal("the repair ran behind the upgrade's hold")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); repair.Loop(ctx, 5*time.Millisecond, r.w, admission.Enter, admission.Isolated, r.now, log) }()
	defer func() { cancel(); <-done }()
	time.Sleep(30 * time.Millisecond)
	if repair.Ready() || runs.Load() != 0 {
		t.Fatal("the repair ran behind the upgrade's hold")
	}
	admission.EndUpgrade()
	wait := func(ready bool) {
		t.Helper()
		for i := 0; i < 400 && repair.Ready() != ready; i++ {
			time.Sleep(5 * time.Millisecond)
		}
		if repair.Ready() != ready {
			t.Fatalf("ready %v, want %v", !ready, ready)
		}
	}
	wait(true)
	if runs.Load() != 1 {
		t.Fatalf("ran %d times, want 1", runs.Load())
	}
	g, err := admission.Begin(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wait(false)
	if err := admission.End(g.ID); err != nil {
		t.Fatal(err)
	}
	wait(true)
	if runs.Load() != 2 {
		t.Fatalf("ran %d times, want 2", runs.Load())
	}
}
