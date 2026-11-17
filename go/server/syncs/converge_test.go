// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/syncs"
)

func (w *engineWorld) exec(q string, args ...any) {
	w.t.Helper()
	if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), q, args...)
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *engineWorld) targets() []paritytest.Row {
	return paritytest.Rows(w.t, w.store, `SELECT canonical_destination, generation, needs_sync, failure_count, last_result,
		next_attempt_at IS NOT NULL AS backed_off FROM sync_targets ORDER BY canonical_destination`)
}

// TestConvergedRunCommits: a run with nothing to push makes CONVERGE.md's
// commits for that path, in its order, and reports them.
func TestConvergedRunCommits(t *testing.T) {
	w := newEngineWorld(t)
	// The first pass converges every Target; then nothing is due.
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	w.exec(`UPDATE sync_targets SET needs_sync = 1 WHERE canonical_destination = '["github-actions","acme","api"]'`)
	var points []string
	var stats []syncs.RunStats
	syncs.OnCommit(w.engine, func(p string) { points = append(points, p) })
	w.engine.OnRun = func(s syncs.RunStats) { stats = append(stats, s) }
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	want := []string{"lease", "values-decrypted", "result", "lease-release", "run-row"}
	if !slices.Equal(points, want) {
		t.Errorf("commits %v, want %v", points, want)
	}
	if len(stats) != 1 || stats[0].Commits != len(want) || stats[0].Generation != 2 || stats[0].Duration <= 0 || stats[0].InJobs <= 0 {
		t.Errorf("reports %+v", stats)
	}
}

// TestRefusedRunIsNotAFailure: every request refused by the outbound
// policy (here each platform resolves to a private address) ends each run
// as a refusal: outbound_refused with its reason, the longest backoff, no
// failure counted, the Target still due; and the refusal audited.
func TestRefusedRunIsNotAFailure(t *testing.T) {
	w := newEngineWorld(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := outbound.New(nil, outbound.Options{Log: log, Resolve: func(context.Context, string) ([]outbound.Answer, error) {
		return []outbound.Answer{{Address: "10.1.2.3", Family: 4}}, nil
	}})
	t.Cleanup(policy.Close)
	w.engine.Policy = policy
	syncs.UseClient(w.engine, nil)
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	for _, r := range w.targets() {
		result, _ := r["last_result"].(string)
		if !strings.HasPrefix(result, "outbound_refused: ") || r["failure_count"] != int64(0) || r["needs_sync"] != int64(1) || r["backed_off"] != int64(1) {
			t.Errorf("%v: %v", r["canonical_destination"], r)
		}
	}
	if len(w.fake.take()) != 0 {
		t.Error("a refused request reached a platform")
	}
	if rows := paritytest.Rows(t, w.store, `SELECT count(*) AS n FROM audit_events WHERE event_type = 'outbound.refused'`); rows[0]["n"].(int64) == 0 {
		t.Error("no refusal audited")
	}
}

// TestOutOfBudgetYields: a run whose deadline passed stops at its next send
// check and yields: still due, nothing counted, no result recorded.
func TestOutOfBudgetYields(t *testing.T) {
	w := newEngineWorld(t)
	w.engine.RunOnce(context.Background(), syncs.RunOptions{RunBudget: time.Microsecond})
	for _, r := range w.targets() {
		if r["needs_sync"] != int64(1) || r["failure_count"] != int64(0) || r["backed_off"] != int64(0) {
			t.Errorf("%v: %v", r["canonical_destination"], r)
		}
	}
	for _, line := range w.fake.take() {
		if !strings.HasPrefix(line, "GET ") && !strings.Contains(line, "/api/query ") {
			t.Errorf("sent past the deadline: %s", line)
		}
	}
	if rows := paritytest.Rows(t, w.store, `SELECT count(*) AS n FROM audit_events WHERE event_type = 'sync.push_result'`); rows[0]["n"].(int64) != 0 {
		t.Error("a push result was recorded")
	}
}

// TestFreezeMidRunYields: an incident freeze while a run sends stops it at
// its next send check; it yields, and no Target is leased again while the
// Organization stays frozen.
func TestFreezeMidRunYields(t *testing.T) {
	w := newEngineWorld(t)
	w.fake.onRequest = func(n int) {
		if n == 2 {
			w.exec(`INSERT INTO organization_freezes (id, organization_id, frozen_by, frozen_at, reason)
				SELECT 'ofz_test', id, (SELECT id FROM identities WHERE name = 'Alice'), 1, 'drill' FROM organizations`)
		}
	}
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	sent := w.fake.take()
	if len(sent) != 2 {
		t.Errorf("sent %d requests, want 2 (the freeze came at the second): %v", len(sent), sent)
	}
	for _, r := range w.targets() {
		if r["failure_count"] != int64(0) {
			t.Errorf("%v: %v", r["canonical_destination"], r)
		}
	}
	before := w.targets()
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	if after := w.targets(); len(w.fake.take()) != 0 || !slices.EqualFunc(before, after, func(a, b paritytest.Row) bool { return a["generation"] == b["generation"] }) {
		t.Errorf("a frozen Organization's Targets were leased: %v then %v", before, after)
	}
}

// TestTriggerScanSkipsNoEvent: TypeScript defect 8, fixed in Go. With 600
// events waiting, the scan reads them in order, 500 then 100: the event at
// event_order 99 (which comes after "100" to "599" as text) marks its
// environment's Targets in the first scan, the 550th event in the second,
// and the cursor ends at the last event. TypeScript's text order passes
// over event 99 for good. The scan reads one batch a pass here, as
// TypeScript's does (defect 10 drains them: TestTriggerScanDrainsBacklog).
func TestTriggerScanSkipsNoEvent(t *testing.T) {
	w := newEngineWorld(t)
	syncs.ScanBatches(w.engine, 1)
	w.exec(`INSERT INTO sync_cursor (singleton, occurred_at, event_id, cursor_order)
		SELECT 1, 0, '', max(event_order) FROM audit_events WHERE true
		ON CONFLICT (singleton) DO UPDATE SET cursor_order = excluded.cursor_order`)
	w.exec(`UPDATE sync_targets SET needs_sync = 0`)
	rows := paritytest.Rows(t, w.store, `SELECT (SELECT max(event_order) FROM audit_events) AS base, (SELECT id FROM environments LIMIT 1) AS env,
		(SELECT id FROM organizations LIMIT 1) AS org`)
	base, env, org := rows[0]["base"].(int64), rows[0]["env"].(string), rows[0]["org"].(string)
	if base >= 98 {
		t.Fatalf("the fixture's database ends at event %d: event 99 must be one of the 600", base)
	}
	second := base + 550
	if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
		for pos := base + 1; pos <= base+600; pos++ {
			named := "env_elsewhereaaaaaaaaaaaaaaaaa"
			if pos == 99 || pos == second {
				named = env
			}
			action := "config.value.write"
			if _, err := audit.Record(context.Background(), tx, audit.Event{
				Type: "value.written", Decision: audit.Info, OrganizationID: &org, Action: &action,
				Resource: jsvalue.Object{{Key: "environmentId", Value: named}},
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	marked := func() int64 {
		return paritytest.Rows(t, w.store, `SELECT count(*) AS n FROM sync_targets WHERE needs_sync = 1`)[0]["n"].(int64)
	}
	cursor := func() int64 {
		return paritytest.Rows(t, w.store, `SELECT cursor_order FROM sync_cursor`)[0]["cursor_order"].(int64)
	}
	if err := syncs.ScanTriggers(context.Background(), w.engine); err != nil {
		t.Fatal(err)
	}
	if marked() == 0 || cursor() != base+500 {
		t.Fatalf("the first scan: %d Targets marked, the cursor at %d; want them marked (event 99) and the cursor at %d", marked(), cursor(), base+500)
	}
	w.exec(`UPDATE sync_targets SET needs_sync = 0`)
	if err := syncs.ScanTriggers(context.Background(), w.engine); err != nil {
		t.Fatal(err)
	}
	if marked() == 0 || cursor() != base+600 {
		t.Fatalf("the second scan: %d Targets marked, the cursor at %d; want them marked (event %d) and the cursor at %d", marked(), cursor(), second, base+600)
	}
}

// triggerBacklog settles every Target (not due: no trigger, its repair
// pass just run), moves the trigger cursor to the end of the audit log, and
// writes n value.written events naming an environment no Target syncs,
// then one naming the environment of the Targets that are its result. It
// answers the cursor before the backlog and those Targets.
func triggerBacklog(t *testing.T, w *engineWorld, n int) (base int64, changed map[string]bool) {
	t.Helper()
	w.exec(fmt.Sprintf(`UPDATE sync_targets SET needs_sync = 0, next_attempt_at = NULL, last_repair_at = %d`, w.engine.Now().UnixMicro()))
	w.exec(`INSERT INTO sync_cursor (singleton, occurred_at, event_id, cursor_order)
		SELECT 1, 0, '', max(event_order) FROM audit_events WHERE true
		ON CONFLICT (singleton) DO UPDATE SET cursor_order = excluded.cursor_order`)
	rows := paritytest.Rows(t, w.store, `SELECT (SELECT max(event_order) FROM audit_events) AS base, (SELECT environment_id FROM sync_targets WHERE revoked_at IS NULL LIMIT 1) AS env,
		(SELECT id FROM organizations LIMIT 1) AS org`)
	base = rows[0]["base"].(int64)
	env, org := rows[0]["env"].(string), rows[0]["org"].(string)
	changed = map[string]bool{}
	for _, r := range paritytest.Rows(t, w.store, `SELECT id FROM sync_targets WHERE revoked_at IS NULL AND environment_id = ?`, env) {
		changed[r["id"].(string)] = true
	}
	record := func(tx *storage.Tx, named string) error {
		action := "config.value.write"
		_, err := audit.Record(context.Background(), tx, audit.Event{
			Type: "value.written", Decision: audit.Info, OrganizationID: &org, Action: &action,
			Resource: jsvalue.Object{{Key: "environmentId", Value: named}},
		})
		return err
	}
	for written := 0; written < n; {
		if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
			for range min(5_000, n-written) {
				if err := record(tx, "env_elsewhereaaaaaaaaaaaaaaaaa"); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		written += min(5_000, n-written)
	}
	if err := w.store.Write(context.Background(), func(tx *storage.Tx) error { return record(tx, env) }); err != nil {
		t.Fatal(err)
	}
	return base, changed
}

func (w *engineWorld) cursorOrder() int64 {
	w.t.Helper()
	return paritytest.Rows(w.t, w.store, `SELECT cursor_order FROM sync_cursor`)[0]["cursor_order"].(int64)
}

// TestTriggerScanDrainsBacklog: TypeScript defect 10, fixed in Go. A value
// change behind 30,000 audit events reaches the engine in the next pass:
// the scan reads every batch to the end of the log, and the pass runs the
// changed environment's Targets, and only those. TypeScript reads one
// batch of 500 a pass, so the change would wait 61 passes (about 30
// minutes).
func TestTriggerScanDrainsBacklog(t *testing.T) {
	w := newEngineWorld(t)
	base, changed := triggerBacklog(t, w, 30_000)
	if len(changed) == 0 {
		t.Fatal("no Target syncs the changed environment")
	}
	var ran []string
	w.engine.OnRun = func(st syncs.RunStats) { ran = append(ran, st.TargetID) }
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	if got, want := w.cursorOrder(), base+30_001; got != want {
		t.Fatalf("after one pass the cursor is at %d, want the end of the log, %d", got, want)
	}
	seen := map[string]bool{}
	for _, id := range ran {
		if !changed[id] {
			t.Errorf("the pass ran Target %s, which no event changed", id)
		}
		seen[id] = true
	}
	for id := range changed {
		if !seen[id] {
			t.Errorf("the pass did not run Target %s, whose environment changed behind the backlog", id)
		}
	}
}

// TestTriggerScanBoundedPass: a pass's scan stops after its batches
// (scanBatches; 3 here), with the rest left for the next pass, which
// reaches the change behind them.
func TestTriggerScanBoundedPass(t *testing.T) {
	w := newEngineWorld(t)
	syncs.ScanBatches(w.engine, 3)
	base, changed := triggerBacklog(t, w, 2_000)
	marked := func() int64 {
		return paritytest.Rows(t, w.store, `SELECT count(*) AS n FROM sync_targets WHERE needs_sync = 1`)[0]["n"].(int64)
	}
	if err := syncs.ScanTriggers(context.Background(), w.engine); err != nil {
		t.Fatal(err)
	}
	if got := w.cursorOrder(); got != base+1_500 || marked() != 0 {
		t.Fatalf("the first pass: the cursor at %d with %d Targets marked; want it at %d (three batches) and none marked", got, marked(), base+1_500)
	}
	if err := syncs.ScanTriggers(context.Background(), w.engine); err != nil {
		t.Fatal(err)
	}
	if got := w.cursorOrder(); got != base+2_001 || marked() != int64(len(changed)) {
		t.Fatalf("the second pass: the cursor at %d with %d Targets marked; want it at %d and %d marked", got, marked(), base+2_001, len(changed))
	}
}
