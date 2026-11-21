// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/syncs"
)

// A stored mapping this server cannot read (imported or migrated data can
// hold one: a TypeScript test fixture's `{}`) is an error, never a panic.
func TestParseMappingRefusesWhatItCannotRead(t *testing.T) {
	for _, text := range []string{
		`{}`, `[]`, `null`, `"explicit"`, `not json`, ``,
		`{"kind":"explicit"}`, `{"kind":"explicit","items":[]}`, `{"items":{}}`,
		`{"kind":"explicit","items":[1]}`, `{"kind":"explicit","items":[{}]}`, `{"kind":"explicit","items":[{"name":""}]}`,
		`{"kind":"explicit","items":[{"name":7}]}`, `{"kind":"explicit","items":[{"name":"A","rename":5}]}`,
		`{"kind":"wildcard","exclude":"A"}`, `{"kind":"wildcard","exclude":[1]}`, `{"kind":"other","items":[{"name":"A"}]}`,
	} {
		if _, err := syncs.ParseMapping(text); !errors.Is(err, syncs.ErrStoredMapping) {
			t.Errorf("%q: %v", text, err)
		}
	}
	for _, text := range []string{
		`{"kind":"wildcard"}`, `{"kind":"wildcard","exclude":["A","B*"]}`,
		`{"kind":"explicit","items":[{"name":"PORT","rename":"HTTP_PORT","secretAffirmed":false},{"name":"API_KEY","secretAffirmed":true}]}`,
		`{"kind":"explicit","items":[{"name":"PORT","rename":null}]}`,
	} {
		if _, err := syncs.ParseMapping(text); err != nil {
			t.Errorf("%q: %v", text, err)
		}
	}
}

// Whatever the column holds, ParseMapping answers without panicking, and
// a mapping it reads writes back as one it reads the same.
func FuzzParseMapping(f *testing.F) {
	for _, seed := range []string{`{}`, `{"kind":"wildcard","exclude":["A*"]}`, `{"kind":"explicit","items":[{"name":"A","rename":"B","secretAffirmed":true}]}`,
		`{"kind":"explicit","items":[{"name":"A"},null]}`, `[{"name":"A"}]`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		m, err := syncs.ParseMapping(text)
		if err != nil {
			return
		}
		again, err := syncs.ParseMapping(string(jsvalue.Stringify(m.JS())))
		if err != nil {
			t.Fatalf("%q read, but its own form %s is not: %v", text, jsvalue.Stringify(m.JS()), err)
		}
		if string(jsvalue.Stringify(again.JS())) != string(jsvalue.Stringify(m.JS())) {
			t.Fatalf("%q: %s, then %s", text, jsvalue.Stringify(m.JS()), jsvalue.Stringify(again.JS()))
		}
	})
}

// A Target whose stored mapping cannot be read fails its own run, named in
// its last result and counted as a failure, and the others converge: the
// loop, and the daemon, go on.
func TestUnreadableMappingFailsOnlyItsTarget(t *testing.T) {
	w := newEngineWorld(t)
	w.exec(`UPDATE sync_targets SET mapping = '{}' WHERE canonical_destination = ?`, ghAPI)
	w.exec(`UPDATE sync_targets SET mapping = ? WHERE canonical_destination = ?`, `{"kind":"explicit","items":[{"rename":5}]}`, appOne)
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	rows := w.targets()
	failed := 0
	for _, r := range rows {
		dest, _ := r["canonical_destination"].(string)
		result, _ := r["last_result"].(string)
		if dest == ghAPI || dest == appOne {
			failed++
			if !strings.Contains(result, "stored mapping is not one this server reads") || r["failure_count"] != int64(1) {
				t.Errorf("%s: %v", dest, r)
			}
			continue
		}
		if strings.Contains(result, "stored mapping") || r["failure_count"] != int64(0) {
			t.Errorf("another Target was failed: %v", r)
		}
	}
	if failed != 2 || len(rows) < 3 {
		t.Fatalf("%v", rows)
	}
	// And again, past the backoff: still no panic, still only those two,
	// each failed once more.
	w.later()
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	for _, r := range w.targets() {
		dest, _ := r["canonical_destination"].(string)
		want := int64(0)
		if dest == ghAPI || dest == appOne {
			want = 2
		}
		if r["failure_count"] != want {
			t.Errorf("second pass, %s: %v", dest, r)
		}
	}
}

// A stored destination this server cannot read is an error on the PATCH
// paths that read it (server/syncs and server/httpserver both go through
// StoredDestination), never a panic.
func TestStoredDestinationRefusesWhatItCannotRead(t *testing.T) {
	for _, text := range []string{`[]`, `"repo"`, `null`, `1`, `not json`, ``} {
		if _, err := syncs.StoredDestination(text); !errors.Is(err, syncs.ErrStoredDestination) {
			t.Errorf("%q: %v", text, err)
		}
	}
	if o, err := syncs.StoredDestination(`{"repo":"api","environment":"production"}`); err != nil || len(o) != 2 {
		t.Errorf("%v %v", o, err)
	}
}

// A run that panics (a bug in rendering or an adapter) fails its own
// Target as an error does, counted and backed off, its lease and run row
// gone; the other Targets converge, and the log names the panic's type,
// never its value. (A test's Crash still stops the engine: the G7 tests.)
func TestPanickingRunFailsOnlyItsTarget(t *testing.T) {
	w := newEngineWorld(t)
	var logged strings.Builder
	w.engine.Log = slog.New(slog.NewTextHandler(&logged, nil))
	value := strings.Join([]string{"a", "value", "in", "the", "panic"}, "-")
	panicked := false
	syncs.OnCommit(w.engine, func(point string) {
		if point == "values-decrypted" && !panicked {
			panicked = true
			panic(errors.New(value))
		}
	})
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	if !panicked {
		t.Fatal("no run reached its values")
	}
	failed := 0
	for _, r := range w.targets() {
		result, _ := r["last_result"].(string)
		if strings.Contains(result, "failed unexpectedly") {
			failed++
			if r["failure_count"] != int64(1) || r["backed_off"] != int64(1) {
				t.Errorf("the panicked Target: %v", r)
			}
			continue
		}
		if r["failure_count"] != int64(0) {
			t.Errorf("another Target failed: %v", r)
		}
	}
	if failed != 1 {
		t.Fatalf("%d Targets failed: %v", failed, w.targets())
	}
	if rows := paritytest.Rows(t, w.store, `SELECT target_id FROM sync_runs`); len(rows) != 0 {
		t.Errorf("run rows left: %v", rows)
	}
	if rows := paritytest.Rows(t, w.store, `SELECT id FROM sync_targets WHERE lease_expires_at IS NOT NULL`); len(rows) != 0 {
		t.Errorf("leases left: %v", rows)
	}
	if !strings.Contains(logged.String(), "sync run panicked") || !strings.Contains(logged.String(), "*errors.errorString") || strings.Contains(logged.String(), value) {
		t.Errorf("the log: %s", logged.String())
	}
	// The next pass, without the bug, converges it.
	w.later()
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	for _, r := range w.targets() {
		if result, _ := r["last_result"].(string); strings.Contains(result, "failed unexpectedly") {
			t.Errorf("still failed: %v", r)
		}
	}
}

// A panic in the failure's own bookkeeping still lets the run's lease and
// row go: nothing waits out the lease's TTL.
func TestPanicInTheFailureBookkeepingStillFinishesTheRun(t *testing.T) {
	w := newEngineWorld(t)
	var logged strings.Builder
	w.engine.Log = slog.New(slog.NewTextHandler(&logged, nil))
	value := strings.Join([]string{"a", "value", "in", "the", "second", "panic"}, "-")
	points := map[string]bool{}
	syncs.OnCommit(w.engine, func(point string) {
		if (point == "values-decrypted" || point == "failure") && !points[point] {
			points[point] = true
			panic(errors.New(value))
		}
	})
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	if !points["values-decrypted"] || !points["failure"] {
		t.Fatalf("panicked at %v", points)
	}
	if rows := paritytest.Rows(t, w.store, `SELECT target_id FROM sync_runs`); len(rows) != 0 {
		t.Errorf("run rows left: %v", rows)
	}
	if rows := paritytest.Rows(t, w.store, `SELECT id FROM sync_targets WHERE lease_expires_at IS NOT NULL`); len(rows) != 0 {
		t.Errorf("leases left: %v", rows)
	}
	if strings.Contains(logged.String(), value) {
		t.Errorf("the log holds the panic's value: %s", logged.String())
	}
	// The next pass converges every Target.
	syncs.OnCommit(w.engine, nil)
	w.later()
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	for _, r := range w.targets() {
		if result, _ := r["last_result"].(string); strings.Contains(result, "failed unexpectedly") {
			t.Errorf("still failed: %v", r)
		}
	}
}
