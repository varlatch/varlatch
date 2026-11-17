// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/syncs"
	"github.com/varlatch/varlatch/go/server/write"
)

// G7 for the converge engine (feature-parity decision 7): a crash after
// every commit of CONVERGE.md's map, and a fence at every provider call.
// Both start from the converge fixture's rows (five Targets on GitHub,
// Coolify and Convex) and run its first pass: every Target forced, with
// read-back, adoption, rewrites, writes and a redeploy.

// engineWorld is one engine on a copy of the fixture's database, with its
// own fake platforms and a clock the test moves.
type engineWorld struct {
	t      *testing.T
	store  *storage.DB
	engine *syncs.Service
	fake   *fakePlatforms
	offset atomic.Int64 // added to the real clock, in nanoseconds
	// platformsAfterTrigger is the platforms' state after retrigger's
	// ordinary run, before its repair pass.
	platformsAfterTrigger string
}

var g7Base struct {
	once    sync.Once
	path    string
	rootKEK []byte
	db      []byte
	err     error
}

// g7Database is a prepared copy of the fixture's database, made once.
func g7Database(t *testing.T) string {
	g7Base.once.Do(func() {
		f, err := paritytest.Read(paritytest.Path("converge-v0.22.0.json"))
		if err != nil {
			g7Base.err = err
			return
		}
		dir, err := os.MkdirTemp("", "varlatch-g7-")
		if err != nil {
			g7Base.err = err
			return
		}
		g7Base.path = filepath.Join(dir, "base.db")
		if g7Base.err = paritytest.Prepare(g7Base.path, f.Rows, convergeTables); g7Base.err != nil {
			return
		}
		if g7Base.rootKEK, g7Base.err = hex.DecodeString(f.RootKEK); g7Base.err != nil {
			return
		}
		g7Base.db, g7Base.err = os.ReadFile(g7Base.path)
	})
	if g7Base.err != nil {
		t.Fatal(g7Base.err)
	}
	return g7Base.path
}

func newEngineWorld(t *testing.T) *engineWorld {
	t.Helper()
	g7Database(t)
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := os.WriteFile(path, g7Base.db, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rootKEK := g7Base.rootKEK
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := outbound.New(nil, outbound.Options{Log: log})
	t.Cleanup(policy.Close)
	w := &engineWorld{t: t, store: store, fake: newFakePlatforms()}
	writer := &write.Writer{Store: store, Gates: write.NewGates()}
	w.engine = &syncs.Service{
		Writer: writer, Approvals: auth.New(store, auth.Options{Log: log, RootKEK: rootKEK}), RootKEK: rootKEK, Policy: policy, Log: log,
		Now: func() time.Time { return time.Now().Add(time.Duration(w.offset.Load())) },
	}
	syncs.UseClient(w.engine, w.fake.client())
	return w
}

// later moves the engine's clock past every lease, run deadline and
// repair interval: what a restart some hours after a crash sees.
func (w *engineWorld) later() { w.offset.Add(int64(7 * time.Hour)) }

// outcome is what a world converged to: every platform's state, and the
// ledger (names, states, fingerprints).
func (w *engineWorld) outcome() string {
	var b strings.Builder
	b.WriteString(w.platforms())
	w.ledger(&b)
	return b.String()
}

// platforms is every platform's state.
func (w *engineWorld) platforms() string {
	w.fake.mu.Lock()
	defer w.fake.mu.Unlock()
	var b strings.Builder
	for _, repo := range slices.Sorted(maps.Keys(w.fake.github)) {
		for _, n := range slices.Sorted(maps.Keys(w.fake.github[repo])) {
			fmt.Fprintf(&b, "github %s %s=%s\n", repo, n, w.fake.github[repo][n])
		}
	}
	for _, res := range slices.Sorted(maps.Keys(w.fake.coolify)) {
		var lines []string
		for _, r := range w.fake.coolify[res] {
			lines = append(lines, fmt.Sprintf("coolify %s %v=%v literal=%v", res, r["key"], r["value"], r["is_literal"]))
		}
		sort.Strings(lines)
		b.WriteString(strings.Join(lines, "\n") + "\n")
	}
	for _, kv := range w.fake.convex {
		fmt.Fprintf(&b, "convex %s=%s\n", kv[0], kv[1])
	}
	return b.String()
}

// ledger is the ledger, the leases, the redeploy debts and the run rows.
func (w *engineWorld) ledger(b *strings.Builder) {
	for _, r := range paritytest.Rows(w.t, w.store, `SELECT t.canonical_destination, l.dest_name, l.state, l.fingerprint
		FROM sync_ledger l JOIN sync_targets t ON t.id = l.target_id ORDER BY 1, 2`) {
		fmt.Fprintf(b, "ledger %v %v %v %v\n", r["canonical_destination"], r["dest_name"], r["state"], r["fingerprint"])
	}
	for _, r := range paritytest.Rows(w.t, w.store, `SELECT canonical_destination, lease_expires_at IS NULL AS released, redeploy_owed = redeploy_paid AS settled
		FROM sync_targets ORDER BY 1`) {
		fmt.Fprintf(b, "target %v released=%v settled=%v\n", r["canonical_destination"], r["released"], r["settled"])
	}
	for _, r := range paritytest.Rows(w.t, w.store, `SELECT count(*) AS runs FROM sync_runs`) {
		fmt.Fprintf(b, "runs %v\n", r["runs"])
	}
}

// recover is a restart hours later: the repair pass, twice.
func (w *engineWorld) recover() {
	syncs.OnCommit(w.engine, nil)
	w.later()
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	w.later()
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
}

// retrigger is a restart minutes later, once the crashed run's lease and
// deadline passed, and a change that marks every Target due: an ordinary
// run, not a repair, which converges by the ledger alone (a name an
// earlier run wrote intent for is ambiguous and written again). Then the
// repair pass settles what an ordinary run leaves (a redeploy owed).
func (w *engineWorld) retrigger() {
	syncs.OnCommit(w.engine, nil)
	w.offset.Add(int64(10 * time.Minute))
	if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
		_, err := tx.ExecContext(context.Background(), `UPDATE sync_targets SET needs_sync = 1, next_attempt_at = NULL`)
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	w.platformsAfterTrigger = w.platforms()
	w.recover()
}

// TestCrashAtEveryCommit: the first pass crashes right after its k-th
// commit, for every k (nothing more is written, not even the run's
// cleanup: a process that died), and a restart hours later converges to
// what the pass converges to without a crash: every platform's values, the
// ledger, the leases released, the redeploys paid, no run left.
func TestCrashAtEveryCommit(t *testing.T) {
	ref := newEngineWorld(t)
	var points []string
	syncs.OnCommit(ref.engine, func(point string) { points = append(points, point) })
	ref.engine.RunOnce(context.Background(), syncs.RunOptions{})
	ref.recover()
	want := ref.outcome()
	if len(points) < 40 || !strings.Contains(want, "github acme/api PORT=8080") {
		t.Fatalf("the reference pass made %d commits and converged to:\n%s", len(points), want)
	}
	wantPlatforms := ref.platforms()
	seen := map[string]bool{}
	for k := range points {
		seen[points[k]] = true
		if k%sampleEvery != 0 {
			continue
		}
		t.Run(fmt.Sprintf("%02d-%s", k+1, points[k]), func(t *testing.T) {
			if sampleEvery == 1 {
				// In parallel, except under the race detector, where the
				// whole module's packages already share the machine.
				t.Parallel()
			}
			crashAt := func(k int) *engineWorld {
				w := newEngineWorld(t)
				n := 0
				syncs.OnCommit(w.engine, func(string) {
					if n++; n == k+1 {
						panic(syncs.Crash{})
					}
				})
				w.engine.RunOnce(context.Background(), syncs.RunOptions{})
				return w
			}
			w := crashAt(k)
			w.recover()
			if got := w.outcome(); got != want {
				t.Errorf("a crash after commit %d (%s), then the repair pass: converged to\n%s\nnot\n%s", k+1, points[k], got, want)
			}
			w = crashAt(k)
			w.retrigger()
			if w.platformsAfterTrigger != wantPlatforms {
				t.Errorf("a crash after commit %d (%s), then an ordinary run: the platforms hold\n%s\nnot\n%s", k+1, points[k], w.platformsAfterTrigger, wantPlatforms)
			}
			if got := w.outcome(); got != want {
				t.Errorf("a crash after commit %d (%s), then an ordinary run and the repair pass: converged to\n%s\nnot\n%s", k+1, points[k], got, want)
			}
		})
	}
	for _, p := range []string{"cursor-init", "trigger-mark", "trigger-cursor", "lease", "cycle-open", "values-decrypted", "adopt",
		"push-attempted", "intent-write", "write-outcome", "push-result", "redeploy-paid", "expiry", "cycle-close", "result", "lease-release", "run-row"} {
		if !seen[p] {
			t.Errorf("the pass made no %s commit: the crash test does not cover it", p)
		}
	}
}

// TestFenceAtEveryProviderCall: during the first pass, the k-th request to
// a platform fences the run that sends it (its Target's generation moves,
// as a pause, a revocation or a new destination moves it), for every k.
// From then on that run sends no write, delete or redeploy request, and
// records nothing under its generation: no ledger entry, no push result,
// no failure. Preparatory reads (usage, read-back) are not gated, as in
// TypeScript.
func TestFenceAtEveryProviderCall(t *testing.T) {
	ref := newEngineWorld(t)
	ref.engine.RunOnce(context.Background(), syncs.RunOptions{})
	total := len(ref.fake.take())
	if total < 20 {
		t.Fatalf("the reference pass sent %d requests", total)
	}
	writes := func(line string) bool {
		return !strings.HasPrefix(line, "GET ") && !strings.Contains(line, "/api/query ")
	}
	for k := 1; k <= total; k++ {
		if k%sampleEvery != 0 && k != total {
			continue
		}
		w := newEngineWorld(t)
		var fencedID string
		var fencedGen int64
		var fencedAt time.Time
		w.fake.onRequest = func(n int) {
			if n != k {
				return
			}
			rows := paritytest.Rows(t, w.store, `SELECT id, generation FROM sync_targets WHERE lease_expires_at IS NOT NULL`)
			if len(rows) != 1 {
				t.Errorf("request %d: %d Targets hold a lease", k, len(rows))
				return
			}
			fencedID, fencedGen = rows[0]["id"].(string), rows[0]["generation"].(int64)
			if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
				_, err := tx.ExecContext(context.Background(), `UPDATE sync_targets SET generation = generation + 1 WHERE id = ?`, fencedID)
				return err
			}); err != nil {
				t.Error(err)
			}
			fencedAt = w.engine.Now()
		}
		before := paritytest.Rows(t, w.store, `SELECT id, failure_count FROM sync_targets ORDER BY id`)
		w.engine.RunOnce(context.Background(), syncs.RunOptions{})
		if fencedID == "" {
			t.Fatalf("request %d was never sent", k)
		}
		log := w.fake.take()
		destination := ""
		for _, r := range paritytest.Rows(t, w.store, `SELECT destination FROM sync_targets WHERE id = ?`, fencedID) {
			destination = r["destination"].(string)
		}
		for i, line := range log[k:] {
			if writes(line) && belongsTo(line, destination) {
				t.Errorf("fenced at request %d (%s): request %d sent after the fence: %s", k, log[k-1], k+1+i, line)
			}
		}
		at := fencedAt.UnixMicro()
		for _, r := range paritytest.Rows(t, w.store, `SELECT dest_name, state FROM sync_ledger WHERE target_id = ? AND generation = ? AND updated_at > ?`, fencedID, fencedGen, at) {
			t.Errorf("fenced at request %d: ledger %v %v recorded after the fence", k, r["dest_name"], r["state"])
		}
		for _, r := range paritytest.Rows(t, w.store, `SELECT event_type FROM audit_events WHERE occurred_at > ? AND json_extract(resource, '$.targetId') = ?
			AND event_type IN ('sync.push_result', 'sync.drift_detected', 'sync.push_attempted', 'sync.target_disabled')`, at, fencedID) {
			t.Errorf("fenced at request %d: %v recorded after the fence", k, r["event_type"])
		}
		after := paritytest.Rows(t, w.store, `SELECT id, failure_count FROM sync_targets ORDER BY id`)
		if fmt.Sprint(before) != fmt.Sprint(after) {
			t.Errorf("fenced at request %d: failures counted: %v, then %v", k, before, after)
		}
		if rows := paritytest.Rows(t, w.store, `SELECT count(*) AS n FROM sync_runs`); rows[0]["n"].(int64) != 0 {
			t.Errorf("fenced at request %d: a run row is left", k)
		}
	}
}

// belongsTo reports whether a logged request goes to the stored
// destination's resource (a repository, an application or service; a
// Convex deployment has one).
func belongsTo(line, destination string) bool {
	for key, prefix := range map[string]string{`"repo":"`: "/repos/acme/", `"applicationUuid":"`: "/applications/", `"serviceUuid":"`: "/services/"} {
		if i := strings.Index(destination, key); i >= 0 {
			rest := destination[i+len(key):]
			name := rest[:strings.Index(rest, `"`)]
			return strings.Contains(line, prefix+name+"/")
		}
	}
	return strings.Contains(line, "convex.cloud")
}
