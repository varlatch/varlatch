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
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/syncs"
	"github.com/varlatch/varlatch/go/server/write"
)

// G7 for the converge engine (feature-parity decision 7): a crash after
// every commit of CONVERGE.md's map and after every request a platform
// accepted, and a fence at every provider call, in three scenarios that
// together reach every mapped commit (g7Scenarios). Each starts from the
// converge fixture's rows: five Targets on GitHub, Coolify and Convex.

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
	return worldFrom(t, g7Snapshot{db: g7Base.db, fake: newFakePlatforms()})
}

// g7Snapshot is a world's state to start others from: its database file
// (closed, so the WAL is in it), its platforms, its clock.
type g7Snapshot struct {
	db     []byte
	fake   *fakePlatforms
	offset int64
}

// snapshot closes w and keeps its state.
func (w *engineWorld) snapshot() g7Snapshot {
	w.t.Helper()
	path := w.store.Path()
	if err := w.store.Close(); err != nil {
		w.t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		w.t.Fatal(err)
	}
	return g7Snapshot{db: b, fake: w.fake.clone(), offset: w.offset.Load()}
}

func worldFrom(t *testing.T, snap g7Snapshot) *engineWorld {
	t.Helper()
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := os.WriteFile(path, snap.db, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() }) // a second Close (after snapshot) is harmless
	rootKEK := g7Base.rootKEK
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := outbound.New(nil, outbound.Options{Log: log})
	t.Cleanup(policy.Close)
	w := &engineWorld{t: t, store: store, fake: snap.fake.clone()}
	w.offset.Store(snap.offset)
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

// outcome is what a world converged to: every platform's state (what a
// Coolify resource runs included), and the ledger (names, states,
// fingerprints), the leases and the run rows.
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
		for k, v := range w.fake.activated[res] {
			lines = append(lines, fmt.Sprintf("coolify %s runs %s=%s", res, k, v))
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

// effective is why the redeploying application does not run what it
// stores ("" when it does): a write whose redeploy was lost leaves it
// running an old value, whatever the debt columns say.
func (w *engineWorld) effective() string {
	w.fake.mu.Lock()
	defer w.fake.mu.Unlock()
	const app = "/applications/app-uuid-1"
	stored := map[string]string{}
	for _, r := range w.fake.coolify[app] {
		k, _ := r["key"].(string)
		v, _ := r["value"].(string)
		stored[k] = v
	}
	if !maps.Equal(stored, w.fake.activated[app]) {
		return fmt.Sprintf("the application stores %v and runs %v", stored, w.fake.activated[app])
	}
	return ""
}

// quiet removes the crash and fence hooks: a restart.
func (w *engineWorld) quiet() {
	syncs.OnCommit(w.engine, nil)
	w.fake.mu.Lock()
	w.fake.crashAfter, w.fake.onRequest = 0, nil
	w.fake.mu.Unlock()
}

// recover is a restart hours later: the repair pass, twice.
func (w *engineWorld) recover() {
	w.quiet()
	w.later()
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	w.later()
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
}

// retrigger is a restart minutes later, once the crashed run's lease and
// deadline passed, and a change that marks every Target due: an ordinary
// run, not a repair, which converges by the ledger alone (a name an
// earlier run wrote intent for is ambiguous and written again). Then the
// repair pass settles what an ordinary run leaves.
func (w *engineWorld) retrigger() {
	w.quiet()
	w.offset.Add(int64(10 * time.Minute))
	w.exec(`UPDATE sync_targets SET needs_sync = 1, next_attempt_at = NULL`)
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	w.platformsAfterTrigger = w.platforms()
	w.recover()
}

// g7Scenario is a setup, made without hooks, then the pass a crash or a
// fence may stop.
type g7Scenario struct {
	name  string
	setup func(w *engineWorld)
	pass  func(w *engineWorld)
	// ordinaryConverges: an ordinary run alone (retrigger) puts back the
	// platforms the pass would have (no drift for a repair to find).
	ordinaryConverges bool
}

const (
	ghAPI  = `["github-actions","acme","api"]`
	appOne = `["coolify","https://coolify.public.example","app-uuid-1"]`
)

var g7Scenarios = []g7Scenario{
	{
		// The first pass: every Target forced, with read-back, an adoption
		// (Convex), rewrites, writes, a redeploy and a credential's expiry.
		name:              "first pass",
		setup:             func(*engineWorld) {},
		pass:              func(w *engineWorld) { w.engine.RunOnce(context.Background(), syncs.RunOptions{}) },
		ordinaryConverges: true,
	},
	{
		// A converged world changed: GitHub's mapping orphans three names
		// (deletions) and adds one GitHub refuses (a failure); the
		// application's mapping renames PORT to HTTP_PORT (one write, a
		// redeploy); a service value drifts behind Varlatch's back; the
		// outbound policy refuses Convex; an event names the environment
		// (the trigger scan). The pass is a repair pass: drift, read-back,
		// repair credit for the names it proves current.
		name: "changes",
		setup: func(w *engineWorld) {
			w.engine.RunOnce(context.Background(), syncs.RunOptions{})
			w.recover()
			w.exec(`UPDATE sync_targets SET mapping = ? WHERE canonical_destination = ?`,
				`{"kind":"explicit","items":[{"name":"PORT","rename":"BROKEN_PORT","secretAffirmed":false},{"name":"API_KEY","secretAffirmed":true}]}`, ghAPI)
			w.exec(`UPDATE sync_targets SET mapping = ? WHERE canonical_destination = ?`,
				`{"kind":"explicit","items":[{"name":"PORT","rename":"HTTP_PORT","secretAffirmed":false},{"name":"DATABASE_URL","secretAffirmed":true}]}`, appOne)
			w.fake.mu.Lock()
			for _, r := range w.fake.coolify["/services/svc-uuid-1"] {
				if r["key"] == "API_KEY" {
					r["value"] = "drifted"
				}
			}
			w.fake.refuse["happy-animal-123.convex.cloud"] = true
			w.fake.mu.Unlock()
			w.event()
		},
		pass: func(w *engineWorld) {
			w.later()
			w.engine.RunOnce(context.Background(), syncs.RunOptions{})
		},
	},
	{
		// A first pass out of budget: each run stops at its first gated
		// request and yields. The cursor row is gone (its first commit).
		name:  "out of budget",
		setup: func(w *engineWorld) { w.exec(`DELETE FROM sync_cursor`) },
		pass: func(w *engineWorld) {
			w.engine.RunOnce(context.Background(), syncs.RunOptions{RunBudget: time.Microsecond})
		},
		ordinaryConverges: true,
	},
}

// event records an event naming the environment, as a value change does.
func (w *engineWorld) event() {
	rows := paritytest.Rows(w.t, w.store, `SELECT (SELECT id FROM environments LIMIT 1) AS env, (SELECT id FROM organizations LIMIT 1) AS org`)
	env, org := rows[0]["env"].(string), rows[0]["org"].(string)
	if err := w.store.Write(context.Background(), func(tx *storage.Tx) error {
		action := "config.value.write"
		_, err := audit.Record(context.Background(), tx, audit.Event{Type: "value.written", Decision: audit.Info, OrganizationID: &org,
			Action: &action, Resource: jsvalue.Object{{Key: "environmentId", Value: env}}})
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
}

var g7Starts sync.Map // scenario name → g7Snapshot after its setup

// start is a fresh world at the scenario's start (its setup run once, then
// copied).
func (sc g7Scenario) start(t *testing.T) *engineWorld {
	t.Helper()
	if snap, ok := g7Starts.Load(sc.name); ok {
		return worldFrom(t, snap.(g7Snapshot))
	}
	w := newEngineWorld(t)
	sc.setup(w)
	w.fake.take()
	snap := w.snapshot()
	g7Starts.Store(sc.name, snap)
	return worldFrom(t, snap)
}

// g7Reference is a scenario run without a crash, then recovered as a
// crashed one is: what every crashed run must converge to.
type g7Reference struct {
	want, platforms string
	points          []string
	requests        []string
}

func g7Run(t *testing.T, sc g7Scenario) g7Reference {
	w := sc.start(t)
	var ref g7Reference
	syncs.OnCommit(w.engine, func(p string) { ref.points = append(ref.points, p) })
	sc.pass(w)
	ref.requests = w.fake.take()
	w.recover()
	ref.want, ref.platforms = w.outcome(), w.platforms()
	if why := w.effective(); why != "" {
		t.Fatalf("%s: the reference itself: %s", sc.name, why)
	}
	return ref
}

// checkRecovered: a crashed world, recovered both ways, converges to the
// reference: the same platforms (what the application runs included), the
// same ledger, the leases released, the debts paid, no run row.
func checkRecovered(t *testing.T, sc g7Scenario, ref g7Reference, where string, crash func(w *engineWorld)) {
	for _, mode := range []string{"the repair pass", "an ordinary run and the repair pass"} {
		w := sc.start(t)
		crash(w)
		sc.pass(w)
		if mode == "the repair pass" {
			w.recover()
		} else {
			w.retrigger()
			if sc.ordinaryConverges && w.platformsAfterTrigger != ref.platforms {
				t.Errorf("%s: %s, then an ordinary run: the platforms hold\n%s\nnot\n%s", sc.name, where, w.platformsAfterTrigger, ref.platforms)
			}
		}
		if got := w.outcome(); got != ref.want {
			t.Errorf("%s: %s, then %s: converged to\n%s\nnot\n%s", sc.name, where, mode, got, ref.want)
		}
		if why := w.effective(); why != "" {
			t.Errorf("%s: %s, then %s: %s", sc.name, where, mode, why)
		}
	}
}

// TestCrashAtEveryCommit: each scenario's pass crashes right after its
// k-th commit, for every k (nothing more is written, not even the run's
// cleanup: a process that died), and recovers to the reference. Together
// the scenarios make every commit CONVERGE.md maps.
func TestCrashAtEveryCommit(t *testing.T) {
	seen := map[string]bool{}
	for _, sc := range g7Scenarios {
		ref := g7Run(t, sc)
		for k, point := range ref.points {
			seen[point] = true
			if k%sampleEvery != 0 {
				continue
			}
			t.Run(fmt.Sprintf("%s/%03d-%s", sc.name, k+1, point), func(t *testing.T) {
				if sampleEvery == 1 {
					// In parallel, except under the race detector, where the
					// whole module's packages already share the machine.
					t.Parallel()
				}
				checkRecovered(t, sc, ref, fmt.Sprintf("a crash after commit %d (%s)", k+1, point), func(w *engineWorld) {
					n := 0
					syncs.OnCommit(w.engine, func(string) {
						if n++; n == k+1 {
							panic(syncs.Crash{})
						}
					})
				})
			})
		}
	}
	for _, p := range []string{"cursor-init", "trigger-mark", "trigger-cursor", "lease", "cycle-open", "values-decrypted", "adopt", "credit",
		"drift", "push-attempted", "intent-write", "write-outcome", "intent-delete", "delete-outcome", "push-result", "redeploy-paid",
		"expiry", "failure", "refusal", "refusal-audit", "yield", "cycle-close", "result", "lease-release", "run-row"} {
		if !seen[p] {
			t.Errorf("no scenario makes a %s commit: the crash test does not cover it", p)
		}
	}
}

// TestCrashAfterProviderAccepts: each scenario's pass crashes right after a
// platform accepted its k-th request, for every k: between the platform's
// success and the outcome's commit (C12, C14, C16). Recovery converges to
// the reference, and the application runs what it stores: a write the
// platform accepted keeps its redeploy (TypeScript defect 9).
func TestCrashAfterProviderAccepts(t *testing.T) {
	for _, sc := range g7Scenarios {
		ref := g7Run(t, sc)
		for k, line := range ref.requests {
			if k%sampleEvery != 0 {
				continue
			}
			t.Run(fmt.Sprintf("%s/%03d", sc.name, k+1), func(t *testing.T) {
				if sampleEvery == 1 {
					t.Parallel()
				}
				checkRecovered(t, sc, ref, fmt.Sprintf("a crash after request %d was accepted (%s)", k+1, line), func(w *engineWorld) {
					w.fake.mu.Lock()
					w.fake.crashAfter = int(w.fake.sent.Load()) + k + 1
					w.fake.mu.Unlock()
				})
			})
		}
	}
}

// TestInterruptedWriteKeepsItsRedeploy: TypeScript defect 9. The
// application's one new value is written, Coolify accepts it, and the
// process dies before the outcome is recorded. The repair pass reads the
// value back and adopts it; it still owes the redeploy that write owed,
// and pays it: the application runs the new value.
func TestInterruptedWriteKeepsItsRedeploy(t *testing.T) {
	sc := g7Scenarios[1]
	ref := g7Run(t, sc)
	at := slices.IndexFunc(ref.requests, func(l string) bool {
		return strings.HasPrefix(l, "POST https://coolify.public.example/api/v1/applications/app-uuid-1/envs ")
	})
	if at < 0 {
		t.Fatalf("the pass writes no new application value: %v", ref.requests)
	}
	w := sc.start(t)
	w.fake.mu.Lock()
	w.fake.crashAfter = int(w.fake.sent.Load()) + at + 1
	w.fake.mu.Unlock()
	sc.pass(w)
	w.fake.take()
	w.recover()
	sent := w.fake.take()
	if !slices.ContainsFunc(sent, func(l string) bool { return strings.Contains(l, "/applications/app-uuid-1/start?force=true") }) {
		t.Errorf("recovery did not redeploy the application: %v", sent)
	}
	w.fake.mu.Lock()
	runs := w.fake.activated["/applications/app-uuid-1"]["HTTP_PORT"]
	w.fake.mu.Unlock()
	if runs != "8080" {
		t.Errorf("the application runs HTTP_PORT=%q, not the value written", runs)
	}
}

// TestFenceAtEveryProviderCall: in each scenario's pass, the k-th request
// to a platform fences the run that sends it (its Target's generation
// moves, as a pause, a revocation or a new destination moves it), for
// every k. From then on that run sends no write, delete or redeploy
// request, and records nothing under its generation: no ledger entry, no
// push result, no drift, no failure. Preparatory reads (usage, read-back)
// are not gated, as in TypeScript.
func TestFenceAtEveryProviderCall(t *testing.T) {
	writes := func(line string) bool {
		return !strings.HasPrefix(line, "GET ") && !strings.Contains(line, "/api/query ")
	}
	for _, sc := range g7Scenarios {
		ref := g7Run(t, sc)
		total := len(ref.requests)
		if total == 0 {
			t.Fatalf("%s: the pass sends nothing", sc.name)
		}
		for k := 1; k <= total; k++ {
			if k%sampleEvery != 0 && k != total {
				continue
			}
			t.Run(fmt.Sprintf("%s/%03d", sc.name, k), func(t *testing.T) {
				if sampleEvery == 1 {
					t.Parallel()
				}
				w := sc.start(t)
				base := int(w.fake.sent.Load())
				var fencedID string
				var fencedGen int64
				var fencedAt time.Time
				var before []paritytest.Row
				w.fake.onRequest = func(n int) {
					if n != base+k {
						return
					}
					rows := paritytest.Rows(t, w.store, `SELECT id, generation FROM sync_targets WHERE lease_expires_at IS NOT NULL`)
					if len(rows) != 1 {
						t.Errorf("%s, request %d: %d Targets hold a lease", sc.name, k, len(rows))
						return
					}
					fencedID, fencedGen = rows[0]["id"].(string), rows[0]["generation"].(int64)
					before = paritytest.Rows(t, w.store, `SELECT failure_count, last_result FROM sync_targets WHERE id = ?`, fencedID)
					w.exec(`UPDATE sync_targets SET generation = generation + 1 WHERE id = ?`, fencedID)
					fencedAt = w.engine.Now()
				}
				sc.pass(w)
				if fencedID == "" {
					t.Fatalf("%s: request %d was never sent", sc.name, k)
				}
				log := w.fake.take()
				destination := paritytest.Rows(t, w.store, `SELECT destination FROM sync_targets WHERE id = ?`, fencedID)[0]["destination"].(string)
				if k <= len(log) {
					for i, line := range log[k:] {
						if writes(line) && belongsTo(line, destination) {
							t.Errorf("%s, fenced at request %d (%s): request %d sent after the fence: %s", sc.name, k, log[k-1], k+1+i, line)
						}
					}
				}
				at := fencedAt.UnixMicro()
				for _, r := range paritytest.Rows(t, w.store, `SELECT dest_name, state FROM sync_ledger WHERE target_id = ? AND generation = ? AND updated_at > ?`, fencedID, fencedGen, at) {
					t.Errorf("%s, fenced at request %d: ledger %v %v recorded after the fence", sc.name, k, r["dest_name"], r["state"])
				}
				for _, r := range paritytest.Rows(t, w.store, `SELECT event_type FROM audit_events WHERE occurred_at > ? AND json_extract(resource, '$.targetId') = ?
				AND event_type IN ('sync.push_result', 'sync.drift_detected', 'sync.push_attempted', 'sync.target_disabled')`, at, fencedID) {
					t.Errorf("%s, fenced at request %d: %v recorded after the fence", sc.name, k, r["event_type"])
				}
				if after := paritytest.Rows(t, w.store, `SELECT failure_count, last_result FROM sync_targets WHERE id = ?`, fencedID); fmt.Sprint(before) != fmt.Sprint(after) {
					t.Errorf("%s, fenced at request %d: the fenced Target recorded a result: %v, then %v", sc.name, k, before, after)
				}
				if rows := paritytest.Rows(t, w.store, `SELECT count(*) AS n FROM sync_runs`); rows[0]["n"].(int64) != 0 {
					t.Errorf("%s, fenced at request %d: a run row is left", sc.name, k)
				}
			})
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
