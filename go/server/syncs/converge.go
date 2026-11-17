// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/lib/storage"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// The converge engine: domain/syncdelivery.ts (ADR-0031, ADR-0050). It
// converges each destination to its Target's current effective output,
// diffing keyed fingerprints against the per-destination ledger; intent
// precedes the wire; a per-Target lease with an increasing generation
// fences stale runs; a repair pass force-writes (or verifies and fixes).
// Every commit is one write job, in the TypeScript engine's order, named
// as CONVERGE.md maps it; none is merged.

const (
	// SyncInterval is startSyncLoop's 30 s.
	SyncInterval = 30 * time.Second
	// RepairInterval is REPAIR_INTERVAL_MS.
	RepairInterval = 6 * time.Hour
	// OutboundRefusedResult prefixes a refused Target's last result.
	OutboundRefusedResult = "outbound_refused"

	leaseTTL       = 300 * time.Second // LEASE_TTL_SECONDS
	runBudget      = 240 * time.Second // RUN_BUDGET_SECONDS
	baseBackoff    = 30 * time.Second
	maxBackoff     = time.Hour
	failureBudget  = 10
	scanBatch      = 500
	maxTargetNotes = 50
)

// nonTriggering is NON_TRIGGERING_EVENTS: events that never change what a
// Target would push.
var nonTriggering = map[string]bool{
	"value.disclosed": true, "secret.disclosed": true, "value.validated": true, "secret.validated": true,
	"capability.issued": true, "capability.exercised": true, "capability.revoked": true, "capability.denied": true,
	"authorization.denied": true, "exposure.revocation_confirmed": true,
}

// RunOptions are SyncRunOptions' test knobs; zero values are the
// TypeScript engine's.
type RunOptions struct {
	RepairInterval time.Duration
	RunBudget      time.Duration
}

func (o RunOptions) repairInterval() time.Duration {
	if o.RepairInterval > 0 {
		return o.RepairInterval
	}
	return RepairInterval
}

func (o RunOptions) runBudget() time.Duration {
	if o.RunBudget > 0 {
		return o.RunBudget
	}
	return runBudget
}

// RunStats is one Target run's report (feature-parity decision 7): its
// commits, its time queued for the writer and in its jobs, and its
// duration.
type RunStats struct {
	TargetID   string
	Generation int64
	Commits    int
	Queued     time.Duration
	InJobs     time.Duration
	Duration   time.Duration
}

// Crash is what a test's commit hook panics with to stop the engine as a
// process that died would: nothing more is written, not even the run's
// cleanup.
type Crash struct{}

// errFenced is a guarded commit that found another generation.
var errFenced = errors.New("syncs: the run was fenced")

// commit runs one write job, the engine's unit of commit, named for
// CONVERGE.md; stats (nil outside a run) counts it.
func (s *Service) commit(ctx context.Context, stats *RunStats, point string, fn func(ctx context.Context, q *query.Queries, tx *storage.Tx) error) error {
	began := time.Now()
	var entered time.Time
	err := s.Writer.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
		entered = time.Now()
		return fn(ctx, query.New(tx), tx)
	})
	if stats != nil && !entered.IsZero() {
		stats.Queued += entered.Sub(began)
		stats.InJobs += time.Since(entered)
	}
	if err != nil {
		return err
	}
	if stats != nil {
		stats.Commits++
	}
	if s.commitHook != nil {
		s.commitHook(point)
	}
	return nil
}

// guarded runs a commit that writes only while generation still holds the
// Target; false when fenced.
func (s *Service) guarded(ctx context.Context, stats *RunStats, point, targetID string, generation int64, fn func(ctx context.Context, q *query.Queries, tx *storage.Tx) error) (bool, error) {
	err := s.commit(ctx, stats, point, func(ctx context.Context, q *query.Queries, tx *storage.Tx) error {
		current, err := q.TargetGeneration(ctx, targetID)
		if errors.Is(err, sql.ErrNoRows) || err == nil && current != generation {
			return errFenced
		}
		if err != nil {
			return err
		}
		return fn(ctx, q, tx)
	})
	if errors.Is(err, errFenced) {
		return false, nil
	}
	return err == nil, err
}

// RunLoop is startSyncLoop: Targets the outbound policy refused are due
// again at start, then a pass at once and one every interval, until ctx
// ends. Each pass enters the maintenance admission (admit, nil for none).
func (s *Service) RunLoop(ctx context.Context, interval time.Duration, admit func() (leave func(), ok bool)) {
	if err := s.commit(ctx, nil, "clear-refused-backoff", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		return q.ClearRefusedBackoff(ctx)
	}); err != nil && ctx.Err() == nil {
		s.logger().Error("sync: clearing refused backoff failed", "error", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		func() {
			if admit != nil {
				leave, ok := admit()
				if !ok {
					return
				}
				defer leave()
			}
			s.RunOnce(ctx, RunOptions{})
		}()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce is runSyncOnce: the trigger scan, expired run rows removed, then
// every due Target in turn. It never fails: each failure is logged.
func (s *Service) RunOnce(ctx context.Context, opts RunOptions) {
	if s.Now != nil {
		ctx = audit.WithClock(ctx, s.Now)
	}
	defer func() {
		if p := recover(); p != nil {
			if _, crashed := p.(Crash); crashed {
				return
			}
			panic(p)
		}
	}()
	if err := s.scanTriggers(ctx); err != nil && ctx.Err() == nil {
		s.logger().Error("sync trigger scan failed", "error", err)
	}
	now := s.now().UnixMicro()
	reader := s.store().Reader()
	if expired, err := query.New(reader).ExpiredRunExists(ctx, now); err == nil && expired {
		if err := s.commit(ctx, nil, "runs-cleanup", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
			return q.DeleteExpiredRuns(ctx, now)
		}); err != nil && ctx.Err() == nil {
			s.logger().Error("sync run cleanup failed", "error", err)
		}
	}
	due, err := query.New(reader).DueTargets(ctx, query.DueTargetsParams{
		Now:          sql.NullInt64{Int64: now, Valid: true},
		RepairBefore: sql.NullInt64{Int64: now - opts.repairInterval().Microseconds(), Valid: true},
	})
	if err != nil {
		if ctx.Err() == nil {
			s.logger().Error("sync target selection failed", "error", err)
		}
		return
	}
	for _, id := range due {
		if ctx.Err() != nil {
			return
		}
		if err := s.reconcile(ctx, id, opts); err != nil && ctx.Err() == nil {
			s.logger().Error("sync reconcile failed", "target", id, "error", err)
		}
	}
}

// scanTriggers is scanSyncTriggers: Targets whose effective output an
// audit event may have changed are marked due, then the cursor advances.
func (s *Service) scanTriggers(ctx context.Context) error {
	reader := s.store().Reader()
	cursor, err := query.New(reader).SyncCursor(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		now := s.now().UnixMicro()
		if err := s.commit(ctx, nil, "cursor-init", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
			return q.InsertSyncCursor(ctx, now)
		}); err != nil {
			return err
		}
		cursor, err = query.New(reader).SyncCursor(ctx)
	}
	if err != nil {
		return err
	}
	events, err := query.New(reader).TriggerEvents(ctx, query.TriggerEventsParams{EventOrder: cursor, Limit: scanBatch})
	if err != nil || len(events) == 0 {
		return err
	}
	environments, projects := []any{}, []any{}
	seenE, seenP := map[string]bool{}, map[string]bool{}
	for _, e := range events {
		if e.Decision == "deny" || nonTriggering[e.EventType] {
			continue
		}
		environment, project := resourceStrings(e.Resource)
		switch {
		case environment != "":
			if !seenE[environment] {
				seenE[environment] = true
				environments = append(environments, environment)
			}
		case project != "" && strings.HasPrefix(e.EventType, "contract."):
			if !seenP[project] {
				seenP[project] = true
				projects = append(projects, project)
			}
		}
	}
	if len(environments)+len(projects) > 0 {
		if err := s.commit(ctx, nil, "trigger-mark", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
			return q.MarkTriggeredTargets(ctx, query.MarkTriggeredTargetsParams{
				EnvironmentIds: string(jsvalue.Stringify(environments)), ProjectIds: string(jsvalue.Stringify(projects)),
			})
		}); err != nil {
			return err
		}
	}
	last := events[len(events)-1]
	return s.commit(ctx, nil, "trigger-cursor", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		return q.AdvanceSyncCursor(ctx, query.AdvanceSyncCursorParams{EventOrder: last.EventOrder, EventID: last.ID})
	})
}

// resourceStrings is an event's resource's environmentId and projectId,
// when they are non-empty strings (a resource stored as a JSON string is
// read twice, as the TypeScript scan reads it).
func resourceStrings(resource sql.NullString) (environment, project string) {
	if !resource.Valid {
		return "", ""
	}
	v, err := jsvalue.Parse([]byte(resource.String))
	if err != nil {
		return "", ""
	}
	if text, ok := v.(string); ok {
		if v, err = jsvalue.Parse([]byte(text)); err != nil {
			return "", ""
		}
	}
	o, _ := v.(jsvalue.Object)
	e, _ := o.Get("environmentId")
	p, _ := o.Get("projectId")
	environment, _ = e.(string)
	project, _ = p.(string)
	return environment, project
}

// ---------------------------------------------------------------------------
// A Target's run.

// note is a TargetNote.
type note struct {
	code       string
	name       *string
	containers []string
	reason     *string
	fix        string
	count      int
}

func (n note) js() jsvalue.Object {
	o := jsvalue.Object{{Key: "code", Value: n.code}}
	if n.code == "held-more" {
		return append(o, jsvalue.Member{Key: "count", Value: n.count})
	}
	if n.name != nil {
		o = append(o, jsvalue.Member{Key: "name", Value: *n.name})
	}
	if len(n.containers) > 0 {
		list := make([]any, len(n.containers))
		for i, c := range n.containers {
			list[i] = c
		}
		o = append(o, jsvalue.Member{Key: "containers", Value: list})
	}
	if n.reason != nil {
		o = append(o, jsvalue.Member{Key: "reason", Value: *n.reason})
	}
	if n.fix != "" {
		o = append(o, jsvalue.Member{Key: "fix", Value: n.fix})
	}
	return o
}

func named(code, name string) note { return note{code: code, name: &name} }

// boundNotes is boundNotes: unique by code and name, each bounded, held
// names first, at most maxTargetNotes.
func boundNotes(notes []note) []note {
	seen := map[string]bool{}
	var held, rest []note
	for _, n := range notes {
		if n.code == "held-more" {
			continue
		}
		key := n.code + " "
		if n.name != nil {
			key += *n.name
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		b := note{code: n.code, fix: n.fix}
		if n.name != nil {
			s := sliceUnits(*n.name, 256)
			b.name = &s
		}
		for i, c := range n.containers {
			if i == 20 {
				break
			}
			b.containers = append(b.containers, sliceUnits(c, 64))
		}
		if n.reason != nil {
			s := sliceUnits(*n.reason, 200)
			b.reason = &s
		}
		if b.code == "held" {
			held = append(held, b)
		} else {
			rest = append(rest, b)
		}
	}
	if len(held) > maxTargetNotes {
		kept := held[:maxTargetNotes-1]
		return append(slices.Clone(kept), note{code: "held-more", count: len(held) - len(kept)})
	}
	out := append(held, rest...)
	if len(out) > maxTargetNotes {
		out = out[:maxTargetNotes]
	}
	return out
}

func notesText(notes []note) string {
	list := make([]any, len(notes))
	for i, n := range notes {
		list[i] = n.js()
	}
	return string(jsvalue.Stringify(list))
}

// sliceUnits is String.prototype.slice(0, max): at most max UTF-16 code
// units, a surrogate pair cut in half leaving a lone surrogate as
// U+FFFD (the strings here are UTF-8).
func sliceUnits(s string, max int) string {
	units := utf16.Encode([]rune(s))
	if len(units) <= max {
		return s
	}
	return string(utf16.Decode(units[:max]))
}

// run is one Target's run under its lease.
type run struct {
	s       *Service
	opts    RunOptions
	target  query.LeaseTargetRow
	gen     int64
	started int64 // the run's start and its deadline, in microseconds
	limit   int64
	stats   RunStats

	conn              query.RunConnectionRow
	credentialVersion *int64
	credential        *string
	observedExpiry    string
	// inspected holds the notes of a completed value check, for a run that
	// fails later (nil: not reached).
	inspected *[]note
	// refused is the first request the outbound policy refused.
	refused *outbound.RefusedError
	client  *http.Client
}

// outcome is RunOutcome; leaseLost is LEASE_LOST.
type outcome struct {
	ok            bool
	result        string
	notes         *[]note
	cycleComplete bool
	leaseLost     bool
}

var leaseLost = outcome{result: "lease-lost", leaseLost: true}

// reconcile is reconcileTarget.
func (s *Service) reconcile(ctx context.Context, targetID string, opts RunOptions) error {
	r := &run{s: s, opts: opts, stats: RunStats{TargetID: targetID}}
	began := time.Now()
	now := s.now().UnixMicro()
	leased := false
	// C1: the lease and the run's row, one job.
	err := s.commit(ctx, &r.stats, "lease", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		row, err := q.LeaseTarget(ctx, query.LeaseTargetParams{
			LeaseExpiresAt: sql.NullInt64{Int64: now + leaseTTL.Microseconds(), Valid: true},
			Now:            sql.NullInt64{Int64: now, Valid: true}, ID: targetID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		limit := now + opts.runBudget().Microseconds()
		if err := q.InsertSyncRun(ctx, query.InsertSyncRunParams{TargetID: row.ID, Generation: row.Generation, StartedAt: now, Deadline: limit}); err != nil {
			return err
		}
		r.target, r.gen, r.started, r.limit, leased = row, row.Generation, now, limit, true
		return nil
	})
	if err != nil || !leased {
		return err
	}
	r.stats.Generation = r.gen
	defer func() {
		if p := recover(); p != nil {
			panic(p) // a crash: nothing more is written
		}
		r.finish(ctx, began)
	}()
	r.attempt(ctx)
	return nil
}

// finish is reconcileTarget's finally: the lease released (C25) and the
// run's row removed (C26), whether or not the run was fenced; then its
// report.
func (r *run) finish(ctx context.Context, began time.Time) {
	ctx = context.WithoutCancel(ctx)
	_ = r.s.commit(ctx, &r.stats, "lease-release", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		return q.ReleaseLease(ctx, query.ReleaseLeaseParams{ID: r.target.ID, Generation: r.gen})
	})
	_ = r.s.commit(ctx, &r.stats, "run-row", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		return q.DeleteRun(ctx, query.DeleteRunParams{TargetID: r.target.ID, Generation: r.gen})
	})
	r.stats.Duration = time.Since(began)
	if r.s.OnRun != nil {
		r.s.OnRun(r.stats)
	}
	r.s.logger().Debug("sync run", "target", r.stats.TargetID, "generation", r.stats.Generation, "commits", r.stats.Commits,
		"queued", r.stats.Queued, "inJobs", r.stats.InJobs, "duration", r.stats.Duration)
}

func (r *run) now() int64 { return r.s.now().UnixMicro() }

// attempt is reconcileTarget's try and catch.
func (r *run) attempt(ctx context.Context) {
	if err := r.try(ctx); err != nil {
		refusal := r.refused
		if refusal == nil {
			refusal = outbound.RefusalOf(err)
		}
		if refusal != nil {
			if err := r.recordRefusal(ctx, refusal, r.inspected); err != nil {
				r.s.logger().Error("sync refusal bookkeeping failed", "target", r.target.ID, "error", err)
			}
			return
		}
		if err := r.recordFailure(ctx, sliceUnits(errorResult(err), 300), true, r.inspected, r.credentialVersion); err != nil {
			r.s.logger().Error("sync failure bookkeeping failed", "target", r.target.ID, "error", err)
		}
	}
}

// errorResult is `${err.name}: ${err.message}`, as the TypeScript engine
// names what it caught.
func errorResult(err error) string {
	var ae *vsync.AdapterError
	if errors.As(err, &ae) {
		return "AdapterError: " + ae.Message
	}
	var se *vsync.ScriptError
	if errors.As(err, &se) {
		return se.Name + ": " + se.Message
	}
	var de *domainerr.Error
	if errors.As(err, &de) {
		return "DomainError: " + de.Message
	}
	return "Error: " + err.Error()
}

// try is reconcileTarget's try block.
func (r *run) try(ctx context.Context) error {
	reader := r.s.store().Reader()
	conn, err := query.New(reader).RunConnection(ctx, query.RunConnectionParams{OrganizationID: r.target.OrganizationID, ID: r.target.ConnectionID})
	live := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if live {
		r.conn = conn
		v := conn.Version
		r.credentialVersion = &v
	}
	if !live || conn.RevokedAt.Valid {
		return r.recordFailure(ctx, "connection-revoked", true, nil, nil)
	}
	if !r.s.allowed(conn.Platform) {
		return r.recordFailure(ctx, "adapter-not-allowed-on-installation", false, nil, nil)
	}
	force := !r.target.LastRepairAt.Valid || r.now()-r.target.LastRepairAt.Int64 >= r.opts.repairInterval().Microseconds()
	var cycleStart sql.NullInt64
	if force {
		// C4: the repair cycle, opened by the first forced run.
		if err := r.s.commit(ctx, &r.stats, "cycle-open", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
			started, err := q.OpenRepairCycle(ctx, query.OpenRepairCycleParams{Now: sql.NullInt64{Int64: r.now(), Valid: true}, ID: r.target.ID, Generation: r.gen})
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			cycleStart = started
			return err
		}); err != nil {
			return err
		}
	}
	out, err := r.underLease(ctx, force, cycleStart)
	if r.observedExpiry != "" {
		// C17, whatever the outcome; never masking the run's own error.
		if e := r.recordExpiry(ctx); e != nil {
			r.s.logger().Error("credential expiry bookkeeping failed", "error", e)
		}
	}
	if err != nil {
		return err
	}
	if out.leaseLost {
		r.afterLeaseLost(ctx)
		return nil
	}
	if r.refused != nil {
		return r.recordRefusal(ctx, r.refused, out.notes)
	}
	if force && out.cycleComplete {
		// C22.
		if err := r.s.commit(ctx, &r.stats, "cycle-close", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
			return q.CloseRepairCycle(ctx, query.CloseRepairCycleParams{Now: sql.NullInt64{Int64: r.now(), Valid: true}, ID: r.target.ID, Generation: r.gen})
		}); err != nil {
			return err
		}
	}
	if !out.ok {
		return r.recordFailure(ctx, out.result, true, out.notes, r.credentialVersion)
	}
	// C23.
	return r.s.commit(ctx, &r.stats, "result", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		p := query.TargetSucceededParams{Result: sql.NullString{String: out.result, Valid: true}, ID: r.target.ID, Generation: r.gen}
		if out.notes != nil {
			p.SetNotes, p.Notes = 1, sql.NullString{String: notesText(*out.notes), Valid: true}
		}
		return q.TargetSucceeded(ctx, p)
	})
}

// afterLeaseLost: only a moved generation proves a successor; out of
// budget or frozen is a yield (C18); otherwise a guarded failure, so
// backoff and retry own the abandoned work (C19).
func (r *run) afterLeaseLost(ctx context.Context) {
	fenced, outOfBudget, frozen := true, false, false
	row, err := query.New(r.s.store().Reader()).SendCheck(ctx, query.SendCheckParams{Generation: r.gen, ID: r.target.ID})
	switch {
	case err != nil:
		// No row, or the probe failed: a successor is not confirmed, so
		// the work is rescheduled (guarded).
		fenced = false
	default:
		fenced = row.Generation != r.gen
		deadline := r.limit // the run's row may be gone: the deadline it was given
		if row.Deadline != 0 {
			deadline = row.Deadline
		}
		outOfBudget = !fenced && deadline <= r.now()
		frozen = !fenced && row.Frozen
	}
	if outOfBudget || frozen {
		if err := r.s.commit(ctx, &r.stats, "yield", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
			return q.YieldTarget(ctx, query.YieldTargetParams{ID: r.target.ID, Generation: r.gen})
		}); err != nil {
			r.s.logger().Error("sync yield bookkeeping failed", "error", err)
		}
		return
	}
	if !fenced {
		if err := r.recordFailure(ctx, "interrupted mid-run; retrying", true, r.inspected, r.credentialVersion); err != nil {
			r.s.logger().Error("sync interruption bookkeeping failed", "error", err)
		}
	}
}

// recordFailure is recordFailure (C2, C3, C19, C24): the failure counted
// under the run's generation, unless the Connection's credential was
// replaced since the run read it; disabled once the budget is spent.
func (r *run) recordFailure(ctx context.Context, result string, backoff bool, notes *[]note, credentialVersion *int64) error {
	return r.s.commit(ctx, &r.stats, "failure", func(ctx context.Context, q *query.Queries, tx *storage.Tx) error {
		if credentialVersion != nil {
			v, err := q.ConnectionVersion(ctx, r.target.ConnectionID)
			if errors.Is(err, sql.ErrNoRows) || err == nil && v != *credentialVersion {
				return nil
			}
			if err != nil {
				return err
			}
		}
		previous, err := q.GuardedFailureCount(ctx, query.GuardedFailureCountParams{ID: r.target.ID, Generation: r.gen})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		failures := previous + 1
		delay := maxBackoff
		if previous < 7 {
			delay = min(baseBackoff<<previous, maxBackoff)
		}
		disable := backoff && failures >= failureBudget
		p := query.TargetFailedParams{
			Failures: failures, Result: sql.NullString{String: sliceUnits(result, 500), Valid: true},
			NextAttemptAt: sql.NullInt64{Int64: r.now() + delay.Microseconds(), Valid: true}, ID: r.target.ID,
		}
		if disable {
			p.Disable = 1
		}
		if notes != nil {
			p.SetNotes, p.Notes = 1, sql.NullString{String: notesText(*notes), Valid: true}
		}
		if err := q.TargetFailed(ctx, p); err != nil {
			return err
		}
		if !disable {
			return nil
		}
		_, err = audit.Record(ctx, tx, r.event("sync.target_disabled", jsvalue.Object{
			{Key: "reason", Value: "failure-budget-exhausted"}, {Key: "failures", Value: failures}, {Key: "lastResult", Value: sliceUnits(result, 300)},
		}))
		return err
	})
}

// recordRefusal is recordRefusal (C20, C21): never counted toward the
// failure budget; due again at the longest backoff, or after a restart.
func (r *run) recordRefusal(ctx context.Context, refusal *outbound.RefusedError, notes *[]note) error {
	if err := r.s.commit(ctx, &r.stats, "refusal", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		p := query.RefuseTargetParams{
			Result:        sql.NullString{String: OutboundRefusedResult + ": " + string(refusal.Reason), Valid: true},
			NextAttemptAt: sql.NullInt64{Int64: r.now() + maxBackoff.Microseconds(), Valid: true}, ID: r.target.ID, Generation: r.gen,
		}
		if notes != nil {
			p.SetNotes, p.Notes = 1, sql.NullString{String: notesText(*notes), Valid: true}
		}
		return q.RefuseTarget(ctx, p)
	}); err != nil {
		return err
	}
	if r.s.Policy == nil {
		return nil
	}
	e, ok := r.s.Policy.RefusalEvent(outbound.RefusalRecord{
		OrganizationID: r.target.OrganizationID, Purpose: outbound.SyncDelivery, Phase: "connection", Refusal: refusal,
		Resource: jsvalue.Object{{Key: "targetId", Value: r.target.ID}, {Key: "connectionId", Value: r.target.ConnectionID}},
	})
	if !ok {
		return nil
	}
	return r.s.commit(ctx, &r.stats, "refusal-audit", func(ctx context.Context, _ *query.Queries, tx *storage.Tx) error {
		_, err := audit.Record(ctx, tx, e)
		return err
	})
}

// recordExpiry is recordCredentialExpiry (C17): only while the Connection
// holds the credential version the run read.
func (r *run) recordExpiry(ctx context.Context) error {
	at, ok := expiryMicros(r.observedExpiry)
	if !ok {
		return nil
	}
	return r.s.commit(ctx, &r.stats, "expiry", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		return q.RecordCredentialExpiry(ctx, query.RecordCredentialExpiryParams{
			ExpiresAt: sql.NullInt64{Int64: at, Valid: true}, SeenAt: sql.NullInt64{Int64: r.now(), Valid: true},
			ID: r.target.ConnectionID, Version: r.conn.Version,
		})
	})
}

func (r *run) event(eventType string, metadata jsvalue.Object) audit.Event {
	org, action := r.target.OrganizationID, "config.sync.manage"
	return audit.Event{
		Type: eventType, Decision: audit.Info, OrganizationID: &org, Action: &action,
		Resource: jsvalue.Object{{Key: "targetId", Value: r.target.ID}, {Key: "environmentId", Value: r.target.EnvironmentID}},
		Metadata: metadata,
	}
}

// guardedEvent is recordGuardedEvent: the event only while the run's
// generation holds the Target.
func (r *run) guardedEvent(ctx context.Context, point string, e audit.Event) (bool, error) {
	return r.s.guarded(ctx, &r.stats, point, r.target.ID, r.gen, func(ctx context.Context, _ *query.Queries, tx *storage.Tx) error {
		_, err := audit.Record(ctx, tx, e)
		return err
	})
}

// ledgerSet is ledgerSet: one name's ledger entry under the run's
// generation, a confirmed change's redeploy debt with it.
func (r *run) ledgerSet(ctx context.Context, point, destName, state string, fingerprint, lastError *string, oweRedeploy bool) (bool, error) {
	return r.s.guarded(ctx, &r.stats, point, r.target.ID, r.gen, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		now := r.now()
		p := query.SetLedgerParams{TargetID: r.target.ID, DestName: destName, State: state, Generation: r.gen, Now: now}
		if state == "written" || state == "tombstone" {
			// A confirmed write or deletion earns repair credit.
			p.RepairedAt = sql.NullInt64{Int64: now, Valid: true}
		}
		if fingerprint != nil {
			p.Fingerprint = sql.NullString{String: *fingerprint, Valid: true}
		}
		if lastError != nil {
			p.LastError = sql.NullString{String: *lastError, Valid: true}
		}
		if err := q.SetLedger(ctx, p); err != nil {
			return err
		}
		if oweRedeploy {
			return q.OweRedeploy(ctx, r.target.ID)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// The adapters' requests.

// httpClient is the run's client: every request through the outbound
// policy's sync_delivery client (or the test's), its first refusal kept
// so the run ends as a refusal.
func (r *run) httpClient() *http.Client {
	if r.client != nil {
		return r.client
	}
	base := r.s.client
	if base == nil {
		base = r.s.Policy.Client(outbound.SyncDelivery)
	}
	next := base.Transport
	if next == nil {
		r.client = base
		return base
	}
	c := *base
	c.Transport = roundTripper(func(req *http.Request) (*http.Response, error) {
		res, err := next.RoundTrip(req)
		if refusal := outbound.RefusalOf(err); refusal != nil && r.refused == nil {
			r.refused = refusal
		}
		return res, err
	})
	r.client = &c
	return r.client
}

// request is adapterRequest: the base identity, the destination, the
// credential (a stored token, opened once per run; its expiry noted when
// the platform reports it), and, when gated, the send check before every
// write, delete or redeploy request.
func (r *run) request(ctx context.Context, destination vsync.Fields, gated bool) (*vsync.Request, error) {
	if r.credential == nil {
		if !r.conn.CredentialEnvelope.Valid {
			return nil, domainerr.New("INTERNAL", "The Connection holds no credential")
		}
		plain, err := r.s.open(ctx, r.s.store().Reader(), r.target.OrganizationID, r.target.ConnectionID, r.conn.CredentialEnvelope.String)
		if err != nil {
			return nil, err
		}
		r.credential = &plain
	}
	req := &vsync.Request{
		BaseIdentity: r.conn.BaseIdentity, Destination: destination, Credential: *r.credential, CredentialKind: vsync.Token,
		Client: r.httpClient(), OnCredentialExpiry: func(at string) { r.observedExpiry = at },
	}
	if gated {
		req.ShouldAbort = r.sendCheck
	}
	return req, nil
}

// sendCheck is the send check (SEND_CHECK_SQL): the generation still
// holds the Target, the run is within its deadline, the Organization is
// not frozen. A check that fails refuses.
func (r *run) sendCheck(ctx context.Context) (bool, error) {
	row, err := query.New(r.s.store().Reader()).SendCheck(ctx, query.SendCheckParams{Generation: r.gen, ID: r.target.ID})
	if err != nil {
		return true, nil
	}
	within := row.Deadline > r.now() // 0: the run's row is gone
	return row.Generation != r.gen || !within || row.Frozen, nil
}

// ---------------------------------------------------------------------------
// The run under its lease (reconcileUnderLease).

type rendered struct {
	name, destName, value, versionID string
}

type desire struct {
	destName, value, fingerprint, versionID string
}

type heldName struct{ name, reason string }

func (r *run) underLease(ctx context.Context, force bool, cycleStart sql.NullInt64) (outcome, error) {
	adapter, err := vsync.GetAdapter(r.conn.Platform)
	if err != nil {
		return outcome{}, err
	}
	reader := r.s.store().Reader()
	read, err := values.ReadForSync(ctx, reader, r.target.ProjectID, r.target.EnvironmentID, r.now())
	if err != nil {
		return outcome{}, err
	}
	switch {
	case read.Gone:
		return outcome{result: "environment-gone"}, nil
	case read.Expired:
		return outcome{result: "environment-expired"}, nil
	}
	destination, err := fieldsOf(r.target.Destination)
	if err != nil {
		return outcome{}, err
	}
	mapping, err := ParseMapping(r.target.Mapping)
	if err != nil {
		return outcome{}, err
	}
	kek, err := r.s.orgKEK(ctx, reader, r.target.OrganizationID)
	if err != nil {
		return outcome{}, err
	}
	defer clear(kek)
	items, flags, heldItems, err := r.render(ctx, adapter, read.Items, mapping, destination, kek)
	if err != nil {
		return outcome{}, err
	}

	ledgerRows, err := query.New(reader).RunLedger(ctx, r.target.ID)
	if err != nil {
		return outcome{}, err
	}
	ledger := map[string]query.RunLedgerRow{}
	for _, l := range ledgerRows {
		ledger[l.DestName] = l
	}
	ambiguous := map[string]bool{}
	for _, l := range ledgerRows {
		if strings.HasPrefix(l.State, "intent-") && l.Generation < r.gen {
			ambiguous[l.DestName] = true
		}
	}
	credited := func(name string) bool {
		at := ledger[name].RepairedAt
		return cycleStart.Valid && at.Valid && at.Int64 >= cycleStart.Int64 && !ambiguous[name]
	}

	fpKey, err := hkdf.Key(sha256.New, kek, nil, "varlatch-sync-fingerprint:"+r.target.ID, 32)
	if err != nil {
		return outcome{}, err
	}
	var desired []desire
	for _, it := range items {
		m := hmac.New(sha256.New, fpKey)
		m.Write([]byte(it.destName + "\x00" + it.value)) // fingerprint(): name, NUL, value
		desired = append(desired, desire{destName: it.destName, value: it.value, fingerprint: hex.EncodeToString(m.Sum(nil)), versionID: it.versionID})
	}
	wanted := func(name string) (desire, bool) {
		for _, d := range desired {
			if d.destName == name {
				return d, true
			}
		}
		return desire{}, false
	}

	heldReasons := make([]string, 0, len(heldItems))
	var heldNotes []note
	for _, h := range heldItems {
		heldReasons = append(heldReasons, h.name+": "+h.reason)
		reason := h.reason
		heldNotes = append(heldNotes, note{code: "held", name: &h.name, reason: &reason})
	}
	var notes []note
	var usage *vsync.UsageReport
	if inspector, ok := adapter.(vsync.UsageInspector); ok {
		var names []string
		for _, d := range desired {
			names = append(names, d.destName)
		}
		for _, l := range ledgerRows {
			if !slices.Contains(names, l.DestName) {
				names = append(names, l.DestName)
			}
		}
		req, err := r.request(ctx, destination, false)
		if err != nil {
			return outcome{}, err
		}
		usage = inspector.InspectUsage(ctx, req, names) // P1: never fails
	}
	usageOf := func(name string) vsync.NameUsage {
		u, _ := usage.Get(name)
		return u
	}
	if usage != nil && !usage.Checked {
		reason := usage.Reason
		if reason == "" {
			reason = "unknown"
		}
		notes = append(notes, note{code: "usage-unchecked", reason: &reason})
	}
	checker, _ := adapter.(vsync.ValueChecker)
	held := map[string]bool{}
	kept := desired[:0:0]
	for _, d := range desired {
		problem := ""
		if usageOf(d.destName).Owned {
			problem = "the platform sets this name itself"
		} else if checker != nil {
			problem = checker.ValueProblem(destination, d.destName, d.value, usage)
		}
		if problem == "" {
			kept = append(kept, d)
			notes = append(notes, usageNotes(d.destName, usageOf(d.destName))...)
			continue
		}
		held[d.destName] = true
		heldReasons = append(heldReasons, d.destName+": "+problem)
		n := note{code: "held", name: &d.destName, reason: &problem}
		if !usageOf(d.destName).Owned && checker != nil {
			n.fix = checker.HeldFix(destination, d.destName, d.value)
		}
		heldNotes = append(heldNotes, n)
	}
	desired = kept
	inspected := boundNotes(append(slices.Clone(heldNotes), notes...))
	r.inspected = &inspected
	notOurs := func(name string) bool {
		return usageOf(name).Owned || adapter.ValidateName(name, destination) != ""
	}
	mayRecreate := func(name string) bool {
		return usageOf(name).Referenced || usage != nil && !usage.Checked
	}

	// P2: verify-and-fix, on a forced run of a platform that reads back.
	var remote map[string]*string
	rewrite := map[string]bool{}
	if force && adapter.SupportsReadBack() {
		if rr, ok := adapter.(vsync.RemoteReader); ok {
			req, err := r.request(ctx, destination, false)
			if err != nil {
				return outcome{}, err
			}
			if state, err := rr.ReadRemote(ctx, req); err == nil {
				remote, rewrite = state.Values, state.Rewrite
			}
		} else if vr, ok := adapter.(vsync.ValueReader); ok {
			req, err := r.request(ctx, destination, false)
			if err != nil {
				return outcome{}, err
			}
			if v, err := vr.ReadValues(ctx, req); err == nil {
				remote = v
			}
		}
	}
	remoteHas := func(name string) bool {
		_, ok := remote[name]
		return ok
	}

	var writes []desire
	var adoptions []desire
	var verified []string
	for _, d := range desired {
		entry, has := ledger[d.destName]
		converged := has && entry.State == "written" && entry.Fingerprint.Valid && entry.Fingerprint.String == d.fingerprint
		repaired := force && converged && credited(d.destName)
		var needsWrite bool
		switch {
		case force && !repaired && remote != nil:
			there := remote[d.destName]
			needsWrite = there == nil || *there != d.value || rewrite[d.destName]
		case force && !repaired:
			needsWrite = true
		default:
			needsWrite = !converged || ambiguous[d.destName]
		}
		switch {
		case needsWrite:
			writes = append(writes, d)
		case force && remote != nil && !converged:
			adoptions = append(adoptions, d)
		case force && remote != nil && !repaired:
			verified = append(verified, d.destName)
		}
	}

	var deletes []string
	for _, l := range ledgerRows {
		name := l.DestName
		if _, want := wanted(name); want || held[name] || notOurs(name) {
			continue
		}
		switch {
		case l.State == "tombstone":
			if mayRecreate(name) {
				notes = append(notes, named("kept-by-platform", name))
			}
			switch {
			case force && !credited(name) && (remote == nil || remoteHas(name)) && !mayRecreate(name):
				deletes = append(deletes, name)
			case ambiguous[name]:
				deletes = append(deletes, name)
			case force && remote != nil && !remoteHas(name) && !credited(name) && !mayRecreate(name):
				verified = append(verified, name)
			}
		case l.State == "intent-delete" || l.State == "failed-delete":
			deletes = append(deletes, name)
		case r.target.RemoveOrphans:
			deletes = append(deletes, name)
		}
	}

	_, isRedeployer := adapter.(vsync.Redeployer)
	redeploys := r.target.Redeploy && adapter.SupportsRedeploy() && isRedeployer
	runNotes := boundNotes(append(slices.Clone(heldNotes), notes...))
	r.inspected = &runNotes

	// C6, C7: ownership of names read back as current. An adopted name an
	// earlier run had begun writing (ambiguous) may be a write the platform
	// accepted before that run died, unconfirmed and unredeployed: it owes
	// the redeploy that write owed (TypeScript defect 9, fixed in Go;
	// CONVERGE.md). The TypeScript engine adopts it without the debt.
	for _, a := range adoptions {
		ok, err := r.ledgerSet(ctx, "adopt", a.destName, "written", &a.fingerprint, nil, redeploys && ambiguous[a.destName])
		if err != nil {
			return outcome{}, err
		}
		if !ok {
			return leaseLost, nil
		}
	}
	if len(verified) > 0 {
		list := make([]any, len(verified))
		for i, v := range verified {
			list[i] = v
		}
		ok, err := r.s.guarded(ctx, &r.stats, "credit", r.target.ID, r.gen, func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
			return q.CreditVerified(ctx, query.CreditVerifiedParams{Now: sql.NullInt64{Int64: r.now(), Valid: true}, TargetID: r.target.ID, Names: string(jsvalue.Stringify(list))})
		})
		if err != nil {
			return outcome{}, err
		}
		if !ok {
			return leaseLost, nil
		}
	}

	if len(writes) == 0 && len(deletes) == 0 {
		owed := ""
		if redeploys {
			req, err := r.request(ctx, destination, true)
			if err != nil {
				return outcome{}, err
			}
			var lost bool
			if owed, lost, err = r.payRedeploy(ctx, adapter, req); err != nil {
				return outcome{}, err
			} else if lost {
				return leaseLost, nil
			}
		}
		result := "converged"
		if len(flags) > 0 {
			result = flagSummary(flags)
		}
		return outcome{ok: len(flags) == 0, result: sliceUnits(withHeld(result, heldReasons)+owed, 500), notes: &runNotes, cycleComplete: force}, nil
	}

	// C9: drift, on a forced run that read the destination back.
	var changed, removed, recreated []string
	if force && remote != nil {
		for _, w := range writes {
			entry, has := ledger[w.destName]
			if !has || entry.State != "written" || !entry.Fingerprint.Valid || entry.Fingerprint.String != w.fingerprint || ambiguous[w.destName] {
				continue
			}
			there, present := remote[w.destName]
			switch {
			case !present:
				removed = append(removed, w.destName)
			case there != nil && *there != w.value:
				changed = append(changed, w.destName)
			}
		}
		for _, name := range deletes {
			if ledger[name].State == "tombstone" && !ambiguous[name] && remoteHas(name) {
				recreated = append(recreated, name)
			}
		}
	}
	drifted := map[string]bool{}
	var driftNames []string
	for _, n := range slices.Concat(changed, removed, recreated) {
		if !drifted[n] {
			drifted[n] = true
			driftNames = append(driftNames, n)
		}
	}
	key := destinationKey(r.target.CanonicalDestination)
	described := r.conn.Platform + ":" + key
	if len(drifted) > 0 {
		var sources []string
		for _, n := range slices.Concat(changed, removed) {
			for _, it := range items {
				if it.destName == n && !slices.Contains(sources, it.name) {
					sources = append(sources, it.name)
				}
			}
		}
		ok, err := r.recordDrift(ctx, driftNames, jsvalue.Object{
			{Key: "destination", Value: described}, {Key: "items", Value: strings.Join(sources, ",")},
			{Key: "changed", Value: strings.Join(changed, ",")}, {Key: "removed", Value: strings.Join(removed, ",")},
			{Key: "recreated", Value: strings.Join(recreated, ",")}, {Key: "count", Value: len(drifted)}, {Key: "generation", Value: r.gen},
		})
		if err != nil {
			return outcome{}, err
		}
		if !ok {
			return leaseLost, nil
		}
	}

	// C10: audit precedes disclosure.
	attempted := make([]string, len(writes))
	for i, w := range writes {
		attempted[i] = w.destName + "@" + w.versionID
	}
	if ok, err := r.guardedEvent(ctx, "push-attempted", r.event("sync.push_attempted", jsvalue.Object{
		{Key: "destination", Value: described}, {Key: "items", Value: strings.Join(attempted, ",")},
		{Key: "deletes", Value: strings.Join(deletes, ",")}, {Key: "generation", Value: r.gen}, {Key: "forced", Value: force},
	})); err != nil {
		return outcome{}, err
	} else if !ok {
		return leaseLost, nil
	}

	req, err := r.request(ctx, destination, true)
	if err != nil {
		return outcome{}, err
	}
	req.Usage = usage
	var writeOutcomes []vsync.NameOutcome
	if len(writes) > 0 {
		// C11: every intent before the wire.
		for _, w := range writes {
			ok, err := r.ledgerSet(ctx, "intent-write", w.destName, "intent-write", &w.fingerprint, nil, false)
			if err != nil {
				return outcome{}, err
			}
			if !ok {
				return leaseLost, nil
			}
		}
		syncItems := make([]vsync.SyncItem, len(writes))
		for i, w := range writes {
			syncItems[i] = vsync.SyncItem{Name: w.destName, Value: w.value}
		}
		// P4.
		if writeOutcomes, err = adapter.WriteValues(ctx, req, syncItems); err != nil {
			return outcome{}, err
		}
		// C12: each outcome; a fenced one records nothing.
		for _, o := range writeOutcomes {
			var fp *string
			for _, w := range writes {
				if w.destName == o.Name {
					f := w.fingerprint
					fp = &f
					break
				}
			}
			state, lastError := "written", (*string)(nil)
			if !o.OK {
				state, lastError = "failed-write", ptrTo(failedText(o))
			}
			entry, has := ledger[o.Name]
			unchanged := has && entry.State == "written" && fp != nil && entry.Fingerprint.Valid && entry.Fingerprint.String == *fp
			owe := o.OK && redeploys && (drifted[o.Name] || !unchanged)
			if _, err := r.ledgerSet(ctx, "write-outcome", o.Name, state, fp, lastError, owe); err != nil {
				return outcome{}, err
			}
		}
		if len(writeOutcomes) < len(writes) {
			return leaseLost, nil
		}
	}

	var deleteOutcomes []vsync.NameOutcome
	if len(deletes) > 0 {
		// C13.
		for _, name := range deletes {
			ok, err := r.ledgerSet(ctx, "intent-delete", name, "intent-delete", nil, nil, false)
			if err != nil {
				return outcome{}, err
			}
			if !ok {
				return leaseLost, nil
			}
		}
		// P5.
		if deleteOutcomes, err = adapter.DeleteNames(ctx, req, deletes); err != nil {
			return outcome{}, err
		}
		// C14.
		for _, o := range deleteOutcomes {
			if o.OK && mayRecreate(o.Name) {
				notes = append(notes, named("kept-by-platform", o.Name))
			}
			state, lastError := "tombstone", (*string)(nil)
			if !o.OK {
				state, lastError = "failed-delete", ptrTo(failedText(o))
			}
			if _, err := r.ledgerSet(ctx, "delete-outcome", o.Name, state, nil, lastError, o.OK && redeploys); err != nil {
				return outcome{}, err
			}
		}
		if len(deleteOutcomes) < len(deletes) {
			return leaseLost, nil
		}
	}

	var failed []string
	written, deleted := 0, 0
	driftRepaired, driftFailed := 0, 0
	for i, o := range slices.Concat(writeOutcomes, deleteOutcomes) {
		switch {
		case o.OK && i < len(writeOutcomes):
			written++
		case o.OK:
			deleted++
		default:
			failed = append(failed, o.Name+" ("+failedText(o)+")")
		}
		if drifted[o.Name] {
			if o.OK {
				driftRepaired++
			} else {
				driftFailed++
			}
		}
	}
	result := "ok"
	if len(failed) > 0 || len(flags) > 0 {
		result = "degraded: " + strings.Join(slices.Concat(failed, flags), "; ")
	}
	result = withHeld(result, heldReasons)
	status := "ok"
	if len(failed) > 0 {
		status = "degraded"
	}
	metadata := jsvalue.Object{
		{Key: "written", Value: written}, {Key: "deleted", Value: deleted}, {Key: "failed", Value: len(failed)}, {Key: "held", Value: len(heldReasons)},
	}
	if len(drifted) > 0 {
		metadata = append(metadata, jsvalue.Member{Key: "driftRepaired", Value: driftRepaired}, jsvalue.Member{Key: "driftFailed", Value: driftFailed})
	}
	metadata = append(metadata, jsvalue.Member{Key: "generation", Value: r.gen}, jsvalue.Member{Key: "result", Value: status})
	// C15: fenced after its last request, the result belongs to nobody,
	// and no redeploy follows.
	if ok, err := r.guardedEvent(ctx, "push-result", r.event("sync.push_result", metadata)); err != nil {
		return outcome{}, err
	} else if !ok {
		return leaseLost, nil
	}
	owed, lost, err := r.payRedeploy(ctx, adapter, req)
	if err != nil {
		return outcome{}, err
	}
	if lost {
		return leaseLost, nil
	}
	final := boundNotes(append(heldNotes, notes...))
	return outcome{
		ok: len(failed) == 0 && len(flags) == 0, result: sliceUnits(result+owed, 500), notes: &final,
		cycleComplete: force && len(failed) == 0,
	}, nil
}

func ptrTo(s string) *string { return &s }

// failedText is `o.error ?? "failed"`.
func failedText(o vsync.NameOutcome) string {
	if o.Error == "" {
		return "failed"
	}
	return o.Error
}

// render is renderEffectiveOutput: the mapped items with their
// destination names, flags for what cannot be pushed, names held for the
// platform; the sync.values_decrypted event (C5) committed before exactly
// those versions are decrypted, and reference expansion only within them.
func (r *run) render(ctx context.Context, adapter vsync.Adapter, resolved []values.Item, mapping Mapping, destination vsync.Fields, kek []byte) ([]rendered, []string, []heldName, error) {
	var flags []string
	var held []heldName
	type selection struct {
		name, destName, valueRowID, versionID string
	}
	var selected []selection
	seen := map[string]bool{}
	find := func(name string) (values.Item, bool) {
		for _, it := range resolved {
			if it.Name == name {
				return it, true
			}
		}
		return values.Item{}, false
	}
	pick := func(name string, rename *string) {
		item, ok := find(name)
		if !ok {
			return // not in the effective output: convergence removes it
		}
		target := name
		if rename != nil {
			target = *rename
		}
		destName := adapter.CanonicalizeName(target)
		if adapter.ValidateName(destName, nil) != "" {
			flags = append(flags, name+": unstorable name")
			return
		}
		if owned := adapter.ValidateName(destName, destination); owned != "" {
			held = append(held, heldName{destName, owned})
			return
		}
		if seen[destName] {
			flags = append(flags, name+": destination name collision ("+destName+")")
			return
		}
		seen[destName] = true
		selected = append(selected, selection{name: name, destName: destName, valueRowID: item.ValueRowID, versionID: item.VersionID})
	}
	if mapping.Wildcard {
		for _, it := range resolved {
			if matchesExclusion(mapping.Exclude, it.Name) {
				continue
			}
			pick(it.Name, nil)
		}
	} else {
		for _, m := range mapping.Items {
			if item, ok := find(m.Name); ok && item.Sensitive && !m.SecretAffirmed {
				flags = append(flags, m.Name+": became a Secret; re-affirmation required")
				continue
			}
			pick(m.Name, m.Rename)
		}
	}
	if len(selected) > 0 {
		versions := make([]string, len(selected))
		for i, it := range selected {
			versions[i] = it.name + "@" + it.versionID
		}
		// C5: unguarded; it records a decryption.
		if err := r.s.commit(ctx, &r.stats, "values-decrypted", func(ctx context.Context, _ *query.Queries, tx *storage.Tx) error {
			_, err := audit.Record(ctx, tx, r.event("sync.values_decrypted", jsvalue.Object{
				{Key: "purpose", Value: "sync-reconcile"}, {Key: "items", Value: strings.Join(versions, ",")}, {Key: "generation", Value: r.gen},
			}))
			return err
		}); err != nil {
			return nil, nil, nil, err
		}
	}
	plaintext := map[string]string{}
	reader := r.s.store().Reader()
	for _, it := range selected {
		v, err := values.OpenForSync(ctx, reader, kek, r.target.OrganizationID, it.valueRowID, it.versionID)
		if err != nil {
			return nil, nil, nil, err
		}
		plaintext[it.name] = v
	}
	var out []rendered
	for _, it := range selected {
		value, err := values.ExpandForSync(plaintext[it.name], func(n string) (string, bool) {
			v, ok := plaintext[n]
			return v, ok
		})
		if err != nil {
			message, ok := values.ExpansionMessage(err)
			if !ok {
				return nil, nil, nil, err
			}
			flags = append(flags, it.name+": "+message)
			continue
		}
		out = append(out, rendered{name: it.name, destName: it.destName, value: value, versionID: it.versionID})
	}
	return out, flags, held, nil
}

// matchesExclusion is matchesExclusion.
func matchesExclusion(exclude []string, name string) bool {
	for _, e := range exclude {
		if prefix, wildcard := strings.CutSuffix(e, "*"); wildcard && strings.HasPrefix(name, prefix) || !wildcard && name == e {
			return true
		}
	}
	return false
}

// usageNotes is usageNotes: hints for a name the run keeps managing.
func usageNotes(name string, u vsync.NameUsage) []note {
	var out []note
	if len(u.ShadowedIn) > 0 {
		out = append(out, note{code: "shadowed", name: &name, containers: u.ShadowedIn})
	}
	if len(u.NotDeliveredTo) > 0 {
		out = append(out, named("not-delivered", name))
	}
	if len(u.UnknownIn) > 0 {
		out = append(out, note{code: "unknown-form", name: &name, containers: u.UnknownIn})
	}
	if u.GeneratedOnce {
		out = append(out, named("generated-once", name))
	}
	return out
}

func flagSummary(flags []string) string {
	return sliceUnits("flagged: "+strings.Join(flags, "; "), 500)
}

// withHeld is withHeld: the held names appended, bounded.
func withHeld(result string, held []string) string {
	if len(held) > 0 {
		result += "; held: " + strings.Join(held, "; ")
	}
	return sliceUnits(result, 500)
}

// destinationKey is destinationKey: the canonical destination's key.
func destinationKey(canonical string) string {
	var parsed []any
	if err := json.Unmarshal([]byte(canonical), &parsed); err != nil || len(parsed) < 3 {
		return "?"
	}
	s, ok := parsed[2].(string)
	if !ok {
		return "?"
	}
	return s
}

// fieldsOf is the stored destination record, as the adapters read it.
func fieldsOf(text string) (vsync.Fields, error) {
	v, err := jsvalue.Parse([]byte(text))
	if err != nil {
		return nil, err
	}
	o, _ := v.(jsvalue.Object)
	f := vsync.Fields{}
	for _, m := range o {
		s, _ := m.Value.(string)
		f = append(f, vsync.Field{Key: m.Key, Value: s})
	}
	return f, nil
}

// recordDrift is recordDrift (C9): the Target's last drift and the
// sync.drift_detected event, under the run's generation.
func (r *run) recordDrift(ctx context.Context, names []string, metadata jsvalue.Object) (bool, error) {
	return r.s.guarded(ctx, &r.stats, "drift", r.target.ID, r.gen, func(ctx context.Context, q *query.Queries, tx *storage.Tx) error {
		eventID := ids.New(ids.AuditEvent)
		list := make([]any, 0, min(len(names), 50))
		for i, n := range names {
			if i == 50 {
				break
			}
			list = append(list, n)
		}
		if err := q.RecordDrift(ctx, query.RecordDriftParams{
			Now: sql.NullInt64{Int64: r.now(), Valid: true}, Count: sql.NullInt64{Int64: int64(len(names)), Valid: true},
			Names: sql.NullString{String: string(jsvalue.Stringify(list)), Valid: true}, EventID: sql.NullString{String: eventID, Valid: true}, ID: r.target.ID,
		}); err != nil {
			return err
		}
		e := r.event("sync.drift_detected", metadata)
		e.ID = eventID
		_, err := audit.Record(ctx, tx, e)
		return err
	})
}

// payRedeploy is payRedeploy: the owed redeploy (P6), settled (C16) only
// for the debt it read and only when the platform accepted it. A refusal
// leaves the debt and shows in the result.
func (r *run) payRedeploy(ctx context.Context, adapter vsync.Adapter, req *vsync.Request) (note string, lost bool, err error) {
	redeployer, ok := adapter.(vsync.Redeployer)
	if !r.target.Redeploy || !adapter.SupportsRedeploy() || !ok {
		return "", false, nil
	}
	debt, err := query.New(r.s.store().Reader()).RedeployDebt(ctx, query.RedeployDebtParams{ID: r.target.ID, Generation: r.gen})
	if errors.Is(err, sql.ErrNoRows) {
		return "", true, nil
	}
	if err != nil {
		return "", false, err
	}
	if !debt.Redeploy || debt.RedeployOwed <= debt.RedeployPaid {
		return "", false, nil
	}
	sent, err := redeployer.TriggerRedeploy(ctx, req)
	if err != nil {
		return "; redeploy failed (" + errorMessage(err) + ")", false, nil
	}
	if sent == "aborted" {
		return "", true, nil
	}
	err = r.s.commit(ctx, &r.stats, "redeploy-paid", func(ctx context.Context, q *query.Queries, _ *storage.Tx) error {
		return q.SettleRedeploy(ctx, query.SettleRedeployParams{Owed: debt.RedeployOwed, ID: r.target.ID, Generation: r.gen})
	})
	return "", false, err
}

// errorMessage is err.message.
func errorMessage(err error) string {
	var ae *vsync.AdapterError
	if errors.As(err, &ae) {
		return ae.Message
	}
	var se *vsync.ScriptError
	if errors.As(err, &se) {
		return se.Message
	}
	var de *domainerr.Error
	if errors.As(err, &de) {
		return de.Message
	}
	return err.Error()
}

// ---------------------------------------------------------------------------
// pushSyncTarget.

// RequestPush is requestPush: the Target due at once, its backoff
// cleared, in a job under the Organization's gate (its liveness checked
// there), the requester's passkey checkpoint after the Target is found.
func (s *Service) RequestPush(ctx context.Context, req Request, org authz.Organization, targetID string) ([]auth.PendingReport, error) {
	var reports []auth.PendingReport
	err := s.Writer.Job(ctx, []write.Gate{write.Organization(org.ID, write.Shared)}, func(ctx context.Context, tx *storage.Tx) error {
		if err := write.CheckLive(ctx, tx, write.Scope{OrganizationID: org.ID}); err != nil {
			return err
		}
		if _, err := GetTarget(ctx, tx, org.ID, targetID); err != nil {
			return err
		}
		var err error
		if reports, err = write.Checkpoint(ctx, tx, req.Principal, org.ID); err != nil {
			return err
		}
		_, err = query.New(tx).RequestPush(ctx, query.RequestPushParams{ID: targetID, OrganizationID: org.ID})
		if errors.Is(err, sql.ErrNoRows) {
			return domainerr.New("RESOURCE_NOT_FOUND", "Sync Target not found")
		}
		return err
	})
	return reports, err
}
