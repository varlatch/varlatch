// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// Report counters (ADR-0054 Decisions 5 and 9; securityreport.ts). A
// control in report mode refuses and changes nothing: each time it would
// have refused, asked for an approval or changed an outcome, a counter
// keyed by (Organization, control, configuration version, operation,
// actor, reason, hour) goes up by one. The summary worker turns each
// hour's rows into security_control.would_block audit events once the hour
// has been over for 10 minutes.
//
// A protected write counts in its own write job (ReportProtectedWrite, or
// Prepared.Count), so only a write that commits is counted. An access
// (passkey-verification) is counted after the response, in a job of its
// own (go/server/values). The TypeScript lock order around the counters
// (the counter upserts after the domain rows and before the audit insert;
// the worker claiming rows SKIP LOCKED) has no row locks to protect here:
// every count and every summary is one job of the single writer, so a
// count and the audit events of its operation commit together, and two
// jobs never interleave (feature-parity decision 5, defect 2).

// Operations a control counts (Decision 5's lists).
var (
	// AdminStepUpOperations is ADMIN_STEP_UP_OPERATIONS.
	AdminStepUpOperations = []string{
		"identity.create", "credential.issue", "identity.reactivate", "oidc_binding.create", "oidc_binding.delete",
		"grant.create", "grant.replace", "grant.revoke",
		"role.create", "role.update", "role.delete",
		"group.create", "group.update", "group.delete", "group.member_add", "group.member_remove",
		"team.create", "team.update", "team.delete", "team.member_add", "team.member_remove",
		"team.project_add", "team.project_remove",
		"member.invite_admin", "member.promote", "member.demote", "member.remove",
		"webhook.create", "webhook.update", "webhook.delete",
		"connection.create", "connection.replace_credential", "connection.delete",
		"github_app.register", "github_app.import", "github_app.replace_key", "github_app.remove",
		"project.delete", "organization.delete", "secret.export",
	}
	// RequirementProtectionOperations is REQUIREMENT_PROTECTION_OPERATIONS.
	RequirementProtectionOperations = []string{"requirement.update", "requirement.revoke"}
	// CredentialLifetimeOperations is CREDENTIAL_LIFETIME_OPERATIONS.
	CredentialLifetimeOperations = []string{"identity.create", "credential.issue"}
)

// Report reasons (REPORT_REASONS).
const (
	ReasonNoApproval        = "no-approval"
	ReasonMachineCredential = "machine-credential"
	ReasonNoEvidence        = "no-evidence"
	ReasonNotUserVerified   = "not-user-verified"
	ReasonUntrustedPasskey  = "untrusted-passkey"
	ReasonWouldDefault      = "would-default"
	ReasonWouldRefuse       = "would-refuse"
)

// ReportReasons is REPORT_REASONS.
var ReportReasons = []string{
	ReasonNoApproval, ReasonMachineCredential, ReasonNoEvidence, ReasonNotUserVerified, ReasonUntrustedPasskey,
	ReasonWouldDefault, ReasonWouldRefuse,
}

// WouldBlock is one attempt a control in report mode would have refused
// or changed.
type WouldBlock struct {
	Control string
	// ConfigVersion is the control's version when the attempt was decided.
	ConfigVersion   int64
	Operation       string
	ActorIdentityID string
	Reason          string
}

// Hour is an hour in microseconds, the counters' bucket.
const Hour = int64(time.Hour / time.Microsecond)

// padVersion is String(v).padStart(10, "0").
func padVersion(v int64) string {
	s := strconv.FormatInt(v, 10)
	if len(s) < 10 {
		s = strings.Repeat("0", 10-len(s)) + s
	}
	return s
}

// CountWouldBlock is countWouldBlock, in the counting operation's write
// job: equal attempts add up, buckets are upserted in key order, each
// into the hour of at (microseconds: when the attempts were decided); a
// bucket the worker already summarized counts in the current hour's
// instead. now is the clock for first_seen, last_seen and that hour.
func CountWouldBlock(ctx context.Context, db query.DBTX, organizationID string, attempts []WouldBlock, at int64, now func() time.Time) error {
	type entry struct {
		key   string
		a     WouldBlock
		count int64
	}
	merged := map[string]*entry{}
	for _, a := range attempts {
		if !slices.Contains(ReportReasons, a.Reason) {
			return fmt.Errorf("security: unknown report reason %s", a.Reason)
		}
		key := strings.Join([]string{organizationID, a.Control, padVersion(a.ConfigVersion), a.Operation, a.ActorIdentityID, a.Reason}, "\x00")
		if e, ok := merged[key]; ok {
			e.count++
		} else {
			merged[key] = &entry{key: key, a: a, count: 1}
		}
	}
	ordered := make([]*entry, 0, len(merged))
	for _, e := range merged {
		ordered = append(ordered, e)
	}
	slices.SortFunc(ordered, func(a, b *entry) int {
		if jsLess(a.key, b.key) {
			return -1
		}
		if jsLess(b.key, a.key) {
			return 1
		}
		return 0
	})
	q := query.New(db)
	for _, e := range ordered {
		seen := now().UnixMicro()
		params := query.CountWouldBlockParams{
			OrganizationID: organizationID, Control: e.a.Control, ConfigVersion: e.a.ConfigVersion, Operation: e.a.Operation,
			ActorIdentityID: e.a.ActorIdentityID, Reason: e.a.Reason, BucketHour: at - at%Hour, Count: e.count, Seen: seen,
		}
		rows, err := q.CountWouldBlock(ctx, params)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			continue
		}
		// The bucket was already summarized: count in the current hour's.
		params.BucketHour = seen - seen%Hour
		if rows, err = q.CountWouldBlock(ctx, params); err != nil {
			return err
		}
		if len(rows) > 0 {
			continue
		}
		// The current hour was summarized too, which only a clock moved
		// back across a summarized hour allows. The TypeScript server drops
		// the count there; here it goes to the hour after the last one
		// summarized for this key, which no summary covers yet, so every
		// committed count still reaches exactly one summary (go/README.md,
		// Known TypeScript defects).
		last, err := q.LastSummarizedBucket(ctx, query.LastSummarizedBucketParams{
			OrganizationID: organizationID, Control: e.a.Control, ConfigVersion: e.a.ConfigVersion, Operation: e.a.Operation,
			ActorIdentityID: e.a.ActorIdentityID, Reason: e.a.Reason,
		})
		if err != nil {
			return err
		}
		params.BucketHour = last + Hour
		if rows, err = q.CountWouldBlock(ctx, params); err != nil {
			return err
		}
		if len(rows) == 0 {
			return fmt.Errorf("security: no open report bucket after %d for %s", last, e.a.Control)
		}
	}
	return nil
}

// CountWouldBlockInLiveOrganization is countWouldBlockInLiveOrganization:
// counts only while the Organization is live, for a job that did not check
// it (a disclosure's audit job, after its snapshot).
func CountWouldBlockInLiveOrganization(ctx context.Context, db query.DBTX, organizationID string, attempts []WouldBlock, at int64, now func() time.Time) error {
	if len(attempts) == 0 {
		return nil
	}
	live, err := query.New(db).LiveOrganizationExists(ctx, organizationID)
	if err != nil || live == 0 {
		return err
	}
	return CountWouldBlock(ctx, db, organizationID, attempts, at, now)
}

// Check is a protected operation's check (ProtectedCheck): a control that
// may act on it and the operation the control counts it as. TTLSeconds is
// credential-lifetime's requested TTL, nil when none was given.
type Check struct {
	Control    string
	Operation  string
	TTLSeconds *int64
}

// reporting is one control's state as a decision read it.
type reporting struct {
	mode    string
	version int64
	config  *Lifetime
}

// activeControls is applicableControls: the Organization's controls at
// report or enforce, read in the operation's job.
func activeControls(ctx context.Context, db query.DBTX, organizationID string) (map[string]reporting, error) {
	rows, err := query.New(db).ActiveSecurityControls(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]reporting, len(rows))
	for _, r := range rows {
		cfg, err := parseLifetime(r.Config)
		if err != nil {
			return nil, err
		}
		out[r.Control] = reporting{mode: r.Mode, version: r.Version, config: cfg}
	}
	return out, nil
}

// LifetimeReason is lifetimeReason: what credential-lifetime would have
// done with a requested TTL: default it, refuse it, or nothing ("").
func LifetimeReason(config *Lifetime, ttlSeconds *int64) string {
	switch {
	case config == nil:
		return ""
	case ttlSeconds == nil:
		return ReasonWouldDefault
	case *ttlSeconds > config.MaxTTLSeconds:
		return ReasonWouldRefuse
	}
	return ""
}

// ReportProtectedWrite is reportProtectedWrite: a protected write's checks
// against the controls in report mode, counted in the write's own job,
// after its domain rows and before its audit events. at is when the write
// was decided.
func ReportProtectedWrite(ctx context.Context, db query.DBTX, organizationID, actorIdentityID string, checks []Check, at int64, now func() time.Time) ([]WouldBlock, error) {
	active, err := activeControls(ctx, db, organizationID)
	if err != nil {
		return nil, err
	}
	var attempts []WouldBlock
	approvalReason := ""
	for _, c := range checks {
		ctl, ok := active[c.Control]
		if !ok || ctl.mode != Report {
			continue
		}
		var reason string
		if c.Control == CredentialLifetime {
			reason = LifetimeReason(ctl.config, c.TTLSeconds)
		} else {
			// Done without an approval: by a person, or by a machine
			// credential, which can never pass one.
			if approvalReason == "" {
				kind, err := query.New(db).IdentityKindOf(ctx, actorIdentityID)
				if err != nil {
					return nil, err
				}
				approvalReason = ReasonMachineCredential
				if kind == "human" {
					approvalReason = ReasonNoApproval
				}
			}
			reason = approvalReason
		}
		if reason != "" {
			attempts = append(attempts, WouldBlock{Control: c.Control, ConfigVersion: ctl.version, Operation: c.Operation, ActorIdentityID: actorIdentityID, Reason: reason})
		}
	}
	if err := CountWouldBlock(ctx, db, organizationID, attempts, at, now); err != nil {
		return nil, err
	}
	return attempts, nil
}

// The summary worker (SECURITY_REPORT).
const (
	// SummaryDelay is how long after its hour ends a bucket is summarized.
	SummaryDelay = 10 * time.Minute
	// Retention is how long counter rows are kept after their summary.
	Retention = 35 * 24 * time.Hour
	// SummaryBatch is the rows per summary job.
	SummaryBatch = 200
	// RetentionBatch is the rows per retention job.
	RetentionBatch = 1000
	// SummaryInterval is the loop's period.
	SummaryInterval = 60 * time.Second
)

// workerGate is the summary worker's singleton gate (decision 4, step 0):
// one pass at a time in the daemon, as the TypeScript worker's advisory
// lock keeps one process emitting.
var workerGate = write.Singleton("security-report", "summary")

// EmitDueSummaries is emitDueSummaries: in one job, up to batch unemitted
// rows of live Organizations whose hour ended at least SummaryDelay ago, in
// key order, marked emitted, and one security_control.would_block event
// each. A job either commits all of it or none, so each summary is written
// once. It returns how many it emitted.
func EmitDueSummaries(ctx context.Context, tx query.DBTX, batch int64, now func() time.Time) (int, error) {
	at := now().UnixMicro()
	q := query.New(tx)
	rows, err := q.DueReportCounters(ctx, query.DueReportCountersParams{Cutoff: at - (Hour + SummaryDelay.Microseconds()), Lim: batch})
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	events := make([]audit.Event, 0, len(rows))
	for _, r := range rows {
		if err := q.MarkReportCounterEmitted(ctx, query.MarkReportCounterEmittedParams{
			Now: sql.NullInt64{Int64: at, Valid: true}, OrganizationID: r.OrganizationID, Control: r.Control, ConfigVersion: r.ConfigVersion, Operation: r.Operation,
			ActorIdentityID: r.ActorIdentityID, Reason: r.Reason, BucketHour: r.BucketHour,
		}); err != nil {
			return 0, err
		}
		actor, org := r.ActorIdentityID, r.OrganizationID
		events = append(events, audit.Event{
			Type: "security_control.would_block", Decision: audit.Info,
			// The actor whose attempts these are; no credential, client or
			// listener: a summary is not a request.
			ActorIdentityID: &actor, CredentialID: audit.Null[string](), Client: audit.Null[string](),
			Listener: audit.Null[string](), Tailnet: audit.Null[any](),
			OrganizationID: &org, Resource: jsvalue.Object{{Key: "control", Value: r.Control}},
			Metadata: jsvalue.Object{
				{Key: "control", Value: r.Control}, {Key: "configVersion", Value: r.ConfigVersion},
				{Key: "operation", Value: r.Operation}, {Key: "reason", Value: r.Reason},
				{Key: "bucketHour", Value: audit.ISOTime(r.BucketHour)}, {Key: "count", Value: r.Count},
				{Key: "firstSeen", Value: audit.ISOTime(r.FirstSeen)}, {Key: "lastSeen", Value: audit.ISOTime(r.LastSeen)},
			},
		})
	}
	// Audit last, after every counter row is marked.
	if _, err := audit.Record(ctx, tx, events...); err != nil {
		return 0, err
	}
	return len(rows), nil
}

// DeleteExpiredCounters is deleteExpiredCounters: counter rows Retention
// after their summary, and any of a deleted Organization, a batch at a
// time.
func DeleteExpiredCounters(ctx context.Context, tx query.DBTX, batch int64, now func() time.Time) (int, error) {
	n, err := query.New(tx).DeleteExpiredReportCounters(ctx, query.DeleteExpiredReportCountersParams{
		Cutoff: sql.NullInt64{Int64: now().UnixMicro() - Retention.Microseconds(), Valid: true}, Lim: batch,
	})
	return int(n), err
}

// RunWorker is runSecurityReportWorker: every due summary, a batch per
// job, then retention, under the worker's gate. It returns how many
// summaries it emitted and how many rows it deleted.
func RunWorker(ctx context.Context, w *write.Writer, now func() time.Time) (emitted, deleted int, err error) {
	ctx, release, err := w.Gates.Acquire(ctx, workerGate)
	if err != nil {
		return 0, 0, err
	}
	defer release()
	for {
		var n int
		if err := w.Store.Write(ctx, func(tx *storage.Tx) error {
			var err error
			n, err = EmitDueSummaries(ctx, tx, SummaryBatch, now)
			return err
		}); err != nil {
			return emitted, deleted, err
		}
		emitted += n
		if n < SummaryBatch {
			break
		}
	}
	for {
		var n int
		if err := w.Store.Write(ctx, func(tx *storage.Tx) error {
			var err error
			n, err = DeleteExpiredCounters(ctx, tx, RetentionBatch, now)
			return err
		}); err != nil {
			return emitted, deleted, err
		}
		deleted += n
		if n < RetentionBatch {
			break
		}
	}
	return emitted, deleted, nil
}

// pass is one admitted pass of the loop.
func pass(ctx context.Context, w *write.Writer, now func() time.Time, log *slog.Logger, admit func() (func(), bool)) {
	if admit != nil {
		leave, ok := admit()
		if !ok {
			return
		}
		defer leave()
	}
	if _, _, err := RunWorker(ctx, w, now); err != nil && ctx.Err() == nil {
		log.Error("security report loop error", "error", err)
	}
}

// RunLoop is startSecurityReportLoop: a pass at once, then one every
// interval, until ctx ends. A pass that fails is logged; the next one runs
// as planned. Each pass enters the maintenance admission (admit, nil for
// none): while a gate is open the pass is skipped, and one admitted is
// counted until it ends, so a gate's drain waits for it.
func RunLoop(ctx context.Context, w *write.Writer, interval time.Duration, now func() time.Time, log *slog.Logger, admit func() (leave func(), ok bool)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		pass(ctx, w, now, log, admit)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// maxReportDays bounds a report's window (1 to 30 days).
const maxReportDays = 30

// ControlReportOf is securityControlReport: the counts of the last days
// days (1 to 30), per control, with the current hour's live counts and
// what is not summarized yet, and per configuration version, operation,
// reason and actor.
func ControlReportOf(ctx context.Context, db query.DBTX, organizationID string, days int64, now func() time.Time) (jsvalue.Object, error) {
	if days < 1 || days > maxReportDays {
		return nil, domainerr.New("VALIDATION_FAILED", "days must be an integer in 1..30")
	}
	at := now().UnixMicro()
	since := at - days*24*Hour
	since -= since % Hour
	hour := at - at%Hour
	rows, err := query.New(db).ReportCounterRows(ctx, query.ReportCounterRowsParams{OrganizationID: organizationID, Since: since, Hour: hour})
	if err != nil {
		return nil, err
	}
	// ORDER BY count DESC, control, operation, reason, actor_identity_id, config_version.
	slices.SortStableFunc(rows, func(a, b query.ReportCounterRowsRow) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		for _, p := range [][2]string{{a.Control, b.Control}, {a.Operation, b.Operation}, {a.Reason, b.Reason}, {a.ActorIdentityID, b.ActorIdentityID}} {
			if c := strings.Compare(p[0], p[1]); c != 0 {
				return c
			}
		}
		return cmp.Compare(a.ConfigVersion, b.ConfigVersion)
	})
	states, err := List(ctx, db, organizationID)
	if err != nil {
		return nil, err
	}
	controls := make([]any, 0, len(Controls))
	for _, st := range states {
		var total, current, pending int64
		entries := []any{}
		for _, r := range rows {
			if r.Control != st.Control {
				continue
			}
			total += r.Count
			current += r.CurrentHour
			pending += r.Pending
			var name, kind any
			if r.ActorName.Valid {
				name = r.ActorName.String
			}
			if r.ActorKind.Valid {
				kind = r.ActorKind.String
			}
			entries = append(entries, jsvalue.Object{
				{Key: "configVersion", Value: r.ConfigVersion}, {Key: "operation", Value: r.Operation}, {Key: "reason", Value: r.Reason},
				{Key: "actor", Value: jsvalue.Object{{Key: "id", Value: r.ActorIdentityID}, {Key: "name", Value: name}, {Key: "kind", Value: kind}}},
				{Key: "count", Value: r.Count}, {Key: "firstSeen", Value: audit.ISOTime(r.FirstSeen)}, {Key: "lastSeen", Value: audit.ISOTime(r.LastSeen)},
			})
		}
		controls = append(controls, jsvalue.Object{
			{Key: "control", Value: st.Control}, {Key: "mode", Value: st.Mode}, {Key: "version", Value: st.Version},
			{Key: "total", Value: total}, {Key: "currentHour", Value: current}, {Key: "pending", Value: pending},
			{Key: "entries", Value: entries},
		})
	}
	return jsvalue.Object{
		{Key: "organizationId", Value: organizationID}, {Key: "days", Value: days},
		{Key: "since", Value: audit.ISOTime(since)}, {Key: "generatedAt", Value: audit.ISOTime(at)},
		{Key: "summaryDelayMinutes", Value: int64(SummaryDelay / time.Minute)}, {Key: "controls", Value: controls},
	}, nil
}
