// SPDX-License-Identifier: AGPL-3.0-or-later

package auditexport

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// The worker's limits (AUDIT_EXPORT_LIMITS).
const (
	// BatchEvents and BatchBytes bound one batch: events, and serialized
	// NDJSON before compression.
	BatchEvents = 1_000
	BatchBytes  = 8 * 1024 * 1024
	// ObjectsPerRun is how many objects one lease writes at most.
	ObjectsPerRun = 20
	// LeaseTime is how long a lease holds the export.
	LeaseTime = 300 * time.Second
	// Interval is the loop's (intervalMs).
	Interval = 60 * time.Second
	// ExpiryMargin: a plan whose retention ends within it is expired
	// (Decision 2).
	ExpiryMargin = time.Hour
	// FailingAfter: failing this long records audit_export.failing, once
	// per episode (Decision 11).
	FailingAfter = 900 * time.Second
	// DrainTime is a drain's fixed deadline after the Organization's
	// deletion (Decision 10).
	DrainTime = 30 * 24 * time.Hour
)

// The words a stopped export keeps.
const ObjectConflict = "An object with this name exists with other content; nothing was overwritten"

// UnsupportedFormat is UNSUPPORTED_FORMAT.
func UnsupportedFormat(format int64) string {
	return fmt.Sprintf("A pending object was planned in format %d, which this release cannot upload; finish it with an earlier release or run `varlatchd admin audit-export discard-plan`", format)
}

// Hooks are test-only fault injection (setAuditExportTestHooks).
type Hooks struct {
	// BeforeUpload runs before an upload is sent; an error fails the
	// attempt without anything reaching the destination.
	BeforeUpload func(query.AuditExportPlan) error
	// AfterUpload runs after an upload succeeded at the destination,
	// before the worker sees the response; an error loses the response.
	AfterUpload func(query.AuditExportPlan) error
	// BeforeCommit runs before a commit's job is queued.
	BeforeCommit func(query.AuditExportPlan)
}

// clocked gives ctx the service's clock for the events it records.
func (s *Service) clocked(ctx context.Context) context.Context {
	if s.Now != nil {
		return audit.WithClock(ctx, s.Now)
	}
	return ctx
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// binding is WorkerBinding: what a lease holder wrote under. A change, a
// new key, a removal, a restart or another lease moves the generation, so
// a holder never commits after them.
type binding struct {
	exportID, organizationID, streamID string
	generation, version                int64
}

func bindingOf(r query.AuditExport) binding {
	return binding{exportID: r.ID, organizationID: r.OrganizationID, streamID: r.StreamID, generation: r.Generation, version: r.Version}
}

// holds is bound: the row is still the binding's, and live.
func (b binding) holds(r *query.AuditExport) bool {
	return r != nil && r.Generation == b.generation && r.Version == b.version && r.StreamID == b.streamID && live(*r)
}

func exportByID(ctx context.Context, db query.DBTX, id string) (*query.AuditExport, error) {
	r, err := query.New(db).AuditExportByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

func planOf(ctx context.Context, db query.DBTX, exportID string) (*query.AuditExportPlan, error) {
	p, err := query.New(db).AuditExportPlanOf(ctx, exportID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &p, err
}

// job is one write job under the export's gate (decision 4): the worker,
// the restarts and the host command meet a change, a new key and a
// removal there.
func (s *Service) job(ctx context.Context, exportID string, fn func(ctx context.Context, tx *storage.Tx) error) error {
	return s.Writer.Job(ctx, []write.Gate{exportGate(exportID)}, fn)
}

// The objects (Decision 4).

func pad(order int64) string { return fmt.Sprintf("%020d", order) }

func hourName(hour time.Time) string { return hour.UTC().Format("2006-01-02T15") }

// batchPlan is batchPlan: a header, then each event in Serialize's shape
// with its position first, so a reader can de-duplicate an overlap by
// position as well as by event id; gzip at the best compression. The
// compressed bytes are this zlib's (Go's), not the TypeScript server's:
// the same content, other bytes (both are stored as planned, and only the
// stored bytes are ever uploaded).
func batchPlan(prefix, organizationID, streamID string, previousLastOrder int64, rows []query.AuditEvent, plannedAt time.Time) (planned, error) {
	var lines [][]byte
	size := 0
	for _, r := range rows {
		ev, err := audit.Serialize(r)
		if err != nil {
			return planned{}, err
		}
		line := jsvalue.Stringify(append(jsvalue.Object{{Key: "position", Value: strconv.FormatInt(r.EventOrder, 10)}}, ev...))
		n := len(line) + 1
		if len(lines) > 0 && (len(lines) >= BatchEvents || size+n > BatchBytes) {
			break
		}
		lines = append(lines, line)
		size += n
	}
	first, last := rows[0].EventOrder, rows[len(lines)-1].EventOrder
	header := jsvalue.Stringify(jsvalue.Object{
		{Key: "format", Value: formatName}, {Key: "version", Value: FormatVersion}, {Key: "kind", Value: "batch"},
		{Key: "organizationId", Value: organizationID}, {Key: "streamId", Value: streamID},
		{Key: "firstOrder", Value: strconv.FormatInt(first, 10)}, {Key: "lastOrder", Value: strconv.FormatInt(last, 10)},
		{Key: "count", Value: len(lines)}, {Key: "previousLastOrder", Value: strconv.FormatInt(previousLastOrder, 10)},
		{Key: "plannedAt", Value: isoMs(plannedAt)},
	})
	ndjson := bytes.Join(append([][]byte{header}, lines...), []byte("\n"))
	body, err := gzipped(append(ndjson, '\n'))
	if err != nil {
		return planned{}, err
	}
	return planned{
		kind: "batch", objectName: streamBase(prefix, organizationID, streamID) + pad(first) + "-" + pad(last) + ".ndjson.gz",
		body: body, contentType: "application/gzip",
		firstOrder: nullInt(first, true), lastOrder: nullInt(last, true), eventCount: nullInt(int64(len(lines)), true),
	}, nil
}

// gzipped is gzipSync(…, { level: 9 }): its header as zlib writes it (no
// name, no time, the best-compression flag, Unix).
func gzipped(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	w.OS = 3
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// heartbeatPlan is heartbeatPlan: the hour's heartbeat/<hour>.json.
func heartbeatPlan(prefix, organizationID, streamID string, hour time.Time, cursor, latestOrder int64, plannedAt time.Time) planned {
	body := jsvalue.Stringify(jsvalue.Object{
		{Key: "format", Value: formatName}, {Key: "version", Value: FormatVersion}, {Key: "kind", Value: "heartbeat"},
		{Key: "organizationId", Value: organizationID}, {Key: "streamId", Value: streamID}, {Key: "hour", Value: hourName(hour)},
		{Key: "cursor", Value: strconv.FormatInt(cursor, 10)}, {Key: "latestOrder", Value: strconv.FormatInt(latestOrder, 10)},
		{Key: "plannedAt", Value: isoMs(plannedAt)},
	})
	return planned{
		kind: "heartbeat", objectName: streamBase(prefix, organizationID, streamID) + "heartbeat/" + hourName(hour) + ".json",
		body: append(body, '\n'), contentType: "application/json", heartbeatHour: nullInt(hour.UnixMicro(), true),
	}
}

// The worker (Decisions 2 and 3).

// takeLease is takeLease, under the export's gate: never on a drain past
// its deadline (Decision 10). Nil when the export is not due.
func (s *Service) takeLease(ctx context.Context, exportID string) (*query.AuditExport, error) {
	var out *query.AuditExport
	err := s.job(ctx, exportID, func(ctx context.Context, tx *storage.Tx) error {
		now := s.now()
		r, err := query.New(tx).TakeAuditExportLease(ctx, query.TakeAuditExportLeaseParams{
			ID: exportID, LeaseUntil: nullInt(now.Add(LeaseTime).UnixMicro(), true), Now: nullInt(now.UnixMicro(), true),
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		out = &r
		return err
	})
	return out, err
}

// workerCredential is workerCredential: the export's key, under the
// Organization KEK while active, the Root KEK while draining.
func (s *Service) workerCredential(ctx context.Context, r query.AuditExport) (Credential, error) {
	if r.State != "draining" {
		return s.storedCredential(ctx, s.store().Reader(), r)
	}
	if !r.CredentialEnvelope.Valid {
		return Credential{}, errors.New("audit export without a key")
	}
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(r.CredentialEnvelope.String), &env); err != nil {
		return Credential{}, err
	}
	plain, err := envelope.Open(s.RootKEK, env, envelope.AuditExportDrainContext(r.OrganizationID, r.ID))
	if err != nil {
		return Credential{}, err
	}
	var c Credential
	err = json.Unmarshal(plain, &c)
	return c, err
}

// planNext is planNext: an hourly heartbeat when its hour has none yet,
// else the next batch after the cursor; nil when there is nothing to
// write. Serialized and compressed outside any job, then stored in one
// job that checks the binding, the cursor it read and that no plan is
// pending.
func (s *Service) planNext(ctx context.Context, b binding) (*query.AuditExportPlan, error) {
	reader := s.store().Reader()
	r, err := exportByID(ctx, reader, b.exportID)
	if err != nil || !b.holds(r) {
		return nil, err
	}
	q := query.New(reader)
	cursor := r.CursorOrder
	now := msTime(s.now())
	hour := time.UnixMilli(now.UnixMilli() / 3_600_000 * 3_600_000).UTC()
	var p *planned
	if !r.LastHeartbeatHour.Valid || r.LastHeartbeatHour.Int64 < hour.UnixMicro() {
		latest, err := q.LatestAuditEventOrder(ctx, nullStr(r.OrganizationID, true))
		if err != nil {
			return nil, err
		}
		h := heartbeatPlan(r.Prefix, r.OrganizationID, r.StreamID, hour, cursor, latest, now)
		p = &h
	} else {
		events, err := q.AuditEventsToExport(ctx, query.AuditEventsToExportParams{OrganizationID: nullStr(r.OrganizationID, true), EventOrder: cursor, Limit: BatchEvents})
		if err != nil {
			return nil, err
		}
		if len(events) > 0 {
			batch, err := batchPlan(r.Prefix, r.OrganizationID, r.StreamID, cursor, events, now)
			if err != nil {
				return nil, err
			}
			p = &batch
		}
	}
	if p == nil {
		return nil, nil
	}
	var out *query.AuditExportPlan
	err = s.job(ctx, b.exportID, func(ctx context.Context, tx *storage.Tx) error {
		locked, err := exportByID(ctx, tx, b.exportID)
		if err != nil || !b.holds(locked) || locked.CursorOrder != cursor {
			return err
		}
		if pending, err := planOf(ctx, tx, b.exportID); err != nil || pending != nil {
			return err
		}
		if err := insertPlan(ctx, tx, b.exportID, b.version, b.streamID, b.generation, *p, retentionOf(*locked), now); err != nil {
			return err
		}
		out, err = planOf(ctx, tx, b.exportID)
		return err
	})
	return out, err
}

// uploadOutcome is UploadOutcome: "delivered" (with what the 412 check
// learned of the key, unknown when it did not run), "conflict" or
// "failed" (with its fixed words).
type uploadOutcome struct {
	kind       string
	keyCanRead sql.NullBool
	message    string
}

// uploadPlan is uploadPlan: the plan exactly as stored. 412 means an
// earlier attempt of this plan landed (Decision 4): the existing object
// is always read (HEAD) and its SHA-256 compared, whatever an earlier
// probe found. Only a HEAD the destination refuses (a write-only key)
// counts the 412 as delivered. ctx carries a drain's deadline.
func (s *Service) uploadPlan(ctx context.Context, cl *backup.Client, plan query.AuditExportPlan) uploadOutcome {
	put := backup.ConditionalPut{Key: plan.ObjectName, Body: plan.Body, SHA256: plan.Sha256, MD5: plan.Md5, ContentType: plan.ContentType}
	if plan.RetentionMode.Valid && plan.RetainUntil.Valid {
		put.Retention = &backup.Retention{Mode: plan.RetentionMode.String, RetainUntil: time.UnixMicro(plan.RetainUntil.Int64).UTC()}
	}
	var err error
	if s.Hooks.BeforeUpload != nil {
		err = s.Hooks.BeforeUpload(plan)
	}
	if err == nil {
		_, err = request(ctx, func(ctx context.Context) (struct{}, error) { return struct{}{}, cl.PutIfAbsent(ctx, put) })
	}
	if err == nil && s.Hooks.AfterUpload != nil {
		err = s.Hooks.AfterUpload(plan)
	}
	if err == nil {
		return uploadOutcome{kind: "delivered"}
	}
	if !backup.IsPreconditionFailed(err) {
		return uploadOutcome{kind: "failed", message: FailureWords("Upload failed", err)}
	}
	sum, err := request(ctx, func(ctx context.Context) (string, error) { return cl.ObjectSHA256(ctx, plan.ObjectName) })
	switch {
	case err == nil && sum == plan.Sha256:
		return uploadOutcome{kind: "delivered", keyCanRead: sql.NullBool{Bool: true, Valid: true}}
	case err == nil:
		return uploadOutcome{kind: "conflict"}
	case backup.IsAccessDenied(err):
		return uploadOutcome{kind: "delivered", keyCanRead: sql.NullBool{Bool: false, Valid: true}}
	}
	return uploadOutcome{kind: "failed", message: FailureWords("The check of an existing object failed", err)}
}

// commitPlan is commitPlan: in one job under the export's gate, only if
// the binding, the pending plan and its stream are all still current. A
// batch moves the cursor; a heartbeat records its hour. A drain whose
// batch holds organization.deleted completes; one whose deadline passed
// during the upload is abandoned instead. "committed", "lost" or
// "abandoned".
func (s *Service) commitPlan(ctx context.Context, b binding, plan query.AuditExportPlan, keyCanRead sql.NullBool) (string, error) {
	if s.Hooks.BeforeCommit != nil {
		s.Hooks.BeforeCommit(plan)
	}
	outcome := "lost"
	err := s.job(ctx, b.exportID, func(ctx context.Context, tx *storage.Tx) error {
		q := query.New(tx)
		locked, err := exportByID(ctx, tx, b.exportID)
		if err != nil || !b.holds(locked) {
			return err
		}
		now := s.now()
		if drainExpired(*locked, now) {
			outcome = "abandoned"
			return abandonLocked(ctx, tx, []query.AuditExport{*locked}, now)
		}
		pending, err := planOf(ctx, tx, b.exportID)
		if err != nil || pending == nil || pending.ID != plan.ID || pending.StreamID != locked.StreamID {
			return err
		}
		if err := q.DeleteAuditExportPlan(ctx, plan.ID); err != nil {
			return err
		}
		cursor := locked.CursorOrder
		if plan.Kind == "batch" {
			cursor = plan.LastOrder.Int64
		}
		completes := false
		if locked.State == "draining" && plan.Kind == "batch" {
			n, err := q.OrganizationDeletedBy(ctx, query.OrganizationDeletedByParams{OrganizationID: nullStr(locked.OrganizationID, true), EventOrder: cursor})
			if err != nil {
				return err
			}
			completes = n > 0
		}
		var heartbeat sql.NullInt64
		if plan.Kind == "heartbeat" {
			heartbeat = plan.HeartbeatHour
		}
		var flag int64
		if completes {
			flag = 1
		}
		if err := q.CommitAuditExportPlan(ctx, query.CommitAuditExportPlanParams{
			ID: b.exportID, CursorOrder: cursor, HeartbeatHour: heartbeat, At: nullInt(now.UnixMicro(), true), KeyCanRead: keyCanRead, Completes: flag,
		}); err != nil {
			return err
		}
		org := locked.OrganizationID
		resource := jsvalue.Object{{Key: "exportId", Value: b.exportID}}
		var events []audit.Event
		if locked.FailingRecorded {
			events = append(events, audit.Event{Type: "audit_export.recovered", Decision: audit.Info, OrganizationID: &org, Resource: resource,
				Metadata: jsvalue.Object{{Key: "failingSince", Value: nullTime(locked.FailingSince)}}})
		}
		if completes {
			events = append(events, audit.Event{Type: "audit_export.completed", Decision: audit.Info, OrganizationID: &org, Resource: resource,
				Metadata: jsvalue.Object{{Key: "streamId", Value: locked.StreamID}, {Key: "lastOrder", Value: strconv.FormatInt(cursor, 10)}}})
		}
		if len(events) > 0 {
			if _, err := audit.Record(ctx, tx, events...); err != nil {
				return err
			}
		}
		outcome = "committed"
		return nil
	})
	return outcome, err
}

// recordFailure is recordFailure: the plan stays; the status records the
// attempt and the fixed words; failing for 15 minutes records
// audit_export.failing once per episode (Decision 11).
func (s *Service) recordFailure(ctx context.Context, b binding, message string) error {
	return s.job(ctx, b.exportID, func(ctx context.Context, tx *storage.Tx) error {
		q := query.New(tx)
		locked, err := exportByID(ctx, tx, b.exportID)
		if err != nil || !b.holds(locked) {
			return err
		}
		now := s.now()
		r, err := q.RecordAuditExportFailure(ctx, query.RecordAuditExportFailureParams{ID: b.exportID, At: nullInt(now.UnixMicro(), true), LastError: nullStr(message, true)})
		if err != nil {
			return err
		}
		if r.FailingRecorded || r.FailingSince.Int64 > now.Add(-FailingAfter).UnixMicro() {
			return nil
		}
		if err := q.MarkAuditExportFailingRecorded(ctx, b.exportID); err != nil {
			return err
		}
		org := locked.OrganizationID
		_, err = audit.Record(ctx, tx, audit.Event{Type: "audit_export.failing", Decision: audit.Info, OrganizationID: &org,
			Resource: jsvalue.Object{{Key: "exportId", Value: b.exportID}},
			Metadata: jsvalue.Object{{Key: "failingSince", Value: nullTime(r.FailingSince)}, {Key: "error", Value: message}}})
		return err
	})
}

// stopExport is stopExport: stopped until a person acts.
func (s *Service) stopExport(ctx context.Context, b binding, reason, message string) error {
	return s.job(ctx, b.exportID, func(ctx context.Context, tx *storage.Tx) error {
		locked, err := exportByID(ctx, tx, b.exportID)
		if err != nil || !b.holds(locked) {
			return err
		}
		return query.New(tx).StopAuditExport(ctx, query.StopAuditExportParams{
			ID: b.exportID, StoppedReason: nullStr(reason, true), LastError: nullStr(message, true), At: nullInt(s.now().UnixMicro(), true),
		})
	})
}

// planExpired is planExpired: the plan's retention ends within the
// margin, so it can no longer be uploaded as planned.
func planExpired(p query.AuditExportPlan, now time.Time) bool {
	return p.RetainUntil.Valid && p.RetainUntil.Int64 < now.Add(ExpiryMargin).UnixMicro()
}

// Outcome is what one lease did (exportOnce's, for tests): "idle",
// "lost", "failed", "stopped", "restarted", "done", "busy" or
// "abandoned".
type Outcome struct {
	Committed int
	Outcome   string
}

// ExportOnce is exportOnce: one export, one lease, up to 20 objects. A
// destination's failure is recorded, never returned; an error is the
// database's (the plan stays, and the next lease holder retries it).
func (s *Service) ExportOnce(ctx context.Context, exportID string) (Outcome, error) {
	ctx = s.clocked(ctx)
	leased, err := s.takeLease(ctx, exportID)
	if err != nil {
		return Outcome{Outcome: "failed"}, err
	}
	if leased == nil {
		abandoned, err := s.abandonIfExpired(ctx, exportID)
		if abandoned {
			return Outcome{Outcome: "abandoned"}, err
		}
		return Outcome{Outcome: "busy"}, err
	}
	b := bindingOf(*leased)
	// A drain's deadline (Decision 10): the lease was taken before it; it
	// is checked again before each upload and at commit, and every request
	// stops when it passes.
	draining := leased.State == "draining"
	runCtx := ctx
	if draining {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, max(0, time.UnixMicro(leased.DrainDeadline.Int64).Sub(s.now())))
		defer cancel()
	}
	defer func() {
		if ctx.Err() != nil {
			return // stopping: the lease runs out by itself
		}
		if err := s.job(ctx, exportID, func(ctx context.Context, tx *storage.Tx) error {
			return query.New(tx).ReleaseAuditExportLease(ctx, query.ReleaseAuditExportLeaseParams{ID: exportID, Generation: b.generation})
		}); err != nil {
			s.log().Warn("audit export: releasing the lease failed; it runs out by itself", "export", exportID, "error", err)
		}
	}()
	cred, err := s.workerCredential(ctx, *leased)
	if err != nil {
		return Outcome{Outcome: "failed"}, s.recordFailure(ctx, b, "The export's key could not be read on this installation")
	}
	cl := s.client(destinationOf(*leased), cred)
	out := Outcome{Outcome: "done"}
	for range ObjectsPerRun {
		plan, err := planOf(ctx, s.store().Reader(), exportID)
		if err != nil {
			return failed(out, err)
		}
		if plan != nil && plan.StreamID != b.streamID {
			out.Outcome = "lost"
			return out, nil
		}
		if plan == nil {
			if plan, err = s.planNext(ctx, b); err != nil {
				return failed(out, err)
			}
		}
		if plan == nil {
			if out.Committed == 0 {
				out.Outcome = "idle"
			}
			return out, nil
		}
		if !uploadableFormats[plan.FormatVersion] {
			out.Outcome = "stopped"
			return out, s.stopExport(ctx, b, "unsupported_format", UnsupportedFormat(plan.FormatVersion))
		}
		if planExpired(*plan, s.now()) {
			out.Outcome = "restarted"
			_, err := s.restartStream(ctx, exportID, plan.ID, "plan_expired", "")
			return out, err
		}
		if draining {
			if abandoned, err := s.abandonIfExpired(ctx, exportID); err != nil || abandoned {
				out.Outcome = "abandoned"
				return out, err
			}
		}
		up := s.uploadPlan(runCtx, cl, *plan)
		switch up.kind {
		case "failed":
			if ctx.Err() != nil {
				// Stopping: the attempt was cut short, not refused.
				out.Outcome = "failed"
				return out, nil
			}
			if draining {
				if abandoned, err := s.abandonIfExpired(ctx, exportID); err != nil || abandoned {
					out.Outcome = "abandoned"
					return out, err
				}
			}
			out.Outcome = "failed"
			return out, s.recordFailure(ctx, b, up.message)
		case "conflict":
			out.Outcome = "stopped"
			return out, s.stopExport(ctx, b, "object_conflict", ObjectConflict)
		}
		result, err := s.commitPlan(ctx, b, *plan, up.keyCanRead)
		if err != nil {
			return failed(out, err)
		}
		if result != "committed" {
			out.Outcome = result
			return out, nil
		}
		out.Committed++
	}
	return out, nil
}

func failed(out Outcome, err error) (Outcome, error) {
	out.Outcome = "failed"
	return out, err
}

// RunOnce is runAuditExportsOnce: every live export whose lease is free,
// in id order. An export's failure is logged; the others still run.
func (s *Service) RunOnce(ctx context.Context) error {
	due, err := query.New(s.store().Reader()).DueAuditExports(ctx, nullInt(s.now().UnixMicro(), true))
	if err != nil {
		return err
	}
	for _, id := range due {
		if ctx.Err() != nil {
			return nil
		}
		if _, err := s.ExportOnce(ctx, id); err != nil && ctx.Err() == nil {
			s.log().Error("audit export failed", "export", id, "error", err)
		}
	}
	return nil
}

// RunLoop is startAuditExportLoop: a pass at once, then one every
// interval, until ctx ends. Each pass enters the maintenance admission
// (admit, nil for none): while a gate is open the pass is skipped, and one
// admitted is counted until it ends. The daemon runs it only when the
// host left the export on.
func (s *Service) RunLoop(ctx context.Context, interval time.Duration, admit func() (leave func(), ok bool)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.pass(ctx, admit)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) pass(ctx context.Context, admit func() (func(), bool)) {
	if admit != nil {
		leave, ok := admit()
		if !ok {
			return
		}
		defer leave()
	}
	if err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
		s.log().Error("audit export loop error", "error", err)
	}
}
