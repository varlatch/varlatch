// SPDX-License-Identifier: AGPL-3.0-or-later

package auditexport

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auditexport/s3fake"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// streaming is a world with a clock and a live export to BucketLocked
// (governance, one day, from the beginning), with key.
func streaming(t *testing.T, key Credential) (*world, *clock, string) {
	t.Helper()
	wd := newWorld(t)
	c := &clock{t: time.Date(2026, 11, 16, 10, 20, 0, 0, time.UTC)}
	wd.s.Now = c.now
	wd.create(CreateInput{Destination: wd.dest(s3fake.BucketLocked), Credential: key, Retention: &Retention{Mode: "governance", Days: 1}, From: "beginning"})
	id, err := LiveID(context.Background(), wd.store.Reader(), wd.org.ID)
	if err != nil {
		t.Fatal(err)
	}
	return wd, c, id
}

func (wd *world) run(id string) Outcome {
	wd.t.Helper()
	out, err := wd.s.ExportOnce(context.Background(), id)
	if err != nil {
		wd.t.Fatalf("export: %v", err)
	}
	return out
}

func (wd *world) row(id string) query.AuditExport {
	wd.t.Helper()
	r, err := exportByID(context.Background(), wd.store.Reader(), id)
	if err != nil || r == nil {
		wd.t.Fatalf("export %s: %v", id, err)
	}
	return *r
}

func (wd *world) plan(id string) *query.AuditExportPlan {
	wd.t.Helper()
	p, err := planOf(context.Background(), wd.store.Reader(), id)
	if err != nil {
		wd.t.Fatal(err)
	}
	return p
}

// events are the Organization's events of type, oldest first, metadata as JSON.
func (wd *world) events(eventType string) []string {
	wd.t.Helper()
	rows, err := wd.store.Reader().Query(`SELECT coalesce(metadata, 'null') FROM audit_events WHERE organization_id = ? AND event_type = ? ORDER BY event_order`, wd.org.ID, eventType)
	if err != nil {
		wd.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var m string
		_ = rows.Scan(&m)
		out = append(out, m)
	}
	return out
}

func (wd *world) record(n int, eventType string) {
	wd.t.Helper()
	evs := make([]audit.Event, n)
	org := wd.org.ID
	for i := range evs {
		evs[i] = audit.Event{Type: eventType, Decision: audit.Info, OrganizationID: &org, Metadata: jsvalue.Object{{Key: "i", Value: i}, {Key: "text", Value: "é ✓  "}}}
	}
	if err := wd.store.Write(context.Background(), func(tx *storage.Tx) error { _, err := audit.Record(context.Background(), tx, evs...); return err }); err != nil {
		wd.t.Fatal(err)
	}
}

func gunzip(t *testing.T, b []byte) []string {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(plain, []byte("\n")) {
		t.Errorf("batch without a final newline")
	}
	return strings.Split(strings.TrimSuffix(string(plain), "\n"), "\n")
}

func object(t *testing.T, wd *world, key string) s3fake.Object {
	t.Helper()
	o, ok := wd.fake.Object(s3fake.BucketLocked, key)
	if !ok {
		t.Fatalf("no object %s; have %v", key, wd.fake.Keys(s3fake.BucketLocked))
	}
	return o
}

func jsonOf(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%q: %v", b, err)
	}
	return m
}

// The stream (Decision 4): the manifest, the hour's heartbeat, then the
// log in batches of NDJSON (each event with its position), gzipped, each
// with the plan's retention and SHA-256 metadata; the cursor moves with
// each batch; a quiet log writes only a heartbeat per hour.
func TestWorkerStreams(t *testing.T) {
	wd, c, id := streaming(t, good())
	out := wd.run(id)
	if out != (Outcome{Committed: 3, Outcome: "done"}) {
		t.Fatalf("first run %+v", out)
	}
	row := wd.row(id)
	base := streamBase("", wd.org.ID, row.StreamID)
	m := object(t, wd, base+"stream.json")
	if mj := jsonOf(t, m.Body); mj["kind"] != "stream" || mj["reason"] != "created" || m.ContentType != "application/json" || m.Mode != "GOVERNANCE" || m.SHA256 != sha256Hex(m.Body) {
		t.Errorf("manifest %v %+v", mj, m)
	}
	h := object(t, wd, base+"heartbeat/2026-11-16T10.json")
	if hj := jsonOf(t, h.Body); hj["hour"] != "2026-11-16T10" || hj["cursor"] != "0" || hj["kind"] != "heartbeat" {
		t.Errorf("heartbeat %v", hj)
	}
	var batch string
	for _, k := range wd.fake.Keys(s3fake.BucketLocked) {
		if strings.HasSuffix(k, ".ndjson.gz") {
			batch = k
		}
	}
	b := object(t, wd, batch)
	if b.ContentType != "application/gzip" || b.SHA256 != sha256Hex(b.Body) || !bytes.Equal(b.Body[:10], []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 3}) {
		t.Errorf("batch %s %s, header % x", batch, b.ContentType, b.Body[:10])
	}
	lines := gunzip(t, b.Body)
	header := jsonOf(t, []byte(lines[0]))
	n := wd.count(`SELECT count(*) FROM audit_events WHERE organization_id = ?`, wd.org.ID)
	if header["kind"] != "batch" || header["count"] != float64(n) || header["previousLastOrder"] != "0" || len(lines) != n+1 ||
		header["lastOrder"] != strconv.FormatInt(row.CursorOrder, 10) || batch != base+pad(must(t, header["firstOrder"]))+"-"+pad(row.CursorOrder)+".ndjson.gz" {
		t.Errorf("batch header %v, %d lines, %d events, cursor %d", header, len(lines), n, row.CursorOrder)
	}
	var types []string
	for _, l := range lines[1:] {
		e := jsonOf(t, []byte(l))
		types = append(types, e["eventType"].(string))
		if !strings.HasPrefix(l, `{"position":"`) || e["eventId"] == nil {
			t.Errorf("line %s", l)
		}
	}
	if !slices.Contains(types, "audit_export.created") || !slices.Contains(types, "audit_export.stream_started") {
		t.Errorf("events %v", types)
	}
	if !row.LastSuccessAt.Valid || row.LastHeartbeatHour.Int64 != time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC).UnixMicro() || row.LeaseExpiresAt.Valid {
		t.Errorf("row %+v", row)
	}
	if out := wd.run(id); out != (Outcome{Outcome: "idle"}) {
		t.Errorf("quiet run %+v", out)
	}
	c.add(time.Hour)
	if out := wd.run(id); out != (Outcome{Committed: 1, Outcome: "done"}) {
		t.Errorf("next hour %+v", out)
	}
	object(t, wd, base+"heartbeat/2026-11-16T11.json")
	// 1,200 events: one batch of 1,000, then one of 200.
	before := wd.row(id).CursorOrder
	wd.record(1200, "organization.renamed")
	if out := wd.run(id); out != (Outcome{Committed: 2, Outcome: "done"}) {
		t.Fatalf("filler %+v", out)
	}
	var counts []int
	for _, k := range wd.fake.Keys(s3fake.BucketLocked) {
		if strings.HasSuffix(k, ".ndjson.gz") && k != batch {
			counts = append(counts, len(gunzip(t, object(t, wd, k).Body))-1)
		}
	}
	slices.Sort(counts)
	if !slices.Equal(counts, []int{200, 1000}) || wd.row(id).CursorOrder != before+1200 {
		t.Errorf("batches %v, cursor %d", counts, wd.row(id).CursorOrder)
	}
}

func must(t *testing.T, v any) int64 {
	t.Helper()
	n, err := strconv.ParseInt(v.(string), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A name already taken (Decision 4): the same content counts as delivered
// (the key read it back), other content stops the export, and a key that
// cannot read counts the 412 as delivered.
func TestWorkerFindsTheNameTaken(t *testing.T) {
	t.Run("same content", func(t *testing.T) {
		wd, _, id := streaming(t, good())
		p := wd.plan(id)
		wd.fake.Plant(s3fake.BucketLocked, p.ObjectName, s3fake.Object{Body: p.Body, SHA256: p.Sha256})
		if out := wd.run(id); out.Outcome != "done" || out.Committed != 3 {
			t.Errorf("%+v", out)
		}
		if r := wd.row(id); !r.KeyCanRead.Valid || !r.KeyCanRead.Bool {
			t.Errorf("key_can_read %+v", r.KeyCanRead)
		}
	})
	t.Run("other content", func(t *testing.T) {
		wd, _, id := streaming(t, good())
		p := wd.plan(id)
		wd.fake.Plant(s3fake.BucketLocked, p.ObjectName, s3fake.Object{Body: []byte("x"), SHA256: sha256Hex([]byte("x"))})
		if out := wd.run(id); out != (Outcome{Outcome: "stopped"}) {
			t.Errorf("%+v", out)
		}
		r := wd.row(id)
		if r.StoppedReason.String != "object_conflict" || r.LastError.String != ObjectConflict || !r.FailingSince.Valid || wd.plan(id) == nil {
			t.Errorf("row %+v", r)
		}
		if out := wd.run(id); out != (Outcome{Outcome: "busy"}) {
			t.Errorf("a stopped export is not leased: %+v", out)
		}
	})
	t.Run("a key that cannot read", func(t *testing.T) {
		wd, _, id := streaming(t, Credential{AccessKeyID: s3fake.KeyNoRead, SecretAccessKey: "x"})
		p := wd.plan(id)
		wd.fake.Plant(s3fake.BucketLocked, p.ObjectName, s3fake.Object{Body: []byte("x"), SHA256: "other"})
		if out := wd.run(id); out.Outcome != "done" {
			t.Errorf("%+v", out)
		}
		if r := wd.row(id); !r.KeyCanRead.Valid || r.KeyCanRead.Bool {
			t.Errorf("key_can_read %+v", r.KeyCanRead)
		}
	})
}

// Failures (Decision 11): the plan stays and the status keeps the fixed
// words; 15 minutes of them record audit_export.failing once; the next
// commit records audit_export.recovered. A lease holder whose binding
// moved during its upload commits nothing; the next one finds the object
// it landed.
func TestWorkerFailuresAndLeases(t *testing.T) {
	wd, c, id := streaming(t, good())
	wd.fake.SetDown(true)
	if out := wd.run(id); out != (Outcome{Outcome: "failed"}) {
		t.Fatalf("%+v", out)
	}
	r := wd.row(id)
	if !strings.HasPrefix(r.LastError.String, "Upload failed") || r.FailingSince.Int64 != c.now().UnixMicro() || r.FailingRecorded || wd.plan(id) == nil {
		t.Errorf("after a failure: %+v", r)
	}
	c.add(14 * time.Minute)
	wd.run(id)
	if n := len(wd.events("audit_export.failing")); n != 0 {
		t.Errorf("%d failing events before 15 minutes", n)
	}
	c.add(2 * time.Minute)
	wd.run(id)
	wd.run(id)
	failing := wd.events("audit_export.failing")
	if len(failing) != 1 || !strings.Contains(failing[0], `"failingSince":"2026-11-16T10:20:00.000Z"`) || !strings.Contains(failing[0], `"error":"Upload failed`) {
		t.Errorf("failing events %v", failing)
	}
	wd.fake.SetDown(false)
	if out := wd.run(id); out.Committed == 0 {
		t.Fatalf("recovery %+v", out)
	}
	recovered := wd.events("audit_export.recovered")
	if r := wd.row(id); len(recovered) != 1 || r.FailingSince.Valid || r.FailingRecorded || r.LastError.Valid {
		t.Errorf("recovered %v, row %+v", recovered, r)
	}

	// Another lease holder meanwhile: busy. A binding moved during the
	// upload: lost, and the next run finds the object landed.
	wd.record(3, "organization.renamed")
	var inner Outcome
	wd.s.Hooks.BeforeUpload = func(query.AuditExportPlan) error {
		wd.s.Hooks.BeforeUpload = nil
		inner, _ = wd.s.ExportOnce(context.Background(), id)
		return nil
	}
	wd.s.Hooks.BeforeCommit = func(query.AuditExportPlan) {
		wd.s.Hooks.BeforeCommit = nil
		wd.exec(`UPDATE audit_exports SET generation = generation + 1, lease_expires_at = NULL WHERE id = ?`, id)
	}
	if out := wd.run(id); out != (Outcome{Outcome: "lost"}) || inner.Outcome != "busy" {
		t.Errorf("moved: %+v, inner %+v", out, inner)
	}
	cursor := wd.row(id).CursorOrder
	if out := wd.run(id); out.Committed != 1 || wd.row(id).CursorOrder != cursor+3 {
		t.Errorf("after the move: %+v", out)
	}
	if got := wd.fake.Requests(); got[len(got)-2].Status != 412 || got[len(got)-1].Method != "HEAD" {
		t.Errorf("the second upload should find the first: %+v", got[len(got)-2:])
	}
}

// Restarts (Decision 2): a plan whose retention would end within the
// hour starts a new stream at the committed cursor, its manifest naming
// the dropped batch as a possible overlap; the host's discard-plan
// refuses a plan that can still be uploaded and restarts one in a format
// this release cannot upload.
func TestPlanRestarts(t *testing.T) {
	ctx := context.Background()
	wd, c, id := streaming(t, good())
	wd.run(id)
	first := wd.row(id)
	if _, err := wd.s.DiscardPlan(ctx, id, "expired"); func() string { c, _ := code(err); return c }() != "RESOURCE_NOT_FOUND" {
		t.Errorf("no plan: %v", err)
	}
	wd.record(2, "organization.renamed")
	wd.fake.SetDown(true)
	wd.run(id)
	p := wd.plan(id)
	if p == nil || p.Kind != "batch" {
		t.Fatalf("pending %+v", p)
	}
	for _, reason := range []string{"expired", "unsupported-format"} {
		if _, err := wd.s.DiscardPlan(ctx, id, reason); func() string { c, _ := code(err); return c }() != "VALIDATION_FAILED" {
			t.Errorf("%s: %v", reason, err)
		}
	}
	wd.fake.SetDown(false)
	c.add(23*time.Hour + 30*time.Minute)
	if out := wd.run(id); out != (Outcome{Outcome: "restarted"}) {
		t.Fatalf("%+v", out)
	}
	r := wd.row(id)
	np := wd.plan(id)
	mj := jsonOf(t, np.Body)
	overlap := map[string]any{"firstOrder": strconv.FormatInt(p.FirstOrder.Int64, 10), "lastOrder": strconv.FormatInt(p.LastOrder.Int64, 10)}
	if r.StreamID == first.StreamID || r.CursorOrder != first.CursorOrder || np.Kind != "manifest" || mj["reason"] != "plan_expired" ||
		mj["previousStreamId"] != first.StreamID || mj["startOrder"] != strconv.FormatInt(first.CursorOrder, 10) || !jsonEqual(mj["possibleOverlap"], overlap) {
		t.Errorf("restart: %+v, manifest %v", r, mj)
	}
	started := wd.events("audit_export.stream_started")
	if last := started[len(started)-1]; !strings.Contains(last, `"reason":"plan_expired"`) || !strings.Contains(last, `"overlapFirstOrder":"`+overlap["firstOrder"].(string)+`"`) {
		t.Errorf("event %s", last)
	}
	if out := wd.run(id); out.Outcome != "done" {
		t.Errorf("the new stream: %+v", out)
	}

	// A plan in a format this release cannot upload: stopped, then
	// discarded by the host.
	wd.record(1, "organization.renamed")
	wd.fake.SetDown(true)
	wd.run(id)
	wd.fake.SetDown(false)
	wd.exec(`UPDATE audit_export_plans SET format_version = 2 WHERE export_id = ?`, id)
	if out := wd.run(id); out != (Outcome{Outcome: "stopped"}) || wd.row(id).LastError.String != UnsupportedFormat(2) {
		t.Fatalf("%+v %+v", out, wd.row(id))
	}
	before := wd.row(id)
	stream, err := wd.s.DiscardPlan(ctx, id, "unsupported-format")
	after := wd.row(id)
	if err != nil || stream != after.StreamID || stream == before.StreamID || after.StoppedReason.Valid || after.Generation != before.Generation+1 {
		t.Fatalf("discard: %v, %+v", err, after)
	}
	if mj := jsonOf(t, wd.plan(id).Body); mj["reason"] != "plan_discarded" || mj["cause"] != "unsupported-format" || mj["possibleOverlap"] == nil {
		t.Errorf("manifest %v", mj)
	}
	started = wd.events("audit_export.stream_started")
	if last := started[len(started)-1]; !strings.Contains(last, `"reason":"plan_discarded","cause":"unsupported-format","overlapFirstOrder"`) {
		t.Errorf("event %s", last)
	}
	if out := wd.run(id); out.Outcome != "done" {
		t.Errorf("after the discard: %+v", out)
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// Decision 4: while a destination change's probe holds the export's gate,
// the worker's lease and the host's discard-plan wait for it, then meet
// the version and stream it made.
func TestWorkerAndHostWaitForAChangesProbe(t *testing.T) {
	ctx := context.Background()
	wd, _, id := streaming(t, good())
	wd.run(id)
	// A pending batch in a format this release cannot upload, which the
	// host may discard.
	wd.record(2, "organization.renamed")
	wd.fake.SetDown(true)
	wd.run(id)
	wd.fake.SetDown(false)
	wd.exec(`UPDATE audit_export_plans SET format_version = 2 WHERE export_id = ?`, id)
	row := wd.row(id)
	other := "moved/"
	in := ChangeInput{Destination: DestinationPatch{Prefix: &other}, ExpectedVersion: 1}
	d, r, _ := in.next(row)
	cl := classify(destinationOf(row), retentionOf(row), d, r)
	approval := "apr_changeaaaaaaaaaaaaaaaaaaaa"
	wd.approve(approval, changeBinding(wd.org, id, d, r, 1, cl))
	req := alice()
	req.Approval = &approval

	wd.fake.Hold, wd.fake.Held = make(chan struct{}), make(chan struct{}, 64)
	changed := make(chan error, 1)
	go func() { _, _, err := wd.s.Change(ctx, req, wd.org, id, in); changed <- err }()
	<-wd.fake.Held
	exported := make(chan Outcome, 1)
	go func() { out, _ := wd.s.ExportOnce(ctx, id); exported <- out }()
	discarded := make(chan error, 1)
	go func() { _, err := wd.s.DiscardPlan(ctx, id, "unsupported-format"); discarded <- err }()
	select {
	case out := <-exported:
		close(wd.fake.Hold)
		t.Fatalf("the worker did not wait for the probe: %+v", out)
	case err := <-discarded:
		close(wd.fake.Hold)
		t.Fatalf("discard-plan did not wait for the probe: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if waiting := wd.s.Writer.Gates.Waiting(); !slices.Equal(waiting, []write.Gate{exportGate(id), exportGate(id)}) {
		t.Errorf("waiting %v", waiting)
	}
	// Let the probe and everything after it through.
	close(wd.fake.Hold)
	if err := <-changed; err != nil {
		t.Fatalf("change: %v", err)
	}
	if out := <-exported; out.Outcome != "done" {
		t.Errorf("the worker after the change: %+v", out)
	}
	// The worker wrote the new stream's manifest, under the new prefix.
	after := wd.row(id)
	if after.Version != 2 || after.Prefix != "moved/" {
		t.Errorf("after: %+v", after)
	}
	if _, ok := wd.fake.Object(s3fake.BucketLocked, streamBase("moved/", wd.org.ID, after.StreamID)+"stream.json"); !ok {
		t.Errorf("no manifest under the new prefix: %v", wd.fake.Keys(s3fake.BucketLocked))
	}
	// discard-plan met the change's new stream: the plan it read is gone,
	// so it discarded nothing.
	if err := <-discarded; func() string { c, _ := code(err); return c }() != "STATE_CHANGED" {
		t.Errorf("discard-plan after the change: %v", err)
	}
}

func (wd *world) drain() string {
	wd.t.Helper()
	var drained string
	if err := wd.s.Writer.Job(context.Background(), nil, func(ctx context.Context, tx *storage.Tx) error {
		var err error
		drained, err = wd.s.RewrapForDrain(ctx, tx, wd.org.ID)
		return err
	}); err != nil {
		wd.t.Fatal(err)
	}
	return drained
}

// Drains (Decision 10): the Organization's deletion seals the export's key
// again under the Root KEK, so the worker still reads it once the
// Organization KEK is destroyed; the batch holding organization.deleted
// completes the drain, which then holds no key.
func TestDrain(t *testing.T) {
	wd, c, id := streaming(t, good())
	wd.run(id)
	before := wd.row(id)
	if got := wd.drain(); got != id {
		t.Fatalf("drained %q", got)
	}
	r := wd.row(id)
	var env envelope.Envelope
	if err := json.Unmarshal([]byte(r.CredentialEnvelope.String), &env); err != nil {
		t.Fatal(err)
	}
	plain, err := envelope.Open(wd.key, env, envelope.AuditExportDrainContext(wd.org.ID, id))
	if err != nil || string(plain) != `{"accessKeyId":"AKIAFIXTUREGOOD","secretAccessKey":"fixture-secret"}` || r.State != "draining" ||
		r.DrainDeadline.Int64 != c.now().Add(DrainTime).UnixMicro() || r.Generation != before.Generation+1 {
		t.Fatalf("drain: %v %+v", err, r)
	}
	if again := wd.drain(); again != "" {
		t.Errorf("a draining export drained again: %q", again)
	}
	wd.exec(`UPDATE organizations SET wrapped_org_kek = NULL, org_kek_destroyed_at = ?, deleted_at = ? WHERE id = ?`, c.now().UnixMicro(), c.now().UnixMicro(), wd.org.ID)
	wd.record(1, "organization.deleted")
	sent := len(wd.fake.Requests())
	if out := wd.run(id); out != (Outcome{Committed: 1, Outcome: "done"}) {
		t.Fatalf("drain run %+v", out)
	}
	r = wd.row(id)
	completed := wd.events("audit_export.completed")
	if r.State != "completed" || r.CredentialEnvelope.Valid || r.LeaseExpiresAt.Valid || len(completed) != 1 ||
		completed[0] != `{"streamId":"`+r.StreamID+`","lastOrder":"`+strconv.FormatInt(r.CursorOrder, 10)+`"}` {
		t.Errorf("completed: %+v %v", r, completed)
	}
	for _, q := range wd.fake.Requests()[sent:] {
		if q.AccessKey != s3fake.KeyGood {
			t.Errorf("drain request with %q", q.AccessKey)
		}
	}
	if out := wd.run(id); out.Outcome != "busy" {
		t.Errorf("a completed export: %+v", out)
	}
}

// A drain not completed by its deadline is abandoned (its key and plan
// dropped, audit_export.abandoned once): by the deletion loop, by the
// worker that may not lease it, and at a commit that finds the deadline
// passed during the upload.
func TestDrainDeadline(t *testing.T) {
	abandoned := func(t *testing.T, wd *world, id string) {
		t.Helper()
		r := wd.row(id)
		ev := wd.events("audit_export.abandoned")
		if r.State != "abandoned" || r.CredentialEnvelope.Valid || wd.plan(id) != nil || len(ev) != 1 || !strings.Contains(ev[0], `"drainDeadline":"2026-12-16T10:20:00.000Z"`) {
			t.Errorf("abandoned: %+v %v", r, ev)
		}
	}
	t.Run("the deletion loop", func(t *testing.T) {
		wd, c, id := streaming(t, good())
		wd.drain()
		if got, err := wd.s.AbandonExpiredDrains(context.Background()); err != nil || got != nil {
			t.Errorf("before the deadline: %v %v", got, err)
		}
		c.add(DrainTime)
		if got, err := wd.s.AbandonExpiredDrains(context.Background()); err != nil || !slices.Equal(got, []string{id}) {
			t.Fatalf("at the deadline: %v %v", got, err)
		}
		abandoned(t, wd, id)
	})
	t.Run("the worker", func(t *testing.T) {
		wd, c, id := streaming(t, good())
		wd.drain()
		c.add(DrainTime + time.Second)
		if out := wd.run(id); out != (Outcome{Outcome: "abandoned"}) {
			t.Errorf("%+v", out)
		}
		abandoned(t, wd, id)
	})
	t.Run("at the commit", func(t *testing.T) {
		wd, c, id := streaming(t, good())
		wd.drain()
		wd.s.Hooks.BeforeCommit = func(query.AuditExportPlan) { c.add(DrainTime) }
		if out := wd.run(id); out != (Outcome{Outcome: "abandoned"}) {
			t.Errorf("%+v", out)
		}
		abandoned(t, wd, id)
	})
}

// A restore (Decision 5) gives every live export a new stream at its
// restored cursor, its pending plan replaced by the new manifest, and
// records stream_started (reason restored) after installation.restored.
func TestRecordRestore(t *testing.T) {
	wd, c, id := streaming(t, good())
	before := wd.row(id)
	restored := audit.Event{Type: "installation.restored", Decision: audit.Info, Metadata: jsvalue.Object{{Key: "archiveId", Value: "a"}}}
	if err := wd.store.Write(context.Background(), func(tx *storage.Tx) error {
		return RecordRestore(context.Background(), tx, restored, c.now())
	}); err != nil {
		t.Fatal(err)
	}
	after := wd.row(id)
	mj := jsonOf(t, wd.plan(id).Body)
	if after.StreamID == before.StreamID || after.Generation != before.Generation+1 || mj["reason"] != "restored" || mj["previousStreamId"] != before.StreamID {
		t.Errorf("restore: %+v %v", after, mj)
	}
	var types []string
	rows, _ := wd.store.Reader().Query(`SELECT event_type FROM audit_events ORDER BY event_order DESC LIMIT 2`)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		types = append(types, s)
	}
	rows.Close()
	if !slices.Equal(types, []string{"audit_export.stream_started", "installation.restored"}) {
		t.Errorf("events %v", types)
	}
	if out := wd.run(id); out.Outcome != "done" {
		t.Errorf("after the restore %+v", out)
	}
}

// A key this installation cannot open is a recorded failure, not an error.
func TestWorkerKeyUnreadable(t *testing.T) {
	wd, _, id := streaming(t, good())
	wd.exec(`UPDATE audit_exports SET credential_envelope = json_set(credential_envelope, '$.ciphertext', 'AAAA') WHERE id = ?`, id)
	if out := wd.run(id); out != (Outcome{Outcome: "failed"}) {
		t.Errorf("%+v", out)
	}
	if r := wd.row(id); r.LastError.String != "The export's key could not be read on this installation" || len(wd.fake.Requests()) != 4 {
		t.Errorf("%+v, %d requests", r, len(wd.fake.Requests()))
	}
}

// replaceKey replaces the export's key through ReplaceCredential with an
// approved intent, as the requester's approval would.
func (wd *world) replaceKey(id string, c Credential, expected int64, approval string) {
	wd.t.Helper()
	orgID := wd.org.ID
	wd.approve(approval, auth.Binding{
		Operation: "audit_export.change", OrganizationID: &orgID, Target: map[string]string{"exportId": id},
		Body:  jsvalue.Object{{Key: "credential", Value: c.js()}, {Key: "expectedVersion", Value: expected}},
		Query: map[string]string{}, ExpectedVersion: &expected,
		Summary: auth.ApprovalSummary{Title: "Replace the key of the audit export of " + wd.org.Name,
			Changes: []auth.ApprovalChange{{Field: "credential", Loosens: true}}},
	})
	req := alice()
	req.Approval = &approval
	if _, err := wd.s.ReplaceCredential(context.Background(), req, wd.org, id, c, expected); err != nil {
		wd.t.Fatalf("replacing the key: %v", err)
	}
}

// A new key (Decision 3) keeps the stream and the pending plan: the next
// lease holder uploads the plan's unchanged bytes with the new key, never
// the old one. A replacement during an upload makes that holder's commit
// lost; the next holder finds the object landed (412, then the HEAD) with
// the new key and commits it.
func TestWorkerUploadsAPendingPlanWithANewKey(t *testing.T) {
	newKey := Credential{AccessKeyID: s3fake.KeyNoRetentionRead, SecretAccessKey: "rotated-secret"}
	t.Run("pending", func(t *testing.T) {
		wd, _, id := streaming(t, good())
		wd.run(id)
		wd.record(3, "organization.renamed")
		wd.fake.SetDown(true)
		wd.run(id)
		wd.fake.SetDown(false)
		pending := wd.plan(id)
		if pending == nil || pending.Kind != "batch" {
			t.Fatalf("pending %+v", pending)
		}
		before := wd.row(id)
		wd.replaceKey(id, newKey, before.Version, "apr_rekeyaaaaaaaaaaaaaaaaaaaaa")
		after := wd.row(id)
		if after.StreamID != before.StreamID || after.Generation != before.Generation+1 || after.KeyCanRead.Valid {
			t.Fatalf("after the replacement: %+v", after)
		}
		if p := wd.plan(id); p == nil || p.ID != pending.ID || !bytes.Equal(p.Body, pending.Body) {
			t.Fatalf("the pending plan changed: %+v", p)
		}
		// The pending batch, then the batch with the replacement's own
		// event (audit_export.credential_replaced), each with the new key.
		sent := len(wd.fake.Requests())
		if out := wd.run(id); out != (Outcome{Committed: 2, Outcome: "done"}) {
			t.Fatalf("%+v", out)
		}
		reqs := wd.fake.Requests()[sent:]
		if len(reqs) != 2 || reqs[0].Method != "PUT" || reqs[0].Key != pending.ObjectName || reqs[0].Status != 200 {
			t.Fatalf("requests %+v", reqs)
		}
		for _, r := range reqs {
			if r.AccessKey != s3fake.KeyNoRetentionRead {
				t.Errorf("a request with the old key: %+v", r)
			}
		}
		if o := object(t, wd, pending.ObjectName); !bytes.Equal(o.Body, pending.Body) || o.SHA256 != pending.Sha256 {
			t.Errorf("uploaded other bytes than the plan's")
		}
		if r := wd.row(id); r.CursorOrder != pending.LastOrder.Int64+1 {
			t.Errorf("cursor %d, want %d", r.CursorOrder, pending.LastOrder.Int64+1)
		}
	})
	t.Run("during an upload", func(t *testing.T) {
		wd, _, id := streaming(t, good())
		wd.run(id)
		wd.record(2, "organization.renamed")
		version := wd.row(id).Version
		wd.s.Hooks.BeforeCommit = func(query.AuditExportPlan) {
			wd.s.Hooks.BeforeCommit = nil
			wd.replaceKey(id, newKey, version, "apr_rekeyduringaaaaaaaaaaaaaaa")
		}
		if out := wd.run(id); out != (Outcome{Outcome: "lost"}) {
			t.Fatalf("the holder the replacement moved: %+v", out)
		}
		pending := wd.plan(id)
		if pending == nil || pending.Kind != "batch" {
			t.Fatalf("pending %+v", pending)
		}
		// The landed batch (412, then the HEAD), then the replacement's
		// event in a batch of its own, all with the new key.
		sent := len(wd.fake.Requests())
		if out := wd.run(id); out != (Outcome{Committed: 2, Outcome: "done"}) {
			t.Fatalf("%+v", out)
		}
		reqs := wd.fake.Requests()[sent:]
		if len(reqs) != 3 || reqs[0].Key != pending.ObjectName || reqs[0].Status != 412 || reqs[1].Method != "HEAD" || reqs[2].Status != 200 {
			t.Fatalf("requests %+v", reqs)
		}
		for _, r := range reqs {
			if r.AccessKey != s3fake.KeyNoRetentionRead {
				t.Errorf("a request with the old key: %+v", r)
			}
		}
		if r := wd.row(id); r.CursorOrder != pending.LastOrder.Int64+1 || !r.KeyCanRead.Valid || !r.KeyCanRead.Bool {
			t.Errorf("after: %+v", r)
		}
	})
}
