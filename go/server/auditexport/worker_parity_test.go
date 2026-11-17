// SPDX-License-Identifier: AGPL-3.0-or-later

package auditexport_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auditexport"
	"github.com/varlatch/varlatch/go/server/auditexport/s3fake"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/write"
)

var writeGoSealedWorker = flag.String("write-go-sealed-worker", "", "write the audit export worker fixture with every key, export credential and drain copy sealed again by Go to this path")

// The worker fixture's tables (go-audit-export-worker-fixture.test.ts).
var workerTables = []string{"installation", "identities", "organizations", "org_memberships", "audit_events", "audit_exports", "audit_export_plans"}

// step is one step of the worker fixture: its action, by Organization slug.
type step struct {
	Name   string `json:"name"`
	Run    string `json:"run"`
	Record string `json:"record"`
	Events []struct {
		Type     string          `json:"type"`
		Metadata json.RawMessage `json:"metadata"`
	} `json:"events"`
	Down          *bool  `json:"down"`
	HeartbeatsOff bool   `json:"heartbeatsOff"`
	Age           string `json:"age"`
	Org           string `json:"org"`
	Format        int    `json:"format"`
	Plant         string `json:"plant"`
	Discard       string `json:"discard"`
	Reason        string `json:"reason"`
	Drain         string `json:"drain"`
}

type workerFixture struct {
	RootKek     string                            `json:"rootKek"`
	Rows        map[string][]paritytest.Row       `json:"rows"`
	Steps       []step                            `json:"steps"`
	Results     []any                             `json:"results"`
	Credentials map[string]auditexport.Credential `json:"credentials"`
}

func readWorker(t *testing.T) workerFixture {
	t.Helper()
	b, err := os.ReadFile(paritytest.Path("audit-export-worker-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f workerFixture
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&f); err != nil {
		t.Fatal(err)
	}
	if len(f.Steps) < 40 || len(f.Results) != len(f.Steps) {
		t.Fatalf("%d steps, %d results: the fixture is incomplete", len(f.Steps), len(f.Results))
	}
	return f
}

var hourName = regexp.MustCompile(`\b\d{4}-\d\d-\d\dT\d\d([^\d:]|$)`)

// hours is the fixture's {hour}: the worker plans on its own clock.
func hours(v any) any {
	switch x := v.(type) {
	case string:
		return hourName.ReplaceAllString(x, "{hour}${1}")
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = hours(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = hours(e)
		}
		return out
	}
	return v
}

// plainJSON is v as JSON reads it back (numbers as float64), so a value
// built here and one read from the file compare the same way.
func plainJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func boolOf(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64 == 1
}

func strOf(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}

// replayWorker runs the fixture's steps against the Go worker on the
// file's rows and compares each step's result with the file's, on the
// recording's clock (paritytest.RecordedClock: a plan's retain_until and a
// drain's deadline mean what they meant when recorded): wall is the date
// outside (time.Now).
func replayWorker(t *testing.T, f workerFixture, wall func() time.Time) {
	clock, err := paritytest.RecordedClock(f.Rows, wall)
	if err != nil {
		t.Fatal(err)
	}
	fake := s3fake.New()
	t.Cleanup(fake.Close)
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, workerTables); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rootKEK, err := hex.DecodeString(f.RootKek)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &auditexport.Service{Writer: &write.Writer{Store: store, Gates: write.NewGates()}, RootKEK: rootKEK,
		Policy: fixturePolicy(t, fake, log), Now: clock, Enabled: true, Log: log}
	n := paritytest.NewNormalizer(f.Rows)
	orgOf := map[string]string{}
	for _, o := range f.Rows["organizations"] {
		orgOf[o["slug"].(string)] = o["id"].(string)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if err := store.Write(ctx, func(tx *storage.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	exportOf := func(slug string) string {
		t.Helper()
		var id string
		if err := store.Reader().QueryRow(`SELECT id FROM audit_exports WHERE organization_id = ? ORDER BY created_at DESC LIMIT 1`, orgOf[slug]).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	for i, s := range f.Steps {
		requests := len(fake.Requests())
		var events int64
		_ = store.Reader().QueryRow(`SELECT coalesce(max(event_order), 0) FROM audit_events`).Scan(&events)
		var result any
		now := clock()
		switch {
		case s.Run != "":
			out, err := svc.ExportOnce(ctx, exportOf(s.Run))
			if err != nil {
				t.Fatalf("%s: %v", s.Name, err)
			}
			result = map[string]any{"committed": out.Committed, "outcome": out.Outcome}
		case s.Record != "":
			org := orgOf[s.Record]
			evs := make([]audit.Event, len(s.Events))
			for j, e := range s.Events {
				md, err := jsvalue.Parse(e.Metadata)
				if err != nil {
					t.Fatal(err)
				}
				evs[j] = audit.Event{Type: e.Type, Decision: audit.Info, OrganizationID: &org, Metadata: md.(jsvalue.Object)}
			}
			if err := store.Write(ctx, func(tx *storage.Tx) error { _, err := audit.Record(ctx, tx, evs...); return err }); err != nil {
				t.Fatal(err)
			}
		case s.Down != nil:
			fake.SetDown(*s.Down)
		case s.HeartbeatsOff:
			exec(`UPDATE audit_exports SET last_heartbeat_hour = ?`, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).UnixMicro())
		case s.Age == "failing":
			exec(`UPDATE audit_exports SET failing_since = ? WHERE id = ?`, now.Add(-20*time.Minute).UnixMicro(), exportOf(s.Org))
		case s.Age == "plan":
			exec(`UPDATE audit_export_plans SET retain_until = ? WHERE export_id = ?`, now.Add(30*time.Minute).UnixMicro(), exportOf(s.Org))
		case s.Age == "drain":
			exec(`UPDATE audit_exports SET drain_deadline = ? WHERE id = ?`, now.Add(-time.Second).UnixMicro(), exportOf(s.Org))
		case s.Format != 0:
			exec(`UPDATE audit_export_plans SET format_version = ? WHERE export_id = ?`, s.Format, exportOf(s.Org))
		case s.Plant != "":
			var name, sum string
			var body []byte
			if err := store.Reader().QueryRow(`SELECT object_name, body, sha256 FROM audit_export_plans WHERE export_id = ?`, exportOf(s.Org)).Scan(&name, &body, &sum); err != nil {
				t.Fatal(err)
			}
			if s.Plant == "other" {
				body = []byte("other content")
				sum = sha256Hex(body)
			}
			fake.Plant(s3fake.BucketLocked, name, s3fake.Object{Body: body, SHA256: sum})
		case s.Discard != "":
			stream, err := svc.DiscardPlan(ctx, exportOf(s.Discard), s.Reason)
			var de *domainerr.Error
			switch {
			case errors.As(err, &de):
				result = map[string]any{"error": de.Code, "message": de.Message}
			case err != nil:
				t.Fatal(err)
			default:
				result = map[string]any{"streamId": stream}
			}
		case s.Drain != "":
			var drained string
			if err := svc.Writer.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
				var err error
				drained, err = svc.RewrapForDrain(ctx, tx, orgOf[s.Drain])
				return err
			}); err != nil {
				t.Fatal(err)
			}
			exec(`UPDATE organizations SET deleted_at = ?, wrapped_org_kek = NULL, org_kek_destroyed_at = ? WHERE id = ?`, now.UnixMicro(), now.UnixMicro(), orgOf[s.Drain])
			var d any
			if drained != "" {
				d = drained
			}
			result = map[string]any{"drained": d}
		default:
			t.Fatalf("step %q: no action", s.Name)
		}
		got := map[string]any{"step": s.Name, "result": result, "exchanges": []any{}, "objects": []any{},
			"exports": workerExports(t, store), "plans": workerPlans(t, store), "events": workerEvents(t, store, events)}
		var exchanges, objects []any
		for _, r := range fake.Requests()[requests:] {
			line := r.Method
			if r.Retention {
				line += " retention"
			}
			exchanges = append(exchanges, fmt.Sprintf("%s %s %d", line, r.AccessKey, r.Status))
			if r.Method != "PUT" || r.Status != 200 {
				continue
			}
			o, _ := fake.Object(r.Bucket, r.Key)
			body := o.Body
			if o.ContentType == "application/gzip" {
				zr, err := gzip.NewReader(bytes.NewReader(o.Body))
				if err != nil {
					t.Fatal(err)
				}
				if body, err = io.ReadAll(zr); err != nil {
					t.Fatal(err)
				}
			}
			// The retention's date as an instant: SDKs write its fraction
			// their own way (the Go SDK drops trailing zeros).
			until := o.Until
			if until != "" {
				at, err := time.Parse(time.RFC3339Nano, until)
				if err != nil {
					t.Fatal(err)
				}
				until = audit.ISOTime(at.UnixMicro())
			}
			objects = append(objects, map[string]any{"name": r.Key, "contentType": o.ContentType, "mode": o.Mode, "until": until,
				"checksum": o.SHA256 == sha256Hex(o.Body), "body": string(body)})
		}
		if exchanges != nil {
			got["exchanges"] = exchanges
		}
		if objects != nil {
			got["objects"] = objects
		}
		normalized := n.Value(hours(plainJSON(t, got)), "")
		if g, w := paritytest.Canonical(normalized), paritytest.Canonical(plainJSON(t, f.Results[i])); g != w {
			t.Fatalf("step %d, %s:\n got %s\nwant %s", i, s.Name, g, w)
		}
	}
}

func workerExports(t *testing.T, store *storage.DB) []any {
	t.Helper()
	rows, err := store.Reader().Query(`SELECT organization_id, state, stream_id, CAST(cursor_order AS TEXT), CAST(generation AS TEXT), version, stopped_reason,
		last_error, failing_recorded, key_can_read, retention_readable, failing_since IS NOT NULL, lease_expires_at IS NOT NULL,
		last_heartbeat_hour IS NOT NULL, last_success_at IS NOT NULL, credential_envelope IS NOT NULL, drain_deadline IS NOT NULL
		FROM audit_exports ORDER BY organization_id, created_at`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []any
	for rows.Next() {
		var org, state, stream, cursor, generation string
		var version int64
		var stopped, lastError sql.NullString
		var failingRecorded, failing, leased, heartbeat, succeeded, keyed, drain bool
		var keyCanRead, retentionReadable sql.NullInt64
		if err := rows.Scan(&org, &state, &stream, &cursor, &generation, &version, &stopped, &lastError, &failingRecorded, &keyCanRead, &retentionReadable,
			&failing, &leased, &heartbeat, &succeeded, &keyed, &drain); err != nil {
			t.Fatal(err)
		}
		out = append(out, map[string]any{"organization_id": org, "state": state, "stream_id": stream, "cursor": cursor, "generation": generation,
			"version": version, "stopped_reason": strOf(stopped), "last_error": strOf(lastError), "failing_recorded": failingRecorded,
			"key_can_read": boolOf(keyCanRead), "retention_readable": boolOf(retentionReadable), "failing": failing, "leased": leased,
			"heartbeat": heartbeat, "succeeded": succeeded, "keyed": keyed, "drain": drain})
	}
	return out
}

func workerPlans(t *testing.T, store *storage.DB) []any {
	t.Helper()
	rows, err := store.Reader().Query(`SELECT x.organization_id, p.kind, p.stream_id, p.object_name, p.format_version, p.retention_mode,
		CAST(p.first_order AS TEXT), CAST(p.last_order AS TEXT), p.event_count, p.heartbeat_hour IS NOT NULL, p.retain_until IS NOT NULL
		FROM audit_export_plans p JOIN audit_exports x ON x.id = p.export_id ORDER BY x.organization_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var org, kind, stream, name string
		var format int64
		var mode, first, last sql.NullString
		var count sql.NullInt64
		var heartbeat, retained bool
		if err := rows.Scan(&org, &kind, &stream, &name, &format, &mode, &first, &last, &count, &heartbeat, &retained); err != nil {
			t.Fatal(err)
		}
		var c any
		if count.Valid {
			c = count.Int64
		}
		out = append(out, map[string]any{"organization_id": org, "kind": kind, "stream_id": stream, "object_name": name, "format_version": format,
			"retention_mode": strOf(mode), "first_order": strOf(first), "last_order": strOf(last), "event_count": c, "heartbeat": heartbeat, "retained": retained})
	}
	return out
}

func workerEvents(t *testing.T, store *storage.DB, after int64) []any {
	t.Helper()
	rows, err := store.Reader().Query(`SELECT event_type, organization_id, resource, metadata FROM audit_events WHERE event_order > ? ORDER BY event_order`, after)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var typ string
		var org, resource, metadata sql.NullString
		if err := rows.Scan(&typ, &org, &resource, &metadata); err != nil {
			t.Fatal(err)
		}
		parse := func(s sql.NullString) any {
			if !s.Valid {
				return nil
			}
			var v any
			if err := json.Unmarshal([]byte(s.String), &v); err != nil {
				t.Fatal(err)
			}
			return v
		}
		out = append(out, map[string]any{"event_type": typ, "organization_id": strOf(org), "resource": parse(resource), "metadata": parse(metadata)})
	}
	return out
}

// The worker fixture gives the TypeScript worker's steps (step 4.11b):
// the stream (manifest, heartbeat, batches with every event's
// serialization), failures and recovery, the expired plan's restart, the
// host's discard-plan, an upload that landed before, an object conflict,
// drains completed and abandoned. gamma's drain sends the key the
// TypeScript code sealed under the Root KEK: G3 at the database level for
// drain copies, ts-to-go.
func TestTypeScriptWorkerFixture(t *testing.T) {
	replayWorker(t, readWorker(t), time.Now)
}

// TestWorkerFixtureLaterDate: the replay does not depend on the date it
// runs on. With the date outside 30 days after today (beyond the
// fixture's longest lifetime, a drain's 30 days), it gives the same
// results.
func TestWorkerFixtureLaterDate(t *testing.T) {
	replayWorker(t, readWorker(t), func() time.Time { return time.Now().Add(30 * 24 * time.Hour) })
}

// TestGoSealedWorkerFixture: the same steps with the canary, every
// Organization KEK, every export credential and gamma's drain copy sealed
// again by Go; with -write-go-sealed-worker, the file for the TypeScript
// side (G3, go-to-ts).
func TestGoSealedWorkerFixture(t *testing.T) {
	f := readWorker(t)
	rootKEK, err := hex.DecodeString(f.RootKek)
	if err != nil {
		t.Fatal(err)
	}
	for _, inst := range f.Rows["installation"] {
		canary, err := envelope.NewCanary(rootKEK, inst["id"].(string))
		if err != nil {
			t.Fatal(err)
		}
		inst["kek_canary"] = envelopeValue(t, canary)
	}
	kekOf := map[string][]byte{}
	for _, o := range f.Rows["organizations"] {
		if o["wrapped_org_kek"] == nil {
			continue
		}
		id := o["id"].(string)
		kek, wrapped, err := envelope.WrapOrgKEK(rootKEK, id)
		if err != nil {
			t.Fatal(err)
		}
		kekOf[id] = kek
		o["wrapped_org_kek"] = envelopeValue(t, wrapped)
	}
	drains := 0
	for _, e := range f.Rows["audit_exports"] {
		if e["credential_envelope"] == nil {
			continue
		}
		id, org := e["id"].(string), e["organization_id"].(string)
		c, ok := f.Credentials[id]
		if !ok {
			t.Fatalf("no credential for %s", id)
		}
		plain := jsvalue.Stringify(jsvalue.Object{{Key: "accessKeyId", Value: c.AccessKeyID}, {Key: "secretAccessKey", Value: c.SecretAccessKey}})
		var sealed envelope.Envelope
		if e["state"] == "draining" {
			sealed, err = envelope.Seal(rootKEK, plain, envelope.AuditExportDrainContext(org, id))
			drains++
		} else {
			sealed, err = envelope.Seal(kekOf[org], plain, envelope.AuditExportCredentialContext(org, id))
		}
		if err != nil {
			t.Fatal(err)
		}
		e["credential_envelope"] = envelopeValue(t, sealed)
	}
	if drains != 1 {
		t.Fatalf("%d drain copies in the fixture, want gamma's", drains)
	}
	replayWorker(t, f, time.Now)
	if *writeGoSealedWorker == "" {
		return
	}
	var raw map[string]json.RawMessage
	b, err := os.ReadFile(paritytest.Path("audit-export-worker-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	comment := "Written by the Go tests (go test ./server/auditexport -run TestGoSealedWorkerFixture -args -write-go-sealed-worker=<file>): the audit export worker fixture with the Root KEK canary, every Organization KEK, every export credential and the drain copy sealed again by Go; services/varlatchd/test/go-audit-export-worker-fixture.test.ts runs its steps with the TypeScript server."
	for k, v := range map[string]any{"comment": comment, "ref": "go", "rows": f.Rows} {
		enc, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		raw[k] = enc
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(*writeGoSealedWorker, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
