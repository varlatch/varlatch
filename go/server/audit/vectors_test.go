// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// testdata/ts-vectors.json comes from the TypeScript server's own audit
// code (services/varlatchd/test/go-audit-vectors.test.ts, which also
// checks it is current).

type rowJSON struct {
	Position   int64                      `json:"position"`
	OccurredAt int64                      `json:"occurredAt"`
	Stored     map[string]json.RawMessage `json:"stored"`
	EventJSON  *string                    `json:"eventJSON"`
	StreamLine *string                    `json:"streamLine"`
	Throws     string                     `json:"throws"`
}

type vectorFile struct {
	EventTypes   []string                   `json:"eventTypes"`
	Attributions map[string]json.RawMessage `json:"attributions"`
	Recordings   []struct {
		Name          string                       `json:"name"`
		Attribution   string                       `json:"attribution"`
		Events        []map[string]json.RawMessage `json:"events"`
		FrozenRefusal *struct {
			Principal    *string `json:"principal"`
			CredentialID *string `json:"credentialId"`
			FreezeID     string  `json:"freezeId"`
			Method       string  `json:"method"`
			Route        string  `json:"route"`
			RequestID    string  `json:"requestId"`
		} `json:"frozenRefusal"`
		Rows []rowJSON `json:"rows"`
	} `json:"recordings"`
	RawRows []struct {
		Input map[string]json.RawMessage `json:"input"`
		rowJSON
	} `json:"rawRows"`
	Exposure   []map[string]string `json:"exposure"`
	ParseItems []struct {
		Items  string          `json:"items"`
		Parsed json.RawMessage `json:"parsed"`
	} `json:"parseItems"`
	ExposureFromEvent []struct {
		Event map[string]json.RawMessage `json:"event"`
		Entry json.RawMessage            `json:"entry"`
	} `json:"exposureFromEvent"`
	Redact []struct {
		URL      string `json:"url"`
		Redacted string `json:"redacted"`
	} `json:"redact"`
}

const org = "org_acme"

func load(t *testing.T) *vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func value(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	if raw == nil {
		return nil
	}
	v, err := jsvalue.Parse(raw)
	if err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	return v
}

func str(t *testing.T, raw json.RawMessage) *string {
	t.Helper()
	if v, ok := value(t, raw).(string); ok {
		return &v
	}
	return nil
}

func object(t *testing.T, raw json.RawMessage) jsvalue.Object {
	t.Helper()
	o, _ := value(t, raw).(jsvalue.Object)
	return o
}

// event is an AuditEventInput from the file: a field absent is undefined,
// null is null.
func event(t *testing.T, m map[string]json.RawMessage) audit.Event {
	t.Helper()
	e := audit.Event{
		Type:                   *str(t, m["eventType"]),
		Decision:               *str(t, m["decision"]),
		ActorIdentityID:        str(t, m["actorIdentityId"]),
		AuthenticationMethodID: str(t, m["authenticationMethodId"]),
		OrganizationID:         str(t, m["organizationId"]),
		Action:                 str(t, m["action"]),
		Resource:               object(t, m["resource"]),
		Authz:                  value(t, m["authz"]),
		RequestID:              str(t, m["requestId"]),
		Metadata:               object(t, m["metadata"]),
	}
	if id := str(t, m["id"]); id != nil {
		e.ID = *id
	}
	opt := func(name string) (audit.Opt[string], bool) {
		raw, ok := m[name]
		switch {
		case !ok:
			return audit.Opt[string]{}, false
		case string(raw) == "null":
			return audit.Null[string](), true
		}
		return audit.Value(*str(t, raw)), true
	}
	if o, ok := opt("credentialId"); ok {
		e.CredentialID = o
	}
	if o, ok := opt("client"); ok {
		e.Client = o
	}
	if o, ok := opt("listener"); ok {
		e.Listener = o
	}
	if raw, ok := m["tailnet"]; ok {
		if string(raw) == "null" {
			e.Tailnet = audit.Null[any]()
		} else {
			e.Tailnet = audit.Value(value(t, raw))
		}
	}
	return e
}

func attribution(t *testing.T, raw json.RawMessage) (audit.Attribution, bool) {
	t.Helper()
	if string(raw) == "null" {
		return audit.Attribution{}, false
	}
	var a struct {
		IdentityID   string          `json:"identityId"`
		CredentialID string          `json:"credentialId"`
		Client       *string         `json:"client"`
		Listener     string          `json:"listener"`
		Tailnet      json.RawMessage `json:"tailnet"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	return audit.Attribution{IdentityID: a.IdentityID, CredentialID: a.CredentialID, Client: a.Client, Listener: a.Listener, Tailnet: value(t, a.Tailnet)}, true
}

func openDB(t *testing.T) *storage.DB {
	t.Helper()
	s, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := db.Init(context.Background(), s, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	exec(t, s,
		`INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES ('org_acme', 'acme', 'Acme', '{}')`,
		`INSERT INTO identities (id, kind, name) VALUES ('idn_alice', 'human', 'idn_alice'), ('idn_bob', 'human', 'idn_bob')`,
		`INSERT INTO identities (id, kind, name, organization_id) VALUES ('idn_svc', 'service', 'idn_svc', 'org_acme')`,
	)
	return s
}

func exec(t *testing.T, s *storage.DB, stmts ...string) {
	t.Helper()
	err := s.Write(context.Background(), func(tx *storage.Tx) error {
		for _, q := range stmts {
			if _, err := tx.ExecContext(context.Background(), q); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEventTypesMatchTypeScript(t *testing.T) {
	if v := load(t); !slices.Equal(v.EventTypes, audit.EventTypes) {
		t.Fatalf("EventTypes differ from AUDIT_EVENT_TYPES:\n go %v\n ts %v", audit.EventTypes, v.EventTypes)
	}
}

// canonical is a stored column's value as jsonb holds it, for comparing
// what PostgreSQL stored (read back by node-postgres) with what SQLite
// stored.
func canonical(v any) string { return string(jsvalue.Stringify(jsvalue.Jsonb(v))) }

func checkRow(t *testing.T, name string, got query.AuditEvent, want rowJSON) {
	t.Helper()
	if got.EventOrder != want.Position {
		t.Errorf("%s: position %d, TypeScript %d", name, got.EventOrder, want.Position)
	}
	text := func(c sql.NullString) any {
		if !c.Valid {
			return nil
		}
		return c.String
	}
	jsonCol := func(c sql.NullString) any {
		if !c.Valid {
			return nil
		}
		v, err := jsvalue.Parse([]byte(c.String))
		if err != nil {
			t.Fatalf("%s: stored JSON %q: %v", name, c.String, err)
		}
		return v
	}
	cols := map[string]any{
		"id": got.ID, "schema_version": got.SchemaVersion, "event_type": got.EventType, "decision": got.Decision,
		"actor_identity_id": text(got.ActorIdentityID), "authentication_method_id": text(got.AuthenticationMethodID),
		"credential_id": text(got.CredentialID), "organization_id": text(got.OrganizationID), "action": text(got.Action),
		"listener": text(got.Listener), "request_id": text(got.RequestID), "client": text(got.Client),
		"resource": jsonCol(got.Resource), "authz": jsonCol(got.Authz), "tailnet": jsonCol(got.Tailnet), "metadata": jsonCol(got.Metadata),
	}
	for col, g := range cols {
		raw, ok := want.Stored[col]
		if !ok {
			t.Fatalf("%s: no stored %s in the vector", name, col)
		}
		w := value(t, raw)
		if col == "schema_version" {
			w = int64(w.(float64))
		}
		if canonical(g) != canonical(w) {
			t.Errorf("%s: %s\n got %s\nwant %s", name, col, canonical(g), canonical(w))
		}
	}
	got.OccurredAt = want.OccurredAt
	line, err := audit.EventJSON(got)
	stream, err2 := audit.ExportStreamLine(got)
	if want.Throws != "" {
		if err == nil || err2 == nil {
			t.Errorf("%s: serialized, TypeScript throws %s", name, want.Throws)
		}
		return
	}
	if err != nil || err2 != nil {
		t.Fatalf("%s: %v %v", name, err, err2)
	}
	if string(line) != *want.EventJSON {
		t.Errorf("%s: event JSON\n got %s\nwant %s", name, line, *want.EventJSON)
	}
	if string(stream) != *want.StreamLine {
		t.Errorf("%s: export stream line\n got %s\nwant %s", name, stream, *want.StreamLine)
	}
	export, err := audit.ExportLines([]query.AuditEvent{got, got})
	if err != nil || string(export) != *want.EventJSON+"\n"+*want.EventJSON+"\n" {
		t.Errorf("%s: export lines %q, %v", name, export, err)
	}
}

// Record stores what recordAuditEvents stores, in and out of a request's
// attribution, at the same positions; the stored rows serialize to the
// same bytes; and the exposure index gets the same rows.
func TestRecordAndSerializeVectors(t *testing.T) {
	v := load(t)
	s := openDB(t)
	bg := context.Background()
	type check struct {
		name string
		want rowJSON
	}
	var checks []check
	for _, rec := range v.Recordings {
		ctx := bg
		if a, ok := attribution(t, v.Attributions[rec.Attribution]); ok {
			ctx = audit.WithAttribution(ctx, a)
		}
		var events []audit.Event
		for _, m := range rec.Events {
			events = append(events, event(t, m))
		}
		if f := rec.FrozenRefusal; f != nil {
			var p *authz.Principal
			if f.Principal != nil {
				p = &authz.Principal{IdentityID: *f.Principal, IdentityKind: "human", CredentialID: *f.CredentialID}
			}
			e := authz.FrozenRefusalEvent(p, &authz.FrozenError{FreezeID: f.FreezeID, OrganizationID: org}, f.Method, f.Route, f.RequestID)
			e.ID = *str(t, rec.Rows[0].Stored["id"]) // the TypeScript ID was random; the file fixes it
			events = append(events, e)
		}
		var got []audit.Recorded
		err := s.Write(ctx, func(tx *storage.Tx) error {
			var err error
			got, err = audit.Record(ctx, tx, events...)
			return err
		})
		if err != nil {
			t.Fatalf("%s: %v", rec.Name, err)
		}
		if len(got) != len(rec.Rows) {
			t.Fatalf("%s: %d events recorded, TypeScript %d", rec.Name, len(got), len(rec.Rows))
		}
		for i, r := range got {
			if r.Position != rec.Rows[i].Position {
				t.Errorf("%s: event %d at position %d, TypeScript %d", rec.Name, i, r.Position, rec.Rows[i].Position)
			}
			checks = append(checks, check{fmt.Sprintf("%s #%d", rec.Name, i), rec.Rows[i]})
		}
	}
	for _, r := range v.RawRows {
		cols := make([]string, 0, len(r.Input))
		args := []any{}
		for c := range r.Input {
			cols = append(cols, c)
		}
		slices.Sort(cols)
		for _, c := range cols {
			val := value(t, r.Input[c])
			if c == "occurred_at" {
				tm, err := time.Parse(time.RFC3339Nano, val.(string))
				if err != nil {
					t.Fatal(err)
				}
				val = tm.UnixMicro()
			}
			if f, ok := val.(float64); ok {
				val = int64(f)
			}
			args = append(args, val)
		}
		q := fmt.Sprintf("INSERT INTO audit_events (%s) VALUES (%s)", strings.Join(cols, ", "), strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", "))
		if err := s.Write(bg, func(tx *storage.Tx) error { _, err := tx.ExecContext(bg, q, args...); return err }); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		checks = append(checks, check{"raw " + *str(t, r.Input["id"]), r.rowJSON})
	}
	if len(checks) < len(audit.EventTypes)+20 {
		t.Fatalf("only %d rows to check", len(checks))
	}
	q := query.New(s.Reader())
	for _, c := range checks {
		row, err := q.GetAuditEvent(bg, *str(t, c.want.Stored["id"]))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		checkRow(t, c.name, row, c.want)
	}

	rows, err := s.Reader().QueryContext(bg, `SELECT organization_id, identity_id, version_id, item_name, environment_id, way
		FROM member_exposure ORDER BY organization_id, identity_id, version_id, environment_id, way`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []map[string]string
	for rows.Next() {
		var o, i, ver, item, env, way string
		if err := rows.Scan(&o, &i, &ver, &item, &env, &way); err != nil {
			t.Fatal(err)
		}
		got = append(got, map[string]string{"organization_id": o, "identity_id": i, "version_id": ver, "item_name": item, "environment_id": env, "way": way})
	}
	gj, _ := json.Marshal(got)
	wj, _ := json.Marshal(v.Exposure)
	if !bytes.Equal(gj, wj) {
		t.Errorf("member_exposure\n got %s\nwant %s", gj, wj)
	}
	var first, last int64
	if err := s.Reader().QueryRowContext(bg, "SELECT min(first_at), max(last_at) FROM member_exposure").Scan(&first, &last); err != nil || first <= 0 || last < first {
		t.Errorf("exposure times %d..%d, %v", first, last, err)
	}
}

func TestExposureVectors(t *testing.T) {
	v := load(t)
	for _, p := range v.ParseItems {
		got, _ := json.Marshal(audit.ParseItems(p.Items))
		if string(got) == "null" {
			got = []byte("[]")
		}
		if want := string(jsvalue.Stringify(value(t, p.Parsed))); string(got) != want {
			t.Errorf("parseItems(%q) = %s, TypeScript %s", p.Items, got, want)
		}
	}
	for i, x := range v.ExposureFromEvent {
		e := audit.Indexable{
			EventType:       *str(t, x.Event["eventType"]),
			ActorIdentityID: str(t, x.Event["actorIdentityId"]),
			OrganizationID:  str(t, x.Event["organizationId"]),
			Resource:        object(t, x.Event["resource"]),
			Metadata:        object(t, x.Event["metadata"]),
		}
		entry, ok := audit.ExposureFromEvent(e)
		got := "null"
		if ok {
			b, _ := json.Marshal(entry)
			got = canonical(value(t, b))
		}
		if want := canonical(value(t, x.Entry)); got != want {
			t.Errorf("exposureFromEvent #%d = %s, TypeScript %s", i, got, want)
		}
	}
}

func TestRedactVectors(t *testing.T) {
	v := load(t)
	if len(v.Redact) < 50 {
		t.Fatalf("only %d redaction vectors", len(v.Redact))
	}
	for _, r := range v.Redact {
		if got := audit.RedactWebhookURL(r.URL); got != r.Redacted {
			t.Errorf("redactWebhookUrl(%q) = %q, TypeScript %q", r.URL, got, r.Redacted)
		}
	}
}
