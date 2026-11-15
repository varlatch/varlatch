// SPDX-License-Identifier: AGPL-3.0-or-later

package paritytest

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

var (
	idPattern  = regexp.MustCompile(`\b([a-z]{2,4})_[a-z2-7]{26}\b`)
	isoPattern = regexp.MustCompile(`\b\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\b`)
)

// Canonical is go-fixture-kit.ts's canonical(): JSON text with object keys
// sorted, JSON.stringify's escaping and numbers. Rows of both servers are
// ordered and compared by it.
func Canonical(v any) string {
	var b bytes.Buffer
	canonical(&b, v)
	return b.String()
}

func canonical(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		jsvalue.Quote(b, x)
	case float64:
		b.WriteString(jsvalue.Number(x))
	case int64:
		b.WriteString(jsvalue.Number(float64(x)))
	case int:
		b.WriteString(jsvalue.Number(float64(x)))
	case json.Number:
		f, _ := x.Float64()
		b.WriteString(jsvalue.Number(f))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			canonical(b, e)
		}
		b.WriteByte(']')
	case jsvalue.Object:
		m := map[string]any{}
		for _, mem := range x {
			m[mem.Key] = mem.Value
		}
		canonical(b, m)
	case map[string]any:
		keys := sortedKeys(x)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			jsvalue.Quote(b, k)
			b.WriteByte(':')
			canonical(b, x[k])
		}
		b.WriteByte('}')
	default:
		jsvalue.Quote(b, fmt.Sprint(x))
	}
}

// less compares as JavaScript compares strings: by UTF-16 code units.
func less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return less(keys[i], keys[j]) })
	return keys
}

// plain is a JSON value as plain Go values (objects as maps), from a
// jsvalue or from JSON text.
func plain(v any) any {
	switch x := v.(type) {
	case jsvalue.Object:
		m := make(map[string]any, len(x))
		for _, mem := range x {
			m[mem.Key] = plain(mem.Value)
		}
		return m
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = plain(e)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = plain(e)
		}
		return out
	}
	return v
}

// Normalizer is go-fixture-kit.ts's (see its header): new domain IDs as
// {<prefix>#<n>} by first appearance, new times as {time}, a side row's
// volatile columns that hold no value of the file's rows as {fresh}, the
// request id as {requestId}.
type Normalizer struct {
	known   map[string]bool
	columns map[string]map[string]bool // table.column: the canonical values the rows hold
	fresh   map[string]string
	counts  map[string]int
}

// NewNormalizer knows the fixture's rows.
func NewNormalizer(rows map[string][]Row) *Normalizer {
	n := &Normalizer{known: map[string]bool{}, columns: map[string]map[string]bool{}, fresh: map[string]string{}, counts: map[string]int{}}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			for _, m := range idPattern.FindAllString(x, -1) {
				n.known[m] = true
			}
			for _, m := range isoPattern.FindAllString(x, -1) {
				n.known[m] = true
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	for table, list := range rows {
		for _, r := range list {
			walk(r)
			for col, v := range r {
				key := table + "." + col
				if n.columns[key] == nil {
					n.columns[key] = map[string]bool{}
				}
				n.columns[key][Canonical(v)] = true
			}
		}
	}
	return n
}

// Text normalizes a text.
func (n *Normalizer) Text(s, requestID string) string {
	if requestID != "" {
		s = strings.ReplaceAll(s, requestID, "{requestId}")
	}
	s = idPattern.ReplaceAllStringFunc(s, func(m string) string {
		if n.known[m] {
			return m
		}
		p, ok := n.fresh[m]
		if !ok {
			prefix := m[:strings.IndexByte(m, '_')]
			n.counts[prefix]++
			p = fmt.Sprintf("{%s#%d}", prefix, n.counts[prefix])
			n.fresh[m] = p
		}
		return p
	})
	return isoPattern.ReplaceAllStringFunc(s, func(m string) string {
		if n.known[m] {
			return m
		}
		return "{time}"
	})
}

// Value normalizes a JSON value, walking objects in sorted key order.
func (n *Normalizer) Value(v any, requestID string) any {
	switch x := v.(type) {
	case string:
		return n.Text(x, requestID)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = n.Value(e, requestID)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for _, k := range sortedKeys(x) {
			out[k] = n.Value(x[k], requestID)
		}
		return out
	}
	return v
}

func (n *Normalizer) masked(v any) string {
	return idPattern.ReplaceAllStringFunc(Canonical(v), func(m string) string {
		if n.known[m] {
			return m
		}
		if p, ok := n.fresh[m]; ok {
			return p
		}
		return "{" + m[:strings.IndexByte(m, '_')] + "}"
	})
}

func (n *Normalizer) unnumbered(r Row) bool {
	for _, m := range idPattern.FindAllString(Canonical(r), -1) {
		if _, ok := n.fresh[m]; !n.known[m] && !ok {
			return true
		}
	}
	return false
}

// Side normalizes one group of side rows (a table's inserted, updated or
// deleted rows, in PostgreSQL's form), as the kit does: volatile columns,
// then the rows ordered by their semantic key with new IDs not numbered
// yet masked (two rows the key cannot tell apart are an error), numbered
// in that order, and kept in the order of their normalized text.
func (n *Normalizer) Side(t SideTable, rows []Row) ([]Row, error) {
	type keyed struct {
		r Row
		k string
	}
	list := make([]keyed, len(rows))
	for i, r := range rows {
		m := Row{}
		for c, v := range r {
			if v != nil && contains(t.Volatile, c) && !n.columns[t.Name+"."+c][Canonical(v)] {
				v = "{fresh}"
			}
			m[c] = v
		}
		key := make([]any, len(t.SortBy))
		for j, c := range t.SortBy {
			key[j] = m[c]
		}
		list[i] = keyed{m, n.masked(key)}
	}
	sort.SliceStable(list, func(i, j int) bool { return less(list[i].k, list[j].k) })
	for i := 1; i < len(list); i++ {
		if list[i].k == list[i-1].k && (n.unnumbered(list[i].r) || n.unnumbered(list[i-1].r)) {
			return nil, fmt.Errorf("%s: two rows share the semantic key %s: anchor their new IDs in the body or the audit events, or declare a sortBy that tells them apart", t.Name, list[i].k)
		}
	}
	out := make([]Row, len(list))
	for i, e := range list {
		out[i] = n.Value(map[string]any(e.r), "").(map[string]any)
	}
	sort.SliceStable(out, func(i, j int) bool { return less(Canonical(out[i]), Canonical(out[j])) })
	return out, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// CheckDigests is go-fixture-kit.ts checkDigests: an answer's state
// digests, recomputed from the manifest in the same answer (stateDigest
// and categoryDigests), so a digest the file masks is still checked: each
// is the manifest's, which the file compares, normalized, byte for byte.
func CheckDigests(t testing.TB, body []byte, where string) {
	t.Helper()
	var b struct {
		Manifest *struct {
			ProjectID   any              `json:"projectId"`
			Environment any              `json:"environment"`
			Contract    any              `json:"contract"`
			Items       []map[string]any `json:"items"`
		} `json:"manifest"`
		StateDigest  *string           `json:"stateDigest"`
		StateDigests map[string]string `json:"stateDigests"`
	}
	if json.Unmarshal(body, &b) != nil || b.Manifest == nil {
		return
	}
	var whole map[string]any
	if err := json.Unmarshal(body, &whole); err != nil {
		return
	}
	digest := func(v any) string {
		canon, err := envelope.CanonicalJSON(v)
		if err != nil {
			t.Fatalf("%s: %v", where, err)
		}
		sum := sha256.Sum256([]byte(canon))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	m := b.Manifest
	if b.StateDigest != nil && *b.StateDigest != digest(whole["manifest"]) {
		t.Errorf("%s: stateDigest is not its manifest's", where)
	}
	if b.StateDigests != nil {
		items, rotation := []any{}, []any{}
		for _, i := range m.Items {
			items = append(items, map[string]any{"name": i["name"], "source": i["source"], "valueRowId": i["valueRowId"], "versionId": i["versionId"]})
			if r, ok := i["retiringVersionId"]; ok {
				rotation = append(rotation, map[string]any{"name": i["name"], "retiringVersionId": r})
			}
		}
		want := map[string]string{
			"environment": digest(map[string]any{"projectId": m.ProjectID, "environment": m.Environment}),
			"contract":    digest(m.Contract), "items": digest(items), "rotation": digest(rotation),
		}
		for k, v := range want {
			if b.StateDigests[k] != v {
				t.Errorf("%s: stateDigests.%s is not its manifest's", where, k)
			}
		}
		if len(b.StateDigests) != len(want) {
			t.Errorf("%s: stateDigests: %v", where, b.StateDigests)
		}
	}
}

// Mask is go-fixture-kit.ts mask: each named member of a JSON text, a
// string or a flat object, reads "{masked}".
func Mask(text string, members []string) string {
	for _, m := range members {
		key, _ := json.Marshal(m)
		re := regexp.MustCompile(`(` + regexp.QuoteMeta(string(key)) + `:)(?:"(?:[^"\\]|\\.)*"|\{[^{}]*\})`)
		text = re.ReplaceAllString(text, `${1}"{masked}"`)
	}
	return text
}

// Target is the server a fixture is replayed against.
type Target struct {
	Handler http.Handler
	Store   *storage.DB
	// Settled waits for the work a response leaves behind (report counts).
	Settled func()
	// Path fills a request's placeholders ({orgId} and the like) in its
	// path and its body.
	Path func(string) string
	// Check, when set, sees every exchange (the OpenAPI check).
	Check func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder)
	// Restart, when set, starts the server afresh on the same database
	// before every WindowBatch-th request, as the kit does.
	Restart func()
	// Inspect, when set, sees each request's answers, audit events and side
	// rows before any normalization, with when it was sent and answered:
	// for checks the normalized comparison cannot make (a new time's value).
	Inspect func(t testing.TB, c Recorded, raw Raw)
	// Now is the clock the server runs on, which Raw's Sent and Done read
	// too (HourClock); nil is time.Now.
	Now func() time.Time
}

// hourOverrun is the replay's failure when its clock has left the hour
// it began in: past it, report counts would be kept in two hours.
func hourOverrun(began, done time.Time) error {
	if done.Truncate(time.Hour).Equal(began.Truncate(time.Hour)) {
		return nil
	}
	return fmt.Errorf("the replay began at %s and ran into the next hour (%s): report counts are kept per hour, so a replay must take less than an hour on HourClock",
		began.UTC().Format(time.RFC3339Nano), done.UTC().Format(time.RFC3339Nano))
}

// checkTimes checks the raw times a request wrote: each audit event after
// event_order before, and each exposure row last seen from sent on, between
// sent and done (microseconds, as stored).
func checkTimes(t testing.TB, name string, store *storage.DB, before int64, sent, done time.Time) {
	t.Helper()
	low, high := sent.UnixMicro(), done.UnixMicro()
	for _, r := range Rows(t, store, "SELECT event_type, occurred_at FROM audit_events WHERE event_order > ? ORDER BY event_order", before) {
		if at := r["occurred_at"].(int64); at < low || at > high {
			t.Errorf("%s: %s at %d, outside the request (%d to %d)", name, r["event_type"], at, low, high)
		}
	}
	for _, r := range Rows(t, store, "SELECT first_at, last_at FROM member_exposure WHERE last_at >= ?", low) {
		if last := r["last_at"].(int64); last > high {
			t.Errorf("%s: an exposure last at %d, after the request (%d to %d)", name, last, low, high)
		}
	}
}

// HourClock is the clock a replay runs its server on: the real clock moved
// back to the start of the hour the replay begins in. Report counts are
// kept per hour (security_control_counters.bucket_hour), and the
// recording's requests counted within one hour; on this clock a replay,
// shorter than an hour, counts within one too, whenever it runs.
func HourClock() func() time.Time { return hourClock(time.Now) }

func hourClock(real func() time.Time) func() time.Time {
	start := real()
	offset := start.Sub(start.Truncate(time.Hour))
	return func() time.Time { return real().Add(-offset) }
}

// Raw is what one request of a replay produced, before normalization.
type Raw struct {
	// Sent is when the request was sent, Done when every answer was in.
	Sent, Done time.Time
	// Statuses and Bodies are the answers, in sending order.
	Statuses []int
	Bodies   [][]byte
	// Audit holds the audit events it wrote, in PostgreSQL's form.
	Audit []map[string]any
	// Side holds the rows it inserted or updated, by table, in
	// PostgreSQL's form.
	Side map[string][]Row
}

// WindowBatch is how many requests each server of a replay answers (the
// kit's WINDOW_BATCH): both sides start a fresh one before every 500th
// request, so no request meets the request window (600 per minute per
// client), however long the fixture grows.
const WindowBatch = 500

// AuditColumns are the audit event columns a fixture records.
var AuditColumns = []string{"event_type", "actor_identity_id", "credential_id", "organization_id", "action", "resource", "decision",
	"authz", "tailnet", "listener", "request_id", "metadata", "client", "schema_version"}

// Rows reads a query's rows, each column by name.
func Rows(t testing.TB, store *storage.DB, q string, args ...any) []Row {
	t.Helper()
	rs, err := store.Reader().Query(q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	cols, _ := rs.Columns()
	var out []Row
	for rs.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rs.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		r := Row{}
		for i, c := range cols {
			r[c] = vals[i]
		}
		out = append(out, r)
	}
	return out
}

// schema is PostgreSQL's column types (db/testdata/pg-v0.22.0.json) and
// the mapping's SQLite names, to read a Go row back in PostgreSQL's form.
type schema struct {
	types  map[string]map[string]string // table -> PostgreSQL column -> type
	sqlite map[string]string            // table -> SQLite table
	cols   map[string]map[string]string // table -> PostgreSQL column -> SQLite column
}

var (
	schemaOnce sync.Once
	schemaVal  schema
	schemaErr  error
)

func readSchema() (schema, error) {
	schemaOnce.Do(func() {
		raw, err := os.ReadFile(filepath.Join(here(), "..", "db", "testdata", "pg-v0.22.0.json"))
		if err != nil {
			schemaErr = err
			return
		}
		var dump struct {
			Tables []struct {
				Name    string `json:"name"`
				Columns []struct {
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"columns"`
			} `json:"tables"`
		}
		if schemaErr = json.Unmarshal(raw, &dump); schemaErr != nil {
			return
		}
		m, err := readMapping()
		if err != nil {
			schemaErr = err
			return
		}
		s := schema{types: map[string]map[string]string{}, sqlite: map[string]string{}, cols: map[string]map[string]string{}}
		for _, t := range dump.Tables {
			s.types[t.Name] = map[string]string{}
			for _, c := range t.Columns {
				s.types[t.Name][c.Name] = c.Type
			}
		}
		for name, t := range m.Tables {
			s.sqlite[name] = t.SQLite
			s.cols[name] = map[string]string{}
			for pg, raw := range t.Columns {
				var col string
				if json.Unmarshal(raw, &col) == nil {
					s.cols[name][pg] = col
				}
			}
		}
		schemaVal = s
	})
	return schemaVal, schemaErr
}

// pgValue is a SQLite value as the pg driver reads the PostgreSQL column
// the mapping copies it from (go-fixture-kit.ts's exportRows).
func pgValue(typ string, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch typ {
	case "boolean":
		n, ok := v.(int64)
		if !ok {
			return nil, fmt.Errorf("boolean %v", v)
		}
		return n != 0, nil
	case "timestamp with time zone":
		n, ok := v.(int64)
		if !ok {
			return nil, fmt.Errorf("time %v", v)
		}
		// A JavaScript Date: milliseconds.
		return time.UnixMicro(n).UTC().Format("2006-01-02T15:04:05.000Z"), nil
	case "bigint":
		// The kit's PGlite reads int8 as a number.
		return v, nil
	case "jsonb", "json", "text[]":
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s %v", typ, v)
		}
		parsed, err := jsvalue.Parse([]byte(s))
		return plain(parsed), err
	}
	return v, nil
}

// pgRows reads a table's rows in PostgreSQL's form, with its column names.
func pgRows(t testing.TB, store *storage.DB, table string) []Row {
	t.Helper()
	s, err := readSchema()
	if err != nil {
		t.Fatal(err)
	}
	var out []Row
	for _, r := range Rows(t, store, "SELECT * FROM "+s.sqlite[table]) {
		pr := Row{}
		for pg, col := range s.cols[table] {
			v, err := pgValue(s.types[table][pg], r[col])
			if err != nil {
				t.Fatalf("%s.%s: %v", table, pg, err)
			}
			pr[pg] = v
		}
		out = append(out, pr)
	}
	return out
}

// sideChange is what a request changed in a side table, by primary key.
type sideChange struct{ inserted, updated, deleted []Row }

func diff(st SideTable, before, after []Row) sideChange {
	key := func(r Row) string {
		k := make([]any, len(st.Key))
		for i, c := range st.Key {
			k[i] = r[c]
		}
		return Canonical(k)
	}
	was, now := map[string]Row{}, map[string]Row{}
	for _, r := range before {
		was[key(r)] = r
	}
	for _, r := range after {
		now[key(r)] = r
	}
	var d sideChange
	for _, r := range after {
		if old, ok := was[key(r)]; !ok {
			d.inserted = append(d.inserted, r)
		} else if Canonical(old) != Canonical(r) {
			d.updated = append(d.updated, r)
		}
	}
	for _, r := range before {
		if _, ok := now[key(r)]; !ok {
			d.deleted = append(d.deleted, r)
		}
	}
	return d
}

type answer struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

var keptHeaders = []string{"Cache-Control", "Retry-After", "Content-Type", "Varlatch-Credential-Expires", "Location"}

// Replay runs every request of f against target and requires the
// TypeScript server's answers.
func Replay(t testing.TB, target Target, f Fixture) {
	t.Helper()
	now := target.Now
	if now == nil {
		now = time.Now
	}
	began := now()
	norm := NewNormalizer(f.Rows)
	for index, c := range f.Requests {
		name := c.ID
		if index > 0 && index%WindowBatch == 0 && target.Restart != nil {
			target.Restart()
		}
		var before sql.NullInt64
		if err := target.Store.Reader().QueryRow("SELECT max(event_order) FROM audit_events").Scan(&before); err != nil {
			t.Fatal(err)
		}
		sideBefore := map[string][]Row{}
		for _, st := range f.SideTables {
			sideBefore[st.Name] = pgRows(t, target.Store, st.Name)
		}
		path := c.Path
		if target.Path != nil {
			path = target.Path(path)
		}
		var body []byte
		switch {
		case c.RawBody != nil:
			body = []byte(*c.RawBody)
		case c.Body != nil:
			var b bytes.Buffer
			if err := json.Compact(&b, *c.Body); err != nil {
				t.Fatalf("%s: the body: %v", name, err)
			}
			body = b.Bytes()
		}
		if body != nil && target.Path != nil {
			body = []byte(target.Path(string(body)))
		}
		n := max(c.Concurrent, 1)
		recs := make([]*httptest.ResponseRecorder, n)
		sent := now()
		var wg sync.WaitGroup
		for i := range n {
			req := httptest.NewRequest(c.Method, path, bytes.NewReader(body))
			if body == nil {
				req = httptest.NewRequest(c.Method, path, http.NoBody)
			}
			req.Header.Set("Content-Type", "application/json")
			ua := c.UserAgent
			if ua == "" {
				ua = CLIAgent
			}
			req.Header.Set("User-Agent", ua)
			for k, v := range c.Headers {
				req.Header.Set(k, v)
			}
			if c.Credential != "none" {
				req.Header.Set("Authorization", "Bearer "+f.Tokens[c.Credential])
			}
			recs[i] = httptest.NewRecorder()
			wg.Add(1)
			go func() {
				defer wg.Done()
				target.Handler.ServeHTTP(recs[i], req)
			}()
		}
		wg.Wait()
		done := now()
		if target.Settled != nil {
			target.Settled()
		}
		ids := map[string]bool{}
		type pre struct {
			rec  *httptest.ResponseRecorder
			id   string
			text string
		}
		pres := make([]pre, n)
		for i, rec := range recs {
			if target.Check != nil {
				target.Check(t, httptest.NewRequest(c.Method, path, bytes.NewReader(body)), body, rec)
			}
			id := rec.Header().Get("X-Request-Id")
			ids[id] = true
			CheckDigests(t, rec.Body.Bytes(), name)
			text := rec.Body.String()
			if id != "" {
				// An answer without the header (a streamed one) names no request id.
				text = strings.ReplaceAll(text, id, "{requestId}")
			}
			pres[i] = pre{rec, id, text}
		}
		sort.SliceStable(pres, func(i, j int) bool {
			if pres[i].rec.Code != pres[j].rec.Code {
				return pres[i].rec.Code < pres[j].rec.Code
			}
			return less(pres[i].text, pres[j].text)
		})
		answers := make([]answer, n)
		for i, p := range pres {
			a := answer{Status: p.rec.Code, Headers: map[string]string{}, Body: norm.Text(Mask(p.text, c.Masked), "")}
			for _, h := range keptHeaders {
				if v := p.rec.Header().Get(h); v != "" {
					a.Headers[h] = norm.Text(v, p.id)
				}
			}
			answers[i] = a
		}
		sort.SliceStable(answers, func(i, j int) bool {
			if answers[i].Status != answers[j].Status {
				return answers[i].Status < answers[j].Status
			}
			return less(answers[i].Body, answers[j].Body)
		})
		got := answers[0]
		if got.Status != c.Expect.Status || got.Body != c.Expect.Body {
			t.Errorf("%s: %d %s\n want %d %s", name, got.Status, got.Body, c.Expect.Status, c.Expect.Body)
		}
		for _, h := range keptHeaders {
			if g, w := got.Headers[h], c.Expect.Headers[h]; g != w {
				t.Errorf("%s: %s %q, want %q", name, h, g, w)
			}
		}
		if c.Concurrent > 0 {
			if g, w := Canonical(plainJSON(answers)), Canonical(plainJSON(c.Answers)); g != w {
				t.Errorf("%s: answers\n  %s\n want %s", name, g, w)
			}
		}
		// The audit events, keys walked sorted, in PostgreSQL's form.
		s, err := readSchema()
		if err != nil {
			t.Fatal(err)
		}
		audit := []any{}
		raw := Raw{Sent: sent, Done: done, Side: map[string][]Row{}}
		for _, rec := range recs {
			raw.Statuses = append(raw.Statuses, rec.Code)
			raw.Bodies = append(raw.Bodies, rec.Body.Bytes())
		}
		for _, r := range Rows(t, target.Store, "SELECT "+strings.Join(AuditColumns, ", ")+" FROM audit_events WHERE event_order > ? ORDER BY event_order", before.Int64) {
			pr := map[string]any{}
			for _, col := range AuditColumns {
				v, err := pgValue(s.types["audit_events"][col], r[col])
				if err != nil {
					t.Fatalf("audit_events.%s: %v", col, err)
				}
				if str, ok := v.(string); ok && ids[str] && col == "request_id" {
					v = "{requestId}"
				}
				pr[col] = v
			}
			raw.Audit = append(raw.Audit, pr)
			audit = append(audit, norm.Value(pr, ""))
		}
		// The raw times: every event, and every exposure row it wrote, on
		// the server's clock while the request was being answered.
		checkTimes(t, name, target.Store, before.Int64, sent, done)
		if target.Now != nil {
			if err := hourOverrun(began, done); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		wantAudit := []any{}
		for _, r := range c.Audit {
			wantAudit = append(wantAudit, r)
		}
		if g, w := Canonical(audit), Canonical(plainJSON(wantAudit)); g != w {
			t.Errorf("%s: audit\n  %s\n want %s", name, g, w)
		}
		gotSide := map[string]any{}
		for _, st := range f.SideTables {
			d := diff(st, sideBefore[st.Name], pgRows(t, target.Store, st.Name))
			raw.Side[st.Name] = append(append([]Row{}, d.inserted...), d.updated...)
			change := map[string]any{}
			for _, g := range []struct {
				name string
				rows []Row
			}{{"inserted", d.inserted}, {"updated", d.updated}, {"deleted", d.deleted}} {
				if len(g.rows) == 0 {
					continue
				}
				rows, err := norm.Side(st, g.rows)
				if err != nil {
					t.Fatal(err)
				}
				list := make([]any, len(rows))
				for i, r := range rows {
					list[i] = map[string]any(r)
				}
				change[g.name] = list
			}
			if len(change) > 0 {
				gotSide[st.Name] = change
			}
		}
		if g, w := Canonical(gotSide), Canonical(plainJSON(c.Side)); g != w {
			t.Errorf("%s: side tables\n  %s\n want %s", name, g, w)
		}
		if target.Inspect != nil {
			target.Inspect(t, c, raw)
		}
	}
	counters := []any{}
	for _, r := range Rows(t, target.Store, "SELECT organization_id, control, config_version, operation, actor_identity_id, reason, count FROM security_control_counters ORDER BY organization_id, control, operation, actor_identity_id, reason") {
		counters = append(counters, norm.Value(map[string]any(r), ""))
	}
	want := []any{}
	for _, r := range f.Counters {
		want = append(want, r)
	}
	if g, w := Canonical(counters), Canonical(plainJSON(want)); g != w {
		t.Errorf("counters %s, want %s", g, w)
	}
}

// plainJSON is a value as JSON reads it back (its own types as plain
// values), so that the file's values and ours compare alike.
func plainJSON(v any) any {
	b, _ := json.Marshal(v)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	_ = dec.Decode(&out)
	return out
}

// PGRows is a table's rows in PostgreSQL's form, as go-fixture-kit.ts's
// exportRows reads them, in no particular order.
func PGRows(t testing.TB, store *storage.DB, table string) []Row { return pgRows(t, store, table) }

// PGAudit is the audit events (AuditColumns) of the given type, in
// PostgreSQL's form, in their order.
func PGAudit(t testing.TB, store *storage.DB, eventType string) []Row {
	t.Helper()
	s, err := readSchema()
	if err != nil {
		t.Fatal(err)
	}
	var out []Row
	for _, r := range Rows(t, store, "SELECT "+strings.Join(AuditColumns, ", ")+" FROM audit_events WHERE event_type = ? ORDER BY event_order", eventType) {
		pr := Row{}
		for _, col := range AuditColumns {
			v, err := pgValue(s.types["audit_events"][col], r[col])
			if err != nil {
				t.Fatalf("audit_events.%s: %v", col, err)
			}
			pr[col] = v
		}
		out = append(out, pr)
	}
	return out
}

// Same reports whether two JSON values are equal, each compared in its
// canonical text after a JSON round trip (the file's json.Number and
// our own types alike).
func Same(got, want any) bool { return Canonical(plainJSON(got)) == Canonical(plainJSON(want)) }
