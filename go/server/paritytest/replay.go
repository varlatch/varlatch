// SPDX-License-Identifier: AGPL-3.0-or-later

package paritytest

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/storage"
)

var (
	idPattern  = regexp.MustCompile(`\b([a-z]{3,4})_[a-z2-7]{26}\b`)
	isoPattern = regexp.MustCompile(`\b\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\b`)
)

// Normalizer is go-fixture-kit.ts's: a domain ID the fixture's rows do not
// hold becomes {<prefix>#<n>}, numbered per prefix by first appearance
// across the run; an ISO timestamp they do not hold becomes {time}; in a
// side table, a volatile column whose value the rows do not hold for that
// column becomes {fresh}; the request id becomes {requestId}.
type Normalizer struct {
	known   map[string]bool
	columns map[string]map[any]bool // table.column: the values the rows hold, in SQLite's form
	fresh   map[string]string
	counts  map[string]int
}

// NewNormalizer knows the fixture's rows.
func NewNormalizer(rows map[string][]Row) *Normalizer {
	n := &Normalizer{known: map[string]bool{}, columns: map[string]map[any]bool{}, fresh: map[string]string{}, counts: map[string]int{}}
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
					n.columns[key] = map[any]bool{}
				}
				if sv, err := SQLiteValue(v); err == nil {
					n.columns[key][fmt.Sprint(sv)] = true
				}
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
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(x))
		for _, k := range keys {
			out[k] = n.Value(x[k], requestID)
		}
		return out
	}
	return v
}

// Side normalizes a side table's changed rows, in SQLite's form: volatile
// columns first, then the rows in the order of their form with new IDs
// masked, then the IDs numbered.
func (n *Normalizer) Side(t SideTable, rows []Row) []Row {
	marked := make([]Row, len(rows))
	for i, r := range rows {
		m := Row{}
		for c, v := range r {
			if v != nil && contains(t.Volatile, c) && !n.columns[t.Name+"."+c][fmt.Sprint(v)] {
				v = "{fresh}"
			}
			m[c] = v
		}
		marked[i] = m
	}
	mask := func(r Row) string {
		b, _ := json.Marshal(r)
		return idPattern.ReplaceAllStringFunc(string(b), func(m string) string {
			if n.known[m] {
				return m
			}
			return "{" + m[:strings.IndexByte(m, '_')] + "}"
		})
	}
	sort.SliceStable(marked, func(i, j int) bool { return mask(marked[i]) < mask(marked[j]) })
	for i, r := range marked {
		marked[i] = n.Value(map[string]any(r), "").(map[string]any)
	}
	return marked
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Target is the server a fixture is replayed against.
type Target struct {
	Handler http.Handler
	Store   *storage.DB
	// Settled waits for the work a response leaves behind (report counts).
	Settled func()
	// Path fills a request's path ({orgId} and the like).
	Path func(string) string
	// Check, when set, sees every exchange (the OpenAPI check).
	Check func(t *testing.T, req *http.Request, body []byte, rec *httptest.ResponseRecorder)
}

// AuditColumns are the audit event columns a fixture records.
var AuditColumns = []string{"event_type", "actor_identity_id", "credential_id", "organization_id", "action", "resource", "decision",
	"authz", "tailnet", "listener", "request_id", "metadata", "client", "schema_version"}

// Rows reads a query's rows, each column by name.
func Rows(t *testing.T, store *storage.DB, q string, args ...any) []Row {
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

// Canonical is a value or JSON text as plain Go values, so two rows
// compare without their member order or their number types.
func Canonical(v any) any {
	if s, ok := v.(string); ok && (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) {
		var out any
		if json.Unmarshal([]byte(s), &out) == nil {
			return out
		}
	}
	if m, ok := v.(map[string]any); ok {
		out := map[string]any{}
		for k, e := range m {
			out[k] = Canonical(e)
		}
		v = out
	}
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

// Replay runs every request of f against target and requires the
// TypeScript server's answers.
func Replay(t *testing.T, target Target, f Fixture) {
	t.Helper()
	norm := NewNormalizer(f.Rows)
	mapped := map[string]string{}
	m, err := readMapping()
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range f.SideTables {
		mapped[st.Name] = m.Tables[st.Name].SQLite
	}
	dump := func(st SideTable) []Row {
		return Rows(t, target.Store, "SELECT * FROM "+mapped[st.Name])
	}
	key := func(r Row) string { b, _ := json.Marshal(r); return string(b) }
	for _, c := range f.Requests {
		name := c.ID
		var before sql.NullInt64
		if err := target.Store.Reader().QueryRow("SELECT max(event_order) FROM audit_events").Scan(&before); err != nil {
			t.Fatal(err)
		}
		sideBefore := map[string]map[string]bool{}
		for _, st := range f.SideTables {
			sideBefore[st.Name] = map[string]bool{}
			for _, r := range dump(st) {
				sideBefore[st.Name][key(r)] = true
			}
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
			body, _ = json.Marshal(*c.Body)
		}
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
		if c.Credential != "none" {
			req.Header.Set("Authorization", "Bearer "+f.Tokens[c.Credential])
		}
		rec := httptest.NewRecorder()
		target.Handler.ServeHTTP(rec, req)
		if target.Settled != nil {
			target.Settled()
		}
		if target.Check != nil {
			target.Check(t, httptest.NewRequest(c.Method, path, bytes.NewReader(body)), body, rec)
		}
		id := rec.Header().Get("X-Request-Id")
		got := norm.Text(rec.Body.String(), id)
		if rec.Code != c.Expect.Status || got != c.Expect.Body {
			t.Errorf("%s: %d %s\n want %d %s", name, rec.Code, got, c.Expect.Status, c.Expect.Body)
		}
		for _, h := range []string{"Cache-Control", "Retry-After", "Content-Type", "Varlatch-Credential-Expires", "Location"} {
			g := rec.Header().Get(h)
			if g != "" {
				g = norm.Text(g, id)
			}
			if w := c.Expect.Headers[h]; g != w {
				t.Errorf("%s: %s %q, want %q", name, h, g, w)
			}
		}
		var audit []any
		for _, r := range Rows(t, target.Store, "SELECT "+strings.Join(AuditColumns, ", ")+" FROM audit_events WHERE event_order > ? ORDER BY event_order", before.Int64) {
			for k, v := range r {
				r[k] = Canonical(v)
			}
			audit = append(audit, Canonical(norm.Value(Canonical(r), id)))
		}
		var wantAudit []any
		for _, r := range c.Audit {
			wantAudit = append(wantAudit, Canonical(r))
		}
		if !reflect.DeepEqual(audit, wantAudit) {
			gb, _ := json.Marshal(audit)
			wb, _ := json.Marshal(wantAudit)
			t.Errorf("%s: audit\n  %s\n want %s", name, gb, wb)
		}
		for _, st := range f.SideTables {
			var changed []Row
			for _, r := range dump(st) {
				if !sideBefore[st.Name][key(r)] {
					changed = append(changed, r)
				}
			}
			var gotSide, wantSide []any
			for _, r := range norm.Side(st, changed) {
				gotSide = append(gotSide, Canonical(r))
			}
			for _, r := range c.Side[st.Name] {
				sr := Row{}
				for k, v := range r {
					sv, err := SQLiteValue(v)
					if err != nil {
						t.Fatal(err)
					}
					sr[k] = sv
				}
				wantSide = append(wantSide, Canonical(sr))
			}
			if !reflect.DeepEqual(gotSide, wantSide) {
				gb, _ := json.Marshal(gotSide)
				wb, _ := json.Marshal(wantSide)
				t.Errorf("%s: %s rows\n  %s\n want %s", name, st.Name, gb, wb)
			}
		}
	}
	var counters []any
	for _, r := range Rows(t, target.Store, "SELECT organization_id, control, config_version, operation, actor_identity_id, reason, count FROM security_control_counters ORDER BY organization_id, control, operation, actor_identity_id, reason") {
		counters = append(counters, Canonical(norm.Value(Canonical(r), "")))
	}
	var want []any
	for _, r := range f.Counters {
		want = append(want, Canonical(r))
	}
	if !reflect.DeepEqual(counters, want) {
		t.Errorf("counters %v, want %v", counters, want)
	}
}
