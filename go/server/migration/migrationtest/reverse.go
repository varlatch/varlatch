// SPDX-License-Identifier: AGPL-3.0-or-later

package migrationtest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/canonical"
)

// FromReverse is the stand-in for the last TypeScript release's `admin
// migration import` (slice 7.2c, decision 16): the reverse bundle b read
// and verified whole (a reverse bundle of this manifest, every row
// canonical, no browser session, its sections well formed, its end's
// counts and SHA-256), then its rows loaded as they are, nothing
// renumbered, into the rebuilt installation under rootKEK: each table's
// rows in the bundle's order, each value as node-postgres gives it back.
// Its audit position is the bundle's last, its frozen point. Exported again
// (Bundle), its rows are the reverse bundle's, byte for byte, as the
// TypeScript import's load and its export's read are.
func FromReverse(t TB, b []byte, rootKEK []byte) Source {
	t.Helper()
	m := Manifest(t)
	r, err := bundle.NewReader(bytes.NewReader(b), m)
	if err != nil {
		t.Fatalf("the reverse bundle: %v", err)
	}
	if h := r.Header(); h.Direction != bundle.Reverse {
		t.Fatalf("the import reads a reverse bundle; this one is %s", h.Direction)
	}
	s := Source{RootKEK: rootKEK, Rows: map[string][]jsvalue.Object{}, Secrets: [][]byte{rootKEK}}
	for range bundle.Tables(m) {
		tb, n, err := r.NextTable()
		if err != nil {
			t.Fatal(err)
		}
		if tb.Source == "session" && n != 0 {
			t.Fatalf("the reverse bundle holds %d browser sessions; a reverse bundle holds none", n)
		}
		for range n {
			row, err := r.Row()
			if err != nil {
				t.Fatal(err)
			}
			v, err := bundle.Decode(tb, row)
			if err != nil {
				t.Fatalf("%s: %v", tb.Source, err)
			}
			o := jsvalue.Object{}
			for i, c := range tb.Columns {
				o = append(o, jsvalue.Member{Key: c.Source, Value: pgValue(t, c.Type, v[i])})
			}
			if tb.Source == "audit_events" {
				for i, c := range tb.Columns {
					if p, _ := v[i].(int64); c.Source == "event_order" && p > s.AuditPosition {
						s.AuditPosition = p
					}
				}
			}
			s.Rows[tb.Source] = append(s.Rows[tb.Source], o)
		}
	}
	if err := r.SkipSections(); err != nil {
		t.Fatalf("the reverse bundle's sections: %v", err)
	}
	if err := r.End(); err != nil {
		t.Fatalf("the reverse bundle's end: %v", err)
	}
	if h := r.Header(); h.FrozenPoint.AuditPosition != s.AuditPosition {
		t.Fatalf("the reverse bundle's frozen point is %d; its last audit position %d", h.FrozenPoint.AuditPosition, s.AuditPosition)
	}
	for _, it := range Items(t, s) {
		s.Secrets = append(s.Secrets, it.Plaintext)
	}
	return s
}

// pgValue is a canonical value (bundle.Decode's) as node-postgres gives it
// back: what Value reads (timestamps as ISO text, bigint as text, bytea in
// PostgreSQL's hex output, jsonb and text[] parsed, booleans as booleans).
func pgValue(t TB, ty canonical.Type, v any) any {
	t.Helper()
	if v == nil {
		return nil
	}
	switch ty {
	case canonical.Timestamptz:
		return time.UnixMicro(v.(int64)).UTC().Format(time.RFC3339Nano)
	case canonical.Integer:
		return float64(v.(int64))
	case canonical.Bigint:
		return strconv.FormatInt(v.(int64), 10)
	case canonical.Boolean:
		return v.(int64) != 0
	case canonical.Jsonb:
		p, err := jsvalue.Parse([]byte(v.(string)))
		if err != nil {
			t.Fatal(err)
		}
		return p
	case canonical.TextArray:
		var a []any
		if err := json.Unmarshal([]byte(v.(string)), &a); err != nil {
			t.Fatal(err)
		}
		return a
	case canonical.Bytea:
		return `\x` + hex.EncodeToString(v.([]byte))
	}
	return v
}
