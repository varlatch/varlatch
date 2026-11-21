// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The vectors: testdata/vectors/placement.json, recorded from placement.ts
// and broker.ts by apps/cli/test/go-vectors-placement.test.ts (internal
// docs/design/go-cli.md, slice 5.5a). Read with lib/jsjson, so a lone
// surrogate in a value or a message stays what JavaScript had.

func loadVectors(t *testing.T) jsjson.Object {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/vectors/placement.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsjson.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc.(jsjson.Object)
}

func field(v any, key string) any {
	f, _ := jsval.Get(v, key)
	return f
}

func str(v any, key string) string {
	s, _ := field(v, key).(string)
	return s
}

func list(v any, key string) []any {
	l, _ := field(v, key).([]any)
	return l
}

func pairsOf(v any) []Pair {
	var out []Pair
	for _, p := range v.([]any) {
		pair := p.([]any)
		out = append(out, Pair{pair[0].(string), pair[1].(string)})
	}
	return out
}

func targetsOf(t *testing.T, v any) map[string][]Target {
	out := map[string][]Target{}
	for _, m := range v.(jsjson.Object) {
		for _, raw := range m.Value.([]any) {
			target, err := ParseTarget(raw.(string))
			if err != nil {
				t.Fatal(err)
			}
			out[m.Key] = append(out[m.Key], target)
		}
	}
	return out
}

// sameBody is whether a body is the recorded one: its bytes, or its
// length and SHA-256.
func sameBody(c any, body []byte) bool {
	if b64, ok := field(c, "bodyB64").(string); ok {
		want, _ := base64.StdEncoding.DecodeString(b64)
		return string(want) == string(body)
	}
	sum := sha256.Sum256(body)
	return field(c, "bodyLength") == float64(len(body)) && str(c, "bodySha256") == hex.EncodeToString(sum[:])
}

func TestPlacementVectors(t *testing.T) {
	doc := loadVectors(t)
	if field(doc, "bodyLimit") != float64(BodyLimit) {
		t.Fatalf("bodyLimit %v, want %d", field(doc, "bodyLimit"), BodyLimit)
	}
	placeholders := map[string]string{}
	for _, m := range field(doc, "placeholders").(jsjson.Object) {
		placeholders[m.Key] = m.Value.(string)
	}
	cases := list(doc, "cases")
	if len(cases) < 80 {
		t.Fatalf("%d cases", len(cases))
	}
	for _, c := range cases {
		name := str(c, "name")
		t.Run(name, func(t *testing.T) {
			var body []byte
			if b64, ok := field(c, "bodyB64").(string); ok {
				body, _ = base64.StdEncoding.DecodeString(b64)
			} else {
				// A recorded input body is never over 4 KiB but this one.
				body = []byte(`{"key":"` + firstPlaceholder(placeholders) + `","filler":"` + strings.Repeat("x", BodyLimit-200) + `"}`)
				if !sameBody(c, body) {
					t.Fatal("the large input body is not the recorded one")
				}
			}
			req := Request{Headers: pairsOf(field(c, "headers")), Body: body}
			if q, ok := field(c, "query").(string); ok {
				req.Query = &q
			}
			got := PlanPlacement(req, placeholders, targetsOf(t, field(c, "targets")))
			want := field(c, "plan")
			if got.Kind != str(want, "kind") {
				t.Fatalf("kind %q (%s %s), want %q", got.Kind, got.Rule, got.Message, str(want, "kind"))
			}
			switch got.Kind {
			case "block":
				if float64(got.Status) != field(want, "status") || got.Rule != str(want, "rule") || got.Message != str(want, "message") {
					t.Fatalf("block %d %s %q, want %v %s %q", got.Status, got.Rule, got.Message, field(want, "status"), str(want, "rule"), str(want, "message"))
				}
				return
			}
			checkStrays(t, got.Strays, list(want, "strays"))
			if got.Kind == "pass" {
				return
			}
			var placements []string
			for _, p := range got.Placements {
				placements = append(placements, p.Item+" "+p.Target)
			}
			var wantPlacements []string
			for _, p := range list(want, "placements") {
				wantPlacements = append(wantPlacements, str(p, "item")+" "+str(p, "target"))
			}
			if !slices.Equal(placements, wantPlacements) {
				t.Fatalf("placements %q, want %q", placements, wantPlacements)
			}
			for k, a := range list(c, "applies") {
				values := map[string]string{}
				for _, m := range field(a, "values").(jsjson.Object) {
					values[m.Key] = m.Value.(string)
				}
				applied := got.Apply(values)
				if applied.OK != (field(a, "ok") == true) {
					t.Fatalf("apply %d: ok %v (%s %q)", k, applied.OK, applied.Rule, applied.Message)
				}
				if !applied.OK {
					if applied.Rule != str(a, "rule") || applied.Message != str(a, "message") {
						t.Fatalf("apply %d: %s %q, want %s %q", k, applied.Rule, applied.Message, str(a, "rule"), str(a, "message"))
					}
					continue
				}
				if !slices.Equal(applied.Headers, pairsOf(field(a, "headers"))) {
					t.Fatalf("apply %d: headers %q, want %q", k, applied.Headers, pairsOf(field(a, "headers")))
				}
				wantQuery, hasQuery := field(a, "query").(string)
				if (applied.Query != nil) != hasQuery || hasQuery && *applied.Query != wantQuery {
					t.Fatalf("apply %d: query %v, want %q", k, applied.Query, wantQuery)
				}
				if !sameBody(a, applied.Body) {
					t.Fatalf("apply %d: body %q", k, applied.Body)
				}
			}
		})
	}
}

func firstPlaceholder(placeholders map[string]string) string {
	for p, item := range placeholders {
		if item == "API_KEY" {
			return p
		}
	}
	return ""
}

func checkStrays(t *testing.T, got []Stray, want []any) {
	t.Helper()
	var g, w []string
	for _, s := range got {
		g = append(g, s.Item+" "+s.Surface)
	}
	for _, s := range want {
		w = append(w, str(s, "item")+" "+str(s, "surface"))
	}
	if !slices.Equal(g, w) {
		t.Fatalf("strays %q, want %q", g, w)
	}
}

func TestPercentEncodeVectors(t *testing.T) {
	for _, v := range list(loadVectors(t), "percentEncode") {
		if got := PercentEncode(str(v, "value")); got != str(v, "encoded") {
			t.Errorf("PercentEncode(%q) = %q, want %q", str(v, "value"), got, str(v, "encoded"))
		}
	}
}

func TestSelectorVectors(t *testing.T) {
	for _, v := range list(loadVectors(t), "selectors") {
		var raw []string
		for _, r := range list(v, "raw") {
			raw = append(raw, r.(string))
		}
		parsed := ParseSelectors(raw)
		want := list(v, "parsed")
		if len(parsed) != len(want) {
			t.Fatalf("%q: %d selectors, want %d", raw, len(parsed), len(want))
		}
		for k, s := range parsed {
			if s.Host != str(want[k], "host") || s.Wildcard != (field(want[k], "wildcard") == true) || s.Port != field(want[k], "port") {
				t.Errorf("%q: selector %d %+v, want %v", raw, k, s, want[k])
			}
		}
		for _, m := range list(v, "matches") {
			port, ok := field(m, "port").(float64)
			if !ok {
				continue // NaN, recorded as null
			}
			if got := MatchesSelectors(parsed, str(m, "host"), port); got != (field(m, "match") == true) {
				t.Errorf("%q: %s:%v matches %v", raw, str(m, "host"), port, got)
			}
		}
	}
}

func TestSameTargetsVectors(t *testing.T) {
	toMap := func(v any) map[string][]string {
		out := map[string][]string{}
		for _, m := range v.(jsjson.Object) {
			out[m.Key] = []string{}
			for _, t := range m.Value.([]any) {
				out[m.Key] = append(out[m.Key], t.(string))
			}
		}
		return out
	}
	for _, v := range list(loadVectors(t), "sameTargets") {
		if got := SameTargets(toMap(field(v, "a")), toMap(field(v, "b"))); got != (field(v, "same") == true) {
			t.Errorf("SameTargets(%v, %v) = %v", field(v, "a"), field(v, "b"), got)
		}
	}
}
