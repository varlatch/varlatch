// SPDX-License-Identifier: AGPL-3.0-or-later

package limits

import (
	"reflect"
	"testing"

	"github.com/varlatch/varlatch/go/server/jsvalue"
)

func TestJoinAndSplit(t *testing.T) {
	plain := jsvalue.Object{{Key: "team", Value: "a"}}
	for _, l := range []Limits{
		{}, {SingleExchange: true}, {ExerciseOnly: true, SingleExchange: true}, {ExerciseOnly: true, SingleExchange: true, RunIDClaim: `a"b`},
	} {
		for _, claims := range []jsvalue.Object{nil, plain} {
			joined := Join(claims, l)
			if l.Any() == (len(joined) == len(claims)) {
				t.Errorf("%+v: joined %v", l, joined)
			}
			// As the column gives it back.
			v, err := jsvalue.Parse(jsvalue.Stringify(jsvalue.Jsonb(joined)))
			if err != nil {
				t.Fatal(err)
			}
			got, gotLimits := Split(v.(jsvalue.Object))
			if gotLimits != l || len(got) != len(claims) || len(got) > 0 && !reflect.DeepEqual(got, claims) {
				t.Errorf("%+v with %v: %v, %+v", l, claims, got, gotLimits)
			}
		}
	}
	if len(plain) != 1 {
		t.Error("Join changed its argument")
	}
}

// A reserved claim that is not exactly what Join writes limits nothing and
// is matched as any claim is: by no token.
func TestAnUnknownLimitStaysAClaim(t *testing.T) {
	for _, text := range []string{
		"", "{}", "x", "null", `{"v":1}`, `{"v":2,"exerciseOnly":true,"singleExchange":true}`, `{"v":1,"exerciseOnly":true}`,
		`{"v":1,"exerciseOnly":true,"singleExchange":true,"more":1}`, `{"v":1,"exerciseOnly":"true","singleExchange":true}`,
		`{"v":1,"runIdClaim":"job","singleExchange":true}`, `{"v":1,"singleExchange":false}`, ` {"v":1,"singleExchange":true}`,
		`{"v":1,"singleExchange":true,"singleExchange":true}`, `{"singleExchange":true,"v":1}`, `{"v":true,"singleExchange":true}`,
	} {
		claims := jsvalue.Object{{Key: claim, Value: text}}
		if rest, l := Split(claims); l.Any() || len(rest) != 1 {
			t.Errorf("%q: %v, %+v", text, rest, l)
		}
	}
	if _, l := Split(jsvalue.Object{{Key: claim, Value: 1}}); l.Any() {
		t.Error("a claim that is no string")
	}
	if rest, l := Split(nil); rest != nil || l.Any() {
		t.Error("no claims")
	}
}

func TestCombine(t *testing.T) {
	ex, run := Limits{ExerciseOnly: true, SingleExchange: true}, Limits{ExerciseOnly: true, SingleExchange: true, RunIDClaim: "job"}
	for _, c := range []struct{ a, b, want Limits }{
		{Limits{}, Limits{}, Limits{}}, {Limits{}, ex, ex}, {ex, run, run}, {run, run, run}, {Limits{SingleExchange: true}, Limits{}, Limits{SingleExchange: true}},
	} {
		for _, p := range [][2]Limits{{c.a, c.b}, {c.b, c.a}} {
			if got, ok := Combine(p[0], p[1]); !ok || got != c.want {
				t.Errorf("%+v and %+v: %+v, %v", p[0], p[1], got, ok)
			}
		}
	}
	if _, ok := Combine(run, Limits{ExerciseOnly: true, SingleExchange: true, RunIDClaim: "run"}); ok {
		t.Error("two run claims combine")
	}
}

func TestIsLimited(t *testing.T) {
	if IsLimited(nil) || IsLimited(jsvalue.Object{{Key: "team", Value: "a"}}) {
		t.Error("plain claims reported as limited")
	}
	if !IsLimited(Join(nil, Limits{SingleExchange: true})) {
		t.Error("known limit not reported as limited")
	}
	if !IsLimited(jsvalue.Object{{Key: claim, Value: `{"v":2,"future":true}`}}) {
		t.Error("unknown reserved limit not reported as limited")
	}
}
