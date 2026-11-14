// SPDX-License-Identifier: AGPL-3.0-or-later

package jsvalue

import (
	"math"
	"testing"
)

// The expectations are JSON.stringify's, taken from Node.js.
func TestNumber(t *testing.T) {
	for _, c := range []struct {
		x    float64
		want string
	}{
		{0, "0"},
		{math.Copysign(0, -1), "0"},
		{1, "1"},
		{-1, "-1"},
		{1.5, "1.5"},
		{0.1, "0.1"},
		{3.333333333333333e-1, "0.3333333333333333"},
		{1e+21, "1e+21"},
		{1e-7, "1e-7"},
		{0.000001, "0.000001"},
		{1.23e-18, "1.23e-18"},
		{5e-324, "5e-324"},
		{1.7976931348623157e+308, "1.7976931348623157e+308"},
		{1.2345678901234567e+19, "12345678901234567000"},
		{9.999999999999999e+20, "999999999999999900000"},
		{1e+20, "100000000000000000000"},
		{123456.789, "123456.789"},
		{-0.000001, "-0.000001"},
		{9.007199254740992e+15, "9007199254740992"},
		{9.007199254740994e+15, "9007199254740994"},
		{1.25e-10, "1.25e-10"},
		{100, "100"},
		{1e+300, "1e+300"},
		{0.000001234, "0.000001234"},
		{math.Inf(1), "null"},
		{math.NaN(), "null"},
	} {
		if got := Number(c.x); got != c.want {
			t.Errorf("Number(%v) = %s, want %s", c.x, got, c.want)
		}
	}
}

func TestParseStringify(t *testing.T) {
	for _, c := range []struct{ in, js, jsonb string }{
		// JSON.parse keeps a repeated key's first position and last value,
		// and puts array indexes first; jsonb sorts by length, then bytes.
		{`{"\u00e9":1,"e":2,"ab":3}`, "{\"\u00e9\":1,\"e\":2,\"ab\":3}", "{\"e\":2,\"ab\":3,\"\u00e9\":1}"},
		{`{"\u00e9":1,"e":2,"ab":3}`, "{\"\u00e9\":1,\"e\":2,\"ab\":3}", "{\"e\":2,\"ab\":3,\"\u00e9\":1}"},
		{`{"\u00e9":1,"e":2,"ab":3}`, "{\"\u00e9\":1,\"e\":2,\"ab\":3}", "{\"e\":2,\"ab\":3,\"\u00e9\":1}"},
		{`[1e400, -0, 1.0, "\u2028</>\u0007\ud83d\ude00"]`, "[null,0,1,\"\u2028</>\\u0007\U0001F600\"]", "[null,0,1,\"\u2028</>\\u0007\U0001F600\"]"},
		{`{"\u00e9":1,"e":2,"ab":3}`, "{\"\u00e9\":1,\"e\":2,\"ab\":3}", "{\"e\":2,\"ab\":3,\"\u00e9\":1}"},
	} {
		v, err := Parse([]byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got := string(Stringify(v)); got != c.js {
			t.Errorf("JSON.stringify(JSON.parse(%s)) = %s, want %s", c.in, got, c.js)
		}
		if got := string(Stringify(Jsonb(v))); got != c.jsonb {
			t.Errorf("jsonb %s = %s, want %s", c.in, got, c.jsonb)
		}
	}
	for _, bad := range []string{``, `{`, `{"a":1} x`, `nul`, "\"\xff\""} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func TestQuote(t *testing.T) {
	got := string(Stringify("\"\\\b\f\n\r\t\x00\x1f\x7f\u2028\xff"))
	want := `"\"\\\b\f\n\r\t\u0000\u001f` + "\x7f\u2028\ufffd" + `"`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
