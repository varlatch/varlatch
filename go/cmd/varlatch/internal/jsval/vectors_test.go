// SPDX-License-Identifier: Apache-2.0

package jsval

import (
	"encoding/hex"
	"os"
	"testing"
	"time"
	_ "time/tzdata" // the vectors' time zone, wherever the test runs

	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The context vectors' sections for JavaScript itself
// (../../testdata/vectors/context.json, written by
// apps/cli/test/go-vectors-context.test.ts): Date.parse in the vectors'
// time zone, readFileSync's UTF-8 decoding, and Number(text).

func loadVectors(t *testing.T) jsjson.Object {
	t.Helper()
	data, err := os.ReadFile("../../testdata/vectors/context.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsjson.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return v.(jsjson.Object)
}

func TestDateParseVectors(t *testing.T) {
	vectors := loadVectors(t)
	zone, err := time.LoadLocation(vectors.Value("timeZone").(string))
	if err != nil {
		t.Fatal(err)
	}
	saved := time.Local
	time.Local = zone
	defer func() { time.Local = saved }()
	cases := vectors.Value("dateParse").([]any)
	if len(cases) < 100 {
		t.Fatalf("only %d Date.parse vectors", len(cases))
	}
	for _, raw := range cases {
		c := raw.(jsjson.Object)
		text := c.Value("text").(string)
		got, ok := DateParse(text)
		want, valid := c.Value("value").(float64)
		if ok != valid || ok && got != want {
			t.Errorf("Date.parse(%q) = %v (%v), want %v", text, got, ok, c.Value("value"))
		}
	}
}

func TestDecodeUTF8Vectors(t *testing.T) {
	for _, raw := range loadVectors(t).Value("utf8").([]any) {
		c := raw.(jsjson.Object)
		b, err := hex.DecodeString(c.Value("hex").(string))
		if err != nil {
			t.Fatal(err)
		}
		if got := DecodeUTF8(b); got != c.Value("text") {
			t.Errorf("%s: %q, want %q", c.Value("hex"), got, c.Value("text"))
		}
	}
}

func TestToNumberVectors(t *testing.T) {
	for _, raw := range loadVectors(t).Value("toNumber").([]any) {
		c := raw.(jsjson.Object)
		text := c.Value("text").(string)
		got, ok := ToNumber(UTF16(text))
		want, valid := c.Value("value").(float64)
		if ok != valid || ok && got != want {
			t.Errorf("Number(%q) = %v (%v), want %v", text, got, ok, c.Value("value"))
		}
	}
}

// FuzzDateParse: no text makes the date parser fail other than with NaN,
// and a time it gives is a whole number of milliseconds in a Date's range.
func FuzzDateParse(f *testing.F) {
	for _, seed := range []string{"2026-11-17T10:00:00Z", "Tue, 17 Nov 2026 10:00:00 GMT+0100 (x)", "12/31/2020 10:00 pm", "+275760-09-13", "Jan 1 2000 10:00 +596523:"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		v, ok := DateParse(text)
		if ok && (v != float64(int64(v)) || v > 8.64e15 || v < -8.64e15) {
			t.Fatalf("Date.parse(%q) = %v", text, v)
		}
	})
}
