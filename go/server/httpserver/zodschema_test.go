// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// zRecord parses as zod 4.6.7's z.record does (each answer below is what
// safeParse gives): with string keys an own "__proto__" member is skipped
// before its value is checked; with enum keys it is an unrecognized key;
// "constructor" and "prototype" are ordinary keys in both.
func TestZRecordProto(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	strs := zRecord{value: zArray{element: zString{}, max: 8}}
	enum := zRecord{keys: zEnum{"environment", "contract", "items", "rotation"}, value: digest}
	for _, c := range []struct {
		name   string
		schema zSchema
		body   string
		out    string // the output's JSON, when it parses
		issues string // VALIDATION_FAILED's message, when it does not
	}{
		{name: "string keys, __proto__ alone, not an array", schema: strs, body: `{"__proto__":"bad"}`, out: `{}`},
		{name: "string keys, __proto__ beside an item", schema: strs, body: `{"__proto__":["header:x"],"A":["y"]}`, out: `{"A":["y"]}`},
		{name: "string keys, constructor and prototype", schema: strs, body: `{"constructor":["x"],"prototype":[1]}`,
			issues: "prototype.0: Invalid input: expected string, received number"},
		{name: "enum keys, every category and __proto__", schema: enum,
			body:   `{"__proto__":"bad","environment":"` + d + `","contract":"` + d + `","items":"` + d + `","rotation":"` + d + `"}`,
			issues: `(root): Unrecognized key: "__proto__"`},
		{name: "enum keys, __proto__ alone", schema: enum, body: `{"__proto__":"x"}`,
			issues: `environment: Invalid input: expected string, received undefined; contract: Invalid input: expected string, received undefined; ` +
				`items: Invalid input: expected string, received undefined; rotation: Invalid input: expected string, received undefined; (root): Unrecognized key: "__proto__"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			body, err := jsvalue.Parse([]byte(c.body))
			if err != nil {
				t.Fatal(err)
			}
			out, err := zParse(c.schema, body)
			if c.issues != "" {
				de, ok := err.(*domainerr.Error)
				if !ok || de.Code != "VALIDATION_FAILED" || de.Message != c.issues {
					t.Fatalf("got %v, want %q", err, c.issues)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := string(jsvalue.Stringify(out)); got != c.out {
				t.Fatalf("got %s, want %s", got, c.out)
			}
		})
	}
}
