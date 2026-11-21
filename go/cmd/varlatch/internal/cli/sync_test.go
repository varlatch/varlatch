// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
)

// TestPushReadsOnlyStringValues: sync push pushes a disclosed or stored
// value only when it is a string. No value, and a value of another type
// (which the TypeScript adapters throw on), is not readable: never pushed
// as its text ("undefined", "12345").
func TestPushReadsOnlyStringValues(t *testing.T) {
	for _, c := range []struct {
		value    any
		readable bool
	}{
		{"s3cr3t", true},
		{"", true},
		{nil, false},
		{apiclient.Undefined, false},
		{float64(12345), false},
		{true, false},
		{[]any{"a"}, false},
	} {
		if got, ok := pushReadable(c.value); ok != c.readable || ok && got != c.value {
			t.Errorf("pushReadable(%#v) = %q, %v; want readable %v", c.value, got, ok, c.readable)
		}
	}
}

// TestCheckComparesOnlyStringValues: a disclosed value that is not a string
// differs from whatever the platform holds, its digits included; no value
// is withheld.
func TestCheckComparesOnlyStringValues(t *testing.T) {
	digits := "12345"
	pairs := []keyPair{{name: "A", destination: "A"}, {name: "B", destination: "B"}, {name: "C", destination: "C"}}
	varlatch := map[string]*string{"A": notAString, "B": nil, "C": &digits}
	platform := map[string]*string{"A": &digits, "B": &digits, "C": &digits}
	got := compareKeys(pairs, varlatch, platform)
	want := []string{"differs", "unreadable", "match"}
	for i, k := range got {
		if k.status != want[i] {
			t.Errorf("%s: %s, want %s", k.name, k.status, want[i])
		}
	}
}
