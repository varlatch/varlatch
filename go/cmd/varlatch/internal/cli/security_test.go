// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/jsjson"
	"github.com/varlatch/varlatch/go/server/outbound"
)

// TestSecurityWordsReadOwnNames: a server's kind, reason or objectLock
// named like a property of Object.prototype reads as a word the table
// lacks ("undefined"), never as the property (step 5 defect 32, not
// reproduced).
func TestSecurityWordsReadOwnNames(t *testing.T) {
	for _, name := range []string{"constructor", "__proto__", "toString", "hasOwnProperty", "valueOf"} {
		for _, table := range []map[string]string{refusedKindWords, outboundRefusalLabels, auditLockWords} {
			if got := wordOf(table, name); got != "undefined" {
				t.Errorf("%s: %q", name, got)
			}
		}
	}
	if got := wordOf(refusedKindWords, "oidc-issuer"); got != "OIDC issuer" {
		t.Errorf("an own word: %q", got)
	}
	if got := wordOf(refusedKindWords, 7.0); got != "undefined" {
		t.Errorf("a word that is not a string: %q", got)
	}
	var line string
	if err := catchJS(func() {
		line = refusedLine(jsjson.Object{{Key: "kind", Value: "constructor"}, {Key: "id", Value: "whk_1"}, {Key: "reason", Value: "__proto__"}}, 30.0, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, "function") || strings.Contains(line, "[object Object]") {
		t.Errorf("a prototype property was printed: %q", line)
	}
}

// TestOutboundWordsAreTheProtocols: the labels and the host note security
// report prints are @varlatch/protocol's, as go/server/outbound holds them.
func TestOutboundWordsAreTheProtocols(t *testing.T) {
	if len(outboundRefusalLabels) != len(outbound.Labels) {
		t.Fatalf("%d labels, outbound has %d", len(outboundRefusalLabels), len(outbound.Labels))
	}
	for reason, label := range outbound.Labels {
		if got := outboundRefusalLabels[string(reason)]; got != label {
			t.Errorf("%s: %q, outbound %q", reason, got, label)
		}
	}
	if outboundHostNote != outbound.HostNote {
		t.Errorf("host note %q, outbound %q", outboundHostNote, outbound.HostNote)
	}
}

// TestCatchJSKeepsOtherPanics: catchJS turns only a builder's TypeError
// back into an error; any other panic is a bug and keeps panicking.
func TestCatchJSKeepsOtherPanics(t *testing.T) {
	if err := catchJS(func() { at(nil, "items") }); err == nil || err.Error() != "Cannot read properties of null (reading 'items')" {
		t.Errorf("null: %v", err)
	}
	if err := catchJS(func() { at(undef, "items") }); err == nil || err.Error() != "Cannot read properties of undefined (reading 'items')" {
		t.Errorf("undefined: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("another panic was swallowed")
		}
	}()
	_ = catchJS(func() { panic("bug") })
}
