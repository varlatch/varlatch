// SPDX-License-Identifier: Apache-2.0

package matcher

import "testing"

// TestMarkerAsNodeWritesIt: an item name holding a lone surrogate (kept as
// WTF-8 bytes from a server's JSON) is written in the marker as Node.js
// writes the string, one U+FFFD; any other name as it is.
func TestMarkerAsNodeWritesIt(t *testing.T) {
	if got := string(Marker("A\xed\xa0\xbdB")); got != "[REDACTED:A�B]" {
		t.Errorf("%q", got)
	}
	if got := string(Marker("API_KEY")); got != "[REDACTED:API_KEY]" {
		t.Errorf("%q", got)
	}
}
