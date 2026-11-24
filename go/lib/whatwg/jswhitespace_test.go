// SPDX-License-Identifier: Apache-2.0

package whatwg

import "testing"

// IsJSWhitespace is JavaScript's \s: its WhiteSpace and LineTerminator
// code points, and any Zs.
func TestIsJSWhitespace(t *testing.T) {
	for _, r := range []rune{' ', '\t', '\n', 0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x202f, 0x3000, 0xfeff} {
		if !IsJSWhitespace(r) {
			t.Errorf("%U is \\s", r)
		}
	}
	for _, r := range []rune{'a', '0', 0x200b, 0x180e, 0x85} {
		if IsJSWhitespace(r) {
			t.Errorf("%U is not \\s", r)
		}
	}
}
