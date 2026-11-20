// SPDX-License-Identifier: Apache-2.0

package typegen

import "testing"

// TestGeneratorOf: typesCommand.ts's /^(?:\/\/|#) Generator: +varlatch
// (\S+)$/m, its first match, lines ended by any JavaScript line terminator.
func TestGeneratorOf(t *testing.T) {
	for _, c := range []struct {
		text, want string
		ok         bool
	}{
		{"// Generator:                  varlatch 0.13.0\n", "0.13.0", true},
		{"# Generator: varlatch 1.2.3+b\n", "1.2.3+b", true},
		{"x\r\n// Generator: varlatch 2\r\n", "2", true},
		{"x\u2028// Generator: varlatch 3\u2029y", "3", true},
		{"// Generator: varlatch 4", "4", true},
		{"// Generator: varlatch 5\n# Generator: varlatch 6\n", "5", true},
		{"//  Generator: varlatch 1\n", "", false},
		{"// Generator:varlatch 1\n", "", false},
		{"// Generator: varlatch  1\n", "", false},
		{"// Generator: varlatch 1 2\n", "", false},
		{"// Generator: varlatch 1\u00a0\n", "", false},
		{"// Generator: varlatch \n", "", false},
		{"// Generator:\n", "", false},
		{"  // Generator: varlatch 1\n", "", false},
		{"/* Generator: varlatch 1\n", "", false},
		{"\ufeff// Generator: varlatch 1\n", "", false},
	} {
		got, ok := GeneratorOf([]byte(c.text))
		if got != c.want || ok != c.ok {
			t.Errorf("GeneratorOf(%q) = %q %v, want %q %v", c.text, got, ok, c.want, c.ok)
		}
	}
}
