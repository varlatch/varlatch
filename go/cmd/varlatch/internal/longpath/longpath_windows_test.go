// SPDX-License-Identifier: Apache-2.0

package longpath

import (
	"strings"
	"testing"
)

// TestOf: a long path gets the prefix (UNC for a share), a
// short one and one with a prefix already are given as they are.
func TestOf(t *testing.T) {
	deep := `C:\` + strings.Repeat(`dir\`, 70) + "f"
	share := `\\server\share\` + strings.Repeat(`dir\`, 70) + "f"
	for given, want := range map[string]string{
		`C:\short\f`:                       `C:\short\f`,
		deep:                               `\\?\` + deep,
		share:                              `\\?\UNC\server\share\` + strings.Repeat(`dir\`, 70) + "f",
		`\\?\` + deep:                      `\\?\` + deep,
		`\\.\C:\dev`:                       `\\.\C:\dev`,
		strings.ReplaceAll(deep, `\`, "/"): `\\?\` + deep,
	} {
		if got := Of(given); got != want {
			t.Errorf("Of(%q)\n got %q\nwant %q", given, got, want)
		}
	}
}
