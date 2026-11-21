// SPDX-License-Identifier: Apache-2.0

package release

import "testing"

// Semantic Versioning's own precedence example, then the cases
// self-update's choice depends on.
func TestCompareVersions(t *testing.T) {
	ordered := []string{
		"0.22.4", "0.50.0-alpha", "0.50.0-alpha.1", "0.50.0-alpha.beta", "0.50.0-beta", "0.50.0-beta.2",
		"0.50.0-beta.11", "0.50.0-rc.1", "0.50.0-rc.2", "0.50.0-rc.10", "0.50.0", "0.50.1", "0.51.0-rc.1", "0.51.0", "1.0.0",
		"10.0.0",
	}
	for i, a := range ordered {
		for j, b := range ordered {
			got, ok := CompareVersions(a, b)
			want := compareInts(i, j)
			if !ok || got != want {
				t.Errorf("CompareVersions(%q, %q) = %d, %v; want %d", a, b, got, ok, want)
			}
		}
	}
	for _, bad := range []string{"", "0.50", "v0.50.0", "0.50.0-", "00.50.0", "0.50.0+build", "0.50.0-rc..1"} {
		if _, ok := CompareVersions(bad, "0.50.0"); ok {
			t.Errorf("%q compared", bad)
		}
	}
	if !Prerelease("0.50.0-rc.1") || Prerelease("0.50.0") {
		t.Error("Prerelease")
	}
}
