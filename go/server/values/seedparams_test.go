// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import "testing"

// A payload whose member totp is present marks a seed whatever its shape,
// null included, so it is never opened or delivered as a value.
func TestSeedParamsAnyMemberTotpIsASeed(t *testing.T) {
	for _, payload := range []string{
		`{"totp":null}`,
		`{"totp":"x"}`,
		`{"totp":{}}`,
	} {
		if _, ok := seedParams(payload); !ok {
			t.Errorf("%s: read as a value", payload)
		}
	}
	if _, ok := seedParams(`{"v":1,"c":"YWJj"}`); ok {
		t.Error("an envelope without totp read as a seed")
	}
}
