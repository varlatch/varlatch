// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import "testing"

func TestFirstAdmin(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "not JSON": "", `{"admins":[]}`: "",
		`{"initialized":true,"admins":[{"id":"idn_a","enabled":false,"hasPasskey":true},{"id":"idn_b","enabled":true,"hasPasskey":false}]}` + "\n": "idn_b",
	} {
		if got := firstAdmin(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if got := enrollLink.FindString("The link, once:\nhttps://v.example/enroll#vle_abc-_9\nend"); got != "https://v.example/enroll#vle_abc-_9" {
		t.Errorf("link %q", got)
	}
}
