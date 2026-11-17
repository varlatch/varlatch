// SPDX-License-Identifier: Apache-2.0

//go:build coolifylive

package sync

import (
	"strings"
	"testing"
)

// The live checks' guard compares normalised origins: only the lab
// Coolify's passes, never the production one.
func TestCoolifyLiveOrigin(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://coolify-lab.private.robotsson.be":           true,
		"https://coolify-lab.private.robotsson.be/":          true,
		"https://COOLIFY-LAB.private.robotsson.be:443":       true,
		"https://coolify-lab.private.robotsson.be.":          true,
		"https://coolify.private.robotsson.be":               false, // production
		"http://coolify-lab.private.robotsson.be":            false,
		"https://coolify-lab.private.robotsson.be:8443":      false,
		"https://coolify-lab.private.robotsson.be.evil.test": false,
		"https://evil.test/coolify-lab.private.robotsson.be": false,
		"": false,
	} {
		if got := normalOrigin(raw) == labOrigin; got != want {
			t.Errorf("%q: lab %v, want %v", raw, got, want)
		}
	}
}

// The services fixture keeps the escaped reference a YAML escape, so the
// adapter's YAML decoding is what finds it (a plain "$" would not test it).
func TestCoolifyLiveEscapedReference(t *testing.T) {
	escape := string(rune(92)) + "u0024"
	if c := servicesCompose("P_"); !strings.Contains(c, `P_ESCAPED_REF: "`+escape+`P_ESCAPED_REF"`) {
		t.Fatalf("the compose fixture's ESCAPED_REF is not a YAML escape:\n%s", c)
	}
}
