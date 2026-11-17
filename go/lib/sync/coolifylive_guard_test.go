// SPDX-License-Identifier: Apache-2.0

//go:build coolifylive

package sync

import "testing"

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
