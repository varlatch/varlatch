// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"slices"
	"strings"
	"testing"
)

// TestAgentNoProxyOnWindows: Windows's environment names are
// case-insensitive, so NO_PROXY and no_proxy are one variable there (the
// transcript case that sets both differently cannot be replayed on
// Windows). A single inherited NO_PROXY: its entries that send every host
// around the Broker are removed and reported under both spellings, as
// Node's case-insensitive process.env reads it twice; the Agent gets one
// no-proxy variable, its other entries kept and the Broker's address added.
func TestAgentNoProxyOnWindows(t *testing.T) {
	env := newOrderedEnv()
	env.Set("PATH", `C:\Windows`)
	env.Set("NO_PROXY", "localhost, * ,.internal")
	removed := setProxy(env, "http://vlt:x@127.0.0.1:4567")
	if want := []string{"NO_PROXY=*", "no_proxy=*"}; !slices.Equal(removed, want) {
		t.Errorf("removed %q, want %q", removed, want)
	}
	var noProxy []string
	for _, line := range env.Lines() {
		if name, _, _ := strings.Cut(line, "="); strings.EqualFold(name, "NO_PROXY") {
			noProxy = append(noProxy, line)
		}
	}
	if want := []string{"NO_PROXY=localhost,.internal,127.0.0.1:4567"}; !slices.Equal(noProxy, want) {
		t.Errorf("the Agent's no-proxy variables %q, want %q", noProxy, want)
	}
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v, ok := env.Get(name); !ok || v != "http://vlt:x@127.0.0.1:4567" {
			t.Errorf("%s: %q, %v", name, v, ok)
		}
	}
}
