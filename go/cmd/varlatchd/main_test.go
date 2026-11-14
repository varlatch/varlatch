// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
)

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--version"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	if want := "varlatchd " + buildinfo.Version + "\n"; out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}, {"serve", "--bogus"}, {"serve", "--config"}, {"admin"}, {"admin", "kek"}} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != exitUsage {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

// The admin commands the conformance harness calls answer NOT_IMPLEMENTED_YET
// until step 3.4 builds them.
func TestAdminNotBuilt(t *testing.T) {
	for _, cmd := range []string{"bootstrap", "recover"} {
		var out, errOut bytes.Buffer
		if code := run([]string{"admin", cmd, "--identity", "idn_x"}, &out, &errOut); code != exitNotBuilt ||
			!strings.HasPrefix(errOut.String(), "NOT_IMPLEMENTED_YET: ") || out.Len() != 0 {
			t.Errorf("admin %s: exit %d, %q", cmd, code, errOut.String())
		}
	}
}
