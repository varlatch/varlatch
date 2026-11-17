// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
)

// The installers read the first line of --version as `varlatch <version>`
// (install.sh, install.ps1); the menu bar app, the tray and the omarchy
// plugin read its first two words (internal docs/design/go-cli.md, decision 6).
func TestVersion(t *testing.T) {
	for _, arg := range []string{"--version", "version"} {
		var out, errOut bytes.Buffer
		if code := run([]string{arg}, strings.NewReader(""), &out, &errOut); code != 0 {
			t.Fatalf("%s: exit %d, stderr %q", arg, code, errOut.String())
		}
		if want := "varlatch " + buildinfo.Version + "\n"; out.String() != want {
			t.Fatalf("%s: got %q, want %q", arg, out.String(), want)
		}
	}
}

func TestVerifyReleaseStaysGos(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"verify-release"}, strings.NewReader(""), &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "usage: varlatch verify-release") {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
}
