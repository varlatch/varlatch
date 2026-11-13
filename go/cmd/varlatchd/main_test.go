// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
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
