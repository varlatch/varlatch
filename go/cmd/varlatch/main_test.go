// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"testing"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
)

func TestVersion(t *testing.T) {
	for _, arg := range []string{"--version", "version"} {
		var out, errOut bytes.Buffer
		if code := run([]string{arg}, &out, &errOut); code != 0 {
			t.Fatalf("%s: exit %d, stderr %q", arg, code, errOut.String())
		}
		if want := "varlatch " + buildinfo.Version + "\n"; out.String() != want {
			t.Fatalf("%s: got %q, want %q", arg, out.String(), want)
		}
	}
}

func TestOtherwiseRefuses(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, &out, &errOut); code != 2 || out.Len() != 0 || errOut.Len() == 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
}
