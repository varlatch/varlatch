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

// The admin commands refuse arguments they do not take before reading any
// configuration (daemon/admin_test.go runs them on an installation).
func TestAdminUsage(t *testing.T) {
	for _, args := range [][]string{
		{"admin", "bootstrap", "--identity", "idn_x"},
		{"admin", "recover"},
		{"admin", "recover", "--identity", "idn_x", "--new-admin"},
		{"admin", "recover", "--identity"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != exitUsage || out.Len() != 0 || !strings.Contains(errOut.String(), "Usage") {
			t.Errorf("%q: exit %d, %q", args, code, errOut.String())
		}
	}
}
