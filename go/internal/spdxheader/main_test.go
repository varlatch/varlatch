// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestWithHeader(t *testing.T) {
	const src = "//go:build go1.22\n\n// Package api is generated.\npackage api\n"
	const want = "// SPDX-License-Identifier: AGPL-3.0-or-later\n\n" + src
	once := withHeader([]byte(src), "AGPL-3.0-or-later")
	if string(once) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", once, want)
	}
	// Running it again (go generate twice without the generator) changes nothing.
	if twice := withHeader(once, "AGPL-3.0-or-later"); string(twice) != want {
		t.Fatalf("not idempotent:\n%s", twice)
	}
}
