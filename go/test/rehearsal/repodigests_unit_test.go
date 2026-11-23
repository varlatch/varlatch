// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"slices"
	"strings"
	"testing"
)

// TestDecodeRepoDigests: item 8's local image's RepoDigests, as docker
// image inspect prints them, decoded rather than compared as text.
func TestDecodeRepoDigests(t *testing.T) {
	ref := "vl-rh-r1-local/varlatchd@sha256:" + strings.Repeat("0", 64)
	for raw, want := range map[string][]string{
		"[]":              {},
		"null":            nil,
		`["` + ref + `"]`: {ref},
	} {
		got, err := decodeRepoDigests(raw)
		if err != nil || !slices.Equal(got, want) || len(got) != len(want) {
			t.Errorf("%s: %q, %v", raw, got, err)
		}
	}
	if _, err := decodeRepoDigests("[sha256:x"); err == nil {
		t.Error("an answer that is not JSON was read")
	}
}
