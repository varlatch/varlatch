// SPDX-License-Identifier: Apache-2.0

//go:build crashpoint || rehearsal

package migrate

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The overrides of a test build only: G5's interruption gate (the
// crashpoint tag, crashpoint.go) and step 7.8b's rehearsals on a real
// source built from a branch (the rehearsal tag, go/test/rehearsal), whose
// TypeScript image is not the published one. A release build has neither
// tag (testonly_guard_test.go), so it has none of this:
//
//   - VARLATCH_MIGRATE_PIN=<repository>@<digest> pins the source's image in
//     place of LastTypeScriptRepository and LastTypeScriptDigest (a
//     release pins 0.23.1's published image, by its registry digest);
//   - VARLATCH_MIGRATE_IMAGE_USER=<uid>:<gid> is the image target's user,
//     for a test that does not run as root;
//   - VARLATCH_TEST_HANDOFF_UNDO_WAIT and VARLATCH_TEST_HANDOFF_DEADLINE
//     (Go durations) shorten the tailnet handoff's undo wait and its
//     deadline, for G5's undo cases (an undo cut short by a control plane
//     gone, or a control plane failing on one device's rename).

var pinText = regexp.MustCompile(`^([^@\s]+)@(sha256:[0-9a-f]{64})$`)

func init() {
	if v := os.Getenv("VARLATCH_MIGRATE_PIN"); v != "" {
		m := pinText.FindStringSubmatch(v)
		if m == nil {
			panic("VARLATCH_MIGRATE_PIN is <repository>@sha256:<64 hex digits>")
		}
		testPin = &imagePin{Repository: m[1], Digest: m[2]}
	}
	if u := os.Getenv("VARLATCH_MIGRATE_IMAGE_USER"); u != "" {
		a, b, _ := strings.Cut(u, ":")
		uid, err1 := strconv.ParseUint(a, 10, 32)
		gid, err2 := strconv.ParseUint(b, 10, 32)
		if err1 != nil || err2 != nil {
			panic("VARLATCH_MIGRATE_IMAGE_USER is <uid>:<gid>")
		}
		ImageUser = Owner{UID: uint32(uid), GID: uint32(gid)}
	}
	if d, err := time.ParseDuration(os.Getenv("VARLATCH_TEST_HANDOFF_UNDO_WAIT")); err == nil && d > 0 {
		testHandoffUndoWait = d
	}
	if d, err := time.ParseDuration(os.Getenv("VARLATCH_TEST_HANDOFF_DEADLINE")); err == nil && d > 0 {
		testHandoffDeadline = d
	}
}
