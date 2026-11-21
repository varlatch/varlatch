// SPDX-License-Identifier: Apache-2.0

//go:build crashpoint

package migrate

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Crash points for G5's interruption gate (go test -tags g5, which builds
// varlatch with -tags crashpoint; server/migration/g5): a build with this
// tag, run with VARLATCH_MIGRATE_LOG set, appends "reached <point>" to that
// file at every point it reaches; with VARLATCH_MIGRATE_PAUSE=<point>, the
// first time it reaches that point it writes "paused <point>" and blocks
// for good, so the gate kills it exactly there. The points: "entered
// <phase>" once each phase is journalled in both places, "barrier held"
// once the source's barrier is up and recorded, "transfer started" once
// the target serves under the transfer's gate, "open source" when the
// source's journal says open but the live open has not run yet, and
// "tailnet <forward|undo|rollback> <step>" once the tailnet handoff has
// journalled a step (prepared, switching, serving closed, serving renamed,
// incoming renamed, opening, done, undoing, undone, undo-pending), before
// its act.
//
// The gate's stand-in source and target need two more of this build only:
// VARLATCH_MIGRATE_PIN=<repository>@<digest> pins the stand-in's image (a
// release pins 0.23.0's, and refuses every source until it is published),
// and VARLATCH_MIGRATE_IMAGE_USER=<uid>:<gid> is the image's user (the gate
// does not run as root). A release has none of this.

var cp struct {
	log   *os.File
	pause string
}

var pinText = regexp.MustCompile(`^([^@\s]+)@(sha256:[0-9a-f]{64})$`)

func init() {
	if path := os.Getenv("VARLATCH_MIGRATE_LOG"); path != "" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			panic(err)
		}
		cp.log = f
	}
	cp.pause = os.Getenv("VARLATCH_MIGRATE_PAUSE")
	// The tailnet handoff's undo wait, shortened for the gate's undo cases
	// (an undo cut short by a control plane gone).
	if d, err := time.ParseDuration(os.Getenv("VARLATCH_TEST_HANDOFF_UNDO_WAIT")); err == nil && d > 0 {
		testHandoffUndoWait = d
	}
	// Its deadline, shortened for the cases where a control plane failing
	// on one device's rename runs it out.
	if d, err := time.ParseDuration(os.Getenv("VARLATCH_TEST_HANDOFF_DEADLINE")); err == nil && d > 0 {
		testHandoffDeadline = d
	}
	if m := pinText.FindStringSubmatch(os.Getenv("VARLATCH_MIGRATE_PIN")); m != nil {
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
}

// crashPoint logs point, and blocks for good when it is the one to pause
// at.
func crashPoint(point string) {
	if cp.log == nil {
		return
	}
	fmt.Fprintf(cp.log, "reached %s\n", point)
	if point == cp.pause {
		fmt.Fprintf(cp.log, "paused %s\n", point)
		_ = cp.log.Sync()
		select {}
	}
}
