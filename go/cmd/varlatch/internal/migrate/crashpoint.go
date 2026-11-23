// SPDX-License-Identifier: Apache-2.0

//go:build crashpoint

package migrate

import (
	"fmt"
	"os"
	"time"
)

// Crash points for G5's interruption gate (go test -tags g5, which builds
// varlatch with -tags crashpoint; server/migration/g5): a build with this
// tag, run with VARLATCH_MIGRATE_LOG set, appends "reached <point>" to that
// file at every point it reaches; with VARLATCH_MIGRATE_PAUSE=<point>, the
// first time it reaches that point it writes "paused <point>" and blocks
// for good, so the gate kills it exactly there. The points:
//
//   - the forward migration: "entered <phase>" once each phase is
//     journalled in both places; "barrier held" once the source's barrier
//     is up and recorded; "transfer started" once the target serves under
//     the transfer's gate; "open source" when the source's journal says
//     open but the live open has not run yet; "switch sidecar started"
//     once the sidecar the tailnet handoff stopped runs again for the
//     source's mark, and "switch marked" once the source is marked
//     migrated out, before the sidecar stops again;
//   - the reverse (--rollback): "rollback barrier held" once Go's barrier
//     is up; "rollback rebuilt" once the TypeScript side runs on its fresh
//     volumes; "rollback go stopped" and "rollback transfer started" in
//     the address's move back; "rollback undone open" once an undo wrote
//     the journals open, before Go's barrier is lifted; "rollback undone
//     released" once it is lifted, before the source's journal records it;
//   - --finish: "finish archived" once the final archive is verified and
//     journalled; "finished source written" between the source's journal
//     saying finished and Go's; "entered finished" once both (or, after a
//     reverse, the source's alone) say it; "finish containers removed"
//     after docker compose down; "finish volume removed" between a
//     volume's removal and its journal entry; "finish go discarded" once
//     Go's copy is discarded after a reverse;
//   - the tailnet handoff: "tailnet <forward|undo|rollback> <step>" once
//     it has journalled a step (prepared, switching, serving closed,
//     serving renamed, incoming renamed, opening, done, undoing, undone,
//     undo-pending), before its act.
//
// The gate's stand-in source and target also take testonly.go's overrides
// (the image pin and the image's user), which this build has too. A
// release has none of this.

var cp struct {
	log   *os.File
	pause string
}

func init() {
	if path := os.Getenv("VARLATCH_MIGRATE_LOG"); path != "" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			panic(err)
		}
		cp.log = f
	}
	cp.pause = os.Getenv("VARLATCH_MIGRATE_PAUSE")
}

// crashPoint logs point, and blocks for good when it is the one to pause
// at.
// seamPaths: the crashpoint build makes a host target under a test root
// (the CLI's VARLATCH_MIGRATE_TARGET_ROOT), so a journal may name its
// configuration there.
const seamPaths = true

func crashPoint(point string) {
	if cp.log == nil {
		return
	}
	fmt.Fprintf(cp.log, "reached %s\n", point)
	if point == cp.pause {
		fmt.Fprintf(cp.log, "paused %s\n", point)
		_ = cp.log.Sync()
		// Asleep on a timer, not in select {}: with every other goroutine
		// blocked, the runtime ends a program that has none
		// ("all goroutines are asleep - deadlock!") before the kill comes
		// (rehearsal r16b and r16c, the kill at "transfer started").
		for {
			time.Sleep(time.Hour)
		}
	}
}
