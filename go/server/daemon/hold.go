// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/maintenance"
	"github.com/varlatch/varlatch/go/server/write"
)

// `varlatchd admin restore` (backup.Hold): what a completed restore leaves
// until the host operator has put right what changed since the archive.
//
//	varlatchd admin restore status
//	varlatchd admin restore resume
//
// status prints JSON. resume records installation.restore_resumed, then
// ends the hold: in the running varlatchd, whose workers go on at their
// next pass, or, with varlatchd stopped, on the data directory. A crash
// between the event and the hold's removal leaves it held; resuming again
// records the event again. Both commands are the host operator's.
const holdUsage = "Usage: varlatchd admin restore status | varlatchd admin restore resume"

type holdStatus struct {
	Held       bool   `json:"held"`
	ArchiveID  string `json:"archiveId,omitempty"`
	RestoredAt string `json:"restoredAt,omitempty"`
	// Unreadable: the hold's file cannot be read; the installation stays
	// held.
	Unreadable bool `json:"unreadable,omitempty"`
}

func runHold(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintf(stderr, "varlatchd admin restore %s: %s\n", rest[0], err.Error())
		return ExitFailure
	}
	switch {
	case len(rest) == 1 && rest[0] == "status":
		st := holdStatus{Held: env.admission.Held()}
		switch h, err := env.admission.Hold(); {
		case err != nil:
			st.Unreadable = true
		case h != nil:
			st.ArchiveID, st.RestoredAt = h.ArchiveID, h.RestoredAt
		}
		return printJSON(stdout, stderr, "varlatchd admin restore status", st)
	case len(rest) == 1 && rest[0] == "resume":
	default:
		fmt.Fprintln(stderr, holdUsage)
		return 64
	}
	leave, ok := env.admission.Enter()
	if !ok {
		return fail(errors.New(MaintenanceRefusal))
	}
	defer leave()
	w := &write.Writer{Store: env.store, Gates: env.gates}
	what, err := env.admission.Resume(func(h *backup.Hold) error {
		meta := jsvalue.Object{{Key: "archiveId", Value: nil}, {Key: "restoredAt", Value: nil}}
		if h != nil {
			meta = jsvalue.Object{{Key: "archiveId", Value: h.ArchiveID}, {Key: "restoredAt", Value: h.RestoredAt}}
		}
		return w.Job(ctx, nil, func(ctx context.Context, tx *storage.Tx) error {
			_, err := audit.Record(ctx, tx, audit.Event{Type: "installation.restore_resumed", Decision: audit.Info, Metadata: meta})
			return err
		})
	})
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(stdout, "Resumed: the installation is no longer held (removed %s, %s). Its background work goes on: sync, webhooks, audit export, organization deletion. What came due meanwhile is done now.\n", backup.HoldFile, what)
	return ExitOK
}

// clearStaleHold is `restore resume` on a stopped varlatchd's data
// directory that holds no database: there is nothing to resume and nowhere
// to record it, and nothing is made. The caller holds the directory's lock.
func clearStaleHold(dir string, stdout, stderr io.Writer) int {
	what, err := backup.RemoveHold(dir)
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "varlatchd admin restore resume: %v\n", err)
		return ExitFailure
	case what == "":
		fmt.Fprintf(stderr, "varlatchd admin restore resume: %v\n", maintenance.ErrNotHeld)
		return ExitFailure
	}
	fmt.Fprintf(stdout, "The data directory has no database: there was nothing to resume. Removed the stale %s (%s).\n", backup.HoldFile, what)
	return ExitOK
}
