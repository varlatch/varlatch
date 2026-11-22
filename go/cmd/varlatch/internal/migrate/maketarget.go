// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// A host target migrate makes (go-step7 decision 20, slice 7.4e): when the
// target's configuration is not there, migrate makes the Go installation
// with setup's steps (the answers from the source, the varlatch user, the
// data directory, /etc/varlatch and the configuration, the unit enabled
// but not started), never its keys: those are the source's, installed by
// `varlatchd admin migrate keys` as for any target. Each item is
// journalled (in the source's journal: the target has no data directory
// yet) before it is made, so an undo before the switch removes exactly
// what migrate made, and never what was there. A target someone prepared
// is used as it is.

// TargetMaker makes a host target.
type TargetMaker interface {
	// Missing is whether the target is to be made: its configuration is
	// not there.
	Missing() bool
	// Make makes it, for the source's ingress (its public URL and
	// dashboard's address) and shape; made is called with each item's
	// name before the item is made. earlier are the items an earlier run
	// of the same migration made: migrate's, so made again where needed,
	// never judged as what was there.
	Make(ctx context.Context, src IngressInfo, kind Ingress, earlier []string, made func(item string) error) error
	// Undo removes the items made, in the reverse order (each again
	// harmlessly).
	Undo(made []string) error
	// KeyItems are the items the keys' files are, when migrate wrote them
	// into a target it made.
	KeyItems() (rootKEK, backupKey string)
	// Present is whether one of KeyItems' files is there.
	Present(item string) (bool, error)
}

// CreatedRecord is a target migrate made: its items, in the order made;
// Undone once they are removed again.
type CreatedRecord struct {
	Made   []string `json:"made"`
	Undone string   `json:"undone,omitempty"`
}

// CleanupPending is whether the journal records a target migrate made
// and has not removed: a released migration with one is not finished
// (--abort and --resume go on removing it), and no new one starts over
// it.
func (j *Journal) CleanupPending() bool {
	return j.Created != nil && j.Created.Undone == "" && len(j.Created.Made) > 0
}

// makeTarget makes the target when it is missing, journalling each item
// first; a failure removes what was made. It returns the record (nil when
// nothing was to be made and none was made before). The journal it writes
// is the run's (a dry run's says so, so a dry run killed here and resumed
// is a dry run still).
func (e *Engine) makeTarget(ctx context.Context, prev *Journal, id string, src SourceInfo, ing IngressInfo, dryRunOnly bool) (*CreatedRecord, error) {
	var rec *CreatedRecord
	if prev != nil && prev.ID == id && prev.Created != nil && prev.Created.Undone == "" {
		rec = prev.Created
	}
	if e.Maker == nil || !e.Maker.Missing() {
		return rec, nil
	}
	if rec == nil {
		rec = &CreatedRecord{}
	}
	// The source's journal, before the target exists: the migration's id
	// and what is being made.
	pre := &Journal{Format: 1, ID: id, Phase: Started, DryRunOnly: dryRunOnly, Source: src, Ingress: e.Options.Ingress, Created: rec, History: []Step{}}
	if prev != nil && prev.ID == id {
		pre.History = prev.History
	}
	e.say("Making the target: the Go installation on this host, with setup's steps (its keys will be the source's).")
	err := e.Maker.Make(ctx, ing, e.Options.Ingress, slices.Clone(rec.Made), func(item string) error {
		if !slices.Contains(rec.Made, item) {
			rec.Made = append(rec.Made, item)
		}
		if err := writeJournal(e.Source.Dir(), pre); err != nil {
			return err
		}
		crashPoint("target " + item)
		return nil
	})
	if err != nil {
		if uerr := e.undoMade(pre); uerr != nil {
			return rec, fmt.Errorf("making the target: %w; removing what was made: %v (varlatch migrate --abort tries again)", err, uerr)
		}
		// Stopped, as a failure before the barrier is: the next run starts
		// again (it is not an interrupted one).
		pre.Stopped = true
		if werr := writeJournal(e.Source.Dir(), pre); werr != nil {
			return rec, fmt.Errorf("making the target: %w; what was made is removed, but recording it as stopped: %v", err, werr)
		}
		return rec, fmt.Errorf("making the target: %w; what was made is removed (varlatch migrate starts again once that is fixed)", err)
	}
	return rec, nil
}

// undoMade removes the target migrate made, recorded in j, and journals
// it undone (the source's journal: the target is gone).
func (e *Engine) undoMade(j *Journal) error {
	rec := j.Created
	if rec == nil || rec.Undone != "" || len(rec.Made) == 0 {
		return nil
	}
	if e.Maker == nil {
		return errors.New("the target migrate made cannot be removed by this run")
	}
	e.say("Removing what migrate made of the target: %v.", rec.Made)
	if err := e.Maker.Undo(rec.Made); err != nil {
		return err
	}
	rec.Undone = e.now().UTC().Format(time.RFC3339Nano)
	return writeJournal(e.Source.Dir(), j)
}

// recordKeys journals the keys' files as made, before `admin migrate
// keys` writes them, when the target is migrate's: each one not there yet
// and not already its (an earlier run of the same migration may have
// written it: it stays recorded). A file there before is never migrate's,
// so never removed. It returns the items it added.
func (e *Engine) recordKeys(j *Journal) ([]string, error) {
	if j.Created == nil || e.Maker == nil || !slices.Contains(j.Created.Made, "config") {
		return nil, nil
	}
	kek, bek := e.Maker.KeyItems()
	var added []string
	for _, item := range []string{kek, bek} {
		if slices.Contains(j.Created.Made, item) {
			continue
		}
		there, err := e.Maker.Present(item)
		if err != nil {
			return nil, fmt.Errorf("preflight: the target's %s: %w", item, err)
		}
		if !there {
			added = append(added, item)
		}
	}
	if len(added) == 0 {
		return nil, nil
	}
	j.Created.Made = append(j.Created.Made, added...)
	return added, writeJournal(e.Source.Dir(), j)
}

// strikeKeys takes back, after `admin migrate keys`, the items recordKeys
// added whose file it did not write (found the same there after all).
func (e *Engine) strikeKeys(j *Journal, added []string, kekState, bekState string) {
	if len(added) == 0 {
		return
	}
	kek, _ := e.Maker.KeyItems()
	for _, item := range added {
		state := bekState
		if item == kek {
			state = kekState
		}
		if state != "written" {
			j.Created.Made = slices.DeleteFunc(j.Created.Made, func(s string) bool { return s == item })
		}
	}
}

// targetUnmade is whether the target migrate was making is not there (not
// made yet, or removed again: its configuration missing): nothing was
// imported into it, and it has no journal of its own.
func (e *Engine) targetUnmade(j *Journal) bool {
	return j.Created != nil && e.Maker != nil && e.Maker.Missing()
}
