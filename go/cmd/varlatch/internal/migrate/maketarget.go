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
	// name before the item is made.
	Make(ctx context.Context, src IngressInfo, kind Ingress, made func(item string) error) error
	// Undo removes the items made, in the reverse order (each again
	// harmlessly).
	Undo(made []string) error
	// KeyItems are the items the keys' files are, when migrate wrote them
	// into a target it made.
	KeyItems() (rootKEK, backupKey string)
}

// CreatedRecord is a target migrate made: its items, in the order made;
// Undone once they are removed again.
type CreatedRecord struct {
	Made   []string `json:"made"`
	Undone string   `json:"undone,omitempty"`
}

// makeTarget makes the target when it is missing, journalling each item
// first; a failure removes what was made. It returns the record (nil when
// nothing was to be made and none was made before).
func (e *Engine) makeTarget(ctx context.Context, prev *Journal, id string, src SourceInfo, ing IngressInfo) (*CreatedRecord, error) {
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
	pre := &Journal{Format: 1, ID: id, Phase: Started, Source: src, Ingress: e.Options.Ingress, Created: rec, History: []Step{}}
	if prev != nil && prev.ID == id {
		pre.History = prev.History
	}
	e.say("Making the target: the Go installation on this host, with setup's steps (its keys will be the source's).")
	err := e.Maker.Make(ctx, ing, e.Options.Ingress, func(item string) error {
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
		return rec, fmt.Errorf("making the target: %w; what was made is removed", err)
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
// keys` writes them, when the target is migrate's; after it, a key found
// the same there (unchanged) is not migrate's and is struck.
func (e *Engine) recordKeys(j *Journal, kekState, bekState string, before bool) error {
	if j.Created == nil || e.Maker == nil || !slices.Contains(j.Created.Made, "config") {
		return nil
	}
	kek, bek := e.Maker.KeyItems()
	if before {
		for _, item := range []string{kek, bek} {
			if !slices.Contains(j.Created.Made, item) {
				j.Created.Made = append(j.Created.Made, item)
			}
		}
		return writeJournal(e.Source.Dir(), j)
	}
	strike := func(item, state string) {
		if state != "written" {
			j.Created.Made = slices.DeleteFunc(j.Created.Made, func(s string) bool { return s == item })
		}
	}
	strike(kek, kekState)
	strike(bek, bekState)
	return nil
}

// targetUnmade is whether the target migrate was making is not there yet
// (its configuration missing): nothing was imported into it, and it has
// no journal of its own.
func (e *Engine) targetUnmade(j *Journal) bool {
	return j.Created != nil && j.Created.Undone == "" && e.Maker != nil && e.Maker.Missing()
}
