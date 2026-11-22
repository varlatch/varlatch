// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"fmt"
	"slices"
	"strings"
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
	// Where is the configuration's path, where the target is made.
	Where() string
}

// CreatedRecord is a target migrate made: its items, in the order made,
// and where (its configuration's path); Undone once they are removed again
// (Forgotten: the operator removed what was left by hand, and --abort
// --forget-target cleared the record).
type CreatedRecord struct {
	Made      []string `json:"made"`
	Config    string   `json:"config,omitempty"`
	Undone    string   `json:"undone,omitempty"`
	Forgotten bool     `json:"forgotten,omitempty"`
}

// CleanupPending is whether the journal records a target migrate made
// and has not removed: a released migration with one is not finished
// (--abort and --resume go on removing it), and no new one starts over
// it.
func (j *Journal) CleanupPending() bool {
	return j.Created != nil && j.Created.Undone == "" && len(j.Created.Made) > 0
}

// TargetMayChange is whether the target migrate made may still be made or
// removed: CleanupPending, and the migration not past its switch (from the
// switch on, the target is the installation, kept).
func (j *Journal) TargetMayChange() bool {
	return j.CleanupPending() && (slices.Contains(beforeBarrier, j.Phase) || slices.Contains(held, j.Phase) || j.Phase == Transfer || j.Phase == Released)
}

// madeAt is where the target in j was made, for the operator.
func madeAt(j *Journal) string {
	if j.Created != nil && j.Created.Config != "" {
		return j.Created.Config
	}
	return "/etc/varlatch/varlatchd.conf"
}

// removalHelp is the way out when removing the target migrate made keeps
// failing, for the messages that say it is not all removed.
func (e *Engine) removalHelp(j *Journal) string {
	if e.Maker == nil {
		return fmt.Sprintf("this run cannot remove it (it was made at %s): run varlatch migrate --abort --config %s, as root", madeAt(j), madeAt(j))
	}
	return fmt.Sprintf("if that keeps failing, remove what is left of %s by hand (varlatch migrate --status names each item's place), run varlatch migrate --abort again, and once nothing is left, varlatch migrate --abort --forget-target clears the record",
		strings.Join(j.Created.Made, ", "))
}

// ForgetTarget is `varlatch migrate --abort --forget-target`: an undone
// migration whose made target could not all be removed, its record cleared
// once the operator removed the rest by hand. It removes nothing, and
// refuses while the configuration migrate made is still there.
func (e *Engine) ForgetTarget(ctx context.Context) (*Journal, error) {
	unlock, err := lockDir(e.Source.Dir())
	if err != nil {
		return nil, err
	}
	defer unlock()
	j, err := readJournal(e.Source.Dir())
	if err != nil {
		return nil, err
	}
	switch {
	case j == nil:
		return nil, fmt.Errorf("%s holds no migration journal: there is nothing to forget", e.Source.Dir())
	case j.Phase != Released || !j.CleanupPending():
		return j, fmt.Errorf("the migration %s records no target left to remove after an undo: --forget-target clears only that record (varlatch migrate --status)", j.ID)
	case e.Maker == nil:
		return j, fmt.Errorf("--forget-target checks the target migrate made at %s: give --config %s", madeAt(j), madeAt(j))
	case !e.Maker.Missing():
		return j, fmt.Errorf("the configuration migrate made at %s is still there: remove what is left by hand (or varlatch migrate --abort), then --forget-target", madeAt(j))
	}
	e.say("Clearing the record of what migrate made of the target (%s): nothing is removed by this run.", strings.Join(j.Created.Made, ", "))
	j.Created.Undone = e.now().UTC().Format(time.RFC3339Nano)
	j.Created.Forgotten = true
	return j, writeJournal(e.Source.Dir(), j)
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
		rec = &CreatedRecord{Config: e.Maker.Where()}
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
			return rec, fmt.Errorf("making the target: %w; removing what was made: %v (varlatch migrate --abort tries again; %s)", err, uerr, e.removalHelp(pre))
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
		return fmt.Errorf("the target migrate made at %s cannot be removed by this run: run varlatch migrate --abort --config %s, as root", madeAt(j), madeAt(j))
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
