// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// `varlatch migrate --finish [--delete-old-data]` (go-step7 decision 17,
// slice 7.6a): the end of a migration's rollback window, by the operator,
// after the 30 days or before them.
//
// After a forward migration (open):
//
//  1. with --delete-old-data, a final archive of the TypeScript
//     installation first (format 2, its own `admin backup create`, uploaded
//     to the destination), downloaded again and verified; recorded in the
//     source's journal before anything else is done;
//  2. finished: both journals say so, and from then no reverse starts
//     (`--rollback` refuses; varlatch upgrade reads Go's journal:
//     RollbackWindowOpen);
//  3. the TypeScript installation's containers removed (`docker compose
//     down`, its volumes kept), and its old node's state and certificates
//     (its Tailscale and Caddy volumes);
//  4. with --delete-old-data, and only once the final archive is verified,
//     its Postgres and Convex volumes.
//
// After a reverse (rolled back): finished in the source's journal (Go's
// stays rolled back: it never starts there again); with --delete-old-data,
// a final archive of Go's copy first (format 3, varlatchd's own backup run,
// verified), then Go's copy discarded and the TypeScript installation's
// pre-migration volumes (unused since the rebuild) removed.
//
// Nothing of the old data is deleted without --delete-old-data, which no
// other option implies. An interruption after finished is finished by
// --resume (each removal is done again harmlessly); before it, --finish is
// run again.

// FinishRecord is --finish's.
type FinishRecord struct {
	// After is the phase finished from: open (a forward migration) or
	// rolled-back (a reverse).
	After         Phase  `json:"after"`
	DeleteOldData bool   `json:"deleteOldData"`
	StartedAt     string `json:"startedAt"`
	// The final archive: its id, format (2: the TypeScript release's; 3:
	// Go's) and when it was verified.
	ArchiveID     string   `json:"archiveId,omitempty"`
	ArchiveFormat int      `json:"archiveFormat,omitempty"`
	VerifiedAt    string   `json:"verifiedAt,omitempty"`
	Removed       []string `json:"removed,omitempty"`
	// Removing are the volumes whose removal began (journalled before
	// `docker volume rm`): one not there and named here was removed by a
	// run killed before it journalled it removed.
	Removing []string `json:"removing,omitempty"`
	// Volumes are the Postgres and the Convex volume the installation ran
	// on when --finish began (its containers' mounts, as the Compose files
	// give them), and Others the old node's, as its containers mount them:
	// the only volumes a forward migration's --finish removes.
	Volumes []VolumeRecord `json:"volumes,omitempty"`
	Others  []VolumeRecord `json:"others,omitempty"`
	// Operator is what is the operator's to remove (Coolify's shape).
	Operator string `json:"operator,omitempty"`
	DoneAt   string `json:"doneAt,omitempty"`
}

// Removals is what --finish removed and began to remove, from the
// source's journal, and how each step is journalled: Intend before a
// volume's removal, Removed after any removal.
type Removals struct {
	// Data: --delete-old-data.
	Data     bool
	Done     []string
	Removing []string
	Intend   func(volume string) error
	Removed  func(item string) error
}

// FinishSource is the TypeScript side's part of --finish.
type FinishSource interface {
	// MountedVolumes are what the installation's containers mount now: its
	// Postgres and Convex volumes (which its Compose files must name too,
	// and which are those recorded when the migration began; without
	// containers, those), and the old node's. Only what it gives is ever
	// removed.
	MountedVolumes(ctx context.Context, recorded []VolumeRecord) (data, others []VolumeRecord, err error)
	// CheckData is RemoveOld's (plan nil: data) or RemoveRetained's (plan's)
	// data volumes checked before anything is done: one that is not the
	// very volume recorded, or not there (and neither done nor begun), is
	// refused, so --delete-old-data stops before its final archive and
	// before the window closes.
	CheckData(ctx context.Context, kind Ingress, plan *RebuildRecord, data []VolumeRecord, r Removals) error
	// ServeForArchive starts what the TypeScript installation's backup
	// needs (its varlatchd, Postgres and Convex, behind its migrated-out
	// gate g, exactly: CheckGate): the services it started (none when all
	// ran already).
	ServeForArchive(ctx context.Context, g GateRef) ([]string, error)
	// StopStarted stops the services ServeForArchive started.
	StopStarted(ctx context.Context, services []string) error
	// RemoveOld removes the TypeScript installation's containers and its
	// old node's state and certificates (others), and its Postgres and
	// Convex volumes (data, nil to keep them), journalling each through r;
	// what r.Done names was removed by an earlier run, and a volume in
	// r.Removing that is not there was too (killed before it was journalled
	// removed). Only the very volumes recorded: a data volume that is
	// another, or not there (neither done nor begun), is an error.
	RemoveOld(ctx context.Context, kind Ingress, data, others []VolumeRecord, r Removals) error
	// RemoveRetained removes the pre-migration volumes a reverse left
	// unused, by the identities plan records: only while the installation
	// runs on plan's fresh ones. It journals as RemoveOld does.
	RemoveRetained(ctx context.Context, plan RebuildRecord, r Removals) error
}

// FinishTarget is the Go side's part.
type FinishTarget interface {
	// FinalArchive is varlatchd's backup run, verified: its archive id.
	FinalArchive(ctx context.Context) (string, error)
}

// RollbackWindowOpen is whether the Go installation whose data directory
// is dir is in a migration's rollback window at now: its journal open,
// switched no more than RollbackWindow ago, and its window not ended by an
// upgrade (WindowEnded); or a reverse begun. An installation never
// migrated, or whose window --finish ended (finished), is not. varlatch
// upgrade asks before a release that ends the window only while it is
// open.
func RollbackWindowOpen(dir string, now time.Time) (bool, error) {
	j, err := readJournal(dir)
	if err != nil || j == nil {
		return false, err
	}
	if slices.Contains(reverseHeld, j.Phase) || j.Phase == RollbackTransfer {
		return true, nil
	}
	if j.Phase != Open || j.WindowEnded != nil {
		return false, nil
	}
	at, ok := switchedAt(j)
	return ok && now.Sub(at) <= RollbackWindow, nil
}

// ReverseUnderWay is whether dir's journal (Go's) says a reverse migration
// is under way: its phase, or "" when none is.
func ReverseUnderWay(dir string) (Phase, error) {
	j, err := readJournal(dir)
	if err != nil || j == nil {
		return "", err
	}
	if slices.Contains(reverseHeld, j.Phase) || j.Phase == RollbackTransfer {
		return j.Phase, nil
	}
	return "", nil
}

// EndRollbackWindow records in Go's journal (dataDir's, written through
// h, beside its running varlatchd) that upgrading to release ends the
// migration's rollback window, before the upgrade runs: from then
// --rollback refuses. Done already, or with no window open, it writes
// nothing.
func EndRollbackWindow(ctx context.Context, h *Host, dataDir, release string, now time.Time) error {
	j, err := readJournal(dataDir)
	if err != nil {
		return fmt.Errorf("the migration journal in %s: %w", dataDir, err)
	}
	if j == nil || j.Phase != Open || j.WindowEnded != nil {
		return nil
	}
	j.WindowEnded = &WindowEndedRecord{Release: release, At: now.UTC().Format(time.RFC3339Nano)}
	return h.WriteJournal(ctx, j)
}

// Finish is `varlatch migrate --finish`.
func (e *Engine) Finish(ctx context.Context, deleteOldData bool) (*Journal, error) {
	unlock, err := lockDir(e.Source.Dir())
	if err != nil {
		return nil, err
	}
	defer unlock()
	j, err := readJournal(e.Source.Dir())
	if err != nil {
		return nil, err
	}
	if err := e.keepProject(ctx, j, false); err != nil {
		return j, err
	}
	switch {
	case j == nil:
		return nil, fmt.Errorf("%s holds no migration journal: there is nothing to finish", e.Source.Dir())
	case j.Phase == Finished && j.Finish != nil:
		// Go's journal agrees first (an interrupted finish written into
		// the source's only is written into Go's now): never another
		// installation archived or removed.
		if err := e.finishAgrees(ctx, j); err != nil {
			return j, err
		}
		if deleteOldData && !j.Finish.DeleteOldData {
			// The window ended earlier; the old data goes now.
			if err := e.recordVolumes(ctx, j, true); err != nil {
				return j, err
			}
			if err := e.checkData(ctx, j); err != nil {
				return j, err
			}
			j.Finish.DeleteOldData, j.Finish.DoneAt = true, ""
			if err := e.archiveOnce(ctx, j); err != nil {
				return j, err
			}
		}
		if j.Finish.DoneAt == "" {
			return j, e.finishRemove(ctx, j)
		}
		// Finished: the handoff's certificate attempts in Go's count, if
		// no run could write them yet (recordNow; each attempt once).
		if j.Finish.After == Open {
			e.recordNow(ctx, j)
		}
		return j, nil
	case j.Phase == Open || j.Phase == RolledBack:
		if err := e.finishAgrees(ctx, j); err != nil {
			return j, err
		}
	default:
		return j, fmt.Errorf("the migration %s is in phase %s: --finish ends an open migration's rollback window, or a rolled back one's record (varlatch migrate --resume first)", j.ID, j.Phase)
	}
	// A run killed after its final archive was verified and journalled
	// (finish archived) keeps that archive, whatever this run's flags: a
	// later --delete-old-data uses it, never makes another.
	if prev := j.Finish; prev != nil && prev.After == j.Phase && prev.DoneAt == "" && prev.VerifiedAt != "" && prev.ArchiveID != "" {
		prev.DeleteOldData = deleteOldData
	} else {
		next := &FinishRecord{After: j.Phase, DeleteOldData: deleteOldData, StartedAt: e.now().UTC().Format(time.RFC3339Nano)}
		if prev != nil && prev.After == j.Phase {
			next.Volumes, next.Others = prev.Volumes, prev.Others
		}
		j.Finish = next
	}
	if err := e.recordVolumes(ctx, j, deleteOldData); err != nil {
		return j, err
	}
	if deleteOldData {
		if err := e.checkData(ctx, j); err != nil {
			return j, err
		}
		if err := e.archiveOnce(ctx, j); err != nil {
			return j, err
		}
	}
	if j.Finish.After == Open {
		// Both journals: the source's, then Go's beside it, and the window
		// is closed. Killed between the two, the next --finish or --resume
		// writes Go's (finishAgrees).
		j.enter(Finished, e.now())
		if err := writeJournal(e.Source.Dir(), j); err != nil {
			return j, err
		}
		crashPoint("finished source written")
		if err := e.Target.WriteJournal(ctx, j); err != nil {
			return j, fmt.Errorf("the journal in the target's data directory: %w; varlatch migrate --resume writes it", err)
		}
		crashPoint("entered finished")
	} else {
		// Go's stays rolled back: it never starts on its copy again.
		j.enter(Finished, e.now())
		if err := writeJournal(e.Source.Dir(), j); err != nil {
			return j, err
		}
		crashPoint("entered finished")
	}
	e.say("Finished: the migration's rollback window is closed.")
	return j, e.finishRemove(ctx, j)
}

// finishAgrees is Go's journal checked against the source's before
// --finish does anything: the same migration, open (a forward migration
// being finished), rolled back (a reverse's record being finished), or
// finished. A forward migration finished in the source's journal whose
// Go journal still says open (a run killed between the two writes) has
// Go's written now, beside its varlatchd, so the rollback window is not
// reported open (RollbackWindowOpen) once --finish closed it.
func (e *Engine) finishAgrees(ctx context.Context, j *Journal) error {
	_, st, err := e.Target.Describe(ctx)
	if err != nil {
		return err
	}
	after := j.Phase
	if j.Phase == Finished {
		after = j.Finish.After
	}
	want := []Phase{after}
	if j.Phase == Finished && after == Open {
		want = []Phase{Open, Finished}
	}
	if st.Journal == nil || st.Journal.ID != j.ID || !slices.Contains(want, st.Journal.Phase) {
		var says any = "nothing"
		if st.Journal != nil {
			says = fmt.Sprintf("the migration %s in phase %s", st.Journal.ID, st.Journal.Phase)
		}
		return fmt.Errorf("the target's journal (--config) says %v, not the migration %s %s: nothing was done", says, j.ID, after)
	}
	if after == Open && j.Rollback != nil && j.Rollback.Unrestored != "" {
		return fmt.Errorf("the last reverse of the migration %s was undone, but the TypeScript installation is not put back (%s): varlatch migrate --resume first; nothing was done", j.ID, j.Rollback.Unrestored)
	}
	if after == Open && st.Barrier != "" {
		return fmt.Errorf("a reverse's barrier stands on the Go installation (%s): varlatch migrate --resume first", st.Barrier)
	}
	if after == Open && st.Barrier == "" && j.Rollback != nil && j.Rollback.Undone != nil && !j.Rollback.Undone.Released {
		// An undone reverse killed between its barrier's release and the
		// record of it (as --resume's finishOpen back-fills it).
		j.Rollback.Undone.Released = true
		if err := writeJournal(e.Source.Dir(), j); err != nil {
			return err
		}
	}
	if j.Phase == Finished && st.Journal.Phase == Open {
		e.say("The migration %s is finished, but Go's journal says open: it is written finished.", j.ID)
		if err := e.Target.WriteJournal(ctx, j); err != nil {
			return fmt.Errorf("the journal in the target's data directory: %w; varlatch migrate --resume writes it", err)
		}
	}
	return nil
}

// archiveOnce is the final archive, unless the journal records one
// verified already for this finish (made by a killed run): that one is
// used, never another made.
func (e *Engine) archiveOnce(ctx context.Context, j *Journal) error {
	if f := j.Finish; f.ArchiveID != "" && f.VerifiedAt != "" {
		e.say("The final archive %s, verified %s, is this run's.", f.ArchiveID, f.VerifiedAt)
		return nil
	}
	return e.finalArchive(ctx, j)
}

// recordVolumes records, once, what the installation's containers mount,
// before anything of --finish is done (its first step takes them down).
// One that cannot be told is no obstacle to a --finish that keeps the data;
// --delete-old-data then refuses.
func (e *Engine) recordVolumes(ctx context.Context, j *Journal, data bool) error {
	if j.Finish.After != Open || j.Ingress == Coolify || len(j.Finish.Volumes) > 0 {
		return nil
	}
	fs, ok := e.Source.(FinishSource)
	if !ok {
		return errors.New("this source has nothing --finish removes")
	}
	vols, others, err := fs.MountedVolumes(ctx, j.Source.Volumes)
	if err != nil {
		if data {
			return fmt.Errorf("%w; nothing was done", err)
		}
		e.say("The data volumes could not be told (%v): they are kept, and --finish --delete-old-data will refuse them.", err)
		return nil
	}
	j.Finish.Volumes, j.Finish.Others = vols, others
	return writeJournal(e.Source.Dir(), j)
}

// checkData is CheckData for j's --delete-old-data.
func (e *Engine) checkData(ctx context.Context, j *Journal) error {
	fs, ok := e.Source.(FinishSource)
	if !ok {
		return errors.New("this source has nothing --finish removes")
	}
	var plan *RebuildRecord
	if j.Finish.After != Open {
		if j.Rollback == nil || j.Rollback.Rebuild == nil {
			return errors.New("the journal records no rebuild: the pre-migration volumes are not known; nothing was done")
		}
		plan = j.Rollback.Rebuild
	}
	if err := fs.CheckData(ctx, j.Ingress, plan, j.Finish.Volumes, Removals{Done: j.Finish.Removed, Removing: j.Finish.Removing}); err != nil {
		return fmt.Errorf("%w; nothing was done", err)
	}
	return nil
}

// finalArchive makes the final archive of the old data and verifies it,
// recorded in the source's journal (only there: the phase does not
// change) before anything is removed.
func (e *Engine) finalArchive(ctx context.Context, j *Journal) error {
	if j.Finish.After == Open {
		// Its backup needs its varlatchd and Postgres, which an earlier
		// --finish took down: up again, behind its migrated-out gate (it
		// serves nothing), then down again with the rest.
		var started []string
		fs, _ := e.Source.(FinishSource)
		// On a failure, what this run started for the archive goes down
		// again (only that: what ran before it is left running).
		failed := func(err error) error {
			if len(started) == 0 {
				return fmt.Errorf("%w; nothing was removed", err)
			}
			if serr := fs.StopStarted(ctx, started); serr != nil {
				return fmt.Errorf("%w; nothing was removed, but %s, started for the archive, could not be stopped again (%v): docker compose stop %s", err, strings.Join(started, ", "), serr, strings.Join(started, " "))
			}
			return fmt.Errorf("%w; nothing was removed, and %s, started for the archive, are stopped again", err, strings.Join(started, ", "))
		}
		if fs != nil {
			var err error
			// A start that failed part way says what it did start.
			if started, err = fs.ServeForArchive(ctx, sourceGate(j)); err != nil {
				return failed(fmt.Errorf("starting the TypeScript installation for its final archive: %w", err))
			}
		}
		// What the archive reads is what is removed after it: the containers
		// it reads from (some started just now) are on the recorded volumes.
		if err := e.checkData(ctx, j); err != nil {
			return failed(err)
		}
		e.say("Final archive: the TypeScript installation, made, uploaded, then downloaded and verified (format 2).")
		id, err := stepOf(e, "making and uploading the final archive", func() (string, error) { return e.Source.Backup(ctx) })
		if err != nil {
			return failed(fmt.Errorf("the final archive: %w", err))
		}
		if err := e.step("downloading and verifying the final archive", func() error { return e.Source.VerifyBackup(ctx, id) }); err != nil {
			return failed(fmt.Errorf("the final archive %s did not verify: %w", id, err))
		}
		j.Finish.ArchiveID, j.Finish.ArchiveFormat = id, 2
	} else {
		ft, ok := e.Target.(FinishTarget)
		if !ok {
			return errors.New("this target makes no final archive")
		}
		// The reverse's barrier still stands on Go's copy, which never
		// starts again: lifted, so its backup run may take the copy. Its
		// frozen copy goes with it, on purpose, before the archive: it is
		// what the reverse was exported from, and Go's own database, which
		// took nothing since, stays until the archive is verified and the
		// retained volumes are removed.
		if rt, ok := e.Target.(ReverseTarget); ok {
			if err := rt.ReleaseBarrier(ctx, j.ID); err != nil {
				return fmt.Errorf("lifting the reverse's barrier on Go's copy: %w; nothing was removed", err)
			}
		}
		e.say("Final archive: Go's copy, made by varlatchd, uploaded, then downloaded and verified (format 3).")
		id, err := stepOf(e, "making, uploading, downloading and verifying the final archive of Go's copy", func() (string, error) { return ft.FinalArchive(ctx) })
		if err != nil {
			return fmt.Errorf("the final archive of Go's copy: %w; nothing was removed", err)
		}
		j.Finish.ArchiveID, j.Finish.ArchiveFormat = id, 3
	}
	j.Finish.VerifiedAt = e.now().UTC().Format(time.RFC3339Nano)
	if err := writeJournal(e.Source.Dir(), j); err != nil {
		return err
	}
	crashPoint("finish archived")
	return nil
}

// finishRemove removes what --finish removes, each step done again
// harmlessly, then records it done.
func (e *Engine) finishRemove(ctx context.Context, j *Journal) error {
	fs, ok := e.Source.(FinishSource)
	if !ok {
		return errors.New("this source has nothing --finish removes")
	}
	f := j.Finish
	data := f.DeleteOldData
	if data && (f.ArchiveID == "" || f.VerifiedAt == "") {
		// Never without its verified archive.
		return errors.New("--delete-old-data, but the journal records no verified final archive: nothing of the old data was removed")
	}
	// Each removal journalled once it is done, so a resume does not
	// expect again what is gone.
	// A volume's removal is journalled begun before `docker volume rm`, so
	// one killed before it was journalled removed is known, not refused.
	removed := func(item string) error {
		if !slices.Contains(f.Removed, item) {
			f.Removed = append(f.Removed, item)
		}
		return writeJournal(e.Source.Dir(), j)
	}
	log := func() Removals {
		return Removals{Data: data, Done: f.Removed, Removing: f.Removing, Removed: removed, Intend: func(v string) error {
			if !slices.Contains(f.Removing, v) {
				f.Removing = append(f.Removing, v)
			}
			return writeJournal(e.Source.Dir(), j)
		}}
	}
	if f.After == Open {
		// The handoff's certificate attempts in Go's count, in case the
		// transfer could not write them (each attempt once).
		e.recordNow(ctx, j)
		var vols []VolumeRecord
		if data {
			if vols = f.Volumes; len(vols) == 0 && j.Ingress != Coolify {
				return errors.New("--delete-old-data, but the journal records no data volumes: nothing was removed")
			}
		}
		err := fs.RemoveOld(ctx, j.Ingress, vols, f.Others, log())
		var human *HumanStep
		if errors.As(err, &human) {
			f.Operator = human.Instruction
			e.say("By hand: %s", human.Instruction)
		} else if err != nil {
			return fmt.Errorf("removing the TypeScript installation: %w; varlatch migrate --resume finishes it", err)
		}
	} else if data {
		e.say("The TypeScript installation's pre-migration volumes are removed, then Go's copy discarded.")
		if j.Rollback == nil || j.Rollback.Rebuild == nil {
			return errors.New("the journal records no rebuild: the pre-migration volumes are not known; left as they are")
		}
		// The installation verified to run on its fresh volumes, and the
		// retained ones removed, before Go's copy goes: while either fails,
		// Go's copy is there.
		if err := fs.RemoveRetained(ctx, *j.Rollback.Rebuild, log()); err != nil {
			return fmt.Errorf("removing the pre-migration volumes: %w; Go's copy is kept; varlatch migrate --resume finishes it", err)
		}
		crashPoint("finish retained removed")
		goCopy := "Go's copy (" + j.Target.DataDir + ")"
		if !slices.Contains(f.Removed, goCopy) {
			if err := e.Target.Discard(ctx, j.ID); err != nil {
				return fmt.Errorf("discarding Go's copy: %w; varlatch migrate --resume finishes it", err)
			}
			if err := removed(goCopy); err != nil {
				return err
			}
		}
		crashPoint("finish go discarded")
	}
	f.DoneAt = e.now().UTC().Format(time.RFC3339Nano)
	if err := writeJournal(e.Source.Dir(), j); err != nil {
		return err
	}
	e.say("%s", finishNotice(j))
	return nil
}

// finishNotice is what can no longer be undone, said once --finish is done.
func finishNotice(j *Journal) string {
	f := j.Finish
	var b strings.Builder
	if f.After == Open && f.Operator != "" {
		b.WriteString("This can no longer be undone: varlatch migrate --rollback cannot return this installation to the TypeScript release. What remains of the TypeScript installation is yours to remove, as said above")
		if f.DeleteOldData {
			fmt.Fprintf(&b, "; its final archive %s (format 2) is verified first, and restores it through the TypeScript release's restore", f.ArchiveID)
		}
		b.WriteString(".")
		return b.String()
	}
	if f.After == Open {
		b.WriteString("This can no longer be undone: varlatch migrate --rollback cannot return this installation to the TypeScript release, and the TypeScript installation's containers")
		if f.DeleteOldData {
			fmt.Fprintf(&b, " and its data (its Postgres and Convex volumes) are removed. The final archive %s (format 2) restores it through the TypeScript release's restore.", f.ArchiveID)
		} else {
			b.WriteString(" are removed; its data volumes are kept until varlatch migrate --finish --delete-old-data.")
		}
		return b.String()
	}
	if f.DeleteOldData {
		fmt.Fprintf(&b, "This can no longer be undone: Go's copy and the TypeScript installation's pre-migration volumes are removed. The final archive %s (format 3) restores Go's copy through a Go varlatchd only (setup --restore). "+
			"It is in %s (and uploaded where the Go configuration's backup destination says); a new migration into that data directory leaves it there.",
			f.ArchiveID, filepath.Join(j.Target.DataDir, "backups"))
	} else {
		b.WriteString("Go's copy and the TypeScript installation's pre-migration volumes are kept until varlatch migrate --finish --delete-old-data.")
	}
	return b.String()
}

// FinalArchive is `varlatchd admin backup run --json --verify-remote`:
// its archive, which varlatchd verified (integrity, compatibility, the
// key), then uploaded to the configuration's backup destination,
// downloaded again and verified as downloaded. Go's copy is discarded
// after it, so the remote copy is the one that restores: without a
// destination configured, refused.
func (h *Host) FinalArchive(ctx context.Context) (string, error) {
	args := []string{"admin", "backup", "run", "--json", "--verify-remote"}
	if h.Config != "" {
		args = append(args, "--config", h.Config)
	}
	r, err := h.Run.Run(ctx, "", h.Varlatchd, args, nil)
	if err != nil {
		return "", err
	}
	if r.Code != 0 {
		if bytes.Contains(r.Said, []byte("No backup destination is configured")) {
			return "", fmt.Errorf("Go's configuration (%s) names no backup destination, and Go's copy is discarded after its final archive, whose uploaded copy is then the only one: "+
				"set backup_destinations_file and backup_destination there (varlatchd admin backup test-bucket checks them), then run varlatch migrate --finish --delete-old-data again", h.configName())
		}
		return "", failure("varlatchd admin backup run", r)
	}
	type verification struct {
		Integrity     bool `json:"integrity"`
		Compatibility bool `json:"compatibility"`
		KeyMatch      bool `json:"keyMatch"`
	}
	passed := func(v *verification) bool { return v != nil && v.Integrity && v.Compatibility && v.KeyMatch }
	var res struct {
		ArchiveID    string        `json:"archiveId"`
		Verification *verification `json:"verification"`
		Delivery     *struct {
			RemoteVerification *verification `json:"remoteVerification"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(lastLine(bytes.TrimSpace(r.Answer)), &res); err != nil || res.ArchiveID == "" {
		return "", errors.New("varlatchd admin backup run did not answer with its archive")
	}
	if !passed(res.Verification) {
		return "", fmt.Errorf("the archive %s did not verify", res.ArchiveID)
	}
	if res.Delivery == nil || !passed(res.Delivery.RemoteVerification) {
		return "", fmt.Errorf("the archive %s's uploaded copy was not downloaded and verified", res.ArchiveID)
	}
	return res.ArchiveID, nil
}

// MountedVolumes: the inventory's, the Postgres and Convex ones as the
// Compose files give them too.
func (c *Compose) MountedVolumes(ctx context.Context, recorded []VolumeRecord) (data, others []VolumeRecord, err error) {
	p, all, err := c.verified(ctx)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := c.config(ctx)
	if err != nil {
		return nil, nil, err
	}
	keys, err := cfg.volumeKeys()
	if err != nil {
		return nil, nil, err
	}
	for i, d := range dataMounts {
		name := cfg.volumeName(keys[i])
		v, err := c.installed(ctx, p, all, d.service, d.target, name, i, recorded)
		switch {
		case err != nil:
			return nil, nil, err
		case v.CreatedAt == "":
			return nil, nil, fmt.Errorf("the volume %s is not there (docker volume inspect)", name)
		case v.Project != p.Name:
			return nil, nil, fmt.Errorf("the volume %s is labelled of the Compose project %s, not of the installation's, %s: migrate does not remove it (remove it yourself if it is the installation's, and finish without --delete-old-data)", v.Name, orWord(v.Project, "none"), p.Name)
		}
		data = append(data, v)
	}
	// The old node's and Caddy's, and varlatch-state, by their keys: each
	// mounted by a container of the project, and of it.
	for _, key := range []string{"tailscale-state", "tailscale-socket", "caddy-data", "caddy-config", stateKey} {
		name := p.Name + "_" + key
		if !slices.ContainsFunc(all, func(l composeContainer) bool {
			return l.project == p.Name && slices.ContainsFunc(l.mounts, func(m containerMount) bool { return m.Type == "volume" && m.Name == name })
		}) {
			continue
		}
		v, err := c.volume(ctx, name)
		if err != nil {
			return nil, nil, err
		}
		if v != nil && v.Project == p.Name {
			others = append(others, *v)
		}
	}
	return data, others, nil
}

// checkVolume refuses a volume that is not the recorded one, or not the
// project's, or, with unused, that a container mounts.
func (c *Compose) checkVolume(ctx context.Context, p *ComposeProject, want VolumeRecord, unused bool) (there bool, err error) {
	v, err := c.volume(ctx, want.Name)
	if err != nil || v == nil {
		return false, err
	}
	if why := v.differs(want); why != "" {
		return true, fmt.Errorf("the volume %s is not the one the journal records (%s): left as it is", want.Name, why)
	}
	if v.Project != p.Name {
		return true, fmt.Errorf("the volume %s is labelled of the Compose project %s, not of the installation's, %s: left as it is (remove it yourself if it is the installation's, and finish without --delete-old-data)", v.Name, orWord(v.Project, "none"), p.Name)
	}
	if unused {
		users, err := c.volumeUsers(ctx, v.Name)
		if err != nil {
			return true, err
		}
		if len(users) > 0 {
			return true, fmt.Errorf("the volume %s is used by %s: left as it is", v.Name, strings.Join(users, ", "))
		}
	}
	return true, nil
}

// checkAll checks the recorded volumes but those done: each the one
// recorded; one not there whose removal began is gone (removed by a killed
// run); any other one not there is an error.
func (c *Compose) checkAll(ctx context.Context, p *ComposeProject, vols []VolumeRecord, unused bool, log Removals) (there, gone []VolumeRecord, err error) {
	var missing []string
	for _, v := range vols {
		if slices.Contains(log.Done, v.Name) {
			continue
		}
		ok, err := c.checkVolume(ctx, p, v, unused)
		switch {
		case err != nil:
			return nil, nil, err
		case ok:
			there = append(there, v)
		case slices.Contains(log.Removing, v.Name):
			gone = append(gone, v)
		default:
			missing = append(missing, v.Name)
		}
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("the volumes %s are not there (docker volume inspect), and no run of --finish began to remove them: removed by hand, or another installation's; none of its data volumes was removed", strings.Join(missing, ", "))
	}
	return there, gone, nil
}

// removeVolumes removes the recorded volumes, all checked first, and each
// again once its removal is journalled begun, right before it: never by
// the name alone. Each is journalled removed after it. (Docker removes by
// name: a volume made again under it in the moment between the check and
// the removal, and used by nothing, would be the one removed. One a
// container mounts by then is refused by Docker itself.)
func (c *Compose) removeVolumes(ctx context.Context, vols []VolumeRecord, log Removals) error {
	p, _, err := c.verified(ctx)
	if err != nil {
		return err
	}
	there, gone, err := c.checkAll(ctx, p, vols, true, log)
	if err != nil {
		return err
	}
	for _, v := range gone {
		if err := log.Removed(v.Name); err != nil {
			return err
		}
	}
	for _, v := range there {
		if err := log.Intend(v.Name); err != nil {
			return err
		}
		if ok, err := c.checkVolume(ctx, p, v, true); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("the volume %s is not there any more, and this run did not remove it: nothing more was removed", v.Name)
		}
		r, err := c.docker(ctx, []string{"volume", "rm", v.Name}, nil)
		if err != nil {
			return err
		}
		if r.Code != 0 {
			return failure("docker volume rm "+v.Name, r)
		}
		crashPoint("finish volume removed")
		if err := log.Removed(v.Name); err != nil {
			return err
		}
	}
	return nil
}

// CheckData: what RemoveOld or RemoveRetained would remove. After a
// reverse, in every shape, the installation is held to run on its fresh
// volumes, and the retained ones to be the journal's, unused. After a
// forward migration, the Compose files, and the containers there are, name
// the volumes the journal records (Coolify's are the operator's: nothing is
// checked).
func (c *Compose) CheckData(ctx context.Context, kind Ingress, plan *RebuildRecord, data []VolumeRecord, log Removals) error {
	if plan != nil {
		if err := c.CheckRebuilt(ctx, *plan, true); err != nil {
			return err
		}
		retained, err := c.retainedVolumes(*plan)
		if err != nil {
			return err
		}
		p, err := c.project(ctx)
		if err != nil {
			return err
		}
		_, _, err = c.checkAll(ctx, p, retained, true, log)
		return err
	}
	if kind == Coolify {
		return nil
	}
	if len(data) != len(dataMounts) {
		return errors.New("the journal does not record which volumes the installation ran on: --delete-old-data removes none by a name made up")
	}
	p, all, err := c.verified(ctx)
	if err != nil {
		return err
	}
	cfg, err := c.config(ctx)
	if err != nil {
		return err
	}
	keys, err := cfg.volumeKeys()
	if err != nil {
		return err
	}
	for i, d := range dataMounts {
		if name := cfg.volumeName(keys[i]); name != data[i].Name {
			return fmt.Errorf("the Compose files give %s the volume %s, and the installation ran on %s: the final archive would not be of what is removed", d.service, name, data[i].Name)
		}
		if _, err := mountedAs(p, all, d.service, d.target, data[i].Name); err != nil {
			return err
		}
	}
	_, _, err = c.checkAll(ctx, p, data, false, log)
	return err
}

// retainedVolumes are the plan's, when it records them.
func (c *Compose) retainedVolumes(plan RebuildRecord) ([]VolumeRecord, error) {
	if len(plan.Retained) != len(dataMounts) {
		return nil, errors.New("the journal does not record which volumes the installation ran on before the reverse (an earlier version's reverse): none is removed by a name made up; " +
			"remove them yourself once you know them (docker volume ls), and finish without --delete-old-data")
	}
	for _, v := range plan.Retained {
		if slices.Contains(plan.Volumes, v.Name) {
			return nil, fmt.Errorf("the journal names %s as a retained volume and as a fresh one: nothing is removed", v.Name)
		}
	}
	return plan.Retained, nil
}

// sameTime is whether two of Docker's creation times are the same one (it
// prints them in the host's time zone, which changes with the season).
func sameTime(a, b string) bool {
	x, xerr := time.Parse(time.RFC3339, a)
	y, yerr := time.Parse(time.RFC3339, b)
	return xerr == nil && yerr == nil && x.Equal(y)
}

// volumeUsers are the containers, running or not, that mount the volume.
func (c *Compose) volumeUsers(ctx context.Context, name string) ([]string, error) {
	r, err := c.docker(ctx, []string{"ps", "-a", "--filter", "volume=" + name, "--format", "{{.Names}}"}, nil)
	if err != nil {
		return nil, err
	}
	if r.Code != 0 {
		return nil, failure("docker ps --filter volume="+name, r)
	}
	return strings.Fields(string(r.Answer)), nil
}

// ServeForArchive starts the TypeScript installation's Postgres, varlatchd
// and Convex (what its backup reads), without their dependencies: never
// its Caddy or Tailscale, whose address is Go's now. Its varlatchd serves
// nothing behind its migrated-out gate, which is held to be there before
// anything starts. Running already, nothing is done.
// Where varlatchd shares the old Tailscale node's network (network_mode:
// service:...), it does not start without that node: refused, its data
// kept.
func (c *Compose) ServeForArchive(ctx context.Context, g GateRef) ([]string, error) {
	need := []string{"postgres", service, "convex-backend"}
	running, err := c.running(ctx)
	if err != nil {
		return nil, err
	}
	start := slices.DeleteFunc(slices.Clone(need), func(s string) bool { return slices.Contains(running, s) })
	cfg, err := c.config(ctx)
	if err != nil {
		return nil, err
	}
	// Its varlatchd runs on for some seconds in a stopped owner's network,
	// where it reaches nothing (B3): what counts is the owner.
	if owner, ok := strings.CutPrefix(cfg.Services[service].NetworkMode, "service:"); ok && (len(start) > 0 || !slices.Contains(running, owner)) {
		names, err := c.dataNames(cfg)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("--delete-old-data is refused here: the TypeScript installation's varlatchd runs in %s's network (network_mode: service:%s), so starting it for the final archive "+
			"would bring the old Tailscale node back beside Go's. Its data volumes are kept. By hand: 1. make a backup of them by your own means and test that it restores; "+
			"2. remove them: docker volume rm %s (on Coolify instead: delete the TypeScript application, its volumes included)", owner, owner, strings.Join(names, " "))
	}
	if len(start) == 0 {
		return nil, nil
	}
	up := slices.DeleteFunc(slices.Clone(start), func(s string) bool { return s == service })
	if len(up) < len(start) {
		if err := c.CheckGate(ctx, g); err != nil {
			return nil, err
		}
	}
	if len(up) > 0 {
		err = c.compose(ctx, "docker compose up -d --no-deps "+strings.Join(up, " "), append([]string{"up", "-d", "--no-deps", "--no-recreate"}, up...)...)
	}
	if err == nil && len(up) < len(start) {
		err = c.startGated(ctx, g, false, "--no-recreate")
	}
	if err != nil {
		// An up that failed part way may have started some: those it did,
		// running now and not before, are this run's to stop again.
		now, perr := c.running(ctx)
		if perr != nil {
			return start, fmt.Errorf("%w; which of %s it started is not known (docker compose ps: %v)", err, strings.Join(start, ", "), perr)
		}
		return slices.DeleteFunc(slices.Clone(start), func(s string) bool { return !slices.Contains(now, s) }), err
	}
	return start, nil
}

// dataNames are the Postgres and Convex volumes' names in the Compose files.
func (c *Compose) dataNames(cfg composeConfig) ([]string, error) {
	keys, err := cfg.volumeKeys()
	if err != nil {
		return nil, err
	}
	return []string{cfg.volumeName(keys[0]), cfg.volumeName(keys[1])}, nil
}

// running are the Compose services running now.
func (c *Compose) running(ctx context.Context) ([]string, error) {
	r, err := c.docker(ctx, []string{"compose", "ps", "--status", "running", "--services"}, nil)
	if err != nil {
		return nil, err
	}
	if r.Code != 0 {
		return nil, failure("docker compose ps", r)
	}
	return strings.Fields(string(r.Answer)), nil
}

// StopStarted: `docker compose stop` of the services named.
func (c *Compose) StopStarted(ctx context.Context, services []string) error {
	return c.compose(ctx, "docker compose stop "+strings.Join(services, " "), append([]string{"stop"}, services...)...)
}

// RemoveOld: `docker compose down` (the containers and networks, never a
// volume), then the old node's state and certificates (Tailscale's and
// Caddy's volumes, those the installation has), and, with data, the
// Postgres and Convex volumes it ran on (and its varlatch-state). In
// Coolify's shape all of it is the operator's, said as steps.
func (c *Compose) RemoveOld(ctx context.Context, kind Ingress, data, others []VolumeRecord, log Removals) error {
	if kind == Coolify {
		steps := "In Coolify, the TypeScript application (not Go's) is yours to remove: 1. Keep it as it is (it serves nothing: its domain is Go's) until varlatch migrate --finish --delete-old-data, " +
			"whose final archive needs its Postgres, varlatchd and Convex. 2. Then delete it, its volumes included."
		if data != nil || log.Data {
			steps = "In Coolify, open the TypeScript application (not Go's): 1. Stop it. 2. Delete it, and when Coolify asks, delete its volumes too, its Postgres and Convex data included (its final archive is verified)."
		}
		return &HumanStep{Instruction: steps + " varlatch migrate does not reach Coolify's resources."}
	}
	// Down every time: a later --delete-old-data started what its final
	// archive read.
	if err := c.compose(ctx, "docker compose down", "down"); err != nil {
		return err
	}
	if err := log.Removed("the TypeScript installation's containers"); err != nil {
		return err
	}
	crashPoint("finish containers removed")
	// The old node's state and certificates: those recorded and still the
	// same, unused (one that is not there, or another now, is left).
	// varlatch-state goes with the data only.
	p, err := c.project(ctx)
	if err != nil {
		return err
	}
	vols := slices.Clone(data)
	for _, v := range others {
		if data == nil && v.Name == p.Name+"_"+stateKey || slices.Contains(log.Done, v.Name) {
			continue
		}
		if ok, err := c.checkVolume(ctx, p, v, true); ok && err == nil || slices.Contains(log.Removing, v.Name) {
			vols = append(vols, v)
		}
	}
	return c.removeVolumes(ctx, vols, log)
}

// RemoveRetained removes the volumes the installation ran on before the
// reverse, by the identities the journal recorded then: only while the
// installation runs on plan's fresh ones (CheckRebuilt), and each verified
// again right before its removal.
func (c *Compose) RemoveRetained(ctx context.Context, plan RebuildRecord, log Removals) error {
	if err := c.CheckRebuilt(ctx, plan, true); err != nil {
		return fmt.Errorf("the pre-migration volumes are left as they are: %w", err)
	}
	retained, err := c.retainedVolumes(plan)
	if err != nil {
		return err
	}
	return c.removeVolumes(ctx, retained, log)
}

// configName is the Go configuration's path, as the operator edits it.
func (h *Host) configName() string {
	if h.Config != "" {
		return h.Config
	}
	return "/etc/varlatch/varlatchd.conf"
}
