// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	// Operator is what is the operator's to remove (Coolify's shape).
	Operator string `json:"operator,omitempty"`
	DoneAt   string `json:"doneAt,omitempty"`
}

// Removals is what --finish removed and began to remove, from the
// source's journal, and how each step is journalled: Intend before a
// volume's removal, Removed after any removal.
type Removals struct {
	Done     []string
	Removing []string
	Intend   func(volume string) error
	Removed  func(item string) error
}

// FinishSource is the TypeScript side's part of --finish.
type FinishSource interface {
	// CheckData is RemoveOld's (plan nil) or RemoveRetained's data volumes
	// inspected before anything is done: one not there (and neither done
	// nor begun) is refused, so --delete-old-data stops before its final
	// archive and before the window closes.
	CheckData(ctx context.Context, kind Ingress, plan *RebuildRecord, r Removals) error
	// ServeForArchive starts what the TypeScript installation's backup
	// needs (its varlatchd, Postgres and Convex, behind its migrated-out
	// gate): the services it started (none when all ran already).
	ServeForArchive(ctx context.Context) ([]string, error)
	// StopStarted stops the services ServeForArchive started.
	StopStarted(ctx context.Context, services []string) error
	// RemoveOld removes the TypeScript installation's containers and its
	// old node's state and certificates, and, with data, its Postgres and
	// Convex volumes, journalling each through r; what r.Done names was
	// removed by an earlier run, and a volume in r.Removing that is not
	// there was too (killed before it was journalled removed). A data
	// volume not there, neither done nor begun, is an error: never a
	// removal claimed for nothing.
	RemoveOld(ctx context.Context, kind Ingress, data bool, r Removals) error
	// RemoveRetained removes the pre-migration volumes a reverse left
	// unused (the installation runs on plan's fresh ones), as RemoveOld.
	RemoveRetained(ctx context.Context, plan RebuildRecord, r Removals) error
}

// FinishTarget is the Go side's part.
type FinishTarget interface {
	// FinalArchive is varlatchd's backup run, verified: its archive id.
	FinalArchive(ctx context.Context) (string, error)
}

// RollbackWindowOpen is whether the Go installation whose data directory
// is dir is in a migration's rollback window: its journal open (or a
// reverse begun). An installation never migrated, or whose window
// --finish ended (finished), is not. varlatch upgrade asks before a release
// that ends the window only while it is open.
func RollbackWindowOpen(dir string) (bool, error) {
	j, err := readJournal(dir)
	if err != nil || j == nil {
		return false, err
	}
	return j.Phase == Open || slices.Contains(reverseHeld, j.Phase) || j.Phase == RollbackTransfer, nil
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
		j.Finish = &FinishRecord{After: j.Phase, DeleteOldData: deleteOldData, StartedAt: e.now().UTC().Format(time.RFC3339Nano)}
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
	if err := fs.CheckData(ctx, j.Ingress, plan, Removals{Done: j.Finish.Removed, Removing: j.Finish.Removing}); err != nil {
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
		if fs != nil && j.Ingress != Coolify {
			var err error
			// A start that failed part way says what it did start.
			if started, err = fs.ServeForArchive(ctx); err != nil {
				return failed(fmt.Errorf("starting the TypeScript installation for its final archive: %w", err))
			}
		}
		e.say("Final archive: the TypeScript installation, made, uploaded, then downloaded and verified (format 2).")
		id, err := e.Source.Backup(ctx)
		if err != nil {
			return failed(fmt.Errorf("the final archive: %w", err))
		}
		if err := e.Source.VerifyBackup(ctx, id); err != nil {
			return failed(fmt.Errorf("the final archive %s did not verify: %w", id, err))
		}
		j.Finish.ArchiveID, j.Finish.ArchiveFormat = id, 2
	} else {
		ft, ok := e.Target.(FinishTarget)
		if !ok {
			return errors.New("this target makes no final archive")
		}
		// The reverse's barrier still stands on Go's copy, which never
		// starts again: lifted, so its backup run may take the copy.
		if rt, ok := e.Target.(ReverseTarget); ok {
			if err := rt.ReleaseBarrier(ctx, j.ID); err != nil {
				return fmt.Errorf("lifting the reverse's barrier on Go's copy: %w; nothing was removed", err)
			}
		}
		e.say("Final archive: Go's copy, made by varlatchd, uploaded, then downloaded and verified (format 3).")
		id, err := ft.FinalArchive(ctx)
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
		return Removals{Done: f.Removed, Removing: f.Removing, Removed: removed, Intend: func(v string) error {
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
		err := fs.RemoveOld(ctx, j.Ingress, data, log())
		var human *HumanStep
		if errors.As(err, &human) {
			f.Operator = human.Instruction
			e.say("By hand: %s", human.Instruction)
		} else if err != nil {
			return fmt.Errorf("removing the TypeScript installation: %w; varlatch migrate --resume finishes it", err)
		}
	} else if data {
		e.say("Go's copy is discarded, and the TypeScript installation's pre-migration volumes removed.")
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
		if j.Rollback == nil || j.Rollback.Rebuild == nil {
			return errors.New("the journal records no rebuild: the pre-migration volumes are not known; left as they are")
		}
		if err := fs.RemoveRetained(ctx, *j.Rollback.Rebuild, log()); err != nil {
			return fmt.Errorf("removing the pre-migration volumes: %w; varlatch migrate --resume finishes it", err)
		}
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
			"It is in %s (and uploaded where the Go configuration's backup destination says): move it out before a new migration into that data directory, which imports into an empty one only.",
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

// dataVolumes are the Postgres and Convex volumes the installation's
// Compose files give it now: migrate's file's fresh ones when COMPOSE_FILE
// names it (after a reverse), else the project's own.
func (c *Compose) dataVolumes(project string) ([]string, bool, error) {
	cf, ok, err := c.envValue("COMPOSE_FILE")
	if err != nil {
		return nil, false, err
	}
	if ok {
		for _, f := range strings.Split(cf, string(os.PathListSeparator)) {
			if filepath.Base(strings.TrimSpace(f)) != OverrideFile {
				continue
			}
			b, err := os.ReadFile(filepath.Join(c.Directory, OverrideFile))
			if err != nil {
				return nil, false, err
			}
			var vols []string
			lines := strings.Split(string(b), "\n")
			for i, l := range lines {
				t := strings.TrimSpace(l)
				if (t == "postgres-data:" || t == "convex-data:") && i+1 < len(lines) {
					if n, ok := strings.CutPrefix(strings.TrimSpace(lines[i+1]), "name: "); ok {
						vols = append(vols, n)
					}
				}
			}
			if len(vols) != 2 {
				return nil, false, fmt.Errorf("%s does not name the Postgres and Convex volumes", OverrideFile)
			}
			return vols, true, nil
		}
	}
	return []string{project + "_postgres-data", project + "_convex-data"}, false, nil
}

// volumeThere is `docker volume inspect`: whether the volume exists.
func (c *Compose) volumeThere(ctx context.Context, name string) (bool, error) {
	r, err := c.docker(ctx, []string{"volume", "inspect", "--format", "{{.Name}}", name}, nil)
	if err != nil {
		return false, err
	}
	if r.Code == 0 {
		return strings.TrimSpace(string(r.Answer)) == name, nil
	}
	if bytes.Contains(bytes.ToLower(r.Said), []byte("no such volume")) {
		return false, nil
	}
	return false, failure("docker volume inspect "+name, r)
}

// inspectVolumes are the volumes of expected and optional that are there
// (but those done), and those not there whose removal began (removed by a
// killed run); an expected one not there, neither done nor begun, is an
// error.
func (c *Compose) inspectVolumes(ctx context.Context, expected, optional []string, r Removals) (there, gone []string, err error) {
	var missing []string
	for _, v := range append(append([]string{}, expected...), optional...) {
		if slices.Contains(r.Done, v) {
			continue
		}
		ok, err := c.volumeThere(ctx, v)
		if err != nil {
			return nil, nil, err
		}
		switch {
		case ok:
			there = append(there, v)
		case slices.Contains(r.Removing, v):
			gone = append(gone, v)
		case slices.Contains(expected, v):
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return nil, nil, fmt.Errorf("the volumes %s are not there (docker volume inspect), and no run of --finish began to remove them: not the installation's Compose project's, or removed by hand; none of its data volumes was removed", strings.Join(missing, ", "))
	}
	return there, gone, nil
}

// removeVolumes removes each volume, inspected first: one done was
// removed by an earlier run; one not there whose removal began was too
// (journalled removed now); an optional one not there is skipped; any
// other one not there is an error, before anything else is removed, so a
// removal is never claimed for a volume that is not the installation's.
// Each removal is journalled begun before `docker volume rm`, and removed
// after it.
func (c *Compose) removeVolumes(ctx context.Context, expected, optional []string, log Removals) error {
	there, gone, err := c.inspectVolumes(ctx, expected, optional, log)
	if err != nil {
		return err
	}
	for _, v := range gone {
		if err := log.Removed(v); err != nil {
			return err
		}
	}
	for _, v := range there {
		if err := log.Intend(v); err != nil {
			return err
		}
		r, err := c.docker(ctx, []string{"volume", "rm", v}, nil)
		if err != nil {
			return err
		}
		if r.Code != 0 {
			return failure("docker volume rm "+v, r)
		}
		crashPoint("finish volume removed")
		if err := log.Removed(v); err != nil {
			return err
		}
	}
	return nil
}

// CheckData: the data volumes RemoveOld or RemoveRetained would remove,
// inspected (Coolify's are the operator's: nothing is checked).
func (c *Compose) CheckData(ctx context.Context, kind Ingress, plan *RebuildRecord, log Removals) error {
	if kind == Coolify {
		return nil
	}
	project, err := c.projectName(ctx)
	if err != nil {
		return err
	}
	var expected []string
	if plan == nil {
		if expected, _, err = c.dataVolumes(project); err != nil {
			return err
		}
	} else {
		expected = []string{project + "_postgres-data", project + "_convex-data"}
	}
	_, _, err = c.inspectVolumes(ctx, expected, nil, log)
	return err
}

// ServeForArchive starts the TypeScript installation's Postgres, varlatchd
// and Convex (what its backup reads), without their dependencies: never
// its Caddy or Tailscale, whose address is Go's now. Its varlatchd serves
// nothing behind its migrated-out gate. Running already, nothing is done.
// Where varlatchd shares the old Tailscale node's network (network_mode:
// service:...), it does not start without that node: refused, its data
// kept.
func (c *Compose) ServeForArchive(ctx context.Context) ([]string, error) {
	need := []string{"postgres", service, "convex-backend"}
	running, err := c.running(ctx)
	if err != nil {
		return nil, err
	}
	start := slices.DeleteFunc(slices.Clone(need), func(s string) bool { return slices.Contains(running, s) })
	if len(start) == 0 {
		return nil, nil
	}
	cfg, err := c.config(ctx)
	if err != nil {
		return nil, err
	}
	if owner, ok := strings.CutPrefix(cfg.Services[service].NetworkMode, "service:"); ok {
		return nil, fmt.Errorf("--delete-old-data is refused here: the TypeScript installation's varlatchd runs in %s's network (network_mode: service:%s), so starting it for the final archive "+
			"would bring the old Tailscale node back beside Go's. Its data volumes are kept. By hand: 1. make a backup of them by your own means and test that it restores; "+
			"2. remove them: docker volume rm %s_postgres-data %s_convex-data", owner, owner, cfg.Name, cfg.Name)
	}
	if err := c.compose(ctx, "docker compose up -d --no-deps "+strings.Join(start, " "), append([]string{"up", "-d", "--no-deps", "--no-recreate"}, start...)...); err != nil {
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
func (c *Compose) RemoveOld(ctx context.Context, kind Ingress, data bool, log Removals) error {
	if kind == Coolify {
		steps := "In Coolify, the TypeScript application (not Go's) is yours to remove: 1. Keep it as it is (it serves nothing: its domain is Go's) until varlatch migrate --finish --delete-old-data, " +
			"whose final archive needs its Postgres, varlatchd and Convex. 2. Then delete it, its volumes included."
		if data {
			steps = "In Coolify, open the TypeScript application (not Go's): 1. Stop it. 2. Delete it, and when Coolify asks, delete its volumes too, its Postgres and Convex data included (its final archive is verified)."
		}
		return &HumanStep{Instruction: steps + " varlatch migrate does not reach Coolify's resources."}
	}
	project, err := c.projectName(ctx)
	if err != nil {
		return err
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
	optional := []string{project + "_tailscale-state", project + "_tailscale-socket", project + "_caddy-data", project + "_caddy-config"}
	var expected []string
	if data {
		vols, _, err := c.dataVolumes(project)
		if err != nil {
			return err
		}
		expected = vols
		optional = append(optional, project+"_varlatch-state")
	}
	return c.removeVolumes(ctx, expected, optional, log)
}

// RemoveRetained removes the project's own Postgres and Convex volumes,
// which a reverse left unused: only while COMPOSE_FILE names migrate's
// file and its fresh volumes are plan's, never a volume in use.
func (c *Compose) RemoveRetained(ctx context.Context, plan RebuildRecord, log Removals) error {
	project, err := c.projectName(ctx)
	if err != nil {
		return err
	}
	inUse, rebuilt, err := c.dataVolumes(project)
	if err != nil {
		return err
	}
	if !rebuilt || !slices.Equal(inUse, plan.Volumes) {
		return fmt.Errorf("the installation does not run on the reverse's fresh volumes %v (its Compose files name %v): the pre-migration volumes are left as they are", plan.Volumes, inUse)
	}
	return c.removeVolumes(ctx, []string{project + "_postgres-data", project + "_convex-data"}, nil, log)
}

// configName is the Go configuration's path, as the operator edits it.
func (h *Host) configName() string {
	if h.Config != "" {
		return h.Config
	}
	return "/etc/varlatch/varlatchd.conf"
}
