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
	DoneAt        string   `json:"doneAt,omitempty"`
}

// FinishSource is the TypeScript side's part of --finish.
type FinishSource interface {
	// RemoveOld removes the TypeScript installation's containers and its
	// old node's state and certificates, and, with data, its Postgres and
	// Convex volumes: what was removed, by name.
	RemoveOld(ctx context.Context, kind Ingress, data bool) ([]string, error)
	// RemoveRetained removes the pre-migration volumes a reverse left
	// unused (the installation runs on plan's fresh ones).
	RemoveRetained(ctx context.Context, plan RebuildRecord) ([]string, error)
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
		if deleteOldData && !j.Finish.DeleteOldData {
			// The window ended earlier; the old data goes now.
			j.Finish.DeleteOldData, j.Finish.DoneAt = true, ""
			if err := e.finalArchive(ctx, j); err != nil {
				return j, err
			}
		}
		if j.Finish.DoneAt == "" {
			return j, e.finishRemove(ctx, j)
		}
		return j, nil
	case j.Phase == Open:
		_, st, err := e.Target.Describe(ctx)
		if err != nil {
			return j, err
		}
		if st.Journal == nil || st.Journal.ID != j.ID || st.Journal.Phase != Open {
			return j, fmt.Errorf("the target's journal says %v, not the migration %s open: nothing was done", st.Journal, j.ID)
		}
		if st.Barrier != "" {
			return j, fmt.Errorf("a reverse's barrier stands on the Go installation (%s): varlatch migrate --resume first", st.Barrier)
		}
	case j.Phase == RolledBack:
	default:
		return j, fmt.Errorf("the migration %s is in phase %s: --finish ends an open migration's rollback window, or a rolled back one's record (varlatch migrate --resume first)", j.ID, j.Phase)
	}
	j.Finish = &FinishRecord{After: j.Phase, DeleteOldData: deleteOldData, StartedAt: e.now().UTC().Format(time.RFC3339Nano)}
	if deleteOldData {
		if err := e.finalArchive(ctx, j); err != nil {
			return j, err
		}
	}
	if j.Finish.After == Open {
		// Both journals: Go's says finished beside it, and the window is
		// closed.
		if err := e.enter(ctx, j, Finished); err != nil {
			return j, err
		}
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

// finalArchive makes the final archive of the old data and verifies it,
// recorded in the source's journal (only there: the phase does not
// change) before anything is removed.
func (e *Engine) finalArchive(ctx context.Context, j *Journal) error {
	if j.Finish.After == Open {
		e.say("Final archive: the TypeScript installation, made, uploaded, then downloaded and verified (format 2).")
		id, err := e.Source.Backup(ctx)
		if err != nil {
			return fmt.Errorf("the final archive: %w; nothing was removed", err)
		}
		if err := e.Source.VerifyBackup(ctx, id); err != nil {
			return fmt.Errorf("the final archive %s did not verify: %w; nothing was removed", id, err)
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
		e.say("Final archive: Go's copy, made and verified by varlatchd (format 3).")
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
	var removed []string
	if f.After == Open {
		r, err := fs.RemoveOld(ctx, j.Ingress, data)
		var human *HumanStep
		if errors.As(err, &human) {
			e.say("By hand: %s", human.Instruction)
		} else if err != nil {
			return fmt.Errorf("removing the TypeScript installation: %w; varlatch migrate --resume finishes it", err)
		}
		removed = r
	} else if data {
		e.say("Go's copy is discarded, and the TypeScript installation's pre-migration volumes removed.")
		if err := e.Target.Discard(ctx, j.ID); err != nil {
			return fmt.Errorf("discarding Go's copy: %w; varlatch migrate --resume finishes it", err)
		}
		crashPoint("finish go discarded")
		if j.Rollback == nil || j.Rollback.Rebuild == nil {
			return errors.New("the journal records no rebuild: the pre-migration volumes are not known; left as they are")
		}
		r, err := fs.RemoveRetained(ctx, *j.Rollback.Rebuild)
		if err != nil {
			return fmt.Errorf("removing the pre-migration volumes: %w; varlatch migrate --resume finishes it", err)
		}
		removed = append([]string{"Go's copy (" + j.Target.DataDir + ")"}, r...)
	}
	f.Removed = removed
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

// FinalArchive is `varlatchd admin backup run --json`: its archive, which
// varlatchd verified (integrity, compatibility, the key).
func (h *Host) FinalArchive(ctx context.Context) (string, error) {
	args := []string{"admin", "backup", "run", "--json"}
	if h.Config != "" {
		args = append(args, "--config", h.Config)
	}
	r, err := h.Run.Run(ctx, "", h.Varlatchd, args, nil)
	if err != nil {
		return "", err
	}
	if r.Code != 0 {
		return "", failure("varlatchd admin backup run", r)
	}
	var res struct {
		ArchiveID    string `json:"archiveId"`
		Verification *struct {
			Integrity     bool `json:"integrity"`
			Compatibility bool `json:"compatibility"`
			KeyMatch      bool `json:"keyMatch"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(lastLine(bytes.TrimSpace(r.Answer)), &res); err != nil || res.ArchiveID == "" {
		return "", errors.New("varlatchd admin backup run did not answer with its archive")
	}
	if v := res.Verification; v == nil || !v.Integrity || !v.Compatibility || !v.KeyMatch {
		return "", fmt.Errorf("the archive %s did not verify", res.ArchiveID)
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

func (c *Compose) removeVolumes(ctx context.Context, names []string) ([]string, error) {
	var removed []string
	for _, v := range names {
		r, err := c.docker(ctx, []string{"volume", "rm", "-f", v}, nil)
		if err != nil {
			return removed, err
		}
		if r.Code != 0 {
			return removed, failure("docker volume rm "+v, r)
		}
		removed = append(removed, v)
	}
	return removed, nil
}

// RemoveOld: `docker compose down` (the containers and networks, never a
// volume), then the old node's state and certificates (Tailscale's and
// Caddy's volumes, those the installation has), and, with data, the
// Postgres and Convex volumes it ran on. In Coolify's shape all of it is
// the operator's, said exactly.
func (c *Compose) RemoveOld(ctx context.Context, kind Ingress, data bool) ([]string, error) {
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	vols, _, err := c.dataVolumes(project)
	if err != nil {
		return nil, err
	}
	if kind == Coolify {
		what := "its containers, and its Tailscale and Caddy volumes (the old node's state and certificates)"
		if data {
			what = "its containers and every volume of it, its Postgres and Convex data included (the final archive is verified)"
		}
		return nil, &HumanStep{Instruction: "In Coolify, delete the TypeScript application's resources: " + what + ". varlatch migrate does not reach Coolify's resources."}
	}
	if err := c.compose(ctx, "docker compose down", "down"); err != nil {
		return nil, err
	}
	removed := []string{"the TypeScript installation's containers"}
	crashPoint("finish containers removed")
	old := []string{project + "_tailscale-state", project + "_tailscale-socket", project + "_caddy-data", project + "_caddy-config"}
	if data {
		old = append(old, vols...)
	}
	r, err := c.removeVolumes(ctx, old)
	return append(removed, r...), err
}

// RemoveRetained removes the project's own Postgres and Convex volumes,
// which a reverse left unused: only while COMPOSE_FILE names migrate's
// file and its fresh volumes are plan's, never a volume in use.
func (c *Compose) RemoveRetained(ctx context.Context, plan RebuildRecord) ([]string, error) {
	project, err := c.projectName()
	if err != nil {
		return nil, err
	}
	inUse, rebuilt, err := c.dataVolumes(project)
	if err != nil {
		return nil, err
	}
	if !rebuilt || !slices.Equal(inUse, plan.Volumes) {
		return nil, fmt.Errorf("the installation does not run on the reverse's fresh volumes %v (its Compose files name %v): the pre-migration volumes are left as they are", plan.Volumes, inUse)
	}
	return c.removeVolumes(ctx, []string{project + "_postgres-data", project + "_convex-data"})
}
