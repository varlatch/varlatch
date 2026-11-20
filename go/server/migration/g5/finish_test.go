// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux

package g5_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// G5 for `varlatch migrate --finish` (go-step7 decision 17, slice 7.6a),
// with interrupt_test.go's and rollback_test.go's stand-ins: the window's
// end after a forward migration and after a reverse, the old data deleted
// only with --delete-old-data and only after its final archive verified,
// killed at each step and finished by --resume.

// finishArgs are --finish's options: the target, and the final archive's
// backup options.
func (w *world) finishArgs(extra ...string) []string {
	a := w.rollbackArgs("--finish", "--bek-file", filepath.Join(w.compose, "bek"), "--backup-destination", "offsite",
		"--read-credentials-file", filepath.Join(w.compose, "read-credentials.json"), "--ts-cli", "varlatch-ts")
	a = slices.DeleteFunc(a, func(s string) bool { return s == "--drain" || s == "5s" || s == "--transfer-timeout" || s == "20s" })
	return append(a, extra...)
}

func (w *world) finish(pause string, extra ...string) int {
	w.t.Helper()
	return w.runArgs(pause, w.finishArgs(extra...))
}

// resumeArgs is --resume with --finish's target only.
func (w *world) resumeFinish() int {
	w.t.Helper()
	return w.runArgs("", w.rollbackArgs("--resume"))
}

// removed are the volumes the stand-in removed, and whether its containers
// went down.
func (w *world) removed() ([]string, bool) {
	b, _ := os.ReadFile(filepath.Join(w.stateDir, "removed-volumes"))
	_, err := os.Stat(filepath.Join(w.stateDir, "down"))
	return strings.Fields(string(b)), err == nil
}

func (w *world) journalPhase() string {
	s, _ := w.phases()
	return s
}

// After a forward migration: --finish closes the window (both journals
// finished, Go serving as before, --rollback refused), removes the
// TypeScript installation's containers and its old node's state and
// certificates, and keeps its data; --finish --delete-old-data later makes
// the final archive, verifies it, then removes the data volumes.
func TestG5Finish(t *testing.T) {
	t.Run("the window closed, the data kept, then deleted", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		if code := w.finish(""); code != 0 {
			t.Fatalf("--finish: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		out := string(w.outputs[len(w.outputs)-1])
		if !strings.Contains(out, "can no longer be undone") || !strings.Contains(out, "data volumes are kept") {
			t.Errorf("the notice:\n%s", out)
		}
		w.expect("finished", "finished", "finished", "target-open", "migrated-out")
		vols, down := w.removed()
		if !down || slices.ContainsFunc(vols, func(v string) bool {
			return strings.HasSuffix(v, "_postgres-data") || strings.HasSuffix(v, "_convex-data")
		}) ||
			!slices.Contains(vols, "compose_tailscale-state") || !slices.Contains(vols, "compose_caddy-data") {
			t.Errorf("removed %v, down %v", vols, down)
		}
		if code := w.rollback("", "--rollback"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "ended its rollback window") {
			t.Errorf("--rollback once finished: %d", code)
		}
		if code := w.rollback("", "--abort"); code != 1 {
			t.Errorf("--abort once finished: %d", code)
		}
		// Go restarts on its journal finished.
		w.useState()
		_ = stopService()
		if w.goRefuses() {
			t.Fatal("varlatchd refuses to start once finished")
		}
		_ = startService(filepath.Join(filepath.Dir(shared.varlatch), "varlatchd"), filepath.Join(w.stateDir, "service.conf"))
		w.expect("restarted", "finished", "finished", "target-open", "migrated-out")
		// The old data, later: archived, verified, then removed.
		if code := w.finish("", "--delete-old-data"); code != 0 {
			t.Fatalf("--finish --delete-old-data: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if out := string(w.outputs[len(w.outputs)-1]); !strings.Contains(out, "Final archive 0f0e0d0c-0b0a-4908-8706-050403020100 (format 2)") {
			t.Errorf("the final archive:\n%s", out)
		}
		vols, _ = w.removed()
		if !slices.Contains(vols, "compose_postgres-data") || !slices.Contains(vols, "compose_convex-data") {
			t.Errorf("the data volumes: %v", vols)
		}
		w.noSecrets()
	})
	t.Run("no verified archive, nothing of the data removed", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		// Without the archive's options the final archive cannot be made.
		bare := slices.DeleteFunc(w.rollbackArgs("--finish", "--delete-old-data"), func(s string) bool {
			return s == "--drain" || s == "5s" || s == "--transfer-timeout" || s == "20s"
		})
		if code := w.runArgs("", bare); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "nothing was removed") {
			t.Fatalf("--delete-old-data without the archive's options: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expect("refused", "open", "open", "target-open", "migrated-out")
		if vols, down := w.removed(); len(vols) != 0 || down {
			t.Errorf("removed %v, down %v", vols, down)
		}
	})
	for _, point := range []string{"finish archived", "entered finished", "finish containers removed"} {
		t.Run("killed at "+point, func(t *testing.T) {
			w := migratedWorld(t, false, false)
			if code := w.finish(point, "--delete-old-data"); code != -1 {
				t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
			}
			vols, _ := w.removed()
			if slices.ContainsFunc(vols, func(v string) bool { return strings.HasSuffix(v, "_postgres-data") }) {
				t.Errorf("killed at %s: the data already removed (%v)", point, vols)
			}
			if point == "finish archived" {
				// Before the window closed: still open, --finish again.
				w.expect("killed", "open", "open", "target-open", "migrated-out")
				if code := w.finish("", "--delete-old-data"); code != 0 {
					t.Fatalf("--finish again: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
			} else {
				w.expect("killed", "finished", "finished", "target-open", "migrated-out")
				if code := w.resumeFinish(); code != 0 {
					t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
			}
			w.expect("finished", "finished", "finished", "target-open", "migrated-out")
			vols, down := w.removed()
			if !down || !slices.Contains(vols, "compose_postgres-data") || !slices.Contains(vols, "compose_convex-data") {
				t.Errorf("removed %v, down %v", vols, down)
			}
			if code := w.resumeFinish(); code != 0 {
				t.Errorf("a second --resume: %d", code)
			}
			w.noSecrets()
		})
	}
	t.Run("Coolify's resources are the operator's", func(t *testing.T) {
		w := migratedWorld(t, false, true)
		if code := w.finish("", "--delete-old-data"); code != 0 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "In Coolify, delete the TypeScript application's resources") {
			t.Fatalf("--finish in Coolify's shape: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if vols, down := w.removed(); len(vols) != 0 || down {
			t.Errorf("removed %v, down %v", vols, down)
		}
		if p := w.journalPhase(); p != "finished" {
			t.Errorf("the journal: %s", p)
		}
	})
}

// After a reverse: --finish ends the record (Go's journal stays rolled
// back, never starting); --delete-old-data makes Go's final archive,
// verified, then discards Go's copy and removes the pre-migration volumes
// the rebuild left unused (never the fresh ones in use); then a new
// migration may begin.
func TestG5FinishAfterARollback(t *testing.T) {
	w := migratedWorld(t, false, false)
	if code := w.rollback("", "--rollback"); code != 0 {
		t.Fatalf("--rollback: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	fresh, _ := w.volume()
	if code := w.finish(""); code != 0 {
		t.Fatalf("--finish: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	s, d := w.phases()
	if s != "finished" || d != "rolled-back" {
		t.Fatalf("the journals: %s / %s", s, d)
	}
	if vols, _ := w.removed(); len(vols) != 0 {
		t.Errorf("removed without --delete-old-data: %v", vols)
	}
	if code := w.run(""); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "Go's copy is kept") {
		t.Errorf("a new migration over Go's kept copy: %d", code)
	}
	if code := w.finish("finish go discarded", "--delete-old-data"); code != -1 {
		t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if _, err := os.Stat(filepath.Join(w.data, "varlatch.db")); !os.IsNotExist(err) {
		t.Fatalf("Go's copy at the kill: %v", err)
	}
	if code := w.resumeFinish(); code != 0 {
		t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	out := strings.Join(func() []string {
		var o []string
		for _, b := range w.outputs {
			o = append(o, string(b))
		}
		return o
	}(), "\n")
	if !strings.Contains(out, "(format 3)") {
		t.Errorf("no final archive of Go's copy:\n%s", out)
	}
	vols, _ := w.removed()
	if !slices.Contains(vols, "compose_postgres-data") || !slices.Contains(vols, "compose_convex-data") || slices.Contains(vols, fresh) {
		t.Errorf("removed %v (fresh %s in use)", vols, fresh)
	}
	if !w.goRefuses() {
		t.Error("varlatchd starts on the discarded copy")
	}
	w.expectReverse("finished", rbState{"finished", "rolled-back", "source", "", false, true, true})
	// Go's copy gone, a new migration may begin, and goes through once the
	// final archive is moved out of the data directory, as the notice says.
	if !strings.Contains(out, "move it out before a new migration") {
		t.Errorf("the notice says nothing of the final archive's place:\n%s", out)
	}
	if err := os.Rename(filepath.Join(w.data, "backups"), filepath.Join(w.stateDir, "final-archive")); err != nil {
		t.Fatal(err)
	}
	if code := w.run(""); code != 0 {
		t.Fatalf("a new migration after the reverse finished: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if s, d := w.phases(); s != "open" || d != "open" {
		t.Errorf("the new migration's journals: %s / %s", s, d)
	}
	w.noSecrets()
}
