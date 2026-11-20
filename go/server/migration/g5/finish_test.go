// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux

package g5_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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

// calls are the stand-in's logged calls of docker (docker-calls) or the
// TypeScript CLI (ts-calls).
func (w *world) calls(file string) []string {
	b, _ := os.ReadFile(filepath.Join(w.stateDir, file))
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (w *world) stopped(svc string) bool {
	_, err := os.Stat(filepath.Join(w.stateDir, "stopped-"+svc))
	return err == nil
}

// remote is a stand-in S3 bucket (PUT and GET objects), which Go's
// configuration names as its backup destination.
type remote struct {
	mu      sync.Mutex
	objects map[string][]byte
	gets    []string
}

func (s *remote) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodPut:
		b, _ := io.ReadAll(r.Body)
		s.objects[r.URL.Path] = b
		rw.Header().Set("ETag", `"etag"`)
	case http.MethodGet:
		b, ok := s.objects[r.URL.Path]
		if !ok {
			rw.WriteHeader(404)
			_, _ = io.WriteString(rw, `<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>no</Message></Error>`)
			return
		}
		s.gets = append(s.gets, r.URL.Path)
		rw.Header().Set("ETag", `"etag"`)
		_, _ = rw.Write(b)
	default:
		rw.WriteHeader(400)
	}
}

// withRemote names a stand-in bucket in Go's configuration (the target's,
// which --finish's final archive reads) as its backup destination; its
// credentials are made here, nothing real.
func (w *world) withRemote() *remote {
	t := w.t
	t.Helper()
	rm := &remote{objects: map[string][]byte{}}
	srv := httptest.NewServer(rm)
	t.Cleanup(srv.Close)
	dir := filepath.Join(w.stateDir, "remote")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	creds, _ := json.Marshal(map[string]string{"accessKeyId": "g5" + "id", "secretAccessKey": "g5" + "-made-in-the-test"})
	dests, _ := json.Marshal(map[string]any{"offsite": map[string]string{"endpoint": srv.URL, "region": "us-east-1", "bucket": "b", "writeCredentialsFile": "write.json"}})
	for name, b := range map[string][]byte{"write.json": creds, "destinations.json": dests} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.OpenFile(w.conf, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("backup_destinations_file = " + filepath.Join(dir, "destinations.json") + "\nbackup_destination = offsite\n"); err != nil {
		t.Fatal(err)
	}
	return rm
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
			!slices.Contains(vols, "g5-installation_tailscale-state") || !slices.Contains(vols, "g5-installation_caddy-data") {
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
		// The first --finish took the TypeScript services down; its backup
		// needs them: started without their dependencies (never Caddy or
		// Tailscale), then down again before the volumes went.
		if !slices.Contains(w.calls("docker-calls"), "compose up -d --no-deps --no-recreate postgres varlatchd convex-backend") {
			t.Errorf("the services not started for the archive: %q", w.calls("docker-calls"))
		}
		if !w.stopped("postgres") || !w.stopped("varlatchd") || !w.stopped("caddy") {
			t.Error("the TypeScript services left running")
		}
		vols, _ = w.removed()
		if !slices.Contains(vols, "g5-installation_postgres-data") || !slices.Contains(vols, "g5-installation_convex-data") {
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
	// varlatchd in the old node's network: nothing removed. (Short names:
	// the socket paths under t.TempDir.)
	t.Run("shared ns", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		if code := w.finish(""); code != 0 {
			t.Fatalf("--finish: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		t.Setenv("G5_SHARED_NAMESPACE", "1")
		if code := w.finish("", "--delete-old-data"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "the old Tailscale node") {
			t.Fatalf("--delete-old-data with varlatchd in the node's network: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if vols, _ := w.removed(); slices.Contains(vols, "g5-installation_postgres-data") || slices.Contains(vols, "g5-installation_convex-data") {
			t.Errorf("removed %v", vols)
		}
		if !w.stopped("tailscale") {
			t.Error("the old node started again")
		}
		w.expect("refused", "finished", "finished", "target-open", "migrated-out")
	})
	// A data volume not there: refused before the window closes.
	t.Run("volume gone", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		// Removed by hand: what the stand-in counts as removed.
		if err := os.WriteFile(filepath.Join(w.stateDir, "removed-volumes"), []byte("g5-installation_convex-data\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := len(w.calls("ts-calls"))
		if code := w.finish("", "--delete-old-data"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "g5-installation_convex-data are not there") {
			t.Fatalf("--delete-old-data, a volume gone: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expect("refused", "open", "open", "target-open", "migrated-out")
		if vols, down := w.removed(); len(vols) != 1 || down {
			t.Errorf("removed %v, down %v", vols, down)
		}
		if slices.ContainsFunc(w.calls("ts-calls")[before:], func(c string) bool { return strings.HasPrefix(c, "admin backup create") }) {
			t.Error("a final archive made before the refusal")
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
				// Before the window closed: still open, --finish again, with
				// the journalled verified archive, not another.
				w.expect("killed", "open", "open", "target-open", "migrated-out")
				creates := func() int {
					return len(slices.DeleteFunc(w.calls("ts-calls"), func(c string) bool { return !strings.HasPrefix(c, "admin backup create") }))
				}
				made := creates()
				if code := w.finish("", "--delete-old-data"); code != 0 {
					t.Fatalf("--finish again: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
				if out := string(w.outputs[len(w.outputs)-1]); !strings.Contains(out, "is this run's") {
					t.Errorf("the archive not reused:\n%s", out)
				}
				if n := creates(); n != made {
					t.Errorf("%d archives made again", n-made)
				}
			} else {
				w.expect("killed", "finished", "finished", "target-open", "migrated-out")
				if code := w.resumeFinish(); code != 0 {
					t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
				}
			}
			w.expect("finished", "finished", "finished", "target-open", "migrated-out")
			vols, down := w.removed()
			if !down || !slices.Contains(vols, "g5-installation_postgres-data") || !slices.Contains(vols, "g5-installation_convex-data") {
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
		if code := w.finish("", "--delete-old-data"); code != 0 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "In Coolify, open the TypeScript application (not Go's): 1. Stop it. 2. Delete it") {
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
	// Go's copy is discarded after its final archive: the archive's uploaded
	// copy must open first, and with no destination it is refused.
	if code := w.finish("", "--delete-old-data"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "names no backup destination") {
		t.Fatalf("--delete-old-data with no destination: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if _, err := os.Stat(filepath.Join(w.data, "varlatch.db")); err != nil {
		t.Fatalf("Go's copy after the refusal: %v", err)
	}
	if vols, _ := w.removed(); len(vols) != 0 {
		t.Errorf("removed after the refusal: %v", vols)
	}
	bucket := w.withRemote()
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
	bucket.mu.Lock()
	if len(bucket.gets) != 1 || len(bucket.objects) != 1 {
		t.Errorf("the archive's remote copy: uploaded %d, downloaded %q", len(bucket.objects), bucket.gets)
	}
	bucket.mu.Unlock()
	vols, _ := w.removed()
	if !slices.Contains(vols, "g5-installation_postgres-data") || !slices.Contains(vols, "g5-installation_convex-data") || slices.Contains(vols, fresh) {
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
