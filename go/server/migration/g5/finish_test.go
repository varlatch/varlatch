// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux

package g5_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"maps"
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

// finishRecord is the source journal's finish record.
func (w *world) finishRecord() (f struct {
	Removed  []string `json:"removed"`
	Removing []string `json:"removing"`
	DoneAt   string   `json:"doneAt"`
}) {
	w.t.Helper()
	var j struct {
		Finish *struct {
			Removed  []string `json:"removed"`
			Removing []string `json:"removing"`
			DoneAt   string   `json:"doneAt"`
		} `json:"finish"`
	}
	b, err := os.ReadFile(filepath.Join(w.compose, "migration.json"))
	if err != nil || json.Unmarshal(b, &j) != nil || j.Finish == nil {
		w.t.Fatalf("the source's journal: %v %s", err, b)
	}
	f.Removed, f.Removing, f.DoneAt = j.Finish.Removed, j.Finish.Removing, j.Finish.DoneAt
	return f
}

// goBarrierFiles is whether Go's data directory holds a reverse's frozen
// copy and a maintenance gate.
func (w *world) goBarrierFiles() (frozen, gate bool) {
	entries, _ := os.ReadDir(w.data)
	for _, e := range entries {
		frozen = frozen || strings.HasPrefix(e.Name(), ".migration-frozen-")
	}
	_, err := os.Stat(filepath.Join(w.data, "maintenance.json"))
	return frozen, err == nil
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
	// Killed between `docker volume rm` and its journal entry: the
	// removal's intent was journalled first, so --resume takes the volume
	// not there for removed and goes on.
	t.Run("killed mid rm", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		if code := w.finish("finish volume removed", "--delete-old-data"); code != -1 {
			t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		f := w.finishRecord()
		first := "g5-installation_postgres-data"
		if vols, _ := w.removed(); !slices.Contains(vols, first) || !slices.Contains(f.Removing, first) || slices.Contains(f.Removed, first) {
			t.Fatalf("at the kill: removed %v, journal removing %v removed %v", vols, f.Removing, f.Removed)
		}
		if code := w.resumeFinish(); code != 0 {
			t.Fatalf("--resume: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		w.expect("resumed", "finished", "finished", "target-open", "migrated-out")
		vols, _ := w.removed()
		if !slices.Contains(vols, "g5-installation_convex-data") || len(slices.DeleteFunc(slices.Clone(vols), func(v string) bool { return v != first })) != 1 {
			t.Errorf("removed %v", vols)
		}
		if f := w.finishRecord(); !slices.Contains(f.Removed, first) || f.DoneAt == "" {
			t.Errorf("the journal after the resume: %+v", f)
		}
	})
	// A data volume gone by hand during an interrupted --finish, its
	// removal never begun: --resume refuses it, and removes no data.
	t.Run("gone, no intent", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		if code := w.finish("finish containers removed", "--delete-old-data"); code != -1 {
			t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		f, err := os.OpenFile(filepath.Join(w.stateDir, "removed-volumes"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("g5-installation_convex-data\n")
		f.Close()
		if code := w.resumeFinish(); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "no run of --finish began to remove them") {
			t.Fatalf("--resume, a volume gone by hand: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if vols, _ := w.removed(); slices.Contains(vols, "g5-installation_postgres-data") {
			t.Errorf("data removed beside the refusal: %v", vols)
		}
		if rec := w.finishRecord(); len(rec.Removing) != 0 || rec.DoneAt != "" {
			t.Errorf("the journal: %+v", rec)
		}
	})
	// Killed between the source's journal and Go's: the source says
	// finished, Go's open, and the window would read open to varlatch
	// upgrade; --resume and --finish again both write Go's finished.
	for _, again := range []string{"--resume", "--finish"} {
		t.Run("between journals, "+again, func(t *testing.T) {
			w := migratedWorld(t, false, false)
			if code := w.finish("finished source written"); code != -1 {
				t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
			}
			w.expect("killed", "finished", "open", "target-open", "migrated-out")
			code := 0
			if again == "--resume" {
				code = w.resumeFinish()
			} else {
				code = w.finish("")
			}
			if code != 0 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "Go's journal says open: it is written finished") {
				t.Fatalf("%s: %d\n%s", again, code, w.outputs[len(w.outputs)-1])
			}
			w.expect(again, "finished", "finished", "target-open", "migrated-out")
		})
	}
	// Killed at "finish archived", then a plain --finish: the verified
	// archive stays journalled, the data kept; a later --delete-old-data
	// uses it, no second archive made.
	t.Run("archived, plain rerun", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		if code := w.finish("finish archived", "--delete-old-data"); code != -1 {
			t.Fatalf("not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		creates := func() int {
			return len(slices.DeleteFunc(w.calls("ts-calls"), func(c string) bool { return !strings.HasPrefix(c, "admin backup create") }))
		}
		made := creates()
		if code := w.finish(""); code != 0 {
			t.Fatalf("--finish: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if out := string(w.outputs[len(w.outputs)-1]); !strings.Contains(out, "Final archive 0f0e0d0c-0b0a-4908-8706-050403020100 (format 2)") || !strings.Contains(out, "the old data kept") {
			t.Errorf("the plain --finish's journal:\n%s", out)
		}
		if vols, _ := w.removed(); slices.Contains(vols, "g5-installation_postgres-data") {
			t.Errorf("data removed by a plain --finish: %v", vols)
		}
		if code := w.finish("", "--delete-old-data"); code != 0 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "is this run's") {
			t.Fatalf("--delete-old-data: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if n := creates(); n != made {
			t.Errorf("%d archives made again", n-made)
		}
		if vols, _ := w.removed(); !slices.Contains(vols, "g5-installation_postgres-data") {
			t.Errorf("the data: %v", vols)
		}
	})
	// The final archive failing after its services were started for it:
	// those go down again, said so, nothing removed.
	t.Run("archive fails", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		if code := w.finish(""); code != 0 {
			t.Fatalf("--finish: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if err := os.WriteFile(filepath.Join(w.stateDir, "fail-backup"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if code := w.finish("", "--delete-old-data"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "started for the archive, are stopped again") {
			t.Fatalf("a failing archive: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		for _, svc := range []string{"postgres", "varlatchd", "convex-backend"} {
			if !w.stopped(svc) {
				t.Errorf("%s left running", svc)
			}
		}
		if vols, _ := w.removed(); slices.Contains(vols, "g5-installation_postgres-data") {
			t.Errorf("removed %v", vols)
		}
		if out := string(w.outputs[len(w.outputs)-1]); strings.Contains(out, "old data to be deleted") || strings.Contains(out, "the old data deleted") {
			t.Errorf("the refusal shown as a deletion:\n%s", out)
		}
	})
	// Another installation's configuration (--config): Go's journal does
	// not name the migration, on the finished path too: refused before any
	// archive.
	t.Run("wrong config", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		if code := w.finish(""); code != 0 {
			t.Fatalf("--finish: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		conf, err := os.ReadFile(w.conf)
		if err != nil {
			t.Fatal(err)
		}
		other := filepath.Join(w.stateDir, "other")
		if err := os.MkdirAll(filepath.Join(other, "data"), 0o700); err != nil {
			t.Fatal(err)
		}
		alt := filepath.Join(other, "varlatchd.conf")
		if err := os.WriteFile(alt, []byte(strings.ReplaceAll(string(conf), "data_dir = "+w.data, "data_dir = "+filepath.Join(other, "data"))), 0o600); err != nil {
			t.Fatal(err)
		}
		before := len(w.calls("ts-calls"))
		args := w.finishArgs("--delete-old-data")
		args[slices.Index(args, w.conf)] = alt
		if code := w.runArgs("", args); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "nothing was done") {
			t.Fatalf("another installation's --config: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if slices.ContainsFunc(w.calls("ts-calls")[before:], func(c string) bool { return strings.HasPrefix(c, "admin backup create") }) {
			t.Error("an archive made with another installation's configuration")
		}
	})
	// An undone reverse killed after Go's barrier was lifted, before the
	// source's journal recorded it: --finish records it (as --resume does).
	t.Run("undo released, then finish", func(t *testing.T) {
		w := migratedWorld(t, false, false)
		if code := w.rollback("rollback barrier held", "--rollback"); code != -1 {
			t.Fatalf("not killed: %d", code)
		}
		if code := w.rollback("rollback undone released", "--abort"); code != -1 {
			t.Fatalf("the undo not killed: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if released, ok := w.undoneReleased(); !ok || released {
			t.Fatalf("at the kill: undone %v, barrier released %v", ok, released)
		}
		if code := w.finish(""); code != 0 {
			t.Fatalf("--finish: %d\n%s", code, w.outputs[len(w.outputs)-1])
		}
		if released, ok := w.undoneReleased(); !ok || !released {
			t.Errorf("after --finish: undone %v, barrier released %v", ok, released)
		}
		w.expect("finished", "finished", "finished", "target-open", "migrated-out")
	})
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
	// Go's copy stays behind the reverse's barrier: its paused gate and its
	// frozen copy, until --delete-old-data (as the rollback said).
	if !strings.Contains(strings.Join(func() []string {
		var o []string
		for _, b := range w.outputs {
			o = append(o, string(b))
		}
		return o
	}(), "\n"), "Go's copy stays in "+w.data) {
		t.Error("the rollback did not say where Go's copy stays")
	}
	if frozen, gate := w.goBarrierFiles(); !frozen || !gate {
		t.Errorf("after a plain --finish: frozen copy %v, gate %v; both kept", frozen, gate)
	}
	if code := w.run(""); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "Go's copy is kept") {
		t.Errorf("a new migration over Go's kept copy: %d", code)
	}
	// Go's copy is discarded after its final archive: the archive's uploaded
	// copy must open first, and with no destination it is refused.
	if code := w.finish("", "--delete-old-data"); code != 1 || !strings.Contains(string(w.outputs[len(w.outputs)-1]), "names no backup destination") {
		t.Fatalf("--delete-old-data with no destination: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if out := string(w.outputs[len(w.outputs)-1]); !strings.Contains(out, "the old data kept") || strings.Contains(out, "old data to be deleted") {
		t.Errorf("the refusal's journal shown as what was asked, not what is recorded:\n%s", out)
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
	if frozen, gate := w.goBarrierFiles(); frozen || gate {
		t.Errorf("after --delete-old-data: frozen copy %v, gate %v; both removed", frozen, gate)
	}
	w.expectReverse("finished", rbState{"finished", "rolled-back", "source", "", false, true, true})
	// Go's copy gone, a new migration may begin, and goes through with the
	// final archive left where it is, in the data directory's backups/
	// (rehearsal r16f: the import refused it, after the barrier).
	if !strings.Contains(out, "a new migration into that data directory leaves it there") {
		t.Errorf("the notice says nothing of the final archive's place:\n%s", out)
	}
	before := dirFiles(t, filepath.Join(w.data, "backups"))
	if len(before) == 0 {
		t.Fatal("no final archive in the data directory's backups/")
	}
	if code := w.run(""); code != 0 {
		t.Fatalf("a new migration after the reverse finished: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	if s, d := w.phases(); s != "open" || d != "open" {
		t.Errorf("the new migration's journals: %s / %s", s, d)
	}
	if after := dirFiles(t, filepath.Join(w.data, "backups")); !maps.Equal(before, after) {
		t.Errorf("the import changed Go's backups/: %v, then %v", before, after)
	}
	w.noSecrets()
}

// dirFiles is each regular file under dir, by its path there, and its
// SHA-256.
func dirFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		rel, _ := filepath.Rel(dir, p)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A name in the target's data directory that is not the migration's is
// refused by the preflight, before the backup and the barrier: the source
// keeps serving, with no gate and no downtime, and the migration goes
// through once the name is gone. Go's backups/, a directory, is not such
// a name; a file of that name is.
func TestG5APreflightRefusesWhatTheImportWould(t *testing.T) {
	w := newWorld(t, false)
	before := w.sourceHash()
	for _, c := range []struct{ name, what string }{
		{"notes.txt", "a stray file"},
		{"backups", "a file named backups"},
	} {
		stray := filepath.Join(w.data, c.name)
		if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		code := w.run("")
		out := string(w.outputs[len(w.outputs)-1])
		if code != 1 || !strings.Contains(out, "preflight: the target's import would be refused") || !strings.Contains(out, c.name) {
			t.Fatalf("%s: %d\n%s", c.what, code, out)
		}
		log, _ := os.ReadFile(filepath.Join(w.stateDir, "crashpoints.log"))
		for _, never := range []string{"entered preflight", "barrier held", "entered barrier"} {
			if strings.Contains(string(log), never) {
				t.Errorf("%s: refused after %q", c.what, never)
			}
		}
		if a, g := w.answers(), w.gateKind(); a != "source" || g != "" {
			t.Errorf("%s: the public URL answers from %s, the source's gate %q", c.what, a, g)
		}
		if err := os.Remove(stray); err != nil {
			t.Fatal(err)
		}
	}
	if w.sourceHash() != before {
		t.Error("the refused runs changed the source")
	}
	// Go's local backup store, a directory, is left as it is.
	kept := filepath.Join(w.data, "backups", "kept.vltbak")
	if err := os.MkdirAll(filepath.Dir(kept), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kept, []byte("an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := w.run(""); code != 0 {
		t.Fatalf("the migration with backups/ in the data directory: %d\n%s", code, w.outputs[len(w.outputs)-1])
	}
	w.expect("after", "open", "open", "target-open", "migrated-out")
	if b, err := os.ReadFile(kept); err != nil || string(b) != "an archive" {
		t.Errorf("backups/ after the import: %q, %v", b, err)
	}
	w.noSecrets()
}
