// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Once StartServing has succeeded at least once for a rollback, the rebuilt
// TypeScript installation may have accepted writes. A subsequent failure on
// --resume (recreating the dashboard, waiting for the public URL, or stopping
// Go) must keep the rebuilt volumes and the rollback-transfer phase without
// calling undo, and a later --resume must finish the rollback.
func TestRollbackRetryAfterStartServingKeepsVolumes(t *testing.T) {
	t.Run("coolify dashboard recreate fails on resume after exit 75", func(t *testing.T) {
		w, src, j := rolledWorld(t, RollbackChecked, Coolify)
		w.tgt.human = true
		firstServedAt := w.eng.now().UTC().Format(time.RFC3339Nano)

		// First transfer pass: StartServing succeeds, public URL answers,
		// then Coolify stops with ErrAwaitingOperator asking operator to stop Go.
		err := w.eng.reverseTransfer(t.Context(), j)
		if !errors.Is(err, ErrAwaitingOperator) {
			t.Fatalf("first reverseTransfer: %v, want ErrAwaitingOperator", err)
		}
		afterFirst, err := readJournal(w.src.dir)
		if err != nil {
			t.Fatal(err)
		}
		if afterFirst.Phase != RollbackTransfer || afterFirst.Rollback.ServedAt != firstServedAt || afterFirst.Rollback.VerifiedAt != firstServedAt || afterFirst.Rollback.Undoing {
			t.Fatalf("after first pass: phase=%s rollback=%+v", afterFirst.Phase, afterFirst.Rollback)
		}

		// Operator stops Go, clock advances, and on --resume recreating the
		// dashboard fails once.
		w.tgt.running = false
		w.eng.sleep(5 * time.Minute)
		recreateErr := errors.New("docker compose up -d --no-deps --force-recreate varlatch-web: failed")
		src.did = nil
		src.startServingErr = recreateErr

		_, err = w.eng.Resume(t.Context())
		if !errors.Is(err, recreateErr) ||
			!strings.Contains(err.Error(), "may have accepted writes since "+firstServedAt) ||
			!strings.Contains(err.Error(), "varlatch migrate --resume") {
			t.Fatalf("resume on dashboard failure: %v", err)
		}
		for _, action := range src.did {
			if strings.HasPrefix(action, "undo ") || strings.HasPrefix(action, "hold ") || action == "stop serving" {
				t.Fatalf("undo action %q was called after StartServing succeeded: %v", action, src.did)
			}
		}
		afterFail, err := readJournal(w.src.dir)
		if err != nil {
			t.Fatal(err)
		}
		if afterFail.Phase != RollbackTransfer || afterFail.Rollback.Undoing || afterFail.Rollback.Undone != nil || afterFail.Rollback.ServedAt != firstServedAt {
			t.Fatalf("journal after failed retry: phase=%s rollback=%+v", afterFail.Phase, afterFail.Rollback)
		}
		if w.tgt.journal == nil || w.tgt.journal.Phase != RollbackTransfer {
			t.Fatalf("target journal after failed retry: %+v", w.tgt.journal)
		}

		// Cause fixed: a second --resume completes the rollback and keeps the
		// first ServedAt timestamp.
		src.did = nil
		src.startServingErr = nil
		w.eng.sleep(2 * time.Minute)
		resumed, err := w.eng.Resume(t.Context())
		if err != nil {
			t.Fatalf("second resume: %v", err)
		}
		if resumed.Phase != RolledBack || resumed.Rollback.ServedAt != firstServedAt || w.tgt.journal.Phase != RolledBack {
			t.Fatalf("after completion: phase=%s servedAt=%s target=%+v", resumed.Phase, resumed.Rollback.ServedAt, w.tgt.journal)
		}
		if slices.Contains(src.did, "undo p_postgres-data-abcdefgh") {
			t.Fatalf("undo was called on completion: %v", src.did)
		}
	})

	t.Run("waitForSource failure after StartServing does not undo", func(t *testing.T) {
		for _, kind := range []Ingress{Public, Coolify} {
			t.Run(string(kind), func(t *testing.T) {
				w, src, j := rolledWorld(t, RollbackChecked, kind)
				w.eng.Options.TransferTimeout = 2 * time.Second
				w.prober.sourceDown = true
				wantServedAt := w.eng.now().UTC().Format(time.RFC3339Nano)

				err := w.eng.reverseTransfer(t.Context(), j)
				if err == nil ||
					!strings.Contains(err.Error(), "did not answer from the TypeScript release") ||
					!strings.Contains(err.Error(), "may have accepted writes since "+wantServedAt) ||
					!strings.Contains(err.Error(), "varlatch migrate --resume") ||
					strings.Contains(err.Error(), "--abort undoes") {
					t.Fatalf("waitForSource failure: %v", err)
				}
				if slices.Contains(src.did, "undo p_postgres-data-abcdefgh") {
					t.Fatalf("undo was called after StartServing: %v", src.did)
				}
				after, rerr := readJournal(w.src.dir)
				if rerr != nil || after.Phase != RollbackTransfer || after.Rollback.ServedAt != wantServedAt || after.Rollback.Undoing {
					t.Fatalf("journal: %+v %v", after, rerr)
				}
			})
		}
	})

	t.Run("stopGo failure on coolify after StartServing does not undo", func(t *testing.T) {
		w, src, j := rolledWorld(t, RollbackChecked, Coolify)
		stopErr := errors.New("systemctl stop varlatchd failed")
		w.tgt.fail["stop"] = stopErr
		wantServedAt := w.eng.now().UTC().Format(time.RFC3339Nano)

		err := w.eng.reverseTransfer(t.Context(), j)
		if !errors.Is(err, stopErr) ||
			!strings.Contains(err.Error(), "may have accepted writes since "+wantServedAt) ||
			!strings.Contains(err.Error(), "varlatch migrate --resume") {
			t.Fatalf("stopGo failure: %v", err)
		}
		if slices.Contains(src.did, "undo p_postgres-data-abcdefgh") {
			t.Fatalf("undo was called after StartServing: %v", src.did)
		}
		after, rerr := readJournal(w.src.dir)
		if rerr != nil || after.Phase != RollbackTransfer || after.Rollback.Undoing || after.Rollback.ServedAt != wantServedAt {
			t.Fatalf("journal: %+v %v", after, rerr)
		}
	})
}

// --abort after StartServing has succeeded must refuse without undoing or
// removing the rebuilt volumes, including when reading a 0.50.0 journal that
// recorded VerifiedAt without ServedAt.
func TestRollbackAbortRefusedAfterStartServing(t *testing.T) {
	servedTime := "2026-11-26T09:15:00Z"

	for _, kind := range []Ingress{Coolify, Public} {
		t.Run("servedAt recorded, "+string(kind), func(t *testing.T) {
			w, src, j := rolledWorld(t, RollbackTransfer, kind)
			j.Rollback.ServedAt = servedTime
			if err := writeJournal(w.src.dir, j); err != nil {
				t.Fatal(err)
			}
			tgt := w.eng.Target.(*reverseTargetFake)

			_, err := w.eng.Abort(t.Context())
			want := "the rebuilt installation may have accepted writes since " + servedTime + "; resume instead"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Abort: %v, want substring %q", err, want)
			}
			if len(src.did) != 0 || tgt.released != 0 {
				t.Fatalf("Abort touched source or target: did=%v released=%d", src.did, tgt.released)
			}
			after, rerr := readJournal(w.src.dir)
			if rerr != nil || after.Phase != RollbackTransfer || after.Rollback.Undoing || after.Rollback.Undone != nil || after.Rollback.ServedAt != servedTime {
				t.Fatalf("journal changed: %+v %v", after, rerr)
			}

			// Defense in depth: undoReverse itself also refuses without marking Undoing.
			err = w.eng.undoReverse(t.Context(), after, errors.New("direct undo"))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("undoReverse: %v, want substring %q", err, want)
			}
			if len(src.did) != 0 || tgt.released != 0 {
				t.Fatalf("undoReverse touched source or target: did=%v released=%d", src.did, tgt.released)
			}
			afterDirect, rerr := readJournal(w.src.dir)
			if rerr != nil || afterDirect.Phase != RollbackTransfer || afterDirect.Rollback.Undoing {
				t.Fatalf("journal after direct undoReverse: %+v %v", afterDirect, rerr)
			}
		})
	}

	t.Run("0.50.0 journal with verifiedAt and no servedAt", func(t *testing.T) {
		w, src, j := rolledWorld(t, RollbackTransfer, Coolify)
		j.Rollback.ServedAt, j.Rollback.RecordsServing = "", false
		j.Rollback.VerifiedAt = servedTime
		if err := writeJournal(w.src.dir, j); err != nil {
			t.Fatal(err)
		}
		// Verify the serialized JSON has no servedAt key, as 0.50.0 wrote it.
		raw, err := os.ReadFile(filepath.Join(w.src.dir, JournalFile))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "servedAt") || strings.Contains(string(raw), "recordsServing") {
			t.Fatalf("unexpected servedAt or recordsServing in 0.50.0-style journal: %s", raw)
		}

		_, err = w.eng.Abort(t.Context())
		want := "the rebuilt installation may have accepted writes since " + servedTime + "; resume instead"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Abort on 0.50.0 journal: %v, want substring %q", err, want)
		}
		if len(src.did) != 0 {
			t.Fatalf("Abort touched source: %v", src.did)
		}

		// A failed StartServing on retry against the 0.50.0 journal also keeps
		// volumes and refuses to undo.
		recreateErr := errors.New("dashboard recreate failed")
		src.startServingErr = recreateErr
		_, err = w.eng.Resume(t.Context())
		if !errors.Is(err, recreateErr) || !strings.Contains(err.Error(), "may have accepted writes since "+servedTime) {
			t.Fatalf("Resume on 0.50.0 journal: %v", err)
		}
		if slices.Contains(src.did, "undo p_postgres-data-abcdefgh") {
			t.Fatalf("undo called on 0.50.0 journal retry: %v", src.did)
		}
		// The --resume recorded the protection: the 0.50.0 CLI no longer
		// reads the journal.
		after, err := readJournal(w.src.dir)
		if err != nil || after.Rollback.ServedAt != servedTime || !after.Rollback.RecordsServing {
			t.Fatalf("the adopted journal: %+v %v", after, err)
		}
	})
}

// Before StartServing has ever succeeded, failures and --abort still undo
// the reverse and return Go to open as before.
func TestRollbackUndoStillHappensBeforeStartServing(t *testing.T) {
	t.Run("a Go stop failure before StartServing undoes", func(t *testing.T) {
		w, src, j := rolledWorld(t, RollbackChecked, Public)
		tgt := w.eng.Target.(*reverseTargetFake)
		stopErr := errors.New("systemctl stop varlatchd failed")
		w.tgt.fail["stop"] = stopErr

		err := w.eng.reverseTransfer(t.Context(), j)
		if !errors.Is(err, stopErr) || !strings.Contains(err.Error(), "the reverse was undone") {
			t.Fatalf("Go stop failure: %v", err)
		}
		if slices.Contains(src.did, "serve") || !slices.Contains(src.did, "undo p_postgres-data-abcdefgh") || tgt.released != 1 {
			t.Fatalf("expected undo without StartServing: did=%v released=%d", src.did, tgt.released)
		}
		after, rerr := readJournal(w.src.dir)
		if rerr != nil || after.Phase != Open || after.Rollback.ServedAt != "" || after.Rollback.Undone == nil {
			t.Fatalf("journal after undo: %+v %v", after, rerr)
		}
	})

	t.Run("abort in rollback-transfer before StartServing undoes", func(t *testing.T) {
		w, src, j := rolledWorld(t, RollbackTransfer, Coolify)
		tgt := w.eng.Target.(*reverseTargetFake)
		if j.Rollback.ServedAt != "" || j.Rollback.VerifiedAt != "" {
			t.Fatalf("precondition: %+v", j.Rollback)
		}

		_, err := w.eng.Abort(t.Context())
		if err != nil {
			t.Fatalf("Abort before StartServing: %v", err)
		}
		if !slices.Contains(src.did, "undo p_postgres-data-abcdefgh") || tgt.released != 1 {
			t.Fatalf("expected undo: did=%v released=%d", src.did, tgt.released)
		}
		after, rerr := readJournal(w.src.dir)
		if rerr != nil || after.Phase != Open || after.Rollback.Undone == nil {
			t.Fatalf("journal after abort: %+v %v", after, rerr)
		}
	})
}

// Journal compatibility:
//   - a 0.50.0 journal without servedAt decodes cleanly in 0.50.1;
//   - a 0.50.1 reverse journal carries recordsServing from its start, which
//     the 0.50.0 CLI's strict decoder refuses (it can neither resume nor
//     undo it), while servedAt is omitted until set;
//   - it keeps format 1 and its phase, so varlatchd's journalHead parser
//     (which ignores other fields) accepts it.
func TestRollbackJournalCompatibility(t *testing.T) {
	dir := t.TempDir()
	v0500 := `{"format":1,"id":"mig_aaaaaaaaaaaaaaaaaaaaaaaaaa","phase":"rollback-transfer","stopped":false,"dryRunOnly":false,"source":{"kind":"compose","dir":"/x","release":"0.23.0","image":"i","digest":"sha256:x","digestRepository":"r"},"target":{"config":"/c","dataDir":"/d"},"maxDowntimeSeconds":600,"drainSeconds":60,"ingress":"coolify","rollback":{"startedAt":"2026-11-25T10:00:00Z","goStopped":false,"asked":true,"verifiedAt":"2026-11-25T10:05:00Z"},"history":[]}`
	if err := os.WriteFile(filepath.Join(dir, JournalFile), []byte(v0500), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := readJournal(dir)
	if err != nil || j == nil || j.Format != 1 || j.Rollback == nil || j.Rollback.ServedAt != "" || servedAt(j) != "2026-11-25T10:05:00Z" {
		t.Fatalf("reading 0.50.0 journal: %+v %v", j, err)
	}

	// Before StartServing: servedAt is omitted from JSON, recordsServing is
	// there.
	j.Rollback.VerifiedAt = ""
	j.Rollback.RecordsServing = true
	b, err := j.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "servedAt") || !strings.Contains(string(b), `"recordsServing": true`) {
		t.Fatalf("pre-StartServing journal: %s", b)
	}

	// After StartServing: format remains 1 and varlatchd 0.50.0's journalHead
	// projection unmarshals cleanly.
	j.Rollback.ServedAt = "2026-11-26T09:00:00Z"
	b, err = j.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var daemonHead struct {
		Format int    `json:"format"`
		ID     string `json:"id"`
		Phase  string `json:"phase"`
	}
	if err := json.Unmarshal(b, &daemonHead); err != nil || daemonHead.Format != 1 || daemonHead.ID != j.ID || daemonHead.Phase != string(RollbackTransfer) {
		t.Fatalf("varlatchd 0.50.0 head parse: %+v %v", daemonHead, err)
	}
}

// The crash window (point f): a run killed after StartServing made the
// rebuilt installation reachable, before anything after it was journalled.
// ServedAt is journalled before StartServing is called, so the journal the
// kill leaves says served: a --resume whose StartServing then fails keeps
// the fresh volumes and the phase, and --abort refuses.
func TestRollbackKilledRightAfterStartServingIsNotUndone(t *testing.T) {
	for _, kind := range []Ingress{Public, Coolify} {
		t.Run(string(kind), func(t *testing.T) {
			w, src, j := rolledWorld(t, RollbackChecked, kind)
			tgt := w.eng.Target.(*reverseTargetFake)
			wantServedAt := w.eng.now().UTC().Format(time.RFC3339Nano)
			type killed struct{}
			var onDisk *Journal
			src.startServing = func() error {
				// What is on disk while StartServing runs is what a kill
				// right after it (or right before it) leaves.
				var err error
				if onDisk, err = readJournal(w.src.dir); err != nil {
					t.Fatal(err)
				}
				panic(killed{})
			}
			func() {
				defer func() {
					if r := recover(); r != (killed{}) {
						t.Fatalf("not killed in StartServing: %v", r)
					}
				}()
				_ = w.eng.reverseTransfer(t.Context(), j)
			}()
			if onDisk == nil || onDisk.Phase != RollbackTransfer || onDisk.Rollback.ServedAt != wantServedAt || onDisk.Rollback.Undoing {
				t.Fatalf("the journal at StartServing: %+v", onDisk)
			}

			// --resume, its StartServing failing: not undone.
			src.did, src.startServing = nil, nil
			startErr := errors.New("docker compose up -d varlatchd: failed")
			src.startServingErr = startErr
			_, err := w.eng.Resume(t.Context())
			if !errors.Is(err, startErr) || !strings.Contains(err.Error(), "may have accepted writes since "+wantServedAt) || !strings.Contains(err.Error(), "varlatch migrate --resume") {
				t.Fatalf("--resume: %v", err)
			}
			if slices.Contains(src.did, "undo p_postgres-data-abcdefgh") || slices.Contains(src.did, "stop serving") || tgt.released != 0 {
				t.Fatalf("undone after the kill: did=%v released=%d", src.did, tgt.released)
			}
			after, err := readJournal(w.src.dir)
			if err != nil || after.Phase != RollbackTransfer || after.Rollback.ServedAt != wantServedAt || after.Rollback.Undoing || after.Rollback.Undone != nil {
				t.Fatalf("the journal after --resume: %+v %v", after, err)
			}

			// --abort refuses.
			src.did = nil
			if _, err := w.eng.Abort(t.Context()); err == nil || !strings.Contains(err.Error(), "may have accepted writes since "+wantServedAt) {
				t.Fatalf("--abort: %v", err)
			}
			if len(src.did) != 0 || tgt.released != 0 {
				t.Fatalf("--abort touched the source or the target: did=%v released=%d", src.did, tgt.released)
			}

			// The cause fixed: --resume finishes it, ServedAt kept.
			src.startServingErr, src.did = nil, nil
			if kind == Coolify {
				w.tgt.running = false
			}
			done, err := w.eng.Resume(t.Context())
			if err != nil || done.Phase != RolledBack || done.Rollback.ServedAt != wantServedAt {
				t.Fatalf("the last --resume: %v %+v", err, done)
			}
		})
	}
}

// P1-1: a first StartServing that fails after the rebuilt varlatchd took a
// connection (Compose starts it before it makes the dashboard again, behind
// a route that runs already) is not undone: ServedAt, journalled before the
// call, is kept, the fresh volumes too, and --abort refuses.
func TestRollbackFirstStartServingFailureKeepsVolumes(t *testing.T) {
	for _, kind := range []Ingress{Coolify, Public} {
		t.Run(string(kind), func(t *testing.T) {
			w, src, j := rolledWorld(t, RollbackChecked, kind)
			tgt := w.eng.Target.(*reverseTargetFake)
			wantServedAt := w.eng.now().UTC().Format(time.RFC3339Nano)
			recreateErr := errors.New("docker compose up -d --no-deps --force-recreate varlatch-web: failed")
			var seen string
			accepted := false
			src.startServing = func() error {
				on, err := readJournal(w.src.dir)
				if err != nil {
					t.Fatal(err)
				}
				seen = on.Rollback.ServedAt
				// varlatchd up: a listener opens and a client's request
				// reaches it, before the dashboard's recreation fails.
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				done := make(chan struct{})
				go func() {
					defer close(done)
					if c, err := l.Accept(); err == nil {
						buf := make([]byte, 5)
						if _, err := io.ReadFull(c, buf); err == nil && string(buf) == "write" {
							accepted = true
						}
						c.Close()
					}
				}()
				c, err := net.Dial("tcp", l.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				_, _ = c.Write([]byte("write"))
				c.Close()
				<-done
				return recreateErr
			}

			err := w.eng.reverseTransfer(t.Context(), j)
			if !errors.Is(err, recreateErr) || !strings.Contains(err.Error(), "may have accepted writes since "+wantServedAt) ||
				!strings.Contains(err.Error(), "varlatch migrate --resume") || strings.Contains(err.Error(), "the reverse was undone") {
				t.Fatalf("first StartServing failure: %v", err)
			}
			if !accepted || seen != wantServedAt {
				t.Fatalf("the listener took the write %v; ServedAt on disk at StartServing %q", accepted, seen)
			}
			if slices.Contains(src.did, "undo p_postgres-data-abcdefgh") || slices.Contains(src.did, "stop serving") || tgt.released != 0 {
				t.Fatalf("undone: did=%v released=%d", src.did, tgt.released)
			}
			after, rerr := readJournal(w.src.dir)
			if rerr != nil || after.Phase != RollbackTransfer || after.Rollback.ServedAt != wantServedAt || after.Rollback.Undoing || after.Rollback.Undone != nil {
				t.Fatalf("the journal: %+v %v", after, rerr)
			}
			src.did = nil
			if _, err := w.eng.Abort(t.Context()); err == nil || !strings.Contains(err.Error(), "may have accepted writes since "+wantServedAt) || len(src.did) != 0 {
				t.Fatalf("--abort: %v, did %v", err, src.did)
			}
		})
	}
}

// P1-2: a 0.50.0 journal in its transfer with neither ServedAt nor
// VerifiedAt (killed after StartServing, or a probe that timed out) may
// have served: --abort refuses, and --resume journals the protection
// before anything else, then goes forward.
func TestRollbackLegacyTransferWithoutTimestampsCountsAsServed(t *testing.T) {
	for _, kind := range []Ingress{Coolify, Public} {
		t.Run(string(kind), func(t *testing.T) {
			w, src, j := rolledWorld(t, RollbackTransfer, kind)
			tgt := w.eng.Target.(*reverseTargetFake)
			entered := "2026-11-25T10:01:00Z"
			j.Rollback.RecordsServing = false
			j.History = append(j.History, Step{Phase: RollbackTransfer, At: entered})
			if kind != Coolify {
				j.Rollback.GoStopped = true
				w.tgt.running = false
			}
			if err := writeJournal(w.src.dir, j); err != nil {
				t.Fatal(err)
			}

			if _, err := w.eng.Abort(t.Context()); err == nil || !strings.Contains(err.Error(), "may have accepted writes since "+entered) {
				t.Fatalf("--abort: %v", err)
			}
			if len(src.did) != 0 || tgt.released != 0 {
				t.Fatalf("--abort touched the source or the target: did=%v released=%d", src.did, tgt.released)
			}

			// --resume: the protection is on disk before anything is checked
			// or started; then it goes forward.
			var first *Journal
			src.check = func() error {
				if first == nil {
					var err error
					if first, err = readJournal(w.src.dir); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}
			done, err := w.eng.Resume(t.Context())
			if first == nil || first.Rollback.ServedAt != entered || !first.Rollback.RecordsServing {
				t.Fatalf("the journal at the first check: %+v", first)
			}
			if err != nil || done.Phase != RolledBack || slices.Contains(src.did, "undo p_postgres-data-abcdefgh") {
				t.Fatalf("--resume: %v %+v did=%v", err, done, src.did)
			}
		})
	}
}

// A 0.50.1 journal in its transfer with no ServedAt has not served (it
// journals one before StartServing): --abort undoes it.
func TestRollbackTransferNotYetServingIsUndone(t *testing.T) {
	w, src, j := rolledWorld(t, RollbackTransfer, Public)
	j.History = append(j.History, Step{Phase: RollbackTransfer, At: "2026-11-25T10:01:00Z"})
	if err := writeJournal(w.src.dir, j); err != nil {
		t.Fatal(err)
	}
	if _, err := w.eng.Abort(t.Context()); err != nil || !slices.Contains(src.did, "undo p_postgres-data-abcdefgh") {
		t.Fatalf("--abort: %v, did %v", err, src.did)
	}
}

// P1-3: the volumes' repair printed before the reverse records a start of
// the rebuilt release keeps varlatchd stopped; once recorded, it starts
// varlatchd with the database services as before.
func TestRollbackRepairKeepsVarlatchdStoppedBeforeServing(t *testing.T) {
	refusal := &notRebuiltError{why: errors.New("postgres runs on p_postgres-data, not on the fresh volume p_postgres-data-abcdefgh the journal names"), help: func(daemon bool) string {
		if daemon {
			return "2. docker compose up -d --no-deps postgres convex-backend varlatchd"
		}
		return "2. docker compose stop varlatchd; 3. docker compose up -d --no-deps postgres convex-backend"
	}}
	for _, served := range []bool{false, true} {
		t.Run(map[bool]string{false: "not yet", true: "recorded"}[served], func(t *testing.T) {
			w, src, j := rolledWorld(t, RollbackTransfer, Coolify)
			if served {
				j.Rollback.ServedAt = "2026-11-26T09:15:00Z"
				if err := writeJournal(w.src.dir, j); err != nil {
					t.Fatal(err)
				}
			}
			src.checkErr = refusal
			_, err := w.eng.Resume(t.Context())
			if err == nil || !strings.Contains(err.Error(), "is not on the fresh volumes") {
				t.Fatalf("--resume: %v", err)
			}
			kept := strings.Contains(err.Error(), "stop varlatchd") && !strings.Contains(err.Error(), "convex-backend varlatchd")
			if kept == served || strings.Contains(err.Error(), "--abort undoes") == served {
				t.Fatalf("served %v: %v", served, err)
			}
			if slices.Contains(src.did, "serve") {
				t.Fatalf("started: %v", src.did)
			}
		})
	}
}

// A 0.50.0 journal whose undo began (0.50.0's defect after it served).
// The undo goes on, since part of it may be done, but does not delete the
// fresh volumes: the installation goes back on its own volumes, the fresh
// ones are journalled (KeptVolumes) and left for the operator, on --resume
// and --abort alike, with a serving timestamp or without.
func TestRollbackUndoBegunBy050KeepsTheFreshVolumes(t *testing.T) {
	for _, verified := range []bool{true, false} {
		for _, abort := range []bool{false, true} {
			name := map[bool]string{false: "resume", true: "abort"}[abort] + map[bool]string{true: ", verified", false: ", no timestamp"}[verified]
			t.Run(name, func(t *testing.T) {
				w, src, j := rolledWorld(t, RollbackTransfer, Public)
				tgt := w.eng.Target.(*reverseTargetFake)
				if verified {
					j.Rollback.VerifiedAt = "2026-11-25T10:05:00Z"
				}
				j.Rollback.Undoing, j.Rollback.RecordsServing = true, false
				if err := writeJournal(w.src.dir, j); err != nil {
					t.Fatal(err)
				}
				if abort {
					if _, err := w.eng.Abort(t.Context()); err != nil {
						t.Fatalf("--abort: %v", err)
					}
				} else if _, err := w.eng.Resume(t.Context()); err == nil || !strings.Contains(err.Error(), "the reverse was undone") {
					t.Fatalf("--resume: %v", err)
				}
				after, err := readJournal(w.src.dir)
				if err != nil || after.Phase != Open || after.Rollback.Undone == nil || tgt.released != 1 {
					t.Fatalf("not undone: %+v %v released=%d", after, err, tgt.released)
				}
				if slices.Contains(src.did, "undo p_postgres-data-abcdefgh") || !slices.Contains(src.did, "undo, keeping p_postgres-data-abcdefgh") ||
					!slices.Equal(after.Rollback.KeptVolumes, []string{"p_postgres-data-abcdefgh", "p_convex-data-abcdefgh"}) {
					t.Fatalf("the fresh volumes: did=%v kept=%v", src.did, after.Rollback.KeptVolumes)
				}
			})
		}
	}
	// Before the transfer too: 0.50.0's printed volume repair started
	// varlatchd, so the phase does not prove nothing served. A reverse of
	// this release (marked) before it records a start removes them, as
	// before.
	for _, marked := range []bool{false, true} {
		t.Run(map[bool]string{false: "before the transfer, 0.50.0", true: "before the transfer, 0.50.1"}[marked], func(t *testing.T) {
			w, src, j := rolledWorld(t, RollbackChecked, Coolify)
			j.Rollback.Undoing, j.Rollback.RecordsServing = true, marked
			if err := writeJournal(w.src.dir, j); err != nil {
				t.Fatal(err)
			}
			if _, err := w.eng.Resume(t.Context()); err == nil || !strings.Contains(err.Error(), "the reverse was undone") {
				t.Fatalf("--resume: %v", err)
			}
			after, _ := readJournal(w.src.dir)
			removed := slices.Contains(src.did, "undo p_postgres-data-abcdefgh")
			if removed != marked || slices.Contains(src.did, "undo, keeping p_postgres-data-abcdefgh") == marked || (len(after.Rollback.KeptVolumes) == 0) != marked {
				t.Fatalf("did=%v kept=%v", src.did, after.Rollback.KeptVolumes)
			}
		})
	}
}

// The open retry (finishRestore): 0.50.0 undid a reverse, Go open, but
// could not put the TypeScript installation back (Unrestored). --resume
// puts it back and does not delete the fresh volumes, whatever phase the
// undo began in.
func TestRollbackOpenRetryOfA050UndoKeepsTheFreshVolumes(t *testing.T) {
	for _, c := range []struct {
		name     string
		verified bool
		from     Phase
	}{{"verified", true, RollbackTransfer}, {"no timestamp", false, RollbackTransfer}, {"undone before the transfer", false, RollbackChecked}} {
		t.Run(c.name, func(t *testing.T) {
			w, src, j := rolledWorld(t, Open, Public)
			if c.verified {
				j.Rollback.VerifiedAt = "2026-11-25T10:05:00Z"
			}
			j.Rollback.RecordsServing = false
			j.Rollback.Unrestored = "putting the TypeScript installation back: docker: failed"
			j.Rollback.Undone = &UndoneRecord{From: c.from, Why: "x", At: "2026-11-25T10:06:00Z", Released: true}
			if err := writeJournal(w.src.dir, j); err != nil {
				t.Fatal(err)
			}
			w.tgt.journal = &JournalHead{ID: j.ID, Phase: Open}
			if _, err := w.eng.Resume(t.Context()); err != nil {
				t.Fatalf("--resume: %v", err)
			}
			after, err := readJournal(w.src.dir)
			if err != nil || after.Rollback.Unrestored != "" || slices.Contains(src.did, "undo p_postgres-data-abcdefgh") || !slices.Contains(src.did, "undo, keeping p_postgres-data-abcdefgh") ||
				!slices.Equal(after.Rollback.KeptVolumes, []string{"p_postgres-data-abcdefgh", "p_convex-data-abcdefgh"}) {
				t.Fatalf("%+v %v did=%v", after, err, src.did)
			}
		})
	}
}

// P3 (second review): the public shape's "stop Go by hand" prompt offers
// --abort only while the reverse may still be undone.
func TestRollbackStopGoPromptOffersAbortOnlyBeforeServing(t *testing.T) {
	for _, served := range []bool{false, true} {
		t.Run(map[bool]string{false: "not yet", true: "adopted 0.50.0 transfer"}[served], func(t *testing.T) {
			w, _, j := rolledWorld(t, RollbackTransfer, Public)
			w.tgt.human = true
			if served {
				j.Rollback.RecordsServing = false
				j.History = append(j.History, Step{Phase: RollbackTransfer, At: "2026-11-25T10:01:00Z"})
			}
			err := w.eng.reverseTransfer(t.Context(), j)
			if !errors.Is(err, ErrAwaitingOperator) {
				t.Fatalf("reverseTransfer: %v", err)
			}
			said := strings.Join(w.said, "\n")
			if strings.Contains(said, "--abort undoes the reverse") == served || !strings.Contains(said, "Then varlatch migrate --resume starts the TypeScript release on the address") {
				t.Fatalf("served %v said:\n%s", served, said)
			}
		})
	}
}

// Point e: the tailnet name's return failing at its Prepare once the
// rebuilt release has served is not undone: the reverse stays in its
// transfer for --resume.
func TestRollbackTailnetPrepareFailureAfterServingIsNotUndone(t *testing.T) {
	w := newTailnetWorld(t)
	j, err := w.eng.Run(t.Context(), false)
	if err != nil || j.Phase != Open {
		t.Fatalf("%v %+v", err, j)
	}
	served := "2026-11-26T09:15:00Z"
	j.Phase = RollbackTransfer
	j.Rollback = &RollbackRecord{ServedAt: served, VerifiedAt: served, Rebuild: &RebuildRecord{Override: OverrideFile, Volumes: []string{"p_postgres-data-abcdefgh"}}}
	w.tgt.journal = &JournalHead{ID: j.ID, Phase: RollbackTransfer}
	w.tgt.running = false
	// The control server gone: Prepare cannot list the devices.
	w.cp.Close()
	err = w.eng.rollbackTailnet(t.Context(), j)
	if err == nil || !strings.Contains(err.Error(), "the tailnet name back") || !strings.Contains(err.Error(), "may have accepted writes since "+served) || !strings.Contains(err.Error(), "varlatch migrate --resume") {
		t.Fatalf("rollbackTailnet: %v", err)
	}
	if j.Phase != RollbackTransfer || j.Rollback.Undoing || j.Rollback.Undone != nil {
		t.Fatalf("undone: phase %s, %+v", j.Phase, j.Rollback)
	}
}
