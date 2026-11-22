// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeMaker stands in for setup's PrepareTarget and UndoTarget.
type fakeMaker struct {
	missing bool
	// failAt fails Make once that item is named; killAt kills the run
	// there (a panic the test recovers: what is on disk stays as it is).
	failAt, killAt string
	// undoFails fails that many Undo calls, each at the user (the last
	// item removed: what comes before it is gone, the configuration too).
	undoFails int
	// present are the keys' files there; there the other items made, on
	// the host.
	present, there map[string]bool
	// where is Where's ("" setup's place).
	where  string
	made   []string
	undone [][]string
	// journals is the source's journal as each item was named.
	journals []string
	dir      string
}

// killed is the panic of a run killed by killAt.
type killed struct{}

func (m *fakeMaker) Missing() bool { return m.missing }
func (m *fakeMaker) Make(_ context.Context, src IngressInfo, kind Ingress, _ []string, made func(string) error) error {
	for _, item := range []string{"user", "etc-dir", "data-dir", "unit-enabled", "config"} {
		if err := made(item); err != nil {
			return err
		}
		b, _ := os.ReadFile(filepath.Join(m.dir, JournalFile))
		m.journals = append(m.journals, string(b))
		if item == m.killAt {
			m.killAt = ""
			panic(killed{})
		}
		if item == m.failAt {
			m.failAt = ""
			return errors.New("useradd: cannot lock /etc/passwd")
		}
		m.made = append(m.made, item)
		if m.there == nil {
			m.there = map[string]bool{}
		}
		m.there[item] = true
	}
	m.missing = false
	return nil
}
func (m *fakeMaker) Undo(made []string) error {
	m.undone = append(m.undone, slices.Clone(made))
	for _, item := range []string{"backup-key", "root-kek", "config", "unit-enabled", "data-dir", "etc-dir", "user"} {
		if !slices.Contains(made, item) {
			continue
		}
		if item == "user" && m.undoFails > 0 {
			m.undoFails--
			return errors.New("userdel: user varlatch is currently used by process 1234")
		}
		delete(m.there, item)
		delete(m.present, item)
		if item == "config" {
			m.missing = true
		}
	}
	m.missing = true
	return nil
}
func (m *fakeMaker) Left(made []string) ([]string, error) {
	var left []string
	for _, item := range made {
		if m.there[item] || m.present[item] {
			left = append(left, item+" (fake)")
		}
	}
	return left, nil
}
func (m *fakeMaker) KeyItems() (string, string)        { return "root-kek", "backup-key" }
func (m *fakeMaker) Present(item string) (bool, error) { return m.present[item], nil }
func (m *fakeMaker) Where() string {
	if m.where != "" {
		return m.where
	}
	return "/etc/varlatch/varlatchd.conf"
}

// runKilled runs f, a run killAt kills.
func runKilled(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != (killed{}) {
			t.Fatalf("not killed: %v", r)
		}
	}()
	f()
	t.Fatal("not killed")
}

// A target migrate makes (slice 7.4e): each item journalled in the source's
// journal before it is made; the migration goes on to it; an undo before
// the switch removes exactly the items made, the keys' files included,
// after both journals say released; a failure while making removes what
// was made; a target that is there is never made, nor removed.
func TestTheTargetMigrateMakes(t *testing.T) {
	t.Run("made, then undone", func(t *testing.T) {
		w := newWorld(t)
		m := &fakeMaker{missing: true, dir: w.src.dir}
		w.eng.Maker = m
		j, err := w.eng.Run(context.Background(), true)
		if err != nil {
			t.Fatal(err)
		}
		for i, item := range []string{"user", "etc-dir", "data-dir", "unit-enabled", "config"} {
			if !strings.Contains(m.journals[i], `"`+item+`"`) {
				t.Errorf("%s was made before the journal named it", item)
			}
		}
		want := []string{"user", "etc-dir", "data-dir", "unit-enabled", "config", "root-kek", "backup-key"}
		if j.Created == nil || !slices.Equal(j.Created.Made, want) {
			t.Fatalf("the record: %+v, want %v", j.Created, want)
		}
		j, err = w.eng.Abort(context.Background())
		if err != nil || j.Phase != Released {
			t.Fatalf("--abort: %v %v", j.Phase, err)
		}
		if len(m.undone) != 1 || !slices.Equal(m.undone[0], want) || j.Created.Undone == "" {
			t.Fatalf("undone %v (record %+v)", m.undone, j.Created)
		}
		if again, err := w.eng.Resume(context.Background()); err != nil || len(m.undone) != 1 || again.Created.Undone == "" {
			t.Errorf("a --resume after: %v, undone %d times", err, len(m.undone))
		}
		// A new migration makes it again.
		if _, err := w.eng.Run(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		if m.missing {
			t.Error("not made again")
		}
	})
	t.Run("a failure while making", func(t *testing.T) {
		w := newWorld(t)
		m := &fakeMaker{missing: true, failAt: "data-dir", dir: w.src.dir}
		w.eng.Maker = m
		_, err := w.eng.Run(context.Background(), true)
		if err == nil || !strings.Contains(err.Error(), "what was made is removed") {
			t.Fatalf("Run: %v", err)
		}
		if len(m.undone) != 1 || !slices.Equal(m.undone[0], []string{"user", "etc-dir", "data-dir"}) {
			t.Fatalf("undone %v", m.undone)
		}
		if len(w.tgt.keys) != 0 {
			t.Error("keys were installed into a target not made")
		}
		// Stopped, not interrupted: once fixed, the next run starts again.
		if j, _ := Status(w.src.dir); j == nil || !j.Stopped || j.Phase != Started {
			t.Fatalf("the journal after the failure: %+v", j)
		}
		if _, err := w.eng.Run(context.Background(), true); err != nil {
			t.Fatalf("the next run: %v", err)
		}
		if m.missing {
			t.Error("not made by the next run")
		}
	})
	t.Run("a target that is there", func(t *testing.T) {
		w := newWorld(t)
		m := &fakeMaker{missing: false, dir: w.src.dir}
		w.eng.Maker = m
		j, err := w.eng.Run(context.Background(), true)
		if err != nil {
			t.Fatal(err)
		}
		if j.Created != nil || len(m.journals) != 0 {
			t.Fatalf("a prepared target was made: %+v", j.Created)
		}
		if _, err := w.eng.Abort(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(m.undone) != 0 {
			t.Error("a prepared target was removed")
		}
	})
	t.Run("keys found the same are not migrate's", func(t *testing.T) {
		w := newWorld(t)
		m := &fakeMaker{missing: true, dir: w.src.dir}
		w.eng.Maker = m
		w.tgt.keysState = "unchanged"
		j, err := w.eng.Run(context.Background(), true)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(j.Created.Made, "root-kek") || slices.Contains(j.Created.Made, "backup-key") {
			t.Errorf("keys there already recorded as made: %v", j.Created.Made)
		}
	})
	t.Run("keys there before are never migrate's, when the preflight stops before judging them", func(t *testing.T) {
		w := newWorld(t)
		m := &fakeMaker{missing: true, dir: w.src.dir, present: map[string]bool{"root-kek": true, "backup-key": true}}
		w.eng.Maker = m
		w.tgt.fail = map[string]error{"keys": errors.New("admin migrate keys: refused")}
		if _, err := w.eng.Run(context.Background(), true); err == nil {
			t.Fatal("the preflight did not stop")
		}
		if j, _ := Status(w.src.dir); slices.Contains(j.Created.Made, "root-kek") || slices.Contains(j.Created.Made, "backup-key") {
			t.Errorf("keys there before recorded as made: %v", j.Created.Made)
		}
		if _, err := w.eng.Abort(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(m.undone) != 1 || slices.Contains(m.undone[0], "root-kek") || slices.Contains(m.undone[0], "backup-key") {
			t.Errorf("--abort removes keys that were there before: %v", m.undone)
		}
	})
	t.Run("keys an earlier run of the migration wrote stay migrate's", func(t *testing.T) {
		w := newWorld(t)
		m := &fakeMaker{missing: true, dir: w.src.dir}
		w.eng.Maker = m
		if _, err := w.eng.Run(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		// The second run finds the files the first wrote.
		m.present = map[string]bool{"root-kek": true, "backup-key": true}
		w.tgt.keysState = "unchanged"
		j, err := w.eng.Run(context.Background(), true)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(j.Created.Made, "root-kek") || !slices.Contains(j.Created.Made, "backup-key") {
			t.Fatalf("the keys the first run wrote were struck: %v", j.Created.Made)
		}
		if _, err := w.eng.Abort(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(m.undone) != 1 || !slices.Contains(m.undone[0], "root-kek") || !slices.Contains(m.undone[0], "backup-key") {
			t.Errorf("the undo leaves the keys migrate wrote: %v", m.undone)
		}
	})
	t.Run("an undo whose removal fails is not done", func(t *testing.T) {
		w := newWorld(t)
		m := &fakeMaker{missing: true, dir: w.src.dir}
		w.eng.Maker = m
		if _, err := w.eng.Run(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		m.undoFails = 1
		j, err := w.eng.Abort(context.Background())
		if err == nil || !strings.Contains(err.Error(), "not all removed") || j.Phase != Released || j.Created.Undone != "" {
			t.Fatalf("--abort with the removal failed: %v (%+v)", err, j)
		}
		// The way out, should it keep failing, is named.
		if !strings.Contains(err.Error(), "remove what is left of user, etc-dir, data-dir, unit-enabled, config") || !strings.Contains(err.Error(), "--abort --forget-target") {
			t.Errorf("no way out named: %v", err)
		}
		if _, err := w.eng.Run(context.Background(), true); err == nil || !strings.Contains(err.Error(), "varlatch migrate --abort removes it") {
			t.Fatalf("a new migration over it: %v", err)
		}
		if j, _ := Status(w.src.dir); j.Created == nil || j.Created.Undone != "" || len(j.Created.Made) == 0 {
			t.Fatalf("the record was lost: %+v", j.Created)
		}
		j, err = w.eng.Abort(context.Background())
		if err != nil || j.Created.Undone == "" || len(m.undone) != 2 {
			t.Fatalf("--abort again: %v, undone %v", err, m.undone)
		}
		if _, err := w.eng.Run(context.Background(), true); err != nil {
			t.Fatalf("a new migration after: %v", err)
		}
	})
	t.Run("a dry run killed while making the target resumes as a dry run", func(t *testing.T) {
		w := newWorld(t)
		m := &fakeMaker{missing: true, dir: w.src.dir, killAt: "config"}
		w.eng.Maker = m
		runKilled(t, func() { _, _ = w.eng.Run(context.Background(), true) })
		if j, _ := Status(w.src.dir); j == nil || !j.DryRunOnly {
			t.Fatalf("the journal of the killed dry run: %+v", j)
		}
		j, err := w.eng.Resume(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if j.Phase != DryRun || !j.Stopped || containsCall(w.src.calls, "barrier") {
			t.Fatalf("--resume went on to %s (stopped %v): a dry run is resumed as one", j.Phase, j.Stopped)
		}
	})
	t.Run("a removal that keeps failing, finished by hand", func(t *testing.T) {
		w := newWorld(t)
		m := &fakeMaker{missing: true, dir: w.src.dir}
		w.eng.Maker = m
		if _, err := w.eng.ForgetTarget(context.Background()); err == nil {
			t.Fatal("--forget-target with no journal")
		}
		if _, err := w.eng.Run(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		if _, err := w.eng.ForgetTarget(context.Background()); err == nil || !strings.Contains(err.Error(), "records no target left to remove") {
			t.Fatalf("--forget-target before an undo: %v", err)
		}
		m.undoFails = 1 << 20
		if _, err := w.eng.Abort(context.Background()); err == nil {
			t.Fatal("--abort did not fail")
		}
		// The undo removed the configuration, then failed at the user:
		// the user is left, so nothing is forgotten.
		if !m.missing {
			t.Fatal("the fake's undo did not remove the configuration before the user")
		}
		if _, err := w.eng.ForgetTarget(context.Background()); err == nil || !strings.Contains(err.Error(), "still there: user (fake)") {
			t.Fatalf("--forget-target with the user there: %v", err)
		}
		// A retried --abort that fails again names the way out too.
		if _, err := w.eng.Abort(context.Background()); err == nil || !strings.Contains(err.Error(), "--abort --forget-target") {
			t.Errorf("--abort again: %v", err)
		}
		// Another place's maker: refused, the place named.
		w.eng.Maker = &fakeMaker{where: "/elsewhere/etc/varlatch/varlatchd.conf"}
		if _, err := w.eng.ForgetTarget(context.Background()); err == nil || !strings.Contains(err.Error(), "is at /etc/varlatch/varlatchd.conf, not this run's") {
			t.Errorf("--forget-target with another place's maker: %v", err)
		}
		// Not this run's to check: the target flags name it.
		w.eng.Maker = nil
		if _, err := w.eng.Abort(context.Background()); err == nil || !strings.Contains(err.Error(), "--abort --config /etc/varlatch/varlatchd.conf") {
			t.Errorf("--abort without the maker: %v", err)
		}
		if _, err := w.eng.Run(context.Background(), true); err == nil || !strings.Contains(err.Error(), "--abort --config /etc/varlatch/varlatchd.conf") {
			t.Errorf("a new migration without the maker: %v", err)
		}
		w.eng.Maker = m
		delete(m.there, "user") // the operator removed the rest by hand
		j, err := w.eng.ForgetTarget(context.Background())
		if err != nil || !j.Created.Forgotten || j.Created.Undone == "" {
			t.Fatalf("--forget-target: %v %+v", err, j.Created)
		}
		m.undoFails = 0
		if _, err := w.eng.Run(context.Background(), true); err != nil {
			t.Fatalf("a new migration after: %v", err)
		}
	})
	t.Run("a journal's record is checked as it is read", func(t *testing.T) {
		w := newWorld(t)
		for _, rec := range []string{
			`{"made":["user"],"config":"/etc/varlatch/varlatchd.conf; rm -rf /"}`,
			`{"made":["user"],"config":"/tmp/x"}`,
			`{"made":["user\u001b[2J"]}`,
			`{"made":["user"],"undone":"soon\u001b[2J"}`,
		} {
			j := `{"format":1,"id":"mig_x","phase":"released","history":[],"created":` + rec + `}`
			if err := os.WriteFile(filepath.Join(w.src.dir, JournalFile), []byte(j), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Status(w.src.dir); err == nil || !strings.Contains(err.Error(), "is not a migration journal") {
				t.Errorf("%s: %v", rec, err)
			}
		}
	})
	t.Run("a source on a tailnet, or the tailnet's authority, is refused before anything is made", func(t *testing.T) {
		// The source serves a tailnet address, the authority given.
		tn := newTailnetWorld(t)
		m := &fakeMaker{missing: true, dir: tn.world.src.dir}
		tn.eng.Maker = m
		_, err := tn.eng.Run(context.Background(), true)
		if err == nil || !strings.Contains(err.Error(), "is never on a tailnet") || !strings.Contains(err.Error(), "nothing was done") {
			t.Fatalf("a tailnet source: %v", err)
		}
		if len(m.journals) != 0 || len(tn.world.tgt.keys) != 0 || containsCall(tn.world.src.calls, "backup") || containsCall(tn.world.src.calls, "kek") {
			t.Fatalf("something was made or backed up: journals %d, keys %d, source calls %v", len(m.journals), len(tn.world.tgt.keys), tn.world.src.calls)
		}
		if j, _ := Status(tn.world.src.dir); j != nil {
			t.Fatalf("a journal was written: %+v", j)
		}
		// The authority given alone, the source on no tailnet.
		w := newWorld(t)
		m = &fakeMaker{missing: true, dir: w.src.dir}
		w.eng.Maker, w.eng.Tailnet = m, &TailnetOptions{}
		if _, err := w.eng.Run(context.Background(), true); err == nil || !strings.Contains(err.Error(), "the tailnet's authority or auth key was given") {
			t.Fatalf("the authority given: %v", err)
		}
		if len(m.journals) != 0 || containsCall(w.src.calls, "backup") {
			t.Fatalf("something was made or backed up: journals %d, source calls %v", len(m.journals), w.src.calls)
		}
	})
	t.Run("a made target whose configuration went missing is undone the ordinary way", func(t *testing.T) {
		w := newWorld(t)
		m := &fakeMaker{missing: true, dir: w.src.dir}
		w.eng.Maker = m
		j, err := w.eng.Run(context.Background(), true)
		if err != nil || j.Target.Config == "" {
			t.Fatalf("the dry run: %v (target %+v)", err, j.Target)
		}
		// Its configuration removed by someone else, mid-migration.
		m.missing = true
		if _, err := w.eng.Abort(context.Background()); err != nil {
			t.Fatal(err)
		}
		// The ordinary undo: the target's own journal says released too.
		if w.tgt.journal == nil || w.tgt.journal.Phase != Released {
			t.Fatalf("the target's journal after the undo: %+v", w.tgt.journal)
		}
	})
}
