// SPDX-License-Identifier: Apache-2.0

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
	// failAt fails Make once that item is named.
	failAt string
	made   []string
	undone [][]string
	// journals is the source's journal as each item was named.
	journals []string
	dir      string
}

func (m *fakeMaker) Missing() bool { return m.missing }
func (m *fakeMaker) Make(_ context.Context, src IngressInfo, kind Ingress, made func(string) error) error {
	for _, item := range []string{"user", "etc-dir", "data-dir", "config", "unit-enabled"} {
		if err := made(item); err != nil {
			return err
		}
		b, _ := os.ReadFile(filepath.Join(m.dir, JournalFile))
		m.journals = append(m.journals, string(b))
		if item == m.failAt {
			return errors.New("useradd: cannot lock /etc/passwd")
		}
		m.made = append(m.made, item)
	}
	m.missing = false
	return nil
}
func (m *fakeMaker) Undo(made []string) error {
	m.undone = append(m.undone, slices.Clone(made))
	m.missing = true
	return nil
}
func (m *fakeMaker) KeyItems() (string, string) { return "root-kek", "backup-key" }

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
		for i, item := range []string{"user", "etc-dir", "data-dir", "config", "unit-enabled"} {
			if !strings.Contains(m.journals[i], `"`+item+`"`) {
				t.Errorf("%s was made before the journal named it", item)
			}
		}
		want := []string{"user", "etc-dir", "data-dir", "config", "unit-enabled", "root-kek", "backup-key"}
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
}
