// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"testing"
)

// RollbackWindowOpen is varlatch upgrade's question (decision 17, #368's
// endsRollbackWindow): open while the Go installation's journal is open or
// a reverse is under way; closed for an installation never migrated, or
// once --finish ended the window (or a reverse rolled it back).
func TestRollbackWindowOpen(t *testing.T) {
	dir := t.TempDir()
	if open, err := RollbackWindowOpen(dir); err != nil || open {
		t.Fatalf("no migration: %v %v", open, err)
	}
	for _, c := range []struct {
		phase Phase
		open  bool
	}{
		{Started, false}, {Transfer, false}, {Switched, false}, {Open, true}, {Rollback, true}, {RollbackChecked, true},
		{RollbackTransfer, true}, {RolledBack, false}, {Finished, false}, {Released, false},
	} {
		if err := writeJournal(dir, &Journal{Format: 1, ID: "mig_aaaaaaaaaaaaaaaaaaaaaaaaaa", Phase: c.phase, History: []Step{}}); err != nil {
			t.Fatal(err)
		}
		if open, err := RollbackWindowOpen(dir); err != nil || open != c.open {
			t.Errorf("%s: %v %v, want %v", c.phase, open, err, c.open)
		}
	}
}
