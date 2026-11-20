// SPDX-License-Identifier: AGPL-3.0-or-later

package schemadiff

import (
	"fmt"

	"github.com/varlatch/varlatch/go/lib/release"
)

// Judge holds a release's declaration (go/release/release.json) against
// the changes from its previous release's schema: what fails G6
// (problems) and what its reviewers confirm (notes).
//
//   - No previous release (before the first Go release): nothing to hold
//     it against; the changes are notes.
//   - A changed schema keeps its version: a problem (every change to
//     schema.sql after a release raises SchemaVersion, with its step).
//   - Declared rollback-safe: each breaking change is a problem, each
//     review change a note for the release checklist.
//   - Not declared rollback-safe: the changes are notes; the declaration
//     already keeps the previous release's varlatchd out.
func Judge(changes []Change, d release.Declaration) (problems, notes []string) {
	if d.Previous == nil {
		notes = append(notes, "no previous Go release: the schema is not held against one")
		for _, c := range changes {
			notes = append(notes, c.String())
		}
		return nil, notes
	}
	p := d.Previous
	if len(changes) > 0 && d.SchemaVersion == p.SchemaVersion {
		problems = append(problems, fmt.Sprintf("the schema changed since %s, but its version is still %d: raise SchemaVersion and add the step", p.Version, p.SchemaVersion))
	}
	for _, c := range changes {
		switch {
		case d.RollbackSafe && c.Class == Breaking:
			problems = append(problems, fmt.Sprintf("declared rollback-safe against %s, but %s", p.Version, c))
		case d.RollbackSafe && c.Class == Review:
			notes = append(notes, fmt.Sprintf("for the release checklist: %s", c))
		default:
			notes = append(notes, c.String())
		}
	}
	return problems, notes
}
