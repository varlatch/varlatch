// SPDX-License-Identifier: AGPL-3.0-or-later

package schemadiff

import (
	"context"
	"database/sql"
	"fmt"
)

// Step is one schema upgrade step as the check sees it: package db's Step
// (go/server/db/upgrade.go), which upgrades version To-1 to To and declares
// CompatibleFrom, the oldest schema version whose varlatchd may open the
// database after it.
type Step struct {
	To             int64  `json:"to"`
	CompatibleFrom int64  `json:"compatibleFrom"`
	SQL            string `json:"-"`
}

// RollbackSafe reports whether the step declares itself rollback-safe: its
// CompatibleFrom is older than its own version, so the varlatchd of the
// version before it (To-1) still opens the database after it.
func (s Step) RollbackSafe() bool { return s.CompatibleFrom < s.To }

// StepChanges is what one step changes: from the schema just before it to
// the schema just after it.
type StepChanges struct {
	Step
	Changes []Change `json:"changes"`
}

// DiffSteps runs the steps in turn on a database of the schema older
// creates, as an upgrade does (schema changes and the rows they need), and
// returns each step's changes, in Diff's order. rest is what still differs
// from the schema the last step leaves to the one newer creates: nothing
// when the steps give newer's schema.
func DiffSteps(ctx context.Context, older string, steps []Step, newer string) (judged []StepChanges, rest []Change, err error) {
	target, err := load(ctx, newer)
	if err != nil {
		return nil, nil, fmt.Errorf("schemadiff: the newer schema: %w", err)
	}
	err = withMemory(ctx, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx, older); err != nil {
			return fmt.Errorf("schemadiff: the older schema: %w", err)
		}
		before, err := read(ctx, conn)
		if err != nil {
			return fmt.Errorf("schemadiff: the older schema: %w", err)
		}
		for _, st := range steps {
			if _, err := conn.ExecContext(ctx, st.SQL); err != nil {
				return fmt.Errorf("schemadiff: the step to schema %d: %w", st.To, err)
			}
			after, err := read(ctx, conn)
			if err != nil {
				return fmt.Errorf("schemadiff: the schema after the step to %d: %w", st.To, err)
			}
			judged = append(judged, StepChanges{Step: st, Changes: compare(before, after)})
			before = after
		}
		rest = compare(before, target)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return judged, rest, nil
}

// JudgeSteps holds each step's own CompatibleFrom against that step's
// changes (ADR-0059 Decision 8): what fails G6 (problems) and what its
// reviewers confirm (notes).
//
// A step that declares itself rollback-safe (CompatibleFrom below its To)
// promises that the varlatchd of the version before it still opens the
// database after it, so it may make only the changes Judge allows a
// release declared rollback-safe: each breaking change is a problem, each
// review change a note for the release checklist. A step whose
// CompatibleFrom is its own To may change anything: the older varlatchd
// refuses its result. As CompatibleFrom never goes down from one step to
// the next, a step judged this way also keeps every older version it
// names: each step after that version is a rollback-safe one, judged
// against the schema just before it.
//
// This is what varlatchd serve relies on in the image, where it applies a
// pending upgrade at start whenever the last step's CompatibleFrom is not
// newer than the database's version (db.UpgradeIfRollbackSafe).
func JudgeSteps(steps []StepChanges) (problems, notes []string) {
	for _, s := range steps {
		if !s.RollbackSafe() {
			notes = append(notes, fmt.Sprintf("the step to schema %d (compatible from %d): %d schema changes, not rollback-safe", s.To, s.CompatibleFrom, len(s.Changes)))
			continue
		}
		notes = append(notes, fmt.Sprintf("the step to schema %d (compatible from %d): %d schema changes, rollback-safe", s.To, s.CompatibleFrom, len(s.Changes)))
		for _, c := range s.Changes {
			switch c.Class {
			case Breaking:
				problems = append(problems, fmt.Sprintf("the step to schema %d declares compatibleFrom %d, so the varlatchd of schema %d must still open the database after it, but %s: raise the step's compatibleFrom to %d, or make the change additive",
					s.To, s.CompatibleFrom, s.To-1, c, s.To))
			case Review:
				notes = append(notes, fmt.Sprintf("for the release checklist: the step to schema %d: %s", s.To, c))
			}
		}
	}
	return problems, notes
}
