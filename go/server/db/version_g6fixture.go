// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g6fixture

package db

// G6's synthetic release (ADR-0059 G6; go/release/g6.sh): before the first
// Go release there is no previous release to check against, so G6 proves
// its machinery with this build, the current schema plus one rollback-safe
// step, against a build of the same commit without it. Never released:
// build-assets.sh does not set the tag.
//
// The step adds what a rollback-safe release may add (a table, a nullable
// column on an existing table) and writes a row of each new kind, so the
// previous build then runs on a database holding them.
const SchemaVersion = 2

// CompatibleFrom is g6compat_safe.go's (1: the step is rollback-safe, so
// version 1 may still open it) or, with the g6unsafe tag as well,
// g6compat_unsafe.go's (2: the same step declared not rollback-safe, which
// G6 checks the previous release then refuses).

const g6FixtureSQL = `
CREATE TABLE g6_fixture (
  id INTEGER NOT NULL PRIMARY KEY,
  note TEXT NOT NULL CHECK (length(note) BETWEEN 1 AND 64)
) STRICT;
ALTER TABLE installation ADD COLUMN g6_note TEXT CHECK (g6_note IS NULL OR length(g6_note) <= 64);
`

var steps = []Step{{
	To: 2, CompatibleFrom: CompatibleFrom,
	SQL: g6FixtureSQL + `
INSERT INTO g6_fixture (note) VALUES ('written by the G6 fixture release');
UPDATE installation SET g6_note = 'written by the G6 fixture release';
`,
}}

// schemaExtra makes a new database of this build the same as an upgraded
// one, without the rows.
const schemaExtra = g6FixtureSQL
