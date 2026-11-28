// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !g6fixture

package db

// SchemaVersion is the version of schema.sql, recorded in the database's
// schema_version table.
//
// The version is a table row, not PRAGMA user_version, for three reasons:
// the storage engine refuses PRAGMA assignments inside a write job, so a
// pragma could not be set in the job that creates or upgrades the schema,
// and the version would not commit atomically with it; the row also holds
// compatible_from, which rollback-safe upgrades need (ADR-0059 Decision 8,
// G6: an older varlatchd may open a database a rollback-safe newer release
// wrote); and it says which release created and last changed the schema.
//
// Up to the first Go release (0.50.0-rc.1, schema 1), schema.sql changed in
// place under version 1. From that release on, every change to schema.sql
// raises this number and adds its Step to releaseSteps (steps.go), which
// Upgrade (`varlatchd admin schema upgrade`, run by `varlatch upgrade`)
// applies; go/release/release.json declares whether the release is
// rollback-safe, and G6 checks it, and each step's own CompatibleFrom
// against that step's changes (server/db/releasecheck).
const SchemaVersion = 7

// CompatibleFrom is the oldest schema version whose varlatchd may open a
// database of this schema: the last step's CompatibleFrom, or SchemaVersion
// when there is none. Init records it for a new database and Upgrade after
// the last step.
const CompatibleFrom = 1

// steps are the upgrades from each released schema version to the next, in
// order: steps[i] upgrades version i+1 to i+2.
var steps = releaseSteps

// schemaExtra is appended to schema.sql for a new database: nothing here
// (G6's fixture build adds its synthetic change).
const schemaExtra = ""
