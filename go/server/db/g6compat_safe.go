// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g6fixture && !g6unsafe

package db

// CompatibleFrom: G6's fixture step is rollback-safe, so a varlatchd of
// schema 1 may still open the database (version_g6fixture.go).
const CompatibleFrom = 1
