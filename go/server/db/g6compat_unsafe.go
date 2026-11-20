// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g6fixture && g6unsafe

package db

// CompatibleFrom: the same fixture step declared not rollback-safe, so a
// varlatchd of schema 1 must refuse the database (version_g6fixture.go; G6's
// not-rollback-safe case).
const CompatibleFrom = 2
