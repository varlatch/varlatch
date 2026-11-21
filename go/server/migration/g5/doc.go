// SPDX-License-Identifier: AGPL-3.0-or-later

// Package g5 is G5's damage gate (ADR-0059 G5; internal
// docs/design/go-step7.md slice 7.3c): the migration's whole Go path,
// through the varlatchd binary (a forward bundle, `admin migrate import`,
// `admin migrate check` with the run key on a pipe), held on a seeded
// installation to every damage G5 lists and those the checks add, each
// failing at its stage and its check, named, with nothing secret printed.
// The gate is g5_test.go, built with the g5 tag; CI's go job runs it as
// its own step (.github/workflows/go.yml, "G5, the migration's damage
// gate"). interrupt_test.go is G5's interrupted half (slice 7.4c): the
// real `varlatch migrate` (built with the crashpoint tag) killed at every
// phase boundary and held to decision 14's stated states, against a real
// target varlatchd and a stand-in for the last TypeScript release (its
// header says what is real and what stands in). reverse_test.go is G5's
// reverse half (slice 7.6a): Go's barrier, the reverse export from its
// frozen copy, the TypeScript import and export stood in for
// (migrationtest.FromReverse), the reverse checks, and a second forward
// migration reproducing the state, on the seeded installation and after
// each kind of change made on Go (kinds_test.go). rollback_test.go is the
// interrupted reverse (slice 7.6a): the real `varlatch migrate --rollback`
// killed at every phase boundary of the reverse, Go running until the
// address moves back, the TypeScript side's rebuild on a fresh volume
// stood in for (its header says what). finish_test.go is --finish: the
// window ended after a forward migration and after a reverse, the old data
// deleted only with --delete-old-data and only after its verified final
// archive, killed at each step and finished by --resume.
// maketarget_test.go is the host target migrate makes (slice 7.4e) under a
// test root: migrated into, undone, killed while making it.
package g5
