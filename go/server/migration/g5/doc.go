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
// header says what is real and what stands in). The reverse half is
// 7.6a's.
package g5
