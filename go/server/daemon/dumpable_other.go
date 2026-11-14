// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package daemon

// varlatchd runs on Linux only (ADR-0059 Decision 1); elsewhere the package
// still builds and vets.
func disableDumps() error { return nil }

func dumpable() (int, error) { return 0, nil }
