// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package daemon

// varlatchd serves on Unix systems only; elsewhere lockDataDir refuses, so
// there is nothing to check.
func checkServeDir(string, int) error  { return nil }
func checkClientDir(string, int) error { return nil }
