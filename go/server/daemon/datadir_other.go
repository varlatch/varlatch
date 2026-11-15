// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package daemon

// varlatchd serves on Unix systems only; elsewhere lockDataDir refuses, so
// there is nothing to check.

type dirID struct{}

func checkServeDir(string, int) (dirID, error)       { return dirID{}, nil }
func checkClientDir(string, int) (int, dirID, error) { return -1, dirID{}, nil }
func serverPeerAllowed(int, int) bool                { return false }
func sameDir(string, dirID) error                    { return nil }
