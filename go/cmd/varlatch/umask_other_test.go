// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

// Windows has no umask; only the read-only bit of a mode is compared there.
func setTranscriptUmask() {}
