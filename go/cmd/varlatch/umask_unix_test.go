// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import "syscall"

// setTranscriptUmask sets goKit.ts's TRANSCRIPT_UMASK: the transcripts were
// recorded under it, so the modes they hold are compared under it too (the
// CLI under test inherits it).
func setTranscriptUmask() { syscall.Umask(0o022) }
