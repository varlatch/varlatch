// SPDX-License-Identifier: Apache-2.0

//go:build unix

package transcript

import "syscall"

// setTranscriptUmask sets goKit.ts's TRANSCRIPT_UMASK.
func setTranscriptUmask() { syscall.Umask(0o022) }
