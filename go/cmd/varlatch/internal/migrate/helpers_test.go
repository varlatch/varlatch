// SPDX-License-Identifier: Apache-2.0

//go:build linux

package migrate

import (
	"crypto/rand"
	"encoding/hex"
)

// Helpers the Linux tests use.

func randomBytes(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
func hexOf(b []byte) string    { return hex.EncodeToString(b) }
