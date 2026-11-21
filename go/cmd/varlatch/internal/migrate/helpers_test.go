// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"crypto/rand"
	"encoding/hex"
)

// Helpers every platform's tests use.

func randomBytes(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
func hexOf(b []byte) string    { return hex.EncodeToString(b) }
