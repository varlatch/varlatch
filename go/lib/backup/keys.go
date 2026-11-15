// SPDX-License-Identifier: Apache-2.0

package backup

import "github.com/varlatch/varlatch/go/lib/envelope"

// CheckKeys reports whether the candidate Root KEKs, by key version, open
// every canary the manifest names: the keys restoring the archive needs
// (packages/backup checkKeys: each canary opens and holds 32 bytes). A
// version without a candidate fails.
func CheckKeys(m Manifest, candidates map[int][]byte) bool {
	for _, c := range m.Canaries {
		key, ok := candidates[c.Version]
		if !ok {
			return false
		}
		env := envelope.Envelope{
			FormatVersion: c.Envelope.FormatVersion, Algorithm: c.Envelope.Algorithm,
			Nonce: c.Envelope.Nonce, Ciphertext: c.Envelope.Ciphertext, AuthTag: c.Envelope.AuthTag,
		}
		// The canary opens, and holds 32 bytes.
		plain, err := envelope.Open(key, env, envelope.KEKCanaryContext(m.InstallationID))
		ok = err == nil && len(plain) == 32
		clear(plain)
		if !ok {
			return false
		}
	}
	return true
}

// CanaryOf is a manifest's canary for a key version, from its envelope.
func CanaryOf(version int, e envelope.Envelope) Canary {
	return Canary{Version: version, Envelope: CanaryEnvelope{
		FormatVersion: e.FormatVersion, Algorithm: e.Algorithm, Nonce: e.Nonce, Ciphertext: e.Ciphertext, AuthTag: e.AuthTag,
	}}
}
