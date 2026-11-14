// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import "github.com/varlatch/varlatch/go/lib/envelope"

// SealValue seals one value version under its Organization's KEK, as
// domain/values.ts setValue does with encryptValue: a fresh DEK opens the
// payload, and the KEK wraps the DEK, each bound to the Organization, the
// value row and the version (ADR-0011). The writes that use it come in
// ADR-0059 step 4; the conformance seed and the G3 tests use it now.
func SealValue(orgKEK []byte, organizationID, valueID, versionID string, plaintext []byte) (envelope.EncryptedValue, error) {
	return envelope.EncryptValue(orgKEK, organizationID, valueID, versionID, plaintext)
}
