// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ids makes domain IDs as the TypeScript server does (db/ids.ts,
// ADR-0018 §5): a typed prefix, "_", and 128 random bits in lowercase
// base32 without padding.
package ids

import (
	"crypto/rand"
	"fmt"
)

// The prefixes in use, by db/ids.ts's kind names.
const (
	Installation       = "inst"
	AuditEvent         = "evt"
	OrganizationFreeze = "ofz"
	Identity           = "idn"
	Credential         = "crd"
	SetupGrant         = "sgr"
	DeviceSignIn       = "dsi"
	// DeviceSignInChallenge and PasskeyConfirmationChallenge are the
	// challenges of a device sign-in approval and a passkey confirmation.
	DeviceSignInChallenge        = "dsc"
	PasskeyConfirmationChallenge = "pcc"
	// ApprovalIntent and ApprovalIntentChallenge are a step-up approval
	// and its challenges (ADR-0054 Decision 3).
	ApprovalIntent          = "apr"
	ApprovalIntentChallenge = "apc"
	// AuthSession and Passkey name rows of the tables varlatchd owns since
	// Better Auth left (ADR-0059 Decision 6); the TypeScript server's rows
	// keep the ids Better Auth gave them.
	AuthSession = "ses"
	Passkey     = "pky"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz234567"

// New returns a new ID with the prefix.
func New(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	out := append([]byte(prefix), '_')
	acc, bits := 0, 0
	for _, c := range b {
		acc = acc<<8 | int(c)
		bits += 8
		for bits >= 5 {
			out = append(out, alphabet[(acc>>(bits-5))&31])
			bits -= 5
		}
		acc &= 1<<bits - 1
	}
	if bits > 0 {
		out = append(out, alphabet[(acc<<(5-bits))&31])
	}
	return string(out)
}

// UUID returns a random (version 4) UUID in lowercase, as Node's
// crypto.randomUUID: the archive and maintenance gate IDs.
func UUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
