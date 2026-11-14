// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ids makes domain IDs as the TypeScript server does (db/ids.ts,
// ADR-0018 §5): a typed prefix, "_", and 128 random bits in lowercase
// base32 without padding.
package ids

import "crypto/rand"

// The prefixes in use, by db/ids.ts's kind names.
const (
	Installation       = "inst"
	AuditEvent         = "evt"
	OrganizationFreeze = "ofz"
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
