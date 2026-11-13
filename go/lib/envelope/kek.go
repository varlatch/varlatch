// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"encoding/hex"
	"fmt"
	"unicode/utf16"
)

// ParseRootKEK reads Root KEK material (the contents of VARLATCH_KEK_FILE,
// or VARLATCH_KEK) exactly as the TypeScript server's parseKekMaterial does
// (services/varlatchd/src/config.ts), so that every key file an operator
// uses today keeps working: trimmed as JavaScript trims, then 64 hex digits,
// or else base64 read the way Node reads it (any mix of the standard and URL
// alphabets, padding optional, other characters skipped, stopping at the
// first '='). The result must be 32 bytes. The error never echoes the
// material.
func ParseRootKEK(material string) ([]byte, error) {
	units := jsTrim(utf16.Encode([]rune(material)))
	var key []byte
	if isHex64(units) {
		b := make([]byte, len(units))
		for i, u := range units {
			b[i] = byte(u)
		}
		var err error
		if key, err = hex.DecodeString(string(b)); err != nil {
			return nil, fmt.Errorf("envelope: Root KEK material is not valid hex")
		}
	} else {
		key = nodeBase64Units(units)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("envelope: Root KEK must be %d bytes (got %d); generate one with: openssl rand -hex 32", KeySize, len(key))
	}
	return key, nil
}

func isHex64(units []uint16) bool {
	if len(units) != 64 {
		return false
	}
	for _, u := range units {
		if !(u >= '0' && u <= '9' || u >= 'a' && u <= 'f' || u >= 'A' && u <= 'F') {
			return false
		}
	}
	return true
}

// jsTrimSet is what JavaScript's String.prototype.trim removes (checked
// against Node by the fixtures): WhiteSpace and LineTerminator.
var jsTrimSet = map[uint16]bool{
	0x09: true, 0x0a: true, 0x0b: true, 0x0c: true, 0x0d: true, 0x20: true, 0xa0: true,
	0x1680: true, 0x2000: true, 0x2001: true, 0x2002: true, 0x2003: true, 0x2004: true,
	0x2005: true, 0x2006: true, 0x2007: true, 0x2008: true, 0x2009: true, 0x200a: true,
	0x2028: true, 0x2029: true, 0x202f: true, 0x205f: true, 0x3000: true, 0xfeff: true,
}

func jsTrim(units []uint16) []uint16 {
	start, end := 0, len(units)
	for start < end && jsTrimSet[units[start]] {
		start++
	}
	for end > start && jsTrimSet[units[end-1]] {
		end--
	}
	return units[start:end]
}

// nodeBase64 decodes s as Node's Buffer.from(s, "base64") does.
func nodeBase64(s string) []byte {
	return nodeBase64Units(utf16.Encode([]rune(s)))
}

// nodeBase64Units decodes JavaScript string code units as Node does: each
// unit's low byte counts; '=' ends the input; characters outside the
// standard and URL alphabets are skipped; a final partial byte is dropped.
func nodeBase64Units(units []uint16) []byte {
	out := make([]byte, 0, len(units)*3/4)
	var acc uint32
	bits := 0
	for _, u := range units {
		c := byte(u)
		if c == '=' {
			break
		}
		v, ok := base64Value(c)
		if !ok {
			continue
		}
		acc = acc<<6 | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
			acc &= 1<<bits - 1
		}
	}
	return out
}

func base64Value(c byte) (byte, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A', true
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26, true
	case c >= '0' && c <= '9':
		return c - '0' + 52, true
	case c == '+' || c == '-':
		return 62, true
	case c == '/' || c == '_':
		return 63, true
	}
	return 0, false
}
