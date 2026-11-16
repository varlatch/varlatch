// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
)

// SealedBox is libsodium's crypto_box_seal, as GitHub's secret encryption
// requires: an ephemeral X25519 key pair, nonce = BLAKE2b-24(epk ||
// recipient), output = epk || box(message). recipient must be 32 bytes.
func SealedBox(message, recipient []byte) ([]byte, error) {
	return sealWith(rand.Reader, message, recipient)
}

// sealWith seals with the ephemeral key read from random (a fixed one in
// the vectors).
func sealWith(random io.Reader, message, recipient []byte) ([]byte, error) {
	if len(recipient) != 32 {
		// tweetnacl's own refusal (nacl.box checks the key's size).
		return nil, &ScriptError{Name: "Error", Message: "bad public key size"}
	}
	var pk [32]byte
	copy(pk[:], recipient)
	epk, esk, err := box.GenerateKey(random)
	if err != nil {
		return nil, err
	}
	nonce, err := sealNonce(epk[:], pk[:])
	if err != nil {
		return nil, err
	}
	return box.Seal(append([]byte(nil), epk[:]...), message, &nonce, &pk, esk), nil
}

// SealedBoxOpen is the counterpart, for tests: the message, or false.
func SealedBoxOpen(sealed, recipient, secret []byte) ([]byte, bool) {
	if len(sealed) < 32+box.Overhead || len(recipient) != 32 || len(secret) != 32 {
		return nil, false
	}
	var epk, pk, sk [32]byte
	copy(epk[:], sealed[:32])
	copy(pk[:], recipient)
	copy(sk[:], secret)
	nonce, err := sealNonce(epk[:], pk[:])
	if err != nil {
		return nil, false
	}
	return box.Open(nil, sealed[32:], &nonce, &epk, &sk)
}

func sealNonce(epk, pk []byte) ([24]byte, error) {
	var nonce [24]byte
	h, err := blake2b.New(24, nil)
	if err != nil {
		return nonce, err
	}
	h.Write(epk)
	h.Write(pk)
	copy(nonce[:], h.Sum(nil))
	return nonce, nil
}

// nodeBase64 is Buffer.from(s, "base64"): Node's forgiving decoder, which
// takes both alphabets, skips every other character (a JavaScript string's
// UTF-16 code units, by their low byte), and stops at the first "=".
func nodeBase64(s string) []byte {
	var out []byte
	var acc uint32
	n := 0
	for _, unit := range codeUnits(s) {
		c := byte(unit)
		if c == '=' {
			break
		}
		v, ok := base64Value(c)
		if !ok {
			continue
		}
		acc = acc<<6 | uint32(v)
		n++
		if n == 4 {
			out = append(out, byte(acc>>16), byte(acc>>8), byte(acc))
			acc, n = 0, 0
		}
	}
	switch n {
	case 2:
		out = append(out, byte(acc>>4))
	case 3:
		out = append(out, byte(acc>>10), byte(acc>>2))
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

// codeUnits is s's UTF-16 code units; a lone surrogate (WTF-8) is one, a
// byte that is not UTF-8 is U+FFFD.
func codeUnits(s string) []uint16 {
	var out []uint16
	for i := 0; i < len(s); {
		if sur, ok := surrogateAt(s, i); ok {
			out = append(out, uint16(sur))
			i += 3
			continue
		}
		r, size := decodeRune(s[i:])
		if r >= 0x10000 {
			r -= 0x10000
			out = append(out, uint16(0xd800+(r>>10)), uint16(0xdc00+(r&0x3ff)))
		} else {
			out = append(out, uint16(r))
		}
		i += size
	}
	return out
}
